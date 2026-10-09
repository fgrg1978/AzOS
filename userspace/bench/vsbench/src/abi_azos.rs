// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! Azos backend: the same measurements over `libsys`.
//!
//! Deliberately thin. Anything clever here — batching, caching, a fast path
//! that the Linux side does not get — would be measuring this file instead of
//! the kernel.

use super::bench_core::{
    Abi, Ipc, Mem, Net, Proc, Role, Shell, Vdso, NET_PAYLOAD, NET_POLL_BUDGET, SPAWN_NAP_NS,
};
use azos_libsys as sys;

pub struct AzosAbi;

impl super::bench_core::Threads for AzosAbi {
    fn thread_spawn(entry: extern "C" fn() -> !, stack_top: usize, ctid: &'static core::sync::atomic::AtomicU32) -> i64 {
        ctid.store(u32::MAX, core::sync::atomic::Ordering::Release);
        // The native entry is called with `(0, stack, arg)`; a body that takes
        // nothing ignores them (the C ABI passes them in registers).
        let entry: sys::ThreadEntry = unsafe { core::mem::transmute(entry) };
        sys::thread_create(entry, stack_top, 0, ctid.as_ptr()) as i64
    }
    fn thread_exit() -> ! { sys::thread_exit(0) }
    fn futex_wait(w: &core::sync::atomic::AtomicU32, val: u32) -> i64 { sys::futex_wait(w, val, 0) as i64 }
    fn futex_wake(w: &core::sync::atomic::AtomicU32, n: u32) -> i64 { sys::futex_wake(w, n) as i64 }
    fn join_wait(w: &core::sync::atomic::AtomicU32, val: u32) -> i64 { sys::futex_wait(w, val, 0) as i64 }
}

impl Abi for AzosAbi {
    /// `getpid`: this kernel's cheapest ring crossing, and the one `latbench`
    /// already uses as its floor — so the two benchmarks are quoting the same
    /// baseline and their numbers can be read side by side.
    #[inline(always)]
    fn ctx_switches(&self) -> Option<(u64, u64)> {
        let mut buf = [0u8; sys::TASKINFO_BYTES];
        if sys::taskinfo(&mut buf) != sys::TASKINFO_BYTES as isize { return None; }
        // Fields 2 and 3 of the blob: voluntary, preempted. See SYS_TASKINFO.
        let g = |i: usize| u64::from_le_bytes(buf[i * 8..i * 8 + 8].try_into().unwrap());
        Some((g(2), g(3)))
    }

    /// Slot 4 of the same blob.
    fn current_cpu(&self) -> Option<u64> {
        let mut buf = [0u8; sys::TASKINFO_BYTES];
        if sys::taskinfo(&mut buf) != sys::TASKINFO_BYTES as isize { return None; }
        Some(u64::from_le_bytes(buf[32..40].try_into().unwrap()))
    }

    fn null_syscall(&self) {
        core::hint::black_box(sys::getpid());
    }

    #[inline(always)]
    fn yield_now(&self) {
        core::hint::black_box(sys::yield_now());
    }

    fn write(&self, bytes: &[u8]) {
        sys::print(bytes);
    }

    /// `/fat/VSBLANES.TXT`, which only a filtered run's disk carries.
    fn lanes(&self) -> super::bench_core::Lanes {
        let h = sys::file_open_typed(b"/fat/VSBLANES.TXT\0", 0);
        if h < 0 { return super::bench_core::Lanes::all(); }
        let mut buf = [0u8; super::bench_core::LANES_MAX];
        let n = sys::file_read_typed(h as u32, &mut buf);
        let _ = sys::close_typed(h as u32);
        if n <= 0 { return super::bench_core::Lanes::all(); }
        super::bench_core::Lanes::from_bytes(&buf[..n as usize])
    }
}

impl Ipc for AzosAbi {
    /// The peer is an **exec'd image**, not a `fork()`ed child, and
    /// `Role::Server` is therefore never returned on this ABI.
    ///
    /// **Why it had to change (RFC-0040 gap 2 stage 4).** A forked child
    /// cannot be addressed by capability: it inherits no capability table
    /// (`sched::process::sys_fork_impl` touches none) and an endpoint's owner
    /// is fixed when the capability is SEEDED, by image name. Retiring
    /// `SYS_IPC_FAST_CALL` (108) required this lane to stop naming a TID, and
    /// that required the peer to become `VSSRV.ELF`.
    ///
    /// **This changes what the lane measures**, and not only its addressing:
    /// the peer is now a separate address space rather than a COW fork of
    /// this one. The figure is not comparable with the published 2,806 for
    /// that reason as well — both baselines are recorded in
    /// `rfcs/RFC-0040-gap2-stage4-design.md`.
    ///
    /// The returned `u64` is a capability HANDLE, not a TID. `round_trip`
    /// below is the only reader and passes it to `SYS_IPC_FAST_CALL_EP`.
    fn spawn_peer(&self) -> Option<Role> {
        if sys::spawn(sys::cstr!(b"/fat/VSSRV.ELF")) <= 0 {
            return None;
        }
        // Pool index 1 is `endpoint.bench`; 0 is `endpoint.demo`. Ring 3 has
        // no by-name endpoint lookup, so this depends on the seeding order of
        // the topology rows — which `tests/host/topology-tests` asserts, so a
        // reordering fails a test instead of pointing this benchmark at the
        // wrong service.
        match sys::cap_lookup(sys::CapKind::Endpoint as u8, 1) {
            h if h > 0 => Some(Role::Client(h as u64)),
            _ => None,
        }
    }

    /// One `SYS_IPC_FAST_CALL_EP`: request, block, and collect the reply in a
    /// single ring crossing. That this is *one* syscall where the Linux side
    /// needs two is the thing being measured.
    ///
    /// `peer` is a `Cap<Endpoint>` handle, not a TID — see `spawn_peer`. The
    /// kernel resolves it through this task's own capability table, so a
    /// caller holding no endpoint capability can reach nothing, which is the
    /// property 108 never had and the reason this lane moved.
    #[inline(always)]
    fn round_trip(&self, peer: u64, val: u64) -> Result<u64, i64> {
        // `fast_ipc_call_ep` collapses the kernel's error code into `None`; go
        // one level down so a failure can be named rather than guessed.
        match sys::fast_ipc_call_ep_full(peer as u32, [val, 0, 0, 0]) {
            Some(r) => Ok(r[0]),
            None => Err(-1),
        }
    }

    /// The server half, written the way a real server is: `SYS_IPC_FAST_REPLY_ACCEPT`
    /// answers one request and takes the next in a single ring crossing, so a
    /// round trip is TWO traps (the client's call, the server's reply-and-accept)
    /// rather than three. That is seL4's `Call` + `ReplyRecv` pair, which is the
    /// figure its published IPC numbers describe; a server that replies and then
    /// accepts as two calls pays a whole extra trap per exchange for nothing.
    ///
    /// **This changed what `ipc-roundtrip` measures on 2026-09-18.** The server
    /// used to reply and accept separately (3,706 instructions per round trip at
    /// one hart, 4,021 before the TID lookup change). Recorded in RFC-0045, because
    /// a lane that quietly measures a different protocol is how a "win" is born.
    /// **Unreachable on this ABI.** Since RFC-0040 gap 2 stage 4 the peer is
    /// an exec'd image (`VSSRV.ELF`), so `spawn_peer` never answers
    /// `Role::Server` and nothing calls this.
    ///
    /// It exits rather than serving, and that is the point: carrying the loop
    /// here would put `SYS_IPC_FAST_ACCEPT`, `_REPLY` and `_REPLY_ACCEPT` in
    /// `VSBENCH.ELF`'s seccomp profile — authority the client does not need,
    /// which `tests/host/seccomp-tests` correctly refuses to let a row grant.
    fn serve(&self, _bound: u64) -> ! {
        sys::println(b"[vsbench] BUG: serve() reached; the peer is VSSRV.ELF");
        sys::exit(2);
        #[allow(unreachable_code)]
        loop {}
    }
}

impl Mem for AzosAbi {
    /// This kernel's `mmap` is anonymous-only: `fd` must be `MAP_ANON_FD` and
    /// `addr`/`flags`/`offset` are ignored -- the mapping always lands at the
    /// current brk. `prot` is honoured since wave 13 (read-write here, the
    /// Linux side's `PROT_READ | PROT_WRITE`).
    fn map(&self, len: u64) -> Result<u64, i64> {
        match sys::mmap(0, len, sys::PROT_READ | sys::PROT_WRITE, 0, sys::MAP_ANON_FD, 0) {
            r if r < 0 => Err(r as i64),
            r => Ok(r as u64),
        }
    }

    fn unmap(&self, base: u64, len: u64) -> Result<(), i64> {
        match sys::munmap(base, len) {
            r if r < 0 => Err(r as i64),
            _ => Ok(()),
        }
    }
}

impl Proc for AzosAbi {
    fn brk_grow(&self, delta: u64) -> Result<u64, i64> {
        // `brk(0)` queries without moving, which is how the base is found.
        let cur = sys::brk(0);
        if cur < 0 { return Err(cur as i64); }
        match sys::brk(cur as u64 + delta) {
            r if r < 0 => Err(r as i64),
            r => Ok(r as u64),
        }
    }

    fn spawn_peer_raw(&self) -> Option<bool> {
        match sys::fork() {
            0 => Some(true),
            tid if tid > 0 => Some(false),
            _ => None,
        }
    }

    fn exit_child(&self) -> ! { sys::exit(0) }

    fn fork_exit(&self) -> Result<(), i64> {
        // The full cycle, the child's exit inside the caller's window: see
        // `Proc::fork_exit` (wave 14).
        self.fork_exit_wait()
    }

    fn fork_exit_wait(&self) -> Result<(), i64> {
        let child = match sys::fork() {
            0 => sys::exit(0),
            tid if tid > 0 => tid,
            e => return Err(e as i64),
        };
        // `sys::waitpid`, not `sys::wait` — and that is what makes this lane
        // and the Linux one the same operation.
        //
        // `wait` returns the FIRST finished child of this task, so the version
        // of this lane that used it had to consume and discard notices left by
        // `fork_exit` above (which, until wave 11, forked N_PROC children and reaped none). The
        // Linux side calls `wait4(pid, ..)`, which targets one child. Two
        // different operations timed against each other is the comparison this
        // whole file refuses elsewhere.
        //
        // `SYS_WAITPID` (562) was added because this lane needed it. Its `-1`
        // means "that child is still running"; `-ECHILD` (-10) means it is not
        // ours or was already reaped, and no amount of polling changes that —
        // so an unexpected `-ECHILD` is reported rather than spun on.
        for _ in 0..POLL_BOUND {
            let r = sys::waitpid(child as u32, core::ptr::null_mut());
            if r == child {
                return Ok(());
            }
            if r == -10 {
                // Before wave 12, reachable when the notice was evicted:
                // `note_exit`'s table held 32 entries and dropped the OLDEST
                // when full, and the lane above left N_PROC unreaped (until
                // wave 11). Notices are kept until reaped since wave 12, so
                // this is a real loss and not a slow child.
                return Err(-2003);
            }
            self.yield_now();
        }
        Err(-2002)
    }
}

/// The image the `spawn+wait` lane starts, NUL-terminated for
/// `SYS_SPAWN_EX`: the shell's multicall tool, which the volume carries for
/// this lane (`build/disk-vsbench.img`). `VSBENCH.ELF` runs under the
/// `autorun` row, which grants `Cap<Launch>` on it in QEMU builds only
/// (`azos_topology`, feature `ipc-endpoint-canary`).
const SPAWN_IMAGE: &[u8] = b"/fat/TOOLBOX.ELF\0";
/// argv: the applet that exits 0 at once.
const SPAWN_ARGV: &[u8] = b"true\0";

impl Shell for AzosAbi {
    fn spawn_wait(&self) -> Result<(), i64> {
        let req = sys::SpawnReq {
            version: sys::SPAWN_REQ_VERSION,
            argv_ptr: SPAWN_ARGV.as_ptr() as u64,
            argv_bytes: SPAWN_ARGV.len() as u32,
            argc: 1,
            ..sys::SpawnReq::default()
        };
        let child = sys::spawn_ex(SPAWN_IMAGE, Some(&req));
        if child <= 0 {
            return Err(child as i64);
        }
        // Targeted, polled, and a SLEEP between looks (`SPAWN_NAP_NS`): the
        // child runs below this task's priority.
        let mut status = -1i32;
        for _ in 0..POLL_BOUND {
            let r = sys::waitpid(child as u32, &mut status as *mut i32);
            if r == child {
                return if status == 0 { Ok(()) } else { Err(-2005) };
            }
            if r == -10 {
                return Err(-2003);
            }
            let _ = sys::sleep_until_ns(sys::vdso_now_ns() + SPAWN_NAP_NS);
        }
        Err(-2002)
    }

    fn pipe_open(&self) -> Result<(u64, u64), i64> {
        let mut ends = [0u32; 2];
        match sys::pipe_typed(&mut ends, 0) {
            0 => Ok((ends[0] as u64, ends[1] as u64)),
            e => Err(e as i64),
        }
    }

    fn pipe_rw(&self, r: u64, w: u64, buf: &mut [u8]) -> Result<(), i64> {
        let n = sys::write(w, buf);
        if n != buf.len() as isize {
            return Err(n as i64);
        }
        let m = sys::read(r, buf);
        if m != buf.len() as isize {
            return Err(m as i64);
        }
        Ok(())
    }

    fn pipe_close(&self, r: u64, w: u64) {
        let _ = sys::close_typed(r as u32);
        let _ = sys::close_typed(w as u32);
    }

    fn fd_read(&self, fd: u64, buf: &mut [u8]) -> isize { sys::read(fd, buf) }

    fn fd_write(&self, fd: u64, buf: &[u8]) -> isize { sys::write(fd, buf) }

    fn fd_close(&self, fd: u64) { let _ = sys::close_typed(fd as u32); }

    fn file_open_read_close(&self, buf: &mut [u8]) -> Result<(), i64> {
        let h = sys::file_open_typed(b"/fat/VSBENCH.ELF\0", 0);
        if h < 0 {
            return Err(h as i64);
        }
        let n = sys::file_read_typed(h as u32, buf);
        let _ = sys::close_typed(h as u32);
        if n != buf.len() as isize {
            return Err(n as i64);
        }
        Ok(())
    }

    /// The native `dup`: libsys aliases the small fd's handle and the close
    /// of the alias drops it again, both in user space (no kernel `dup`,
    /// owner decision 38; only the LAST close of a handle traps).
    fn file_dup_close(&self, fd: u64) -> Option<Result<(), i64>> {
        let d = sys::dup(fd);
        if d < 0 {
            return Some(Err(d as i64));
        }
        let c = sys::close(d as u64);
        if c != 0 {
            return Some(Err(c as i64));
        }
        Some(Ok(()))
    }

    /// `VSBENCH.ELF` opened read-only and installed at the lowest closed
    /// small fd from 3, which `file_dup_close` duplicates.
    fn file_hold(&self) -> Result<u64, i64> {
        let Some(fd) = (3..sys::FD_TABLE_LEN as u64).find(|&f| sys::fd_get(f) == sys::FdEntry::Closed) else {
            return Err(-24); // EMFILE
        };
        let h = sys::file_open_typed(b"/fat/VSBENCH.ELF\0", 0);
        if h < 0 {
            return Err(h as i64);
        }
        sys::fd_install(fd, h as u32);
        Ok(fd)
    }

    fn file_release(&self, fd: u64) {
        let _ = sys::close(fd);
    }

    fn tmp_setup(&self) -> Result<(), i64> {
        // O_RDWR | O_CREAT: the tree grant on `/tmp` admits the create.
        let h = sys::file_open_typed(TMP_PATH, 0x42);
        if h < 0 {
            return Err(h as i64);
        }
        let n = sys::file_write_typed(h as u32, &[0x5Au8; 64]);
        let _ = sys::close_typed(h as u32);
        if n != 64 {
            return Err(n as i64);
        }
        Ok(())
    }

    fn disk_setup(&self) -> Result<(), i64> { Ok(()) }

    fn disk_write_close(&self, data: &[u8], fsync: bool) -> Result<(), i64> {
        // O_RDWR | O_CREAT | O_TRUNC.
        let h = sys::file_open_typed(DISK_PATH, 0x242);
        if h < 0 {
            return Err(h as i64);
        }
        let n = sys::file_write_typed(h as u32, data);
        let s = if fsync { sys::fsync_typed(h as u32) } else { 0 };
        let c = sys::close_typed(h as u32);
        if n != data.len() as isize { return Err(n as i64); }
        if s != 0 { return Err(s as i64); }
        if c != 0 { return Err(c as i64); }
        Ok(())
    }

    fn tmp_open_read_close(&self, buf: &mut [u8]) -> Result<(), i64> {
        let h = sys::file_open_typed(TMP_PATH, 0);
        if h < 0 {
            return Err(h as i64);
        }
        let n = sys::file_read_typed(h as u32, buf);
        let _ = sys::close_typed(h as u32);
        if n != buf.len() as isize {
            return Err(n as i64);
        }
        Ok(())
    }
}

/// `tmp-ord`'s file: ramfs, under the autorun row's `/tmp` tree grant.
const TMP_PATH: &[u8] = b"/tmp/VSB.TMP\0";
/// Wave 15 `file-write`: a FAT32 file on the boot disk.
const DISK_PATH: &[u8] = b"/fat/VSBW.DAT\0";

/// Poll attempts before `fork_exit_wait` gives up.
///
/// Sized to be unreachable in a working system and small enough that a broken
/// one fails in seconds instead of hanging the gate.
const POLL_BOUND: u32 = 100_000;

impl Vdso for AzosAbi {
    /// The page is mapped into every process, and `vdso_uptime_ticks` returns
    /// 0 if the magic does not match. A 0 here would mean "no vDSO", not "the
    /// clock reads zero": the counter is monotonic and has already advanced by
    /// the time this runs.
    fn vdso_ready(&self) -> bool {
        sys::vdso_uptime_ticks() != 0
    }

    #[inline(always)]
    fn clock_vdso(&self) -> u64 {
        // **Exact nanoseconds**, not the page's cooked value.
        //
        // This used to be `vdso_uptime_ms()`, which is cheap (28 ns) and hands
        // back a number with **10 ms granularity**: refreshed by the ISR at
        // 100 Hz. Comparing that with Linux's `__vdso_clock_gettime`, which
        // gives exact nanoseconds, was comparing two different products under
        // the same label.
        //
        // It now does what Linux does: read `rdtime` and convert with the
        // frequency the page publishes. Same product, so the price can finally
        // be compared.
        sys::vdso_now_ns()
    }

    #[inline(always)]
    fn clock_syscall(&self) -> u64 {
        // `SYS_UPTIME`: the SAME quantity the page serves, via the trap.
        // Them being the same quantity is what makes the ratio mean anything:
        // if one gave ticks and the other milliseconds, the difference would
        // include the conversion arithmetic and not just the mechanism.
        sys::uptime_ecall() as u64
    }

    /// This kernel does not publish CPU identity in the vDSO page.
    ///
    /// Reported as absent rather than improvising an equivalent: the Linux
    /// vDSO serves `getcpu`, and our not doing so is precisely the kind of
    /// difference this lane exists to show.
    fn cpu_vdso(&self) -> Option<u64> { None }
    fn cpu_syscall(&self) -> Option<u64> { None }
}

/// The process's local socket, set by `net_setup`. An `UnsafeCell` rather than
/// `static mut` to avoid the `static_mut_refs` lint — this tree treats warnings
/// as failures.
struct NetSlot(core::cell::UnsafeCell<(isize, bool)>);
unsafe impl Sync for NetSlot {}
static NET: NetSlot = NetSlot(core::cell::UnsafeCell::new((-1isize, false)));
/// The egress lane's socket (`egress_setup`).
static EGRESS: NetSlot = NetSlot(core::cell::UnsafeCell::new((-1isize, false)));
/// The TCP bulk lanes' stream (`tcp_open`).
static TCP: NetSlot = NetSlot(core::cell::UnsafeCell::new((-1isize, false)));
/// How many sends the current TCP bulk stream had refused (see `tcp_send`).
static TCP_REFUSED: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

impl Net for AzosAbi {
    fn net_ready(&self) -> bool {
        // With no IP assigned there is no local delivery: the loopback in
        // `ip::send` is conditioned on `dst == our_ip` and with `0.0.0.0` it is
        // deliberately off.
        sys::net_getip() > 0
    }

    fn net_setup(&self, local_port: u16, peer_port: u16) -> Result<(), i64> {
        let raw = sys::net_getip();
        if raw <= 0 { return Err(-1); }
        let ip = (raw as u32).to_be_bytes();

        let fd = sys::socket(2, 2, 0);          // AF_INET, SOCK_DGRAM
        if fd < 0 { return Err(-2000 + fd as i64); }
        let rb = sys::bind(fd as u64, &sys::sockaddr_in(ip, local_port));
        if rb != 0 { return Err(-3000 + rb as i64); }
        let rc = sys::connect(fd as u64, &sys::sockaddr_in(ip, peer_port));
        if rc != 0 { return Err(-4000 + rc as i64); }
        unsafe { *NET.0.get() = (fd, true) };
        Ok(())
    }

    #[inline(always)]
    fn net_round_trip(&self) -> Option<usize> {
        let (fd, ok) = unsafe { *NET.0.get() };
        if !ok { return None; }
        let out = [0xA5u8; NET_PAYLOAD];
        if sys::send(fd as u64, &out, 0) != NET_PAYLOAD as isize { return None; }

        // Poll with yield: this kernel's `recv` does not block. The Linux side
        // does the same with `MSG_DONTWAIT` so the comparison is of one
        // algorithm and not "blocking versus polling".
        let mut buf = [0u8; NET_PAYLOAD];
        for _ in 0..NET_POLL_BUDGET {
            let n = sys::recv(fd as u64, &mut buf, 0);
            if n > 0 { return Some(n as usize); }
            sys::yield_now();
        }
        None
    }

    fn net_stop_echo(&self) {
        let (fd, ok) = unsafe { *NET.0.get() };
        if !ok { return; }
        let _ = sys::send(fd as u64, &[super::bench_core::NET_STOP; NET_PAYLOAD], 0);
    }

    fn egress_setup(&self) -> Result<(), i64> {
        if sys::net_getip() <= 0 { return Err(-1); }
        let fd = sys::socket(2, 2, 0);          // AF_INET, SOCK_DGRAM
        if fd < 0 { return Err(-2000 + fd as i64); }
        let rc = sys::connect(fd as u64, &sys::sockaddr_in([255, 255, 255, 255], 9));
        if rc != 0 { return Err(-4000 + rc as i64); }
        unsafe { *EGRESS.0.get() = (fd, true) };
        Ok(())
    }

    #[inline(always)]
    fn egress_send(&self) -> bool {
        let (fd, ok) = unsafe { *EGRESS.0.get() };
        if !ok { return false; }
        let out = [0x5Au8; NET_PAYLOAD];
        sys::send(fd as u64, &out, 0) == NET_PAYLOAD as isize
    }

    /// `/fat/VSBTCP.TXT`: the port, in decimal. Only the TCP pass's disk
    /// carries it.
    fn tcp_peer_port(&self) -> Option<u16> {
        let h = sys::file_open_typed(b"/fat/VSBTCP.TXT\0", 0);
        if h < 0 { return None; }
        let mut buf = [0u8; 8];
        let n = sys::file_read_typed(h as u32, &mut buf);
        let _ = sys::close_typed(h as u32);
        if n <= 0 { return None; }
        super::bench_core::parse_port(&buf[..n as usize])
    }

    /// The source port is the kernel's: `connect` asks for local port 0 and
    /// the TCP layer picks a free ephemeral one, so back-to-back streams
    /// never share a 4-tuple.
    fn tcp_open(&self, port: u16) -> Result<(), i64> {
        use core::sync::atomic::Ordering::Relaxed;
        let fd = sys::socket(2, 1, 0);          // AF_INET, SOCK_STREAM
        if fd < 0 { return Err(-2000 + fd as i64); }
        TCP_REFUSED.store(0, Relaxed);
        // Blocks until the handshake completes (or fails).
        let rc = sys::connect(fd as u64, &sys::sockaddr_in(super::bench_core::TCP_HOST_IP, port));
        if rc != 0 {
            let _ = sys::sock_shutdown(fd as u64);
            return Err(-4000 + rc as i64);
        }
        unsafe { *TCP.0.get() = (fd, true) };
        Ok(())
    }

    /// 0 when the send window or buffer is full; this kernel copies at most
    /// 1460 bytes per call.
    ///
    /// **-1 is answered as 0 and counted.** `tcp::send_data` answers -1 both
    /// for a connection that cannot send and for a segment that did not leave
    /// (`send_segment_with_window` failed, e.g. the NIC's TX ring full: it
    /// takes the bytes back, so nothing of the call is in the stream and the
    /// connection is intact). The lane cannot tell them apart from the
    /// return value, so it does not try: a dead connection is caught by the
    /// lane's next `recv`, which answers -1 for it, and a stream that stops
    /// moving fails on `TCP_STALL_NS`. The count is printed with the lane
    /// (`sends refused`); 0 in every run so far.
    #[inline(always)]
    fn tcp_send(&self, buf: &[u8]) -> isize {
        let (fd, ok) = unsafe { *TCP.0.get() };
        if !ok { return -1; }
        let r = sys::send(fd as u64, buf, 0);
        if r == -1 {
            TCP_REFUSED.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
            return 0;
        }
        r
    }

    fn tcp_send_refused(&self) -> u64 {
        TCP_REFUSED.load(core::sync::atomic::Ordering::Relaxed)
    }

    /// Runs the stack's receive path (`net_poll`) first, then reads at most
    /// 4096 bytes; -1 once the peer has closed and nothing is left.
    #[inline(always)]
    fn tcp_recv(&self, buf: &mut [u8]) -> isize {
        let (fd, ok) = unsafe { *TCP.0.get() };
        if !ok { return -1; }
        sys::recv(fd as u64, buf, 0)
    }

    fn tcp_close(&self) {
        let (fd, ok) = unsafe { *TCP.0.get() };
        if !ok { return; }
        let _ = sys::sock_shutdown(fd as u64);
        unsafe { *TCP.0.get() = (-1, false) };
    }

    fn net_echo(&self, n: u64) {
        let (fd, ok) = unsafe { *NET.0.get() };
        if !ok { return; }
        let mut buf = [0u8; NET_PAYLOAD];
        let mut served = 0u64;
        while served < n {
            let got = sys::recv(fd as u64, &mut buf, 0);
            if got > 0 && buf[0] == super::bench_core::NET_STOP { return; }
            if got > 0 {
                let _ = sys::send(fd as u64, &buf[..got as usize], 0);
                served += 1;
            } else {
                sys::yield_now();
            }
        }
    }
}
