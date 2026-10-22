// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
// SPDX-FileCopyrightText: 2026 Fernando Rodriguez
//! The micro kernel over a fake machine, with the topology the QEMU image
//! ships (`micro/topology`), parsed and admitted by the same code the image
//! runs.

use azos_abi::cap::{ty, CapHandle};
use azos_abi::error::Errno;
use azos_abi::invoke::{DOMAIN_SELF, DOMAIN_UPTIME, INVOKE_REGS, LOG_CONSOLE_WRITE};
use azos_abi::syscall_nr::*;
use azos_micro::config::*;
use azos_micro::kernel::*;
use azos_micro::pmp_core::{PmpEntry, R, W, X};
use azos_topology::{parse_caps, parse_sched, Topology};

/// The uptime op of the task's own domain, as the six argument registers.
const UPTIME_CALL: [usize; 6] =
    [DOMAIN_SELF.as_raw() as usize, (INVOKE_REGS | DOMAIN_UPTIME as u64) as usize, 0, 0, 0, 0];

const SCHED: &str = include_str!("../../../../micro/topology/SCHED.TOM");
const CAPS: &str = include_str!("../../../../micro/topology/CAPS.in");

extern "C" fn nop(_: usize, _: usize) -> ! {
    loop {}
}

static IMAGES: [Image; 5] = [
    Image { name: "IDLE.ELF", entry: nop },
    Image { name: "ECHO.ELF", entry: nop },
    Image { name: "CAPTEST.ELF", entry: nop },
    Image { name: "SPAWNEE.ELF", entry: nop },
    Image { name: "FAULTER.ELF", entry: nop },
];

struct FakeHw {
    now: u64,
    out: String,
    pmp: [PmpEntry; PMP_ENTRIES],
    programmed: usize,
}

impl Hw for FakeHw {
    fn now(&self) -> u64 {
        self.now
    }
    fn console(&mut self, bytes: &[u8]) {
        self.out.push_str(&String::from_utf8_lossy(bytes));
    }
    fn program_pmp(&mut self, table: &[PmpEntry; PMP_ENTRIES]) {
        self.pmp = *table;
        self.programmed += 1;
    }
    fn read_user(&self, addr: usize, out: &mut [u8]) {
        // SAFETY: tests pass addresses inside buffers they own.
        unsafe { core::ptr::copy_nonoverlapping(addr as *const u8, out.as_mut_ptr(), out.len()) }
    }
}

/// A leaked, aligned block of host memory standing in for a pool.
fn mem(size: usize, align: usize) -> (usize, usize) {
    let v: &'static mut [u8] = Box::leak(vec![0xAAu8; size + align].into_boxed_slice());
    let base = (v.as_ptr() as usize + align - 1) & !(align - 1);
    (base, base + size)
}

fn topology(sched: &'static str, caps: &'static str) -> &'static Topology<'static> {
    let t: &'static mut Topology<'static> = Box::leak(Box::new(Topology::empty()));
    parse_sched(sched.as_bytes(), t).expect("SCHED parses");
    parse_caps(caps.as_bytes(), t).expect("CAPS parses");
    t.admission_check().expect("the topology is admitted");
    t
}

fn with_header(body: &str) -> &'static str {
    Box::leak(format!("format = 5\n{body}").into_boxed_str())
}

struct Sim {
    k: Box<Kernel<'static>>,
    hw: FakeHw,
    code: (usize, usize),
}

impl Sim {
    fn boot(sched: &'static str, caps: &'static str) -> Result<Sim, BootError> {
        let topo = topology(sched, caps);
        // Not a power of two: the window is a TOR pair whatever the host aligned it to.
        let code = mem(0x3ff8, 4);
        let info = BootInfo { code, pool: mem(64 * 1024, 4096), contig: mem(64 * 1024, 4096), gp: 0x1234 };
        let mut hw = FakeHw { now: 1000, out: String::new(), pmp: [PmpEntry::OFF; PMP_ENTRIES], programmed: 0 };
        let mut k = Box::new(Kernel::new());
        k.boot(&mut hw, topo, &IMAGES, info)?;
        Ok(Sim { k, hw, code })
    }

    fn shipped() -> Sim {
        Sim::boot(SCHED, with_header(CAPS)).expect("the shipped topology boots")
    }

    fn slot(&self, name: &str) -> usize {
        self.k.slot_of(name).unwrap_or_else(|| panic!("no row {name}"))
    }

    /// Dispatch until `name` is the task the scheduler runs.
    fn run(&mut self, name: &str) -> usize {
        let want = self.slot(name);
        let got = self.k.schedule(&mut self.hw);
        assert_eq!(got, want, "the scheduler picked slot {got}, wanted {name}");
        want
    }

    /// The running task `slot` executes `ecall`: registers in, result out.
    /// `None` when the call left the task without an answer (it blocked or
    /// ended).
    fn sys(&mut self, slot: usize, nr: u64, a: [usize; 6]) -> Option<isize> {
        assert_eq!(self.k.current(), slot, "only the running task can trap");
        let f = self.k.frame(slot);
        f.x[17] = nr as usize;
        for (i, v) in a.iter().enumerate() {
            f.x[10 + i] = *v;
        }
        let pc = f.pc;
        self.k.syscall(&mut self.hw);
        assert_eq!(self.k.frame(slot).pc, pc + 4, "the ecall is stepped over");
        match self.k.state(slot) {
            State::Calling { .. } | State::Accepting | State::Dead => None,
            _ => Some(self.k.frame(slot).x[10] as isize),
        }
    }

    /// The handle of the endpoint capability `slot` holds for endpoint 0.
    fn ep(&mut self, slot: usize) -> usize {
        self.sys(slot, SYS_CAP_INFO, [0, CAP_INFO_LOOKUP as usize, ty::ENDPOINT.raw() as usize, 0, 0, 0]).expect("lookup answers at once") as usize
    }

    fn reg(&mut self, slot: usize, n: usize) -> usize {
        self.k.frame(slot).x[10 + n]
    }

    fn info(&mut self, slot: usize) -> StartInfo {
        let at = self.reg(slot, 1) as *const StartInfo;
        // SAFETY: the kernel wrote it into the task's region at start; the
        // task's frame was never run, so a1 still points at it.
        unsafe { core::ptr::read(at) }
    }
}

// ── boot ────────────────────────────────────────────────────────────────

#[test]
fn the_shipped_topology_boots_and_the_scheduler_runs_the_most_urgent_row() {
    let mut s = Sim::shipped();
    for name in ["IDLE.ELF", "ECHO.ELF", "CAPTEST.ELF"] {
        assert_eq!(s.k.state(s.slot(name)), State::Ready, "{name} starts");
    }
    for name in ["SPAWNEE.ELF", "FAULTER.ELF"] {
        assert_eq!(s.k.state(s.slot(name)), State::Unborn, "{name} waits for a launch");
    }
    assert!(s.hw.out.contains("[MICRO] 5 tasks, 1 endpoints, 1 pipelines"), "{}", s.hw.out);
    // ECHO (level 8) before CAPTEST (12) before IDLE (31).
    let first = s.run("ECHO.ELF");
    assert_eq!(s.k.current(), first);
}

#[test]
fn a_task_starts_with_its_region_start_block_stack_and_the_images_gp() {
    let mut s = Sim::shipped();
    let cap = s.slot("CAPTEST.ELF");
    let info = s.info(cap);
    assert_eq!(info.n, 3, "the Anon part, the UART window and the contiguous block");
    let anon = info.regions[0];
    assert_eq!((anon.kind, anon.perm), (REGION_ANON, R | W));
    assert_eq!(anon.base as usize, s.reg(cap, 0));
    assert_eq!(info.regions[1].kind, REGION_PHYS);
    assert_eq!(info.regions[1].perm, W, "the row asked for write only");
    assert_eq!(info.regions[1].base as usize, azos_limits::MICRO_UART_BASE);
    assert_eq!(info.regions[2].kind, REGION_CONTIG);
    assert_eq!(info.regions[2].size, 4096);
    assert_eq!(info.regions[2].base % 4096, 0, "a block on its own alignment is one NAPOT entry");
    let sp = s.k.frame(cap).x[2];
    let info_at = s.reg(cap, 1);
    assert_eq!(sp, info_at, "the stack grows down from the start block");
    assert_eq!(sp % 16, 0);
    assert!(sp < anon.base as usize + anon.size as usize);
    assert_eq!(s.k.frame(cap).x[3], 0x1234, "gp");
    assert_eq!(s.k.frame(cap).pc, nop as *const () as usize);
}

#[test]
fn dispatch_loads_the_code_window_then_the_tasks_domain_and_switches_the_rest_off() {
    let mut s = Sim::shipped();
    let echo = s.run("ECHO.ELF");
    let t = s.hw.pmp;
    // The code window: a TOR pair, read + execute, no write.
    assert_eq!(t[0], PmpEntry { cfg: 0, addr: s.code.0 >> 2 });
    assert_eq!(t[1], PmpEntry { cfg: 0x08 | R | X, addr: s.code.1 >> 2 });
    // The echo server's domain is its own part (a TOR pair: a part that is
    // not a power of two) and nothing else.
    let info = s.info(echo);
    assert_eq!(info.n, 1);
    let r = info.regions[0];
    assert_eq!(t[2], PmpEntry { cfg: 0, addr: r.base as usize >> 2 });
    assert_eq!(t[3], PmpEntry { cfg: 0x08 | R | W, addr: (r.base + r.size) as usize >> 2 });
    assert!(t[4..].iter().all(|e| *e == PmpEntry::OFF), "everything else off");
    // The captest task's domain adds the two windows it holds.
    s.sys(echo, SYS_IPC_FAST_ACCEPT, [0; 6]);
    let cap = s.run("CAPTEST.ELF");
    let n: Vec<_> = s.hw.pmp.iter().filter(|e| e.cfg != 0 || e.addr != 0).collect();
    assert!(n.len() >= 6, "code pair, own part pair, UART, block: {n:?}");
    let _ = cap;
}

#[test]
fn a_task_cannot_reach_the_kernel_or_the_grants_but_reaches_what_it_was_given() {
    let mut s = Sim::shipped();
    let cap = s.slot("CAPTEST.ELF");
    let info = s.info(cap);
    let (abase, asize) = (info.regions[0].base as usize, info.regions[0].size as usize);
    s.run("ECHO.ELF");
    // Syscalls that take a pointer are the only way the kernel touches task
    // memory: the console's WRITE op is checked against the domain.
    let echo = s.k.current();
    s.sys(echo, SYS_IPC_FAST_ACCEPT, [0; 6]);
    let cap = s.run("CAPTEST.ELF");
    let msg = b"hello";
    // SAFETY: inside the task's own part.
    unsafe { core::ptr::copy_nonoverlapping(msg.as_ptr(), abase as *mut u8, msg.len()) };
    let console = s.sys(cap, SYS_CAP_INFO, [0, CAP_INFO_LOOKUP as usize, ty::CONSOLE.raw() as usize, 0, 0, 0]).expect("the console handle") as usize;
    let op = (INVOKE_REGS | LOG_CONSOLE_WRITE as u64) as usize;
    assert_eq!(s.sys(cap, SYS_INVOKE, [console, op, abase, 5, 0, 0]), Some(5));
    assert!(s.hw.out.ends_with("hello"), "{}", s.hw.out);
    assert_eq!(s.sys(cap, SYS_INVOKE, [console, op, abase + asize - 2, 5, 0, 0]), Some(-1), "past the part: into the grants");
    assert_eq!(s.sys(cap, SYS_INVOKE, [console, op, s.code.0, 4, 0, 0]), Some(4), "the code window is readable");
    assert_eq!(s.sys(cap, SYS_INVOKE, [console, op, 0x10, 4, 0, 0]), Some(-1), "an address nobody gave it");
    assert_eq!(
        s.sys(cap, SYS_INVOKE, [console, LOG_CONSOLE_WRITE as usize, abase, 5, 0, 0]),
        Some(-(Errno::EINVAL as isize)),
        "the register form only"
    );
}

// ── refusals at boot ────────────────────────────────────────────────────

fn boot_caps(body: &str) -> Result<Sim, BootError> {
    Sim::boot(SCHED, with_header(Box::leak(body.to_string().into_boxed_str())))
}

const IDLE_ROW: &str = "[task.IDLE.ELF]\nclass = \"idle\"\npriority = 31\nmem_pages = 1\nstart = true\ncaps = []\n";

#[test]
fn a_topology_without_an_idle_row_is_refused() {
    let body = "[task.ECHO.ELF]\nclass = \"rt\"\npriority = 8\nmem_pages = 2\nstart = true\ncaps = []\n";
    assert_eq!(boot_caps(body).err(), Some(BootError::NoIdle));
}

#[test]
fn a_row_with_no_image_no_memory_or_too_little_is_refused() {
    let row = |name: &str, pages: &str| format!("{IDLE_ROW}\n[task.{name}]\nclass = \"rt\"\npriority = 8\n{pages}start = true\ncaps = []\n");
    assert_eq!(boot_caps(&row("NOSUCH.ELF", "mem_pages = 2\n")).err(), Some(BootError::UnknownImage(1)));
    assert_eq!(boot_caps(&row("ECHO.ELF", "")).err(), Some(BootError::NoMemBudget(1)));
    // Twelve instances of a 32 KiB row are more than the test's 64 KiB pool.
    let many = format!("{IDLE_ROW}\n[task.ECHO.ELF]\nclass = \"rt\"\npriority = 8\nmem_pages = 8\ninstances = 12\nstart = false\ncaps = []\n");
    assert_eq!(boot_caps(&many).err(), Some(BootError::PoolExhausted));
}

#[test]
fn two_rows_serving_one_endpoint_are_refused() {
    let body = format!(
        "{IDLE_ROW}\n[task.ECHO.ELF]\nclass = \"rt\"\npriority = 8\nmem_pages = 2\nstart = true\ncaps = [ {{ kind = \"endpoint\", target = \"endpoint.echo\", perm = \"r\" }} ]\n\
         [task.CAPTEST.ELF]\nclass = \"rt\"\npriority = 9\nmem_pages = 2\nstart = true\ncaps = [ {{ kind = \"endpoint\", target = \"endpoint.echo\", perm = \"r\" }} ]\n"
    );
    assert_eq!(boot_caps(&body).err(), Some(BootError::TwoServers(2)));
}

#[test]
fn a_domain_that_needs_more_pmp_entries_than_a_task_has_is_refused() {
    // Anon (two entries: the part is not a power of two) plus eight
    // contiguous blocks: ten entries against eight.
    let mut caps = String::new();
    let mut pipes = String::new();
    for i in 0..8 {
        caps += &format!("{{ kind = \"memobj\", target = \"pipeline.p{i}\", perm = \"rw\" }},\n");
        pipes += &format!("[pipeline.p{i}]\ndma_kb = 4\n");
    }
    let body = format!("{IDLE_ROW}\n[task.ECHO.ELF]\nclass = \"rt\"\npriority = 8\nmem_pages = 2\nstart = true\ncaps = [\n{caps}]\n{pipes}");
    let e = boot_caps(&body).err();
    assert!(
        matches!(e, Some(BootError::Domain(1, _)) | Some(BootError::TooManyCaps(1)) | Some(BootError::ContigExhausted)),
        "{e:?}"
    );
}

#[test]
fn a_capability_this_kernel_does_not_mint_or_a_target_it_cannot_resolve_is_refused() {
    let one = |cap: &str| format!("{IDLE_ROW}\n[task.ECHO.ELF]\nclass = \"rt\"\npriority = 8\nmem_pages = 2\nstart = true\ncaps = [ {cap} ]\n");
    assert_eq!(boot_caps(&one("{ kind = \"port\", target = \"gpio.1\", perm = \"rw\" }")).err(), Some(BootError::UnsupportedCap(1)));
    assert_eq!(boot_caps(&one("{ kind = \"device\", target = \"mmio.9\", perm = \"r\" }")).err(), Some(BootError::BadTarget(1)));
    assert_eq!(boot_caps(&one("{ kind = \"device\", target = \"mmio.1\", perm = \"r\" }")).err(), Some(BootError::BadTarget(1)), "the test finisher is write-only");
    assert_eq!(boot_caps(&one("{ kind = \"memobj\", target = \"pipeline.none\", perm = \"r\" }")).err(), Some(BootError::BadTarget(1)));
    assert_eq!(boot_caps(&one("{ kind = \"node\", target = \"NOSUCH.ELF\", perm = \"x\" }")).err(), Some(BootError::BadTarget(1)));
    // An op mask restricts a kernel-hosted interface; micro hosts none, so a row
    // that carries one would run with a wider reach than it declares.
    assert_eq!(boot_caps(&one("{ kind = \"endpoint\", target = \"inspect\", perm = \"r\", ops = 3 }")).err(), Some(BootError::OpMask(1)));
}

// ── syscalls ────────────────────────────────────────────────────────────

/// The ABI cases both kernels' captest run, against this kernel.
struct HostEnv<'a> {
    sim: &'a mut Sim,
    slot: usize,
    results: Vec<(String, bool, isize)>,
}

#[path = "../../../../userspace/tests/captest/src/abi_cases.rs"]
mod shared;

impl HostEnv<'_> {
    fn call(&mut self, nr: u64, a: [usize; 6]) -> isize {
        self.sim.sys(self.slot, nr, a).expect("these calls answer at once")
    }
}

impl shared::Env for HostEnv<'_> {
    fn close_typed(&mut self, handle: usize) -> isize {
        self.call(SYS_CAP_CLOSE, [handle, 0, 0, 0, 0, 0])
    }
    fn cap_lookup(&mut self, kind: usize, resource: usize) -> isize {
        self.call(SYS_CAP_INFO, [0, CAP_INFO_LOOKUP as usize, kind, resource, 0, 0])
    }
    fn fast_call(&mut self, endpoint: usize, w: [usize; 4]) -> isize {
        self.call(SYS_IPC_FAST_CALL_EP, [endpoint, w[0], w[1], w[2], w[3], 0])
    }
    fn fast_reply(&mut self, handle: usize, w: [usize; 4]) -> isize {
        self.call(SYS_IPC_FAST_REPLY, [handle, w[0], w[1], w[2], w[3], 0])
    }
    fn uptime(&mut self) -> usize {
        self.call(SYS_INVOKE, UPTIME_CALL) as usize
    }
    fn report(&mut self, name: &[u8], ok: bool, rc: isize) {
        self.results.push((String::from_utf8_lossy(name).into_owned(), ok, rc));
    }
}

#[test]
fn the_abi_cases_shared_with_the_main_kernels_captest_pass_here() {
    let mut s = Sim::shipped();
    let echo = s.run("ECHO.ELF");
    s.sys(echo, SYS_IPC_FAST_ACCEPT, [0; 6]);
    let cap = s.run("CAPTEST.ELF");
    let mut env = HostEnv { sim: &mut s, slot: cap, results: vec![] };
    shared::run(&mut env);
    let bad: Vec<_> = env.results.iter().filter(|r| !r.1).collect();
    assert!(bad.is_empty(), "failed: {bad:?}");
    assert_eq!(env.results.len(), 8, "every case reported: {:?}", env.results);
}

#[test]
fn canary_the_shared_cases_catch_a_kernel_that_answers_differently() {
    // The same cases against a handle that IS live: closing it succeeds, so
    // a case that expects stale for it would be wrong, and the harness must
    // say so. Proves the cases discriminate rather than pass on anything.
    let mut s = Sim::shipped();
    let echo = s.run("ECHO.ELF");
    s.sys(echo, SYS_IPC_FAST_ACCEPT, [0; 6]);
    let cap = s.run("CAPTEST.ELF");
    let h = s.sys(cap, SYS_CAP_INFO, [0, CAP_INFO_LOOKUP as usize, ty::ENDPOINT.raw() as usize, 0, 0, 0]).unwrap();
    assert!(h > 0, "the row grants the endpoint");
    assert_eq!(s.sys(cap, SYS_CAP_CLOSE, [h as usize, 0, 0, 0, 0, 0]), Some(0), "a live handle closes");
    assert_eq!(
        s.sys(cap, SYS_CAP_CLOSE, [h as usize, 0, 0, 0, 0, 0]),
        Some(-(Errno::ECAPSTALE as isize)),
        "and is stale at once"
    );
    // Without the capability a call reaches no one.
    assert_eq!(s.sys(cap, SYS_IPC_FAST_CALL_EP, [h as usize, 1, 2, 3, 4, 0]), Some(-1));
}

#[test]
fn a_call_is_served_and_the_reply_comes_back_in_the_callers_registers() {
    let mut s = Sim::shipped();
    let echo = s.run("ECHO.ELF");
    assert_eq!(s.sys(echo, SYS_IPC_FAST_ACCEPT, [0; 6]), None, "no request yet: the server waits");
    assert_eq!(s.k.state(echo), State::Accepting);
    let cap = s.run("CAPTEST.ELF");
    let ep = s.sys(cap, SYS_CAP_INFO, [0, CAP_INFO_LOOKUP as usize, ty::ENDPOINT.raw() as usize, 0, 0, 0]).unwrap() as usize;
    assert_eq!(s.sys(cap, SYS_IPC_FAST_CALL_EP, [ep, 10, 20, 30, 40, 0]), None, "the caller waits for the reply");
    // The server was woken with the request in its registers.
    assert_eq!(s.k.state(echo), State::Ready);
    let echo = s.run("ECHO.ELF");
    let handle = s.reg(echo, 0);
    assert_eq!([s.reg(echo, 2), s.reg(echo, 3), s.reg(echo, 4), s.reg(echo, 5)], [10, 20, 30, 40]);
    assert_eq!(s.reg(echo, 1), cap + 1, "the caller's TID");
    assert_eq!(s.reg(echo, 6), 0, "no capability moved");
    // A stranger cannot answer it, and a wrong generation is stale.
    assert_eq!(s.sys(echo, SYS_IPC_FAST_REPLY, [handle ^ 0x100, 1, 1, 1, 1, 0]), Some(-2));
    // The reply: the server answers and waits again; the caller runs with it.
    assert_eq!(s.sys(echo, SYS_IPC_FAST_REPLY_ACCEPT, [handle, 0, 11, 20, 30, 40]), None);
    assert_eq!(s.k.state(echo), State::Accepting);
    let cap = s.run("CAPTEST.ELF");
    assert_eq!([s.reg(cap, 0), s.reg(cap, 1), s.reg(cap, 2), s.reg(cap, 3)], [11, 20, 30, 40]);
}

#[test]
fn a_reply_needs_the_server_the_exchange_and_a_live_handle() {
    let mut s = Sim::shipped();
    let echo = s.run("ECHO.ELF");
    s.sys(echo, SYS_IPC_FAST_ACCEPT, [0; 6]);
    let cap = s.run("CAPTEST.ELF");
    let ep = s.sys(cap, SYS_CAP_INFO, [0, CAP_INFO_LOOKUP as usize, ty::ENDPOINT.raw() as usize, 0, 0, 0]).unwrap() as usize;
    s.sys(cap, SYS_IPC_FAST_CALL_EP, [ep, 1, 2, 3, 4, 0]);
    let echo = s.run("ECHO.ELF");
    let handle = s.reg(echo, 0);
    assert_eq!(s.sys(echo, SYS_IPC_FAST_REPLY, [handle, 5, 6, 7, 8, 0]), Some(0));
    assert_eq!(s.sys(echo, SYS_IPC_FAST_REPLY, [handle, 5, 6, 7, 8, 0]), Some(-2), "once");
    assert_eq!(s.sys(echo, SYS_IPC_FAST_REPLY, [0x7f00, 5, 6, 7, 8, 0]), Some(-2), "an exchange that never was");
    assert_eq!(s.sys(echo, SYS_IPC_FAST_REPLY, [0x7f00 | 200, 5, 6, 7, 8, 0]), Some(-1), "a caller that is no task");
    s.sys(echo, SYS_IPC_FAST_ACCEPT, [0; 6]);
    // The caller cannot answer its own call either: it does not serve.
    let cap = s.run("CAPTEST.ELF");
    assert_eq!(s.sys(cap, SYS_IPC_FAST_REPLY, [handle, 1, 1, 1, 1, 0]), Some(-2), "the call is over");
}

#[test]
fn a_task_that_is_not_the_server_cannot_answer_an_exchange() {
    let mut s = Sim::shipped();
    let echo = s.run("ECHO.ELF");
    s.sys(echo, SYS_IPC_FAST_ACCEPT, [0; 6]);
    let cap = s.run("CAPTEST.ELF");
    let ep = s.sys(cap, SYS_CAP_INFO, [0, CAP_INFO_LOOKUP as usize, ty::ENDPOINT.raw() as usize, 0, 0, 0]).unwrap() as usize;
    s.sys(cap, SYS_IPC_FAST_CALL_EP, [ep, 1, 2, 3, 4, 0]);
    let echo = s.run("ECHO.ELF");
    let handle = s.reg(echo, 0);
    // The server sleeps with the request in hand; the idle task runs and
    // tries to answer it.
    s.sys(echo, SYS_SLEEP_UNTIL, [1000000000, SLEEP_RELATIVE as usize, 0, 0, 0, 0]);
    let idle = s.run("IDLE.ELF");
    assert_eq!(s.sys(idle, SYS_IPC_FAST_REPLY, [handle, 6, 6, 6, 6, 0]), Some(-1), "not the server of this exchange");
    assert_eq!(s.k.state(cap), State::Calling { ep: 0, gen: (handle >> 8) as u16, accepted: true }, "the call is still waiting");
    // An exchange that is not yet accepted cannot be answered by anyone.
    assert_eq!(s.sys(idle, SYS_IPC_FAST_REPLY_ACCEPT, [handle, 0, 6, 6, 6, 6]), Some(-3));
}

#[test]
fn a_server_that_ends_tells_the_callers_waiting_on_it() {
    let mut s = Sim::shipped();
    let echo = s.run("ECHO.ELF");
    s.sys(echo, SYS_IPC_FAST_ACCEPT, [0; 6]);
    let cap = s.run("CAPTEST.ELF");
    let ep = s.sys(cap, SYS_CAP_INFO, [0, CAP_INFO_LOOKUP as usize, ty::ENDPOINT.raw() as usize, 0, 0, 0]).unwrap() as usize;
    s.sys(cap, SYS_IPC_FAST_CALL_EP, [ep, 1, 2, 3, 4, 0]);
    let echo = s.run("ECHO.ELF");
    // The server takes the request and exits without answering.
    assert_eq!(s.sys(echo, SYS_EXIT, [9, 0, 0, 0, 0, 0]), None);
    assert_eq!(s.k.state(echo), State::Dead);
    assert_eq!(s.k.exit_code(echo), 9);
    let cap = s.run("CAPTEST.ELF");
    assert_eq!(s.reg(cap, 0) as isize, -(Errno::EPEERDIED as isize));
    // A later call finds no server.
    assert_eq!(s.sys(cap, SYS_IPC_FAST_CALL_EP, [ep, 1, 2, 3, 4, 0]), Some(-1));
}

#[test]
fn a_task_that_faults_ends_and_is_named() {
    let mut s = Sim::shipped();
    let echo = s.run("ECHO.ELF");
    s.k.fault(&mut s.hw, 7, 0x8000_0000);
    assert_eq!(s.k.state(echo), State::Dead);
    assert_eq!(s.k.exit_code(echo), -1);
    assert!(s.hw.out.contains("ECHO.ELF: fault cause=7 tval=0x80000000"), "{}", s.hw.out);
    assert_eq!(s.k.schedule(&mut s.hw), s.slot("CAPTEST.ELF"), "the next task runs");
}

#[test]
fn sleep_blocks_until_the_tick_after_the_deadline_and_uptime_is_the_timebase() {
    let mut s = Sim::shipped();
    let echo = s.run("ECHO.ELF");
    s.sys(echo, SYS_IPC_FAST_ACCEPT, [0; 6]);
    let cap = s.run("CAPTEST.ELF");
    assert_eq!(s.sys(cap, SYS_INVOKE, UPTIME_CALL), Some(s.hw.now as isize));
    assert_eq!(s.reg(cap, 1), 0, "nothing above a 64-bit word");
    assert_eq!(s.sys(cap, SYS_SLEEP_UNTIL, [5000000, SLEEP_RELATIVE as usize, 0, 0, 0, 0]), Some(0), "the sleeper's result is set in advance");
    assert_eq!(s.k.state(cap), State::Sleeping);
    assert_eq!(s.k.schedule(&mut s.hw), s.slot("IDLE.ELF"));
    s.hw.now += (TIMEBASE_HZ as u64) / 1000 * 4;
    s.k.on_tick(&mut s.hw);
    assert_eq!(s.k.state(cap), State::Sleeping, "4 ms of 5");
    s.hw.now += (TIMEBASE_HZ as u64) / 1000;
    s.k.on_tick(&mut s.hw);
    assert_eq!(s.k.state(cap), State::Ready);
    assert_eq!(s.k.schedule(&mut s.hw), cap);
}

#[test]
fn spawn_ex_starts_a_row_under_a_launch_capability_and_only_then() {
    let mut s = Sim::shipped();
    let echo = s.run("ECHO.ELF");
    s.sys(echo, SYS_IPC_FAST_ACCEPT, [0; 6]);
    let cap = s.run("CAPTEST.ELF");
    let info = s.info(cap);
    let at = info.regions[0].base as usize;
    let put = |name: &[u8]| {
        // SAFETY: inside the task's own part.
        unsafe { core::ptr::copy_nonoverlapping(name.as_ptr(), at as *mut u8, name.len()) };
    };
    put(b"SPAWNEE.ELF\0");
    let tid = s.sys(cap, SYS_SPAWN_EX, [at, 0, 0, 0, 0, 0]).unwrap();
    assert_eq!(tid, s.slot("SPAWNEE.ELF") as isize + 1);
    assert_eq!(s.k.state(s.slot("SPAWNEE.ELF")), State::Ready);
    // No free slot of the row left.
    assert_eq!(s.sys(cap, SYS_SPAWN_EX, [at, 0, 0, 0, 0, 0]), Some(-(Errno::EAGAIN as isize)));
    // A row the caller holds no launch capability for.
    put(b"ECHO.ELF\0");
    assert_eq!(s.sys(cap, SYS_SPAWN_EX, [at, 0, 0, 0, 0, 0]), Some(-(Errno::EACCES as isize)));
    // A name that is no row; a request block (not supported: no arguments).
    put(b"NOSUCH.ELF\0");
    assert_eq!(s.sys(cap, SYS_SPAWN_EX, [at, 0, 0, 0, 0, 0]), Some(-(Errno::EACCES as isize)));
    put(b"SPAWNEE.ELF\0");
    assert_eq!(s.sys(cap, SYS_SPAWN_EX, [at, at, 0, 0, 0, 0]), Some(-(Errno::EINVAL as isize)));
    // A path outside the caller's memory.
    assert_eq!(s.sys(cap, SYS_SPAWN_EX, [0x10, 0, 0, 0, 0, 0]), Some(-(Errno::EFAULT as isize)));
}

#[test]
fn a_spawned_task_has_the_capabilities_of_its_row_and_a_dead_slot_starts_again() {
    let mut s = Sim::shipped();
    let echo = s.run("ECHO.ELF");
    s.sys(echo, SYS_IPC_FAST_ACCEPT, [0; 6]);
    let cap = s.run("CAPTEST.ELF");
    let at = s.info(cap).regions[0].base as usize;
    // SAFETY: inside the task's own part.
    unsafe { core::ptr::copy_nonoverlapping(b"SPAWNEE.ELF\0".as_ptr(), at as *mut u8, 12) };
    s.sys(cap, SYS_SPAWN_EX, [at, 0, 0, 0, 0, 0]).unwrap();
    // CAPTEST (12) is more urgent than SPAWNEE (14): block it to run the child.
    s.sys(cap, SYS_SLEEP_UNTIL, [100000000, SLEEP_RELATIVE as usize, 0, 0, 0, 0]);
    let kid = s.run("SPAWNEE.ELF");
    assert_eq!(s.info(kid).n, 1, "no device, no block: the row declares neither");
    let ep = s.sys(kid, SYS_CAP_INFO, [0, CAP_INFO_LOOKUP as usize, ty::ENDPOINT.raw() as usize, 0, 0, 0]).unwrap();
    assert!(ep > 0, "the child holds the row's endpoint capability");
    let first_incarnation = ep as usize;
    assert_eq!(
        s.sys(kid, SYS_CAP_INFO, [0, CAP_INFO_LOOKUP as usize, ty::LAUNCH.raw() as usize, 3, 0, 0]),
        Some(-(Errno::ENOENT as isize)),
        "and none of its parent's"
    );
    s.sys(kid, SYS_EXIT, [7, 0, 0, 0, 0, 0]);
    assert_eq!(s.k.state(kid), State::Dead);
    assert_eq!(s.k.exit_code(kid), 7);
    // The parent wakes and starts it again: the dead slot is reused with a
    // fresh table.
    s.hw.now += TIMEBASE_HZ as u64;
    s.k.on_tick(&mut s.hw);
    let cap = s.run("CAPTEST.ELF");
    assert_eq!(s.sys(cap, SYS_SPAWN_EX, [at, 0, 0, 0, 0, 0]), Some(kid as isize + 1));
    assert_eq!(s.k.state(kid), State::Ready);
    // The new incarnation's endpoint capability is a later generation of the
    // same slot: the first incarnation's handle names nothing.
    s.sys(cap, SYS_SLEEP_UNTIL, [100000000, SLEEP_RELATIVE as usize, 0, 0, 0, 0]);
    let kid = s.run("SPAWNEE.ELF");
    let second = s.sys(kid, SYS_CAP_INFO, [0, CAP_INFO_LOOKUP as usize, ty::ENDPOINT.raw() as usize, 0, 0, 0]).unwrap() as usize;
    assert_ne!(second, first_incarnation);
    assert_eq!(
        CapHandle::from_raw(second as u32).generation(),
        CapHandle::from_raw(first_incarnation as u32).generation() + 1,
    );
    assert_eq!(
        s.sys(kid, SYS_CAP_CLOSE, [first_incarnation, 0, 0, 0, 0, 0]),
        Some(-(Errno::ECAPSTALE as isize)),
        "a handle of the dead incarnation"
    );
}

#[test]
fn only_the_server_holds_read_on_an_endpoint_and_closing_it_tells_the_callers() {
    let mut s = Sim::shipped();
    let echo = s.run("ECHO.ELF");
    let ep = s.sys(echo, SYS_CAP_INFO, [0, CAP_INFO_LOOKUP as usize, ty::ENDPOINT.raw() as usize, 0, 0, 0]).unwrap();
    assert!(ep > 0);
    // The server has no WRITE: it cannot call its own endpoint.
    assert_eq!(s.sys(echo, SYS_IPC_FAST_CALL_EP, [ep as usize, 1, 2, 3, 4, 0]), Some(-1));
    s.sys(echo, SYS_IPC_FAST_ACCEPT, [0; 6]);
    let cap = s.run("CAPTEST.ELF");
    let h = s.sys(cap, SYS_CAP_INFO, [0, CAP_INFO_LOOKUP as usize, ty::ENDPOINT.raw() as usize, 0, 0, 0]).unwrap() as usize;
    s.sys(cap, SYS_IPC_FAST_CALL_EP, [h, 1, 2, 3, 4, 0]);
    let echo = s.run("ECHO.ELF");
    // The server closes its endpoint instead of answering.
    assert_eq!(s.sys(echo, SYS_CAP_CLOSE, [ep as usize, 0, 0, 0, 0, 0]), Some(0));
    s.sys(echo, SYS_SLEEP_UNTIL, [1000000000, SLEEP_RELATIVE as usize, 0, 0, 0, 0]);
    let cap = s.run("CAPTEST.ELF");
    assert_eq!(s.reg(cap, 0) as isize, -(Errno::EREVOKED as isize));
}

// ── priority ceiling, end to end ────────────────────────────────────────

const CEILING_CAPS: &str = "[task.IDLE.ELF]\nclass = \"idle\"\npriority = 31\nmem_pages = 1\nstart = true\ncaps = []\n\
[task.ECHO.ELF]\nclass = \"rt\"\npriority = 20\nmem_pages = 2\nstart = true\ncaps = [ { kind = \"endpoint\", target = \"endpoint.echo\", perm = \"r\" } ]\n\
[task.CAPTEST.ELF]\nclass = \"rt\"\npriority = 12\nmem_pages = 2\nstart = true\ncaps = [ { kind = \"endpoint\", target = \"endpoint.echo\", perm = \"w\" } ]\n\
[task.SPAWNEE.ELF]\nclass = \"rt\"\npriority = 15\nmem_pages = 1\nstart = true\ncaps = []\n";

#[test]
fn a_server_runs_at_the_endpoints_ceiling_while_it_works_and_not_before_or_after() {
    let mut s = Sim::boot(SCHED, with_header(CEILING_CAPS)).unwrap();
    let (echo, cap, mid) = (s.slot("ECHO.ELF"), s.slot("CAPTEST.ELF"), s.slot("SPAWNEE.ELF"));
    // The client (12) runs first; the middle task (15) is next; the server
    // (20) waits behind both. Let the client block in sleep, the middle task
    // block, and the server get to its accept.
    s.run("CAPTEST.ELF");
    s.sys(cap, SYS_SLEEP_UNTIL, [1000000000, SLEEP_RELATIVE as usize, 0, 0, 0, 0]);
    s.run("SPAWNEE.ELF");
    s.sys(mid, SYS_SLEEP_UNTIL, [1000000000, SLEEP_RELATIVE as usize, 0, 0, 0, 0]);
    s.run("ECHO.ELF");
    assert_eq!(s.sys(echo, SYS_IPC_FAST_ACCEPT, [0; 6]), None);
    // Wake the client and the middle task together.
    s.hw.now += TIMEBASE_HZ as u64 * 2;
    s.k.on_tick(&mut s.hw);
    s.run("CAPTEST.ELF");
    let ep = s.sys(cap, SYS_CAP_INFO, [0, CAP_INFO_LOOKUP as usize, ty::ENDPOINT.raw() as usize, 0, 0, 0]).unwrap() as usize;
    assert_eq!(s.sys(cap, SYS_IPC_FAST_CALL_EP, [ep, 1, 2, 3, 4, 0]), None);
    // Both the middle task (15) and the server (20) are runnable. Without a
    // ceiling the middle task would run: the server's request would wait for
    // it. With the ceiling of the endpoint (its most urgent client, 12) the
    // server runs first.
    assert_eq!(s.k.state(mid), State::Ready);
    assert_eq!(s.k.schedule(&mut s.hw), echo, "the server works at the ceiling");
    let handle = s.reg(echo, 0);
    s.sys(echo, SYS_IPC_FAST_REPLY, [handle, 9, 9, 9, 9, 0]).unwrap();
    // The reply ends the service: the server is back at its own level, behind
    // the client (12, now runnable with its answer) and the middle task.
    assert_eq!(s.k.schedule(&mut s.hw), cap);
    s.sys(cap, SYS_SLEEP_UNTIL, [1000000000, SLEEP_RELATIVE as usize, 0, 0, 0, 0]);
    assert_eq!(s.k.schedule(&mut s.hw), mid, "the middle task before the unboosted server");
}

// ── a deadline row ──────────────────────────────────────────────────────

#[test]
fn a_row_with_a_profile_is_a_reservation_and_runs_ahead_of_real_time_until_its_budget_is_spent() {
    let sched = "[sched]\npartition_window_us = 10000\n\
[class.hard]\ncpu_budget_min_pct = 20\ncpu_budget_max_pct = 60\npolicy = \"edf\"\npriority_range = [0, 7]\npreemption = \"always\"\ntime_slice_ms = 0\nadmission_control = true\n\
[class.rt]\ncpu_budget_min_pct = 20\ncpu_budget_max_pct = 100\npolicy = \"fifo\"\npriority_range = [8, 30]\npreemption = \"timer-only\"\ntime_slice_ms = 10\nadmission_control = false\n\
[class.idle]\ncpu_budget_min_pct = 0\ncpu_budget_max_pct = 100\npolicy = \"idle\"\npriority_range = [31, 31]\npreemption = \"timer-only\"\ntime_slice_ms = 10\nadmission_control = false\n";
    let caps = "[task.IDLE.ELF]\nclass = \"idle\"\npriority = 31\nmem_pages = 1\nstart = true\ncaps = []\n\
[task.ECHO.ELF]\nclass = \"rt\"\npriority = 9\nmem_pages = 1\nstart = true\ncaps = []\n\
[task.CAPTEST.ELF]\nclass = \"hard\"\npriority = 2\nmem_pages = 1\nmem = \"locked\"\nstart = true\nperiod_us = 10000\nruntime_us = 2000\ncaps = []\n";
    let mut s = Sim::boot(Box::leak(sched.to_string().into_boxed_str()), with_header(Box::leak(caps.to_string().into_boxed_str()))).unwrap();
    let dl = s.slot("CAPTEST.ELF");
    assert_eq!(s.run("CAPTEST.ELF"), dl, "the reservation outranks the level-9 task");
    // It runs for 3 ms of its 2 ms budget: the next trap charges it, throttles
    // it, and real time gets the processor until the period ends.
    s.hw.now += TIMEBASE_HZ as u64 * 3 / 1000;
    s.k.on_tick(&mut s.hw);
    assert_eq!(s.k.schedule(&mut s.hw), s.slot("ECHO.ELF"));
    // At the deadline the budget is back.
    s.hw.now += TIMEBASE_HZ as u64 * 8 / 1000;
    s.k.on_tick(&mut s.hw);
    assert_eq!(s.k.schedule(&mut s.hw), dl);
}

#[test]
fn a_profile_the_cbs_cannot_take_is_refused() {
    // runtime longer than the deadline: the topology's own admission
    // refuses it before the kernel sees it.
    let sched = "[sched]\npartition_window_us = 10000\n\
[class.hard]\ncpu_budget_min_pct = 20\ncpu_budget_max_pct = 60\npolicy = \"edf\"\npriority_range = [0, 7]\npreemption = \"always\"\ntime_slice_ms = 0\nadmission_control = true\n\
[class.idle]\ncpu_budget_min_pct = 0\ncpu_budget_max_pct = 100\npolicy = \"idle\"\npriority_range = [31, 31]\npreemption = \"timer-only\"\ntime_slice_ms = 10\nadmission_control = false\n";
    let caps = "[task.IDLE.ELF]\nclass = \"idle\"\npriority = 31\nmem_pages = 1\nstart = true\ncaps = []\n\
[task.CAPTEST.ELF]\nclass = \"hard\"\npriority = 2\nmem_pages = 1\nstart = true\nperiod_us = 1000\nruntime_us = 2000\ncaps = []\n";
    let t: &'static mut Topology<'static> = Box::leak(Box::new(Topology::empty()));
    parse_sched(sched.as_bytes(), t).unwrap();
    let r = parse_caps(with_header(Box::leak(caps.to_string().into_boxed_str())).as_bytes(), t);
    assert!(r.is_err() || t.deadline_admission(1).is_err(), "the topology refuses runtime > period");
}

// ── a capability moves with a call ──────────────────────────────────────

#[test]
fn a_capability_with_transfer_moves_to_the_server_and_leaves_the_caller() {
    let caps = "[task.IDLE.ELF]\nclass = \"idle\"\npriority = 31\nmem_pages = 1\nstart = true\ncaps = []\n\
[task.ECHO.ELF]\nclass = \"rt\"\npriority = 8\nmem_pages = 2\nstart = true\ncaps = [ { kind = \"endpoint\", target = \"endpoint.echo\", perm = \"r\" } ]\n\
[task.CAPTEST.ELF]\nclass = \"rt\"\npriority = 12\nmem_pages = 2\nstart = true\ncaps = [\n\
  { kind = \"endpoint\", target = \"endpoint.echo\", perm = \"w\" },\n\
  { kind = \"node\", target = \"SPAWNEE.ELF\", perm = \"xt\" },\n\
  { kind = \"node\", target = \"FAULTER.ELF\", perm = \"x\" },\n]\n\
[task.SPAWNEE.ELF]\nclass = \"rt\"\npriority = 14\nmem_pages = 1\nstart = false\ncaps = []\n\
[task.FAULTER.ELF]\nclass = \"rt\"\npriority = 14\nmem_pages = 1\nstart = false\ncaps = []\n";
    let mut s = Sim::boot(SCHED, with_header(Box::leak(caps.to_string().into_boxed_str()))).unwrap();
    let echo = s.run("ECHO.ELF");
    s.sys(echo, SYS_IPC_FAST_ACCEPT, [0; 6]);
    let cap = s.run("CAPTEST.ELF");
    let ep = s.sys(cap, SYS_CAP_INFO, [0, CAP_INFO_LOOKUP as usize, ty::ENDPOINT.raw() as usize, 0, 0, 0]).unwrap() as usize;
    let spawnee_row = 3;
    let launch = s.sys(cap, SYS_CAP_INFO, [0, CAP_INFO_LOOKUP as usize, ty::LAUNCH.raw() as usize, spawnee_row, 0, 0]).unwrap() as usize;
    let no_transfer = s.sys(cap, SYS_CAP_INFO, [0, CAP_INFO_LOOKUP as usize, ty::LAUNCH.raw() as usize, 4, 0, 0]).unwrap() as usize;
    // Without TRANSFER the move is refused before anything is queued.
    assert_eq!(s.sys(cap, SYS_IPC_FAST_CALL_EP, [ep, 1, 2, 3, 4, no_transfer]), Some(-1));
    // A handle that is not live is refused too.
    assert_eq!(s.sys(cap, SYS_IPC_FAST_CALL_EP, [ep, 1, 2, 3, 4, launch + 0x1000]), Some(-1));
    assert_eq!(s.sys(cap, SYS_IPC_FAST_CALL_EP, [ep, 1, 2, 3, 4, launch]), None);
    let echo = s.run("ECHO.ELF");
    let moved = s.reg(echo, 6);
    let handle = s.reg(echo, 0);
    assert_ne!(moved, 0, "the server is told the handle in its own table");
    assert_eq!(
        s.sys(echo, SYS_CAP_INFO, [0, CAP_INFO_LOOKUP as usize, ty::LAUNCH.raw() as usize, spawnee_row, 0, 0]),
        Some(moved as isize),
        "the server holds it"
    );
    // The caller no longer does: the handle is stale, the lookup finds nothing.
    let h = CapHandle::from_raw(launch as u32);
    assert_eq!(h.kind(), ty::LAUNCH.raw());
    s.sys(echo, SYS_IPC_FAST_REPLY, [handle, 1, 1, 1, 1, 0]).unwrap();
    s.sys(echo, SYS_IPC_FAST_ACCEPT, [0; 6]);
    let cap = s.run("CAPTEST.ELF");
    assert_eq!(
        s.sys(cap, SYS_CAP_INFO, [0, CAP_INFO_LOOKUP as usize, ty::LAUNCH.raw() as usize, spawnee_row, 0, 0]),
        Some(-(Errno::ENOENT as isize))
    );
    assert_eq!(s.sys(cap, SYS_CAP_CLOSE, [launch, 0, 0, 0, 0, 0]), Some(-(Errno::ECAPSTALE as isize)));
}

#[test]
fn unknown_numbers_and_unsupported_calls_answer_minus_one_like_the_main_kernel() {
    let mut s = Sim::shipped();
    let echo = s.run("ECHO.ELF");
    for nr in [0, 34, 401, 0x7fff, 116] {
        assert_eq!(s.sys(echo, nr, [0; 6]), Some(-1), "syscall {nr}");
    }
}

#[test]
fn getpid_and_yield() {
    let mut s = Sim::shipped();
    let echo = s.run("ECHO.ELF");
    assert_eq!(s.sys(echo, SYS_GETPID, [0; 6]), Some(echo as isize + 1));
    assert_eq!(s.sys(echo, SYS_YIELD, [0; 6]), Some(0));
    // Its slice is spent: a peer would go first; there is none of level 8.
    assert_eq!(s.k.schedule(&mut s.hw), echo);
}

#[test]
fn the_cap_lookup_of_a_handle_fits_a_positive_32_bit_result() {
    // A handle is returned in a register read as signed on rv32: no kind may
    // set the sign bit. The kernel asserts it at build time; this is the
    // value every row's capabilities actually produce.
    let mut s = Sim::shipped();
    let cap = s.slot("CAPTEST.ELF");
    s.run("ECHO.ELF");
    let echo = s.k.current();
    s.sys(echo, SYS_IPC_FAST_ACCEPT, [0; 6]);
    let _ = cap;
    let cap = s.run("CAPTEST.ELF");
    for (kind, res) in [(ty::ENDPOINT, 0), (ty::MMIO, 0), (ty::SHM, 0), (ty::LAUNCH, 3)] {
        let h = s.sys(cap, SYS_CAP_INFO, [0, CAP_INFO_LOOKUP as usize, kind.raw() as usize, res, 0, 0]).unwrap();
        assert!(h > 0 && (h as u32) < (1 << 31), "{kind:?}: {h:#x}");
    }
}

// ── an endpoint nobody serves ───────────────────────────────────────────

#[test]
fn a_server_that_closed_its_endpoint_serves_no_more() {
    let mut s = Sim::shipped();
    let echo = s.run("ECHO.ELF");
    let ep = s.ep(echo);
    assert_eq!(s.sys(echo, SYS_CAP_CLOSE, [ep, 0, 0, 0, 0, 0]), Some(0));
    // Nothing left to serve: accept does not wait for a request nobody can send.
    assert_eq!(s.sys(echo, SYS_IPC_FAST_ACCEPT, [0; 6]), Some(-1));
    assert_eq!(s.k.state(echo), State::Ready);
    assert_eq!(s.sys(echo, SYS_IPC_FAST_REPLY_ACCEPT, [0x7f00, 0, 1, 1, 1, 1]), Some(-2), "a stale reply is told so, nothing is accepted");
    s.sys(echo, SYS_SLEEP_UNTIL, [1000000000, SLEEP_RELATIVE as usize, 0, 0, 0, 0]);
    // The client still holds its capability, and the call is refused rather
    // than queued behind a server that will never accept.
    let cap = s.run("CAPTEST.ELF");
    let h = s.ep(cap);
    assert_eq!(s.sys(cap, SYS_IPC_FAST_CALL_EP, [h, 1, 2, 3, 4, 0]), Some(-1));
    assert_eq!(s.k.state(cap), State::Ready, "it did not block");
}

#[test]
fn a_server_started_again_serves_again() {
    // CAPTEST launches ECHO; the server closes its endpoint and ends; the
    // next incarnation is given the capability anew and is called.
    let caps = "[task.IDLE.ELF]\nclass = \"idle\"\npriority = 31\nmem_pages = 1\nstart = true\ncaps = []\n\
[task.ECHO.ELF]\nclass = \"rt\"\npriority = 8\nmem_pages = 2\nstart = false\ncaps = [ { kind = \"endpoint\", target = \"endpoint.echo\", perm = \"r\" } ]\n\
[task.CAPTEST.ELF]\nclass = \"rt\"\npriority = 12\nmem_pages = 2\nstart = true\ncaps = [ { kind = \"endpoint\", target = \"endpoint.echo\", perm = \"w\" }, { kind = \"node\", target = \"ECHO.ELF\", perm = \"x\" } ]\n";
    let mut s = boot_caps(caps).unwrap();
    let (echo, cap) = (s.slot("ECHO.ELF"), s.slot("CAPTEST.ELF"));
    let cap_ = s.run("CAPTEST.ELF");
    assert_eq!(cap_, cap);
    let name = s.reg(cap, 0);
    // SAFETY: the first bytes of the task's own part.
    unsafe { core::ptr::copy_nonoverlapping(b"ECHO.ELF\0".as_ptr(), name as *mut u8, 9) };
    let h = s.ep(cap);
    assert_eq!(s.sys(cap, SYS_IPC_FAST_CALL_EP, [h, 1, 2, 3, 4, 0]), Some(-1), "nobody serves it before the launch");
    assert_eq!(s.sys(cap, SYS_SPAWN_EX, [name, 0, 0, 0, 0, 0]), Some(echo as isize + 1));
    s.run("ECHO.ELF");
    let ep = s.ep(echo);
    assert_eq!(s.sys(echo, SYS_CAP_CLOSE, [ep, 0, 0, 0, 0, 0]), Some(0));
    assert_eq!(s.sys(echo, SYS_EXIT, [0; 6]), None);
    s.run("CAPTEST.ELF");
    assert_eq!(s.sys(cap, SYS_IPC_FAST_CALL_EP, [h, 1, 2, 3, 4, 0]), Some(-1), "its server ended");
    assert_eq!(s.sys(cap, SYS_SPAWN_EX, [name, 0, 0, 0, 0, 0]), Some(echo as isize + 1));
    s.run("ECHO.ELF");
    assert_eq!(s.sys(echo, SYS_IPC_FAST_ACCEPT, [0; 6]), None, "it serves again, so it waits");
    let cap_ = s.run("CAPTEST.ELF");
    assert_eq!(cap_, cap);
    // The caller's old handle is still its own capability of the endpoint.
    assert_eq!(s.sys(cap, SYS_IPC_FAST_CALL_EP, [h, 1, 2, 3, 4, 0]), None, "the call is taken");
    assert_eq!(s.k.state(echo), State::Ready);
}

#[test]
fn a_row_that_holds_both_ends_of_an_endpoint_cannot_call_itself() {
    let body = format!("{IDLE_ROW}\n[task.ECHO.ELF]\nclass = \"rt\"\npriority = 8\nmem_pages = 2\nstart = true\ncaps = [ {{ kind = \"endpoint\", target = \"endpoint.echo\", perm = \"rw\" }} ]\n");
    let mut s = boot_caps(&body).unwrap();
    let echo = s.run("ECHO.ELF");
    let ep = s.ep(echo);
    // Calling would queue the server behind itself: refused, and it keeps running.
    assert_eq!(s.sys(echo, SYS_IPC_FAST_CALL_EP, [ep, 1, 2, 3, 4, 0]), Some(-1));
    assert_eq!(s.k.state(echo), State::Ready);
    // It can still serve.
    assert_eq!(s.sys(echo, SYS_IPC_FAST_ACCEPT, [0; 6]), None);
    assert_eq!(s.k.state(echo), State::Accepting);
}

// ── the clock ───────────────────────────────────────────────────────────

#[test]
fn the_uptime_is_a_pair_of_words_because_one_32_bit_word_wraps_in_minutes() {
    let hz = 10_000_000u64;
    // 215 s at 10 MHz: one word alone already reads negative (the result
    // register is signed), 430 s and it has wrapped. The pair carries all of it.
    let (lo, hi) = split_words(215 * hz, 32);
    assert!((lo as u32 as i32) < 0 && hi == 0, "a0 alone is not a clock: it reads as an error code");
    for secs in [1u64, 214, 215, 430, 3600, 30 * 86_400, 400 * 86_400] {
        let now = secs * hz;
        let (lo, hi) = split_words(now, 32);
        assert!(lo <= u32::MAX as u64);
        assert_eq!(join_words(lo, hi, 32), now, "{secs} s");
    }
    // Across the wrap the low word runs backwards and the pair does not; the
    // difference of the low words is still right.
    let (before, after) = (0xFFFF_FF00u64, 0x1_0000_0100u64);
    let (l0, h0) = split_words(before, 32);
    let (l1, h1) = split_words(after, 32);
    assert!(l1 < l0);
    assert!(join_words(l1, h1, 32) > join_words(l0, h0, 32));
    assert_eq!((l1 as u32).wrapping_sub(l0 as u32), 0x200);
    // A 64-bit word has room for all of it in a0.
    assert_eq!(split_words(u64::MAX - 7, 64), (u64::MAX - 7, 0));
    assert_eq!(join_words(u64::MAX - 7, 0, 64), u64::MAX - 7);
    // The kernel's own split is the one for this host's word.
    let (lo, hi) = uptime_words(0x1_2345_6789);
    assert_eq!(join_words(lo as u64, hi as u64, usize::BITS), 0x1_2345_6789);
}

// ── the code window ─────────────────────────────────────────────────────

#[test]
fn a_code_window_the_pmp_cannot_express_is_refused_at_boot() {
    let (b, e) = mem(0x3ff8, 4);
    for (name, code) in [("unaligned start", (b + 1, e)), ("unaligned end", (b, e - 1)), ("empty", (b, b)), ("reversed", (e, b))] {
        let info = BootInfo { code, pool: mem(64 * 1024, 4096), contig: mem(64 * 1024, 4096), gp: 0 };
        let mut hw = FakeHw { now: 1000, out: String::new(), pmp: [PmpEntry::OFF; PMP_ENTRIES], programmed: 0 };
        let mut k = Box::new(Kernel::new());
        let topo = topology(SCHED, with_header(CAPS));
        assert_eq!(k.boot(&mut hw, topo, &IMAGES, info).err(), Some(BootError::CodeWindow), "{name}");
    }
}

// ── the idle floor and the classes of an endpoint ───────────────────────

#[test]
fn a_server_in_the_idle_class_with_a_client_above_it_is_refused() {
    let row = |server_class: &str, server_prio: u32, client_class: &str, client_prio: u32| {
        format!(
            "{IDLE_ROW}\n[task.ECHO.ELF]\nclass = \"{server_class}\"\npriority = {server_prio}\nmem_pages = 2\nstart = true\ncaps = [ {{ kind = \"endpoint\", target = \"endpoint.echo\", perm = \"r\" }} ]\n\
             [task.CAPTEST.ELF]\nclass = \"{client_class}\"\npriority = {client_prio}\nmem_pages = 2\nstart = true\ncaps = [ {{ kind = \"endpoint\", target = \"endpoint.echo\", perm = \"w\" }} ]\n"
        )
    };
    // The server would never be picked to reach its accept.
    assert_eq!(boot_caps(&row("idle", 31, "rt", 12)).err(), Some(BootError::ServerBelowClient(1)));
    // Canaries: the same rows with the classes the other way, and both idle, boot.
    assert!(boot_caps(&row("rt", 20, "rt", 12)).is_ok());
    assert!(boot_caps(&row("rt", 20, "idle", 31)).is_ok());
    assert!(boot_caps(&row("idle", 31, "idle", 31)).is_ok());
}

#[test]
fn the_idle_floor_never_blocks_and_never_ends() {
    let mut s = Sim::shipped();
    let echo = s.run("ECHO.ELF");
    s.sys(echo, SYS_IPC_FAST_ACCEPT, [0; 6]);
    let cap = s.run("CAPTEST.ELF");
    s.sys(cap, SYS_SLEEP_UNTIL, [1000000000, SLEEP_RELATIVE as usize, 0, 0, 0, 0]);
    let idle = s.run("IDLE.ELF");
    // Nothing else is runnable: the floor must stay so.
    assert_eq!(s.sys(idle, SYS_SLEEP_UNTIL, [50000000, SLEEP_RELATIVE as usize, 0, 0, 0, 0]), Some(0));
    assert_eq!(s.k.state(idle), State::Ready, "a sleep that would leave the hart with nothing to run");
    assert_eq!(s.sys(idle, SYS_IPC_FAST_ACCEPT, [0; 6]), Some(-1), "it serves nothing, so it does not wait");
    assert_eq!(s.k.schedule(&mut s.hw), idle);
    // An exit and a fault start it again instead of leaving no task to run.
    let f = s.k.frame(idle);
    f.x[17] = SYS_EXIT as usize;
    f.x[10] = 3;
    s.k.syscall(&mut s.hw);
    assert_eq!(s.k.state(idle), State::Ready);
    assert_eq!(s.k.exit_code(idle), 3);
    assert_eq!(s.k.frame(idle).pc, nop as *const () as usize, "back at its entry");
    assert_eq!(s.k.schedule(&mut s.hw), idle);
    s.k.fault(&mut s.hw, 2, 0);
    assert_eq!(s.k.state(idle), State::Ready);
    assert_eq!(s.k.exit_code(idle), -1);
    assert_eq!(s.k.schedule(&mut s.hw), idle);
    assert!(s.hw.out.contains("IDLE.ELF is the idle floor: started again"), "{}", s.hw.out);
}

#[test]
fn an_idle_row_that_holds_an_endpoint_is_not_a_floor() {
    // It could call or accept and block, leaving nothing to run.
    let body = "[task.IDLE.ELF]\nclass = \"idle\"\npriority = 31\nmem_pages = 1\nstart = true\ncaps = [ { kind = \"endpoint\", target = \"endpoint.echo\", perm = \"w\" } ]\n\
[task.ECHO.ELF]\nclass = \"rt\"\npriority = 8\nmem_pages = 2\nstart = true\ncaps = [ { kind = \"endpoint\", target = \"endpoint.echo\", perm = \"r\" } ]\n";
    assert_eq!(boot_caps(body).err(), Some(BootError::NoIdle));
}
