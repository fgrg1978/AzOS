# Interface definition language

An interface is a Rust trait annotated `#[azos_interface(id = N, level = L)]`.
The macro (crate `azos_idl_macros`, re-exported by `azos_idl`) generates, from
one op table, the client stub, the server dispatcher and an in-process stub, so
that the same interface can be served by the kernel or by a ring-3 task and
callers do not know which. The wire form is the message descriptor
([abi.md](abi.md#the-message-descriptor)); the endpoints it travels over are in
[ipc.md](ipc.md#endpoints).

Contents:

- [Declaring an interface](#declaring-an-interface)
- [Generated items](#generated-items)
- [Wire form](#wire-form)
- [Op attributes](#op-attributes)
- [Interface ids and the registry](#interface-ids-and-the-registry)
- [Placement: kernel-hosted and ring-3 endpoints](#placement-kernel-hosted-and-ring-3-endpoints)
- [The IDL lint](#the-idl-lint)

## Declaring an interface

```rust
use azos_idl::azos_interface;

#[azos_interface(id = 1, level = 1)]
pub trait Adder {
    #[idempotent]
    fn add(&mut self, a: u32, b: u32) -> u32;
}
```

Arguments of `#[azos_interface(..)]`:

| Argument | Required | Meaning |
|---|:-:|---|
| `id = N` | yes | 32-bit interface id; non-zero (0 is reserved so a zeroed message names no interface) |
| `level = L` | yes | the interface's stability level, from 1 (0 is reserved). One linear number per interface; a server serves a request whose level is at most its own, else `IdlError::LevelTooNew` |
| `words = W` | no | inline words available to a request or a reply, `1..=8` (default `INLINE_WORDS_MAX` = 8). `words = 4` makes the interface fit the register-only fast call |

Shape rules the macro enforces, each as a compile error with the offending span:

- the item is a trait with no generics, no supertraits, no `unsafe`, and at
  least one method; its items are methods only (no consts, types or macros);
- a method is a plain `fn` taking `&self` or `&mut self`: no body, `async`,
  `const`, `unsafe`, `extern`, variadics, generics or where clause; each
  parameter is a plain `name: Type`;
- op numbers are 16 bits, so fewer than `u16::MAX` methods; two methods whose
  upper-cased names collide are refused (their `OP_*` constants would);
- the request, the reply and the capability entries fit the declared words and
  `CAPS_MAX` (8), checked at compile time with an assertion per op;
- every parameter and return type is a [wire type](#wire-form).

## Generated items

For `trait Name`:

| Item | What it is |
|---|---|
| `Name` | the trait as written, with the op attributes removed |
| `NameIdl` | a unit struct holding `ID`, `LEVEL`, `WORDS`, the per-op constants `OP_<METHOD>`, `REQ_WORDS_<METHOD>`, `REQ_CAPS_<METHOD>`, `REP_WORDS_<METHOD>`, `REP_CAPS_<METHOD>`, the op table `OPS: [OpInfo; N]` (one row per method, in method order) and the server dispatcher `dispatch` |
| `NameCall` | the caller's trait, implemented by both stubs below; its methods return `azos_idl::Result<T>` |
| `NameClient<T: Transport>` | the endpoint-call stub: packs the arguments into a `MsgDesc`, calls the transport, unpacks the reply. `NameClient::new(transport)`; `with_deadline(ns)` makes every call carry that absolute deadline (monotonic clock; 0 none) |
| `NameDirect<S: Name>` | the direct-call stub: the same calls on an implementation in this address space, with no message |
| `NamePlaced<S, T>` | an enum `Direct(NameDirect<S>)` / `Endpoint(NameClient<T>)` that implements `NameCall`; the host that holds it picks the variant per call from the driver's current placement |

`NameIdl::dispatch(server, &req, &mut reply)` decodes the request, calls the
trait implementation and writes the reply. The reply is always valid: its
status word says whether the request was served, and the returned
`azos_idl::Result` says the same for the server's own accounting.

A `Transport` is what a client stub calls through:
`fn call(&self, msg: &mut MsgDesc) -> Result`. It sends the request in `*msg`,
blocks until answered and leaves the reply in `*msg`. An `Err` is a failure of
the transport, not of the interface. Transports in the tree:

| Transport | Over | Notes |
|---|---|---|
| `azos_libsys::dev::Ep(handle)` | `SYS_IPC_CALL_V2` | any interface |
| `azos_libsys::dev::Regs(handle)` | `SYS_IPC_FAST_CALL_EP` | four words each way, no capability; only for an interface declared `words = 4` |
| `azos_syscall::kcall::KernelEndpoint(handle)` | the v2 call from a kernel task | for a task-served endpoint; `kcall::endpoint_handle_badged` mints the handle with a badge for a server that tells its callers apart |

The kernel's call has no wait bound of its own: it blocks until the server
answers (the deadline in the message is checked before the call is queued and
read by the server). A kernel component that must not wait on a server that
hangs makes the call from a task of its own and waits for that task with a timer
(the behavior loop's `ml-infer`, `kernel/src/behavior_ml.rs`). A client that
needs to keep a `Cap<T>` argument wraps the transport so the entries go as
copies (`kernel/src/behavior_infer.rs`, `Lending`).

Source: `crates/core/idl-macros/src/lib.rs`, `crates/core/idl/src/lib.rs`,
`crates/core/libsys/src/dev.rs`, `crates/core/syscall/src/kcall.rs`.

## Wire form

The request is a `MsgDesc`.

- Word 0 is the header: `id << 32 | level << 16 | op` (`header`, `header_id`,
  `header_level`, `header_op`). The op number of a method is its position in
  the trait, counted from 1; op 0 is never valid, so a zeroed message is
  refused.
- Then each argument in order. A scalar is one word. An array is its elements
  in order. A `Cap<T>` is one capability entry of mode MOVE and no word. A
  `Lent<T>` is a presence word and, when present, one entry of mode DUP with
  explicit rights and a deadline (an attenuated child of the server's own
  capability that lapses at the deadline); a reply may carry fewer entries than
  the op's bound, never more.
- The reply's word 0 is the status: 0 (`STATUS_OK`) when served, else an
  `IdlError` status. It is always small and non-negative because the fast path
  shares reply word 0 with its error code. The return value follows in the same
  form.

Wire types (trait `Wire`, with `WORDS` and `CAPS` constants and `put`/`get`):

| Type | Words | Caps | Encoding |
|---|---:|---:|---|
| `()` | 0 | 0 | nothing |
| `u8`, `u16`, `u32`, `u64` | 1 | 0 | zero-extended; a value that does not fit on read marks the message malformed |
| `i8`, `i16`, `i32`, `i64` | 1 | 0 | sign-extended |
| `bool` | 1 | 0 | 0 or 1; any other value is malformed |
| `f32` | 1 | 0 | the bits as a `u32` |
| `f64` | 1 | 0 | the bits |
| `[T; N]` | `N * T::WORDS` | `N * T::CAPS` | elements in order |
| `Cap<T>` | 0 | 1 | MOVE entry; the sender's handle goes stale |
| `Lent<T>` | 1 | 1 | presence word, then a DUP entry when present; `Lent::none()`, `Lent::dup(handle, rights)`, `Lent::dup_until(handle, rights, expiry_ns)` (rights 0 lend nothing) |

Nothing else is an interface type. `Reader` decoding is sticky: a read that does
not fit returns 0 and `Reader::finish` reports it. `Reader::expect` requires at
least the op's words and exactly its capability entries (extra words are
tolerated, since a register transport pads; extra capabilities are not, because
a capability nobody reads would leak); `Reader::expect_reply` allows fewer
entries than the bound for an op that may answer without the capability it
usually returns.

`IdlError` and the status word it travels as:

| Status | `IdlError` | Meaning |
|---:|---|---|
| 0 | none | served |
| 1 | `BadInterface` | the request names another interface |
| 2 | `BadOp` | the interface has no such op |
| 3 | `LevelTooNew` | the client was built against a newer level |
| 4 | `Malformed` | the message does not have the shape of its op; also the status of `Transport(code)` (the transport's own code, for the v2 call the kernel's negative code) |
| 5 | `NoConnection` | the service is on another node and the session to it is gone, or the reply never came and the op may not be asked again: the outcome is unknown, which is neither a dead server nor a refusal |
| 6 | `PeerDied` | the server that held the call died or the endpoint was destroyed while the call was queued or in service |
| 7 | `DeadlineExpired` | the call's deadline passed before a node's RPC server read it, or while it waited; nothing ran |
| 8 | `Refused` | a node's RPC server refused the call before any server saw it (interface not exported to this peer, a real-time caller, or a capability that cannot cross) |

An unknown status read from a reply is `Malformed`. An op's own refusals are
values of its interface, not statuses: the device interfaces in `azos_devif`
return `Out<T>` (a code from `azos_devif::outcome` and a value).

Source: `crates/core/idl/src/lib.rs`, `crates/core/devif/src/outcome.rs`.

## Op attributes

Attributes on a method:

| Attribute | Argument | Meaning |
|---|---|---|
| `#[idempotent]` | none | the op may be retried freely: running it twice is the same as once (`Delivery::Idempotent`, flag `OP_IDEMPOTENT` = 1) |
| `#[at_most_once]` | none | a retry is deduplicated: it is resent with the same identity and the receiving side answers a duplicate from the reply it kept and never runs the op twice (`Delivery::AtMostOnce`, flag `OP_AT_MOST_ONCE` = 2) |
| `#[once_only]` | none | the op is never retried: if the answer is lost, the outcome is unknown and the op is not asked again, as for an actuation (`Delivery::OnceOnly`, flag `OP_ONCE_ONLY` = 4) |
| `#[on_failure(..)]` | `degrade`, `safe_state`, `restart` or `escalate` | what the system does when the service that runs the op fails |
| `#[deadline_ns = N]` | positive integer literal | the longest the op may take from request to reply, in nanoseconds |
| `#[budget_us = N]` | positive integer literal | the longest the server may compute for one request, in microseconds of CPU |

At most one of the three delivery attributes per method; each of `on_failure`,
`deadline_ns` and `budget_us` at most once; `N` is a non-zero literal (zero
"declares nothing"). A `#[once_only]` op must declare `#[on_failure(..)]`
([lint rule 5](#the-idl-lint)). All of these are removed from the emitted trait
and carried in the op table.

`OnFailure` variants:

| Attribute | Variant | Meaning |
|---|---|---|
| `degrade` | `OnFailure::Degrade` | keep going with reduced function: the caller gets a refusal or a coarser answer and the rest of the system is untouched |
| `safe_state` | `OnFailure::SafeState` | drive the effect to its safe state (a motor stops, a valve closes); the service is then restarted or left down as its supervisor decides |
| `restart` | `OnFailure::Restart` | restart the service and let the caller ask again |
| `escalate` | `OnFailure::Escalate` | hand the failure up to the supervisor of the service's parent, and from there to the safety path |

One row of the op table is an `OpInfo`:

| Field | Meaning |
|---|---|
| `op: u16` | op number, from 1 |
| `name: &'static str` | method name |
| `flags: u8` | `OP_IDEMPOTENT`, `OP_AT_MOST_ONCE` or `OP_ONCE_ONLY`, at most one |
| `req_words`, `req_caps` | words (header included) and capability entries of the request |
| `rep_words`, `rep_caps` | words (status included) and capability entries of the reply |
| `on_failure: Option<OnFailure>` | `None` for an op that declares nothing |
| `deadline_ns: u64` | 0 when none declared |
| `budget_us: u32` | 0 when none declared |

Methods: `idempotent()`, `at_most_once()`, `once_only()`, `retry_safe()` (true
for an idempotent op) and `delivery() -> Option<Delivery>`. `delivery()` is
`None` for an op that declares no delivery class; a transport that can lose a
request or its reply carries no such op, since it would have to guess between
running the op twice and not at all.

Consumers of the op table in the tree: the RPC engine
(`userspace/lib/rpc/src/engine.rs`) refuses, with `IdlError::Refused`, an op with
no delivery class instead of sending it over a link; the kernel's motor host
(`crates/core/syscall/src/motor_host.rs`) reads `deadline_ns` and `budget_us` of
a motor op as the deadline and the placement latency it hands the actuation
gate.

Source: `crates/core/idl/src/lib.rs`, `crates/core/idl-macros/src/lib.rs`.

## Interface ids and the registry

An interface id is a non-zero `u32` chosen by the author of the interface; the
ids in `azos_devif` are four-character ASCII tags (`GPIO_ID` is `0x4750_494F`,
"GPIO"). It is the high half of every request header, so a server answers
`IdlError::BadInterface` for a request that names another interface.

The kernel-hosted and driver interfaces are listed in the registry
`azos_devif::IFACES`. Each `Iface` has:

| Field | Meaning |
|---|---|
| `name` | the word a topology row uses: `endpoint = "<name>[.<resource>]"` |
| `id` | the IDL interface id |
| `key` | the host key of a kernel-hosted endpoint of it (1-based, dense; `azos_devif::key`) |
| `resource` | maps the resource spelling after the name (`17` in `gpio.17`, empty for an interface with none) to the badge, or `None` when the spelling names nothing |

`parse_target`, `by_name` and `by_key` look entries up. The registry holds
`entropy`, `linkkey`, `power`, `flight`, `behavior`, `config`, `ota`, `gpio`,
`i2c`, `pwm`, `motor`, `sensor`, `time`, `block`, `clock`, `spi`, `can`, `uart`,
`adc`, `vm`, `vcpu`, `net`, `display`, `memctl`, `keys`, `sound` and `volume`. Interfaces that are served only by ring-3 services
(for example `Decisions`, id `0x4445_4349`, in `userspace/lib/decisions`) declare
their id with the macro and are not in the registry.

Source: `crates/core/devif/src/lib.rs`.

## Placement: kernel-hosted and ring-3 endpoints

A device or a service is an endpoint, not a syscall number and not a capability
kind. A task that may read a pin or command a wheel holds an `Endpoint`
capability whose *badge* names the resource (a pin, a bus and an address, a
wheel, a partition) and whose *rights* are the op classes the holder may use:
`READ` observes, `WRITE` acts, `EXEC` controls (binds, resets, administers). The
call is a message in the wire form above on that endpoint.

- **Kernel-hosted.** The kernel implements the trait itself for a driver it
  hosts. The endpoint's owner is the kernel (`KERNEL_HOST_BASE` plus the host
  key, see [ipc.md](ipc.md#endpoints)); a caller holding any non-empty right may
  call it, and the op class is checked per op inside the call. Code inside the
  kernel that holds the implementation uses `NameDirect`: no message.
- **Ring-3.** A task serves the same trait from an endpoint it owns: it accepts
  a request (`SYS_IPC_ACCEPT_V2`, or the register-form accept for a `words = 4`
  interface), runs `NameIdl::dispatch` on it and replies. Callers use
  `NameClient` over a transport.
- **Either.** `NameCall` is implemented by both stubs, so code that calls through
  it does not know where the implementation is. `NamePlaced` is the enum a host
  holds when a driver can move between the two.
- **Another node.** An endpoint whose name starts with `rpc-` is a proxy served
  by the RPC server; a lost link surfaces as `IdlError::NoConnection`, and a
  real-time caller is refused with `-ERTPROXY` ([ipc.md](ipc.md#endpoints)).

A task finds the endpoint capability its topology row grants with
`azos_libsys::dev::lookup(key, badge)`. An image profile names the device
interfaces it may call in its `ifaces` word (`crates/core/sched/src/seccomp.rs`),
so a role cannot reach a device by syscall number.

Source: `crates/core/devif/src/lib.rs`, `crates/core/ipc/src/endpoint.rs`,
`crates/core/libsys/src/dev.rs`.

## The IDL lint

The macro rejects a family of Unix habits at compile time. The rules are
`crates/core/idl-macros/src/lint.rs` and match on names and types (the macro
cannot know what a value means); names are matched case-insensitively on their
`_`-separated segments. The rules are pinned end to end by `compile_fail` doc
tests in `crates/core/idl/src/lint.rs`, each with a twin that compiles and
differs only in the offending item.

| # | Refused | Why | Use instead |
|---:|---|---|---|
| 1 | a parameter whose name has a segment `fd`, `fds` or `fildes` and whose type is an integer (`i8`..`i64`, `u8`..`u64`, `isize`, `usize`, `c_int`, `c_uint`, `c_long`, `c_ulong`, `RawFd`, or an array of them); an fd-named method returning an integer; the types `RawFd` or `Fd` | an integer into a global table is ambient authority | `Cap<T>` (a `Cap<T>` named `fd` passes) |
| 2 | a method, parameter or type named `errno`/`Errno`; any `Result<..>` return type | errno is a global side channel | a typed value; `IdlError` is the transport's failure |
| 3 | `str`, `String`, `Path`, `PathBuf`, `OsStr`, `OsString`, `CStr`, `CString` anywhere in a type; any reference or raw pointer; a parameter with a segment `path`, `paths`, `pathname`, `filename`, `fname` or `dirname` unless it is a float or an array of floats | a name is not authority; nothing crosses a call by address | `Cap<T>` |
| 4 | a method named `ioctl` or `fcntl` | magic-number control | one typed method per operation |
| 5 | a `#[once_only]` op without `#[on_failure(..)]` | an irreversible op (an actuation, a power-off, an install) must say what happens when its service fails; a deadline or budget does not stand in for it, and the other delivery classes do not need it | `#[once_only] #[on_failure(escalate)] fn ..` |
| 6 | `usize`, `isize`, `uintptr_t`, `intptr_t` or `ptrdiff_t` anywhere in a type; a parameter with a segment `addr`, `addrs`, `address`, `addresses`, `vaddr`, `paddr`, `ptr`, `ptrs`, `pointer`, `pointers`, `va` or `pa` and a 64-bit integer type (or an array of them); a method of such a name returning a 64-bit integer; `NonNull<T>` and `fn(..)` types | an address is not a value that crosses a call, and a width that follows the machine's pointer breaks a CHERI-clean wire (the ABI passes handles and explicit `(base, len, perms)` extents, never a pointer) | a `Cap<T>` naming the memory plus explicit `offset`, `len` and rights parameters; `base`/`len` pairs and integers narrower than 64 bits (a 7-bit bus address) pass |

The lint is an approximation: a path carried as `[u8; 64]` under a name like `p`
passes. It catches the habit, not the determined author; review catches the
rest. An unknown `on_failure` policy, a zero bound and a repeated contract
attribute are refused too, as is any parameter or return type that is not a
wire type and any request, reply or capability count that does not fit.

Source: `crates/core/idl-macros/src/lint.rs`, `crates/core/idl/src/lint.rs`.
