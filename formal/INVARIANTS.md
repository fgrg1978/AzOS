# System invariants

This is the ledger of system-wide invariants. Each row names the code that
maintains the property and the test or proof that checks it. A row is only as
strong as its last column: the gate runs the Kani harnesses (see
`formal/README.md`) and the host test crates, and does not run the TLA+ specs.

Each row carries two stable names, `INV-n` and a requirement tag `REQ-nnn`.
The code carries the tag: a `// REQ-nnn` comment line above each item a row
names as its enforcer and above each test or harness it names as its check.
`tools/req_trace.py` (gate tier n0) fails when the ledger and the code
disagree, and `python3 tools/req_trace.py --csv` prints the trace for an
auditor.

Source: the files named in each row; `formal/README.md`; `tools/ci_check.sh`;
`tools/req_trace.py`.

## Capabilities

Source: `crates/core/ipc/src/cap.rs`, `crates/core/ipc/src/objref.rs`, `crates/core/abi/src/cap.rs`.

| ID | Invariant | Enforced by | Checked by |
|---|---|---|---|
| INV-1 (REQ-001) | A capability slot's generation only grows and is never reissued. A slot whose generation reaches `CapHandle::MAX_GENERATION` is retired: it is never allocated again, so a revoked handle cannot validate against a later grant of the same slot. | `CapTable::allocate_slot` (skips a slot whose generation is not below `CapHandle::MAX_GENERATION`), with `CapTable::bump_generation` as a second check, both called by `CapTable::grant_warranted` in `crates/core/ipc/src/cap.rs`; the field width is `CapHandle::GEN_BITS` in `crates/core/abi/src/cap.rs` | `RetiredNeverReissued` in `formal/tla/cap_table.tla` (not run by the gate); host tests `an_exhausted_slot_is_retired_and_never_reissues_a_generation` and `bump_generation_refuses_a_spent_slot_instead_of_wrapping` |
| INV-2 (REQ-002) | A revoked capability is never accepted. A capability derived from a revoked one is refused with `CapError::Revoked` before the revocation sweep frees it. | `CapTable::revoke` and the occupancy, generation and `chain_alive` checks in `CapTable::resolve` | Kani `cap_revoked_stale`; host tests `revoked_cap_is_stale` and, in `tests/host/cap-tests`, `revoking_a_capability_revokes_what_was_derived_from_it_and_keeps_it` |
| INV-3 (REQ-003) | A capability resolves only against the kind it was granted for: the slot's stored kind must equal the target type's kind. | `CapTable::resolve` (`w_ty_is(w, T::TYPE)`) in `crates/core/ipc/src/cap.rs` | Kani `cap_forge_impossible_empty_slot`; host test `wrong_kind_fails` |
| INV-4 (REQ-004) | A use succeeds only if the slot's stored permissions contain every permission the use needs. | `CapTable::resolve` (`w_perms(w).contains(need)`) | Kani `cap_perms_required`; host test `missing_perms_rejected` |
| INV-16 (REQ-016) | Deriving a capability never widens it: rights are a subset of the source's, the deadline is no later, the quota is no larger, the chain is exactly one link deeper and never past `WARRANT_DEPTH_MAX`, a weak chain stays weak, and the source's caveats are kept. | `derive_warrant` in `crates/core/ipc/src/cap.rs` | Kani `cap_derive_never_widens` |
| INV-17 (REQ-017) | In degraded mode no `WRITE` resolves through `CapTable::get`; reads are unaffected. | `degraded_active` and the containment step of `CapTable::resolve` | Kani `cap_contained_when_degraded` |
| INV-18 (REQ-018) | A packed object reference (Port, Shm, IoRing) carries the generation of the object at its pool index. Generation 0 means vacant, a slot never hands out generation 0, and a bare index never equals a live generation. A slot whose generation wraps first has the stale capabilities naming its index revoked in every task's table (`sweep_index`). | `Layout::pack`, `take_slot_gen`, `sweep_index` in `crates/core/ipc/src/objref.rs` | Kani `pack_unpack_round_trip`, `a_taken_slot_generation_is_never_zero`, `a_bare_index_never_matches_a_live_generation`; host test `take_slot_gen_hands_out_one_to_gen_max_then_wraps` |

## Scheduling and topology

Source: `crates/core/topology/src`, `kernel/src/boot/topology.rs`.

| ID | Invariant | Enforced by | Checked by |
|---|---|---|---|
| INV-5 (REQ-005) | The sum of the classes' `cpu_budget_min_pct` in an installed topology is at most 100. | `Topology::admission_check` (`AdmissionError::BudgetOverflow`) in `crates/core/topology/src/types.rs` | host test `budget_overflow_rejected_by_admission` in `tests/host/topology-tests` |
| INV-19 (REQ-019) | The real-time rows of an installed topology are schedulable under partitioned EDF: on every CPU the summed density (`runtime / min(deadline, period)`) is at most 100 %, computed in integer parts per million rounded up. | `admit` in `crates/core/topology/src/deadline.rs`, reached through `Topology::deadline_admission` in `crates/core/topology/src/types.rs` from the boot admission in `kernel/src/boot/topology.rs` | host tests `two_60_percent_tasks_pinned_to_one_cpu_are_refused` and `a_task_over_its_class_budget_is_refused_though_the_cpu_has_room` in `tests/host/topology-tests` |
| INV-15 (REQ-015) | A topology becomes readable only after it was filled (and, when it comes from the volume, its signature verified), passed `admission_check`, and passed the boot admission. A refused candidate is emptied and never visible through `azos_topology::get`. The boot then installs the built-in topology or halts, as Kconfig `TOPOLOGY_SOURCE` says; it does not continue without one. In `kernel_main` the topology is installed before the scheduler is set up. | `try_init_with` in `crates/core/topology/src/state.rs`; `signed::decide` in `crates/core/topology/src/signed.rs`; `install_topology` in `kernel/src/boot/topology.rs`, called from `kernel_main` | `SpawnImpliesLoaded` in `formal/tla/topology_load.tla` (a simplification of this path; not run by the gate); host tests `the_source_policy_table` and `tampered_caps_is_refused_by_its_signature` in `tests/host/topology-tests` |

## Update and boot trust

Source: `crates/core/ota/src`, `crates/core/mm/src`, `kernel/src/boot/ota.rs`, `kernel/src/boot/early.rs`.

| ID | Invariant | Enforced by | Checked by |
|---|---|---|---|
| INV-6 (REQ-006) | In a build with the `secure-boot-enforced` feature the boot gate runs a slot only if its manifest signature verifies against the compiled-in key (`BootTrust::Verified`); the policy is fixed at compile time and no runtime flag relaxes it. An update below the firmware or epoch floor is refused. | `secure_boot_verify_slot_detailed` and `BootTrust::is_bootable` in `crates/core/ota/src/secure_boot.rs`; the boot gate in `kernel/src/boot/ota.rs`; `ota_check_rollback_pure` and the epoch check in `crates/core/ota/src/pure.rs` | host tests `rollback_check_rejects_older_version`, `rollback_refuses_a_last_good_that_failed_secure_boot`, `a_manifest_below_the_epoch_floor_is_refused_and_writes_nothing` and `a_bad_signature_is_refused_before_anything_is_read_or_written` in `tests/host/ota-tests` |
| INV-14 (REQ-014) | The anti-rollback floor only rises, and only when a boot is confirmed. The floor is raised from the confirmed slot's own signed version and epoch, never from a value read off the volume. With Kconfig `OTA_FLOOR_TPM_NV` the floor in force is the higher of BOOTMETA's and a TPM NV index's, so deleting BOOTMETA cannot lower it below the hardware value. | `ota_mark_boot_good_pure` and `ota_confirmed_epoch` in `crates/core/ota/src/pure.rs`; `lift` and `commit` in `crates/core/ota/src/floor.rs` | host tests `mark_boot_good_does_not_lower_floor`, `mark_boot_good_does_not_advance_floor_for_an_unauthenticated_install`, `the_floor_moves_only_when_a_boot_is_confirmed`, `a_forged_bootmeta_floor_never_reaches_the_backend` in `tests/host/ota-tests` |
| INV-13 (REQ-013) | After boot, no page of the kernel image is both writable and executable: `.text` is RX, `.rodata` RO, `.data` and `.bss` RW. Outside the image, execute permission is removed from RAM. The page table is read back to confirm it. | `wx::plan` and `wx::is_write_exec` in `crates/core/mm/src/wx.rs`; `enforce_wx`, `verify_wx` and `strip_exec_outside_image` in `crates/core/mm/src/vmm.rs`, called from `kernel/src/boot/early.rs` | host tests `only_a_valid_mapping_can_violate_wx` and `write_exec_outranks_a_flag_match` in `tests/host/mm-tests`; kernel test `mm_wx_image` in `kernel/src/ktest.rs`; the boot marker `[MM] W^X ok` matched by the gate |

## Actuation and the brain link

Source: `crates/core/actuation/src/estop.rs`, `domains/robot/behavior/src`, `domains/robot/robot/src/motor.rs`.

| ID | Invariant | Enforced by | Checked by |
|---|---|---|---|
| INV-8 (REQ-008) | Once the emergency-stop latch is armed, `motor_envelope` returns zero for every command, whatever else is set; a motor write with no gate installed is zero; and the latch is cleared only by a caller holding a `ReleaseAuthority`, which an operator-signed release with a fresh nonce produces. No latency bound from trigger to zero output is stated or measured. | `estop_activate`, `estop_release`, `verify_operator_release` in `crates/core/actuation/src/estop.rs`; `motor_envelope` in `domains/robot/behavior/src/safety.rs`; `gate_speed` in `domains/robot/robot/src/motor.rs` | host tests `estop_forces_zero_whatever_else_is_set` in `tests/host/behavior-tests` and, in `tests/host/behavior-tests/src/estop_release_authority.rs`, `a_replayed_release_is_refused` and `a_nonce_older_than_the_floor_is_refused` |
| INV-12 (REQ-012) | A frame on the brain link reaches the dispatcher only if it opens under the current session's receive key at the next expected message counter. A forged, repeated, reordered or dropped frame fails the AEAD and ends the session (the link leaves `Established` and its keys are wiped); a frame recorded in an earlier session never opens in a later one, because every connection derives fresh keys from fresh ephemerals. There is no other replay floor and no MAC-only mode, so no reboot gap: the counter lives and dies with the session. | `Link::open_frame` in `crates/core/crypto/src/secure_channel.rs`; `BrainRxStream::feed` in `kernel/src/tasks/brain_link.rs` | host tests `a_replayed_a_reordered_and_a_dropped_frame_are_terminal`, `a_frame_from_another_session_does_not_open` and `a_terminal_event_ends_the_session_at_the_event` in `tests/host/aead-link-tests`; the gate's `link: encrypted end to end` row (phase 5: a tampered frame closes the session) |

## Identifiers

Source: `formal/INVARIANTS.md` itself; `crates/core/ota/src/lib.rs`.

Identifiers are stable: a retired one, `INV-n` or `REQ-nnn`, is not reused. Those not listed above
are retired because the property they named has no code in this tree:

- INV-7 (recovery slot read-only after boot) depended on flash write
  protection outside the tree.
- INV-9 and INV-10 (no allocation in the safety scheduler path, static loop
  bounds) were rules for a lint that does not exist; see
  `Documentation/design/safety-coding-standard.md` for what is checked.
- INV-11 (every `unsafe` block justified) is a coding rule; the
  `clippy::undocumented_unsafe_blocks` lint is enabled on `crates/core/ota`
  only.

## Adding or changing an invariant

Source: `formal/README.md`.

1. State the invariant as one sentence and give it the next free identifier.
2. Name the function that maintains it, by path and item name rather than
   line number.
3. Name the test, harness or spec that checks it, and say whether the gate
   runs it. If nothing checks it, say so in the last column.
4. Add the row in the same change as the code, test or proof.
5. Give the row a `REQ-nnn` tag in its ID cell (`INV-20 (REQ-020)`) and put
   `// REQ-nnn` above the enforcing item and above each named test; run
   `python3 tools/req_trace.py`.
