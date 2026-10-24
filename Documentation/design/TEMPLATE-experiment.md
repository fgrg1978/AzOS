# Title of the experiment

> **Status:** draft
>
> One of `draft`, `running`, `accepted`, `rejected`, `superseded by <note>`.
>
> - `draft`: the hypothesis is written and the experiment has not started.
> - `running`: the change is in the tree, behind a switch, and the results are
>   not in yet.
> - `accepted`: the exit criteria were met and the change is permanent. The note
>   describes the code as it is.
> - `rejected`: the experiment ended, the change was reverted or disabled, and
>   the negative result is recorded below. A rejected note is kept.
> - `superseded by <note>`: replaced by a newer note.
>
> **Companion design note:** a link to a `TEMPLATE.md` note, or none.

This is the template for an experiment note: a proposal that claims a
measurable improvement (latency, throughput, memory, size, worst-case execution
time, instruction count) and must be validated against a baseline before it is
accepted or rejected. Use `TEMPLATE.md` for a design note, where correctness is
argued by construction instead of measured. If the claim is "this will be
faster, smaller or safer", it belongs here. If it is "this is the right
structure", it belongs in a design note. If you cannot write a falsifiable
hypothesis with a baseline number, it is a design note.

How to use it: copy the file, fill every field, delete the guidance. Every
section ends with a `Source:` line naming the files that back it. Cite
repo-relative paths, name the Rust items, and leave out names of people and the
history of how decisions were reached. Record each measurement with the revision
it was taken at.

## Summary

Three to five sentences: what change is proposed, which subsystem or hot path
it touches (with the path), the property it should improve, and the measurable
target.

Source: the files the change touches.

## Hypothesis

The heart of the experiment. Fill every field before writing the change. The
hypothesis must be falsifiable: if you cannot say what failure looks like, you
do not have one.

**Claim:** one sentence with a direction, a metric and a magnitude.

**Primary metric:** exactly one, named so that someone else can run it: the
program and lane that prints it (a lane of `userspace/bench/vsbench` or
`userspace/bench/latbench`, for example), the instruction count of a boot run
under QEMU `-icount`, or a size the build reports. State the unit.

**Baseline:** the value measured before the change, with the revision, the
number of samples and the spread. Measure it before writing the note; do not
leave it open.

**Target:** the value the metric must reach, and the direction. A two-sided
claim is acceptable if the improvement has a natural ceiling.

**Confidence:** `low`, `medium` or `high`, with one or two sentences of reasons,
including anything in the measurement setup that could hide the effect.

**Time horizon:** how many runs, on how many distinct revisions, before a
verdict. An experiment with no end drifts into permanent work in progress.

Source: the files that implement the metric and the code it measures.

## Measurement method

How to reproduce the numbers by hand, so that the baseline and the result are
comparable.

- The exact commands, the configuration (`.config` or defconfig) and the ISA.
- Whether the run is on QEMU or on a board, and with how many harts.
- How noise is controlled. Wall-clock numbers under QEMU vary from run to run
  and with host load; prefer a count that does not depend on the host (an
  instruction count under `-icount`) where the lane supports it, and report the
  spread otherwise.
- For a claim against another system, the same work measured on that system
  under the same conditions, for example with `tools/bench/vsbench_compare.sh`, which
  runs the same ring-3 workload on AzOS and on Linux under one QEMU and
  compares what was measured.

Source: the benchmark programs and scripts used (`userspace/bench/`, `tools/`).

## Canary

Every check that decides the verdict needs a deliberate break that turns it
red, or it proves nothing. Name the break for each criterion below: a build
switch that disables the change, a seeded fault, a stand-in that is known to be
slower. The tree's `*-canary` Cargo features are the pattern. Report, for each
check, whether the canary discriminated.

Source: the feature or script that provides each canary.

## What would make this fail

An experiment with no kill criteria is a wish. List concrete, checkable
conditions. When any one fires, the experiment moves to `rejected` whatever the
primary metric is doing.

- [ ] The primary metric moves less than half of the claimed amount after
  `<N>` runs.
- [ ] A secondary metric `<name>` regresses by `<percent>` from its own
  baseline.
- [ ] The worst-case execution time of `<point>` increases by `<percent>`.
- [ ] The kernel image (`.text`, `.rodata`, `.bss`) grows by `<N>` KiB on
  `<configuration>` without a justification recorded in the note.
- [ ] A host test suite or gate row that passed before the change fails
  (`make check0` runs the host suites the diff reaches; `make check1` adds the
  smoke boots and gate rows; `make ci` runs the whole gate).
- [ ] Any ISA or configuration the change touches fails to build, or builds with
  a warning (the gate treats warnings as failures).
- [ ] Add domain-specific criteria here.

Source: the gate rows and suites each criterion refers to.

## Exit criteria

State what "done" means in both directions. The experiment must close; it
cannot stay `running` indefinitely.

### Success: status `accepted`

1. The primary metric meets or beats the target in `<N>` consecutive runs on the
   same configuration.
2. No kill criterion fired during the experiment.
3. The gate passes on every ISA the change touches.
4. The change is made permanent: the switch is removed or defaulted on, and the
   baselines in this note are replaced by the new measurements and the revision
   they were taken at.
5. Fill in the Results section.

### Failure: status `rejected`

1. Any kill criterion fires, or the primary metric has not moved in the claimed
   direction when the time horizon ends.
2. Revert the change, or leave it behind a switch that is off by default.
3. Fill in the Results section. The negative result is the deliverable.

Source: the build switch that carries the change.

## Risk if it succeeds

Improvements carry costs that show only after the change is permanent. List
them now, while it is still easy to say no.

- **Data-structure growth:** fields added, with the per-entry and total sizes
  at the configuration's limits.
- **Interface growth:** new syscalls, Kconfig symbols, file-format keys or
  packet types. Each one is something to keep supporting.
- **Build complexity:** new Cargo features, build-time probes, gate rows.
- **Interaction with other notes and subsystems:** any design note whose
  assumptions the change invalidates, even subtly.
- **Per-ISA behaviour:** whether the change is the same on riscv64, aarch64 and
  x86_64, and if it is not, why.

Source: the files where each cost would show.

## Detailed design

The design must already exist: do not propose an experiment for code you have
not sketched. Keep this section shorter than a design note's; the detail lives
in the code. Link the companion design note if the scope warrants one.

- **Interface:** new syscalls, packet types, configuration keys or exported
  traits.
- **Data structures:** changed or new types and constants, with source paths.
- **Behaviour and edge cases:** what happens at the limits and on error.
- **Interaction with other subsystems:** scheduler, network stack, update path,
  capability table, whichever the change touches.

Source: the files and the main Rust items.

## Plan with measurement checkpoints

Each phase has its own measurement. A later phase does not start if an earlier
one fails its check, which keeps the experiment incremental and reversible.

| Phase | Scope | Measurement | Check |
|-------|-------|-------------|-------|
| 1 | Land the scaffolding with the change off by default. | The primary metric matches the baseline within its spread. | Re-measure before phase 2. |
| 2 | Turn the change on behind a switch. | The primary metric shows first movement toward the target. | If it does not move after `<N>` runs, re-examine the hypothesis. |
| 3 | Turn it on by default. | The primary metric meets the target. | All exit criteria checked. |

Add phases as needed.

Source: the switch and the files each phase touches.

## Drawbacks

What the change costs whether or not the hypothesis holds: complexity, build
time, memory, new things to test.

Source: files that show each cost.

## Alternatives

**Do nothing** is always the first alternative: the cost of not making the
change is the baseline value of the primary metric. State why that cost is or is
not acceptable for the intended use; if it is acceptable, the experiment should
not run.

- **Alternative A:** what it is, and why it was not chosen or was deferred.
- **Alternative B:** the same.

Source: files that show why an alternative does not fit.

## Unresolved questions

What must be settled before the experiment can move from `draft` to `running`.

- [ ] Question 1.
- [ ] Question 2.

Source: files that show the open point, if any.

## Results

Fill this in after the experiment ends, whatever the verdict. Do not close the
note with it empty.

- **Concluded at revision:** `<revision>`.
- **Final value of the primary metric:** value, spread and number of samples.
- **Baseline, for comparison:** the value from the Hypothesis section.
- **Kill criteria that fired:** none, or which.
- **Canaries:** for each check, whether the canary turned it red.
- **Verdict:** `accepted` or `rejected`.

### If accepted

Which phases produced the signal and which runs provided the consecutive
successes.

### If rejected

The most valuable part of a rejected note. Explain what the data showed (the
trace of the primary metric and any secondary metric that moved), which
criterion fired first or why the time horizon ended without a signal, what the
root cause is believed to be even if uncertain, and what a different approach
would look like if the goal is still worth pursuing. A later note that proposes
something similar should find this section and understand why the idea did not
work.

Source: the commands and output files the verdict rests on.
