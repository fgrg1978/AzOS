# Title of the design note

> **Status:** draft
>
> One of `draft`, `accepted`, `implemented`, `superseded by <note>`, `rejected`.
> **Supersedes:** none
> **Superseded by:** none

This is the template for a design note: a document that states an architectural
choice or the structure of a subsystem, and argues that it is correct by
construction. If the note instead claims that a change is faster, smaller or
otherwise measurably better, use `TEMPLATE-experiment.md`.

How to use it: copy the file, replace the title, delete this paragraph and the
guidance in each section, and keep the headings that apply. Every section ends
with a `Source:` line naming the files that back it.

Writing rules:

- Describe what the code does, or what the note proposes it should do, and
  say which. For a note with status `implemented`, verify each claim against the
  tree (for example with `git grep` for every function, type, Kconfig symbol or
  file the text names) and drop what the code does not do.
- Cite repo-relative paths, for example `crates/core/topology/src/parser.rs`.
  Name Rust items so that a search finds them.
- Leave out dates, names of people, the history of how a decision was reached,
  hardware or schedule status, test or benchmark results, and claims about the
  maturity of the project. Version control records who changed what and when.

Status values:

| Status | Meaning |
|--------|---------|
| `draft` | Proposed and open to change. Not authoritative. |
| `accepted` | Agreed. Implementation may start; the interface is stable. |
| `implemented` | The code is in the tree and the note describes it as it is. |
| `superseded by <note>` | Replaced by a newer note, kept for the record. |
| `rejected` | Considered and not done. Kept so the reasoning is not lost. |

## Summary

One paragraph in plain language: what the note proposes or describes, which
subsystem it concerns, and the main idea.

Source: the files that implement it, or that the proposal changes.

## Motivation

Why this is needed. What problem it solves, who runs into it, and what happens
if nothing is done.

Source: files that show the problem.

## Detailed design

The body of the note. Cover at least:

- Interface: syscalls, file formats, configuration keys, exported types.
- Data structures: the types and constants involved, with their sizes where
  they matter.
- Behaviour, including edge cases and limits.
- Failure modes: what happens on each error and what the caller sees.
- Interaction with other subsystems, and with other notes.
- Configuration: the Kconfig symbols that change it, per ISA where they differ.

Code samples, tables and diagrams are welcome when they carry information the
prose does not.

Source: the files and the main Rust items (`path/to/file.rs`, `ItemName`).

## Drawbacks

What the design costs: implementation complexity, run-time or memory cost,
constraints it puts on other code, lock-in, what it makes harder.

Source: files that show each cost.

## Rationale and alternatives

Why this design and not another. For each alternative: what it would be, and
the specific reason it was not chosen.

Source: files that show why the alternative does not fit, if any.

## Prior art

Existing systems, papers or standards the design draws on or departs from, with
a link or reference for each.

Source: external references.

## Unresolved questions

What is not known yet. A note should not move to `accepted` while a question
that decides its shape is still open.

Source: files that show the open point, if any.

## Future possibilities

Extensions that the design leaves room for. These are signposts, not
commitments.

Source: files where the extension would attach.
