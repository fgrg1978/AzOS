#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-only
# SPDX-FileCopyrightText: 2026 Fernando Rodriguez
# Absolute-claim scanner — a REVIEW AID, NOT A GATE. It always exits 0.
#
# ── Why this exists ─────────────────────────────────────────────────────────
#
# This tree has repeatedly shipped comments that assert a property the code
# did not have. Not lies — sentences that were true of the design the author
# had in their head, and were never re-checked against the code that landed:
#
#   * "structurally unbypassable", written beside a path that could be
#     bypassed;
#   * "single source of truth", written beside a constant that was in fact
#     duplicated in a second file (the local IP lives in both `NET_CFG` and
#     `tcp.rs`; the syscall numbers live in three places);
#   * "every path", written where one path was not covered;
#   * "the code already does this", written where the code had stopped doing
#     it several commits ago.
#
# The damage is not the wrong sentence. The damage is that a confident
# absolute is *load-bearing*: the next reader — a human, or an agent — stops
# verifying at the comment and builds on it. A false "cannot be reached" is
# worth less than no comment at all, because no comment prompts a check and
# a false guarantee suppresses one.
#
# So: absolutes are not banned, and they are not bugs. They are the
# sentences that carry the most weight per word, which means they are the
# ones that most deserve to be re-read against the code every so often.
# This script makes them ENUMERABLE. That is its whole job.
#
# ── What this script CANNOT do ──────────────────────────────────────────────
#
# It cannot tell a true claim from a false one. It has no idea what the code
# next to the comment does. Every single hit it prints may be perfectly
# correct — most of them are. It performs no analysis of any kind; it is a
# regular expression over text.
#
# Specifically, it cannot:
#
#   * decide whether "can never lap the consumer" is enforced by the
#     arithmetic below it, or merely hoped for;
#   * tell an assertion ("this is always true") from a directive ("callers
#     must always do this first") from a plain narrative ("the old code
#     never freed the page"). It flags all three;
#   * tell a claim about THIS code from a claim about someone else's — a
#     comment describing what Linux, seL4 or QEMU guarantees reads exactly
#     like a comment describing what we guarantee;
#   * see a claim phrased without any of the words below. A comment saying
#     "the gate is here, so we're safe" is exactly as absolute as
#     "structurally unbypassable" and this script will not find it. Absence
#     of hits proves nothing whatsoever;
#   * see through negation and hedging. "This is NOT guaranteed to hold" and
#     "it is guaranteed to hold" both match.
#
# It over-reports on purpose. The alternative — hand-tuning the patterns
# until the output is short — would mean this script had made an editorial
# judgement about which claims matter that it has no basis to make, and the
# next reader would have no way to know what it silently dropped. A long
# list you can skim beats a short list you cannot trust.
#
# ── How to read the output ──────────────────────────────────────────────────
#
# Hits are grouped by claim class, and within a class by file, so that a
# file with sixty absolutes stands out as its own finding — a dense cluster
# of guarantees usually marks either the most carefully reasoned module in
# the tree or the least, and either way it is where a reviewer should start.
# Every hit is printed as `file:line: text` so it can be clicked or pasted
# straight into an editor. A "top files" summary and per-class counts follow
# at the end.
#
# The useful question for each hit is not "is this word banned?" but:
#
#     If this sentence were false today, what in the tree would fail?
#     If the answer is "nothing — no test, no assert, no type" then the
#     sentence is doing the job of a check, and it should either become one
#     or be softened to describe what the code actually does.
#
# A line that makes two different kinds of claim is printed under both
# classes, deliberately: "cannot be bypassed by any caller" is both an
# impossibility claim and an absolute, and a reviewer scanning only one of
# the two sections should still see it. The grand total is therefore the sum
# of the class counts; the count of distinct source lines is printed
# alongside it.
#
# ── Portability notes (this machine) ────────────────────────────────────────
#
# `rg` does not exist for scripts here, `perl` and `timeout` are not
# available, and BSD `sed` does not understand `\b`. So: `grep` (pinned to
# /usr/bin/grep when present, because an interactive shell function on this
# machine shadows `grep` with `ugrep`), `awk`, and bash. Word boundaries are
# written as an explicit `(^|[^[:alnum:]_])` guard rather than `\b`: BSD
# grep does accept `\b`, but the character class is plain POSIX ERE and
# works on every engine. It is not cosmetic — without it, `call sites`
# matches the pattern `all sites`, and `is_complete` matches `complete`.
#
# Usage: ./tools/claims_check.sh          (no arguments, run from anywhere)

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT" || exit 0

# Pin the real grep. In an interactive shell on this machine `grep` is a
# function that runs `ugrep`; both engines handle these patterns, but a
# scanner whose results depend on who invoked it is not worth much.
GREP=grep
[ -x /usr/bin/grep ] && GREP=/usr/bin/grep

# ── What gets scanned ───────────────────────────────────────────────────────
#
# Source, docs, build glue and linker scripts. Pruned by directory NAME at
# any depth, not just at the root: `target/` exists under a dozen crates,
# not only at the top. Beyond the build/VCS/agent directories, the `* 2`
# variants are iCloud sync duplicates of the same trees (this repo lives in
# iCloud Drive and has been bitten by them before) — scanning them would
# report every hit twice, at line numbers from a stale copy.
EXCLUDE_DIRS=(
    target "target 2" build "build 2"
    .git .codex .claude
    node_modules __pycache__ .venv
)

INCLUDE_GLOBS=(
    '*.rs' '*.md' '*.S' '*.ld' '*.sh' '*.py' '*.toml' '*.c' '*.h' '*.txt'
    'Kconfig' 'Kconfig.*' 'Makefile' '*.tla'
)

grep_args=()
for g in "${INCLUDE_GLOBS[@]}"; do grep_args+=("--include=$g"); done
for d in "${EXCLUDE_DIRS[@]}"; do grep_args+=("--exclude-dir=$d"); done

# ── The claim classes ───────────────────────────────────────────────────────
#
# Four classes, each a POSIX ERE alternation matched case-insensitively. The
# leading word-boundary guard is added by `scan()`, so patterns here start at
# the first real word.
#
# The phrasings are deliberately claim-shaped rather than bare keywords:
# "never" on its own hits 1436 lines in this tree and is useless, while
# "can never" / "is never" / "never fails" is the shape a guarantee actually
# takes. This is the one place where a judgement was made about wording, and
# it is about GRAMMAR, not about which modules deserve scrutiny.

# 1. Absolutes: quantifiers and universals. The claim is about scope —
#    it holds for all of something, or for all time.
CLASS_1_NAME="ABSOLUTES — always / never / every path / all callers"
CLASS_1_RE='(can|could|will|would|shall|is|are|it|they|we|which|that)[[:space:]]+never'\
'|never[[:space:]]+(happens|fails|failed|returns|panics|blocks|occurs|be|gets|leaves|exceeds|wraps|races|deadlocks|overflows|reaches|observes|sees|misses|runs|fires|escapes|reorders)'\
'|(is|are|was|were|will|would|must|shall|it|they|which|that)[[:space:]]+always'\
'|always[[:space:]]+(holds|true|safe|correct|valid|the case|succeeds|succeed|set|clear|zero|non-null|ordered|consistent)'\
'|(every|all|any|each|no)[[:space:]]+(path|paths|caller|callers|callsite|callsites|call site|call sites|write|writes|access|accesses|entry|entries|exit|exits|reader|readers|writer|writers|branch|branches|arm|arms)'\
'|in all cases|in every case|without exception|under all circumstances|at all times|in either case'\
'|guaranteed[[:space:]]+(to|that|by|not)|guarantees[[:space:]]+that'

# 2. Authority: this location is the one that counts. The failure mode is a
#    second copy appearing elsewhere and nobody noticing.
CLASS_2_NAME="AUTHORITY — single source of truth / canonical / the only place"
CLASS_2_RE='single source of truth|source of truth|sources of truth'\
'|canonical|authoritative|definitive'\
'|the only (place|copy|caller|writer|owner|path|way|one|module|file)'\
'|the one (place|copy|true|and only)'\
'|sole (owner|writer|source|caller)|owns it exclusively|exclusive owner'\
'|kept in sync|stays in sync|must match|must agree|mirrors'

# 3. Impossibility: an assertion that some state or path is unreachable.
#    This is the class this repo has been most confidently wrong about.
CLASS_3_NAME="IMPOSSIBILITY — cannot / unbypassable / by construction"
CLASS_3_RE='(can|could|will|would|must)[[:space:]]*not[[:space:]]+be[[:space:]]+[a-z-]+'\
'|cannot[[:space:]]+(happen|occur|be|fail|race|deadlock|overflow|wrap|escape|reach|observe|see|exceed|bypass|skip)'\
'|(is|are|was|were|it)[[:space:]]+impossible|impossible[[:space:]]+(to|for|by)'\
'|unbypassable|un-bypassable|unforgeable|un-forgeable|unspoofable'\
'|no way (to|for|that|around|of)|there is no (way|path|route|means)'\
'|by construction|structurally|by design[[:space:]]+(impossible|unreachable|safe)'\
'|(is|are|remains|stays|becomes)[[:space:]]+unreachable|unreachable[[:space:]]+(state|code|branch|arm|path|by)'\
'|makes it impossible|rules out|precludes|forbids any|prevents any'\
'|(cannot|can not|never) (be )?(bypassed|circumvented|forged|spoofed|defeated|subverted|skipped|disabled)'

# 4. Completeness: an assertion that a set has been fully enumerated or
#    fully handled. The failure mode is a case added later, elsewhere.
CLASS_4_NAME="COMPLETENESS — exhaustive / covers all / handles every case"
CLASS_4_RE='exhaustive|exhaustively'\
'|(covers|cover|covering|covered)[[:space:]]+(all|every|each|both|the full)'\
'|(handles|handle|handling|handled)[[:space:]]+(all|every|each|both)'\
'|(checks|checked|validates|validated|enumerates|enumerated)[[:space:]]+(all|every|each)'\
'|(full|complete|total|100%)[[:space:]]+(coverage|cover)|fully (covered|covers|handled|handles|verified|tested|audited)'\
'|(all|every|each)[[:space:]]+(case|cases|variant|variants|field|fields|state|states|combination|combinations)[[:space:]]+(is|are|were|have|has|get|gets)'\
'|no gaps|nothing (is )?(missed|left out|uncovered)|leaves nothing|complete list|full list of'

# ── Machinery ───────────────────────────────────────────────────────────────

TMP="$(mktemp -d "${TMPDIR:-/tmp}/claims_check.XXXXXX")" || exit 0
trap 'rm -rf "$TMP"' EXIT

# Keep only lines that a reader would read as prose: everything in a
# document, and only comment lines in source. Without this, `never_type`,
# `is_complete()` and `#[non_exhaustive]` swamp the real sentences.
#
# The comment marker depends on the language, and the `.rs` case matters:
# `#` opens a comment in shell/python/toml/Kconfig, but in Rust it opens an
# attribute — `#![no_std]`, `#[non_exhaustive]` — so Rust must never fall
# through to the `#` branch. It does not: its branch ends in `next`.
#
# Also truncates the printed text. Markdown tables in this tree run to 900
# characters on one line; a single one of those would otherwise bury the
# section it appears in. The `file:line:` prefix is never touched, so the
# hit stays clickable.
FILTER_AWK='
{
    path = $1
    rest = $0
    sub(/^[^:]*:[0-9]*:/, "", rest)

    keep = 0
    if (path ~ /\.(md|txt|tla)$/)                       keep = 1
    else if (path ~ /\.(rs|c|h|S|ld)$/)                 keep = (rest ~ /(\/\/|\/\*|^[ \t]*\*[^\/])/)
    else                                                keep = (rest ~ /#/)
    if (!keep) next

    # collapse leading indentation, keep the sentence readable
    gsub(/^[ \t]+/, "", rest)
    if (length(rest) > 150) rest = substr(rest, 1, 147) "..."

    split($0, p, ":")
    printf "%s:%s: %s\n", p[1], p[2], rest
}'

# scan <regex> -> file:line: text, one per line, sorted by path
scan() {
    "$GREP" -rn -I -i -E "(^|[^[:alnum:]_])($1)" "${grep_args[@]}" . 2>/dev/null \
        | "$GREP" -v '^\./tools/claims_check\.sh:' \
        | awk -F: "$FILTER_AWK" \
        | sort -t: -k1,1 -k2,2n
}

report() { # report <index> <title> <regex>
    local idx="$1" title="$2" re="$3"
    local out="$TMP/class.$idx"
    scan "$re" > "$out"
    local n
    n="$(wc -l < "$out" | tr -d ' ')"
    COUNTS[$idx]="$n"
    TITLES[$idx]="$title"

    echo ""
    echo "════════════════════════════════════════════════════════════════════"
    echo " $idx. $title"
    echo "    $n hit(s)"
    echo "════════════════════════════════════════════════════════════════════"
    if [ "$n" -eq 0 ]; then
        echo "    (none — which proves nothing; see the header comment)"
        return
    fi
    # Group by file: print the file once, then its hits (still fully
    # qualified, so every printed line remains clickable on its own).
    awk -F: '
        { if ($1 != last) { printf "\n  %s\n", $1; last = $1 } print "   " $0 }
    ' "$out"
}

declare -a COUNTS TITLES

echo "AzOS absolute-claim scan"
echo "  root:  $REPO_ROOT"
echo "  note:  REVIEW AID, NOT A GATE. This script always exits 0."
echo "         A hit is a sentence to re-check against the code, not a defect."
echo "         It cannot tell a true claim from a false one — only a human can."

report 1 "$CLASS_1_NAME" "$CLASS_1_RE"
report 2 "$CLASS_2_NAME" "$CLASS_2_RE"
report 3 "$CLASS_3_NAME" "$CLASS_3_RE"
report 4 "$CLASS_4_NAME" "$CLASS_4_RE"

# ── Summary ─────────────────────────────────────────────────────────────────

cat "$TMP"/class.* 2>/dev/null | sort -u > "$TMP/all_unique"
UNIQUE="$(wc -l < "$TMP/all_unique" | tr -d ' ')"

TOTAL=0
for i in 1 2 3 4; do TOTAL=$((TOTAL + ${COUNTS[$i]})); done

FILES_HIT="$(awk -F: '{print $1}' "$TMP/all_unique" | sort -u | wc -l | tr -d ' ')"

echo ""
echo "════════════════════════════════════════════════════════════════════"
echo " DENSEST FILES (distinct claim lines, all classes)"
echo "════════════════════════════════════════════════════════════════════"
echo ""
awk -F: '{print $1}' "$TMP/all_unique" | sort | uniq -c | sort -rn | \
while read -r count path; do
    printf '  %5d  %s\n' "$count" "$path"
done > "$TMP/dense"
awk 'NR <= 15' "$TMP/dense"
DENSE_N="$(wc -l < "$TMP/dense" | tr -d ' ')"
if [ "$DENSE_N" -gt 15 ]; then
    echo "         ... and $((DENSE_N - 15)) more file(s) with at least one hit."
fi
echo ""
echo "  A dense file is not a bad file. It is either the most carefully"
echo "  reasoned module in the tree or the least, and the only way to know"
echo "  which is to read it."

echo ""
echo "════════════════════════════════════════════════════════════════════"
echo " TOTALS"
echo "════════════════════════════════════════════════════════════════════"
for i in 1 2 3 4; do
    printf '  %5d  %s\n' "${COUNTS[$i]}" "${TITLES[$i]}"
done
echo "  -----"
printf '  %5d  GRAND TOTAL (class hits; a line matching two classes counts twice)\n' "$TOTAL"
printf '  %5d  distinct source lines\n' "$UNIQUE"
printf '  %5d  distinct files\n' "$FILES_HIT"
echo ""
echo "  Nothing above is a failure. For each hit worth the minute, ask:"
echo "  if this sentence were false today, what in this tree would fail?"
echo "  If the answer is \"nothing\", the sentence is standing in for a check"
echo "  that does not exist — make it one, or soften it to the truth."

exit 0
