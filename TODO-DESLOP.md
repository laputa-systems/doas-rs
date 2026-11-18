Prefix: DSLP
Next: 6

Deslop campaign backlog ([plan](https://github.com/laputa-systems/stuff/blob/main/docs/campaigns/deslop.md), tier A). One agent works this file with the `deslop` skill: take the lowest-numbered open ticket whose area does not start with `Needs owner ·`. After DSLP-5, work the open P1 and P2 findings, then fill in `## Report` below.

## Report

Ground (DSLP-1) passed at base `122fb3fa42e1b70ccddd0eaab69bc6f0716a52be`. [Verification](AGENTS.md#verification) records the Alpine suite, CLI and policy boundaries, and the separate guest harness. The local lint target shares the hosted Clippy command.


The first Diagnose slice at `932754a` traces option parsing and help in
`src/cli.rs`, rule grammar and location-bearing diagnostics in `src/config.rs`,
and the `-C` query path in `src/main.rs`. `tests/cli.rs` exercises exact
arguments, configuration failure, rule ordering, the `permit nopass` outcome
and the help footer. The README now includes all three query results. The
help footer also points to the repository's enabled issue tracker. Installed
privilege behavior retains its separate guest gate. Remaining review stays
open. No host policy or credentials were used.


**Strict ownership checks**

In the pinned Alpine 3.24.2 ARM64 image, adding
`-D clippy::redundant_clone -D clippy::needless_pass_by_value` to the
all-target Clippy command rejects the baseline's unused clones and owned
check-mode argument. The adopted profile moves the owned paths and strings
into their existing consumers and borrows the parsed policy. It also drops
three unused clones in the CLI and authentication fixtures.

Clippy and all 166 ordinary tests passed in the image with networking
disabled and Cargo locked and offline. The broader candidate profile
reported 100 binary visibility, 12 integer conversion, 11 unwrap and two
wildcard diagnostics. DSLP-3 retains those dispositions. The installed
privilege check remains a separate guest test.

## Tickets

### DSLP-2 · P2 · Diagnose: ultrareview into this backlog

- **Area:** deslop · diagnose
- **Where:** whole repository
- **Problem:** No review has ranked this repository's risks for the deslop pass.
- **Recommendation:** Run the deslop Diagnose step. Accept: the diff touches only docs, comments, and this file, and every finding names its Fix with.
- **Fix with:** deslop
- **Effort:** S

### DSLP-3 · P2 · Types: strict profile and typing findings

- **Area:** deslop · types
- **Where:** type checker and lint configuration; Rust sources
- **Problem:** The native Alpine ownership pass adopted two Clippy checks. Visibility, integer conversions, unwrap calls and wildcard matches still need disposition.
- **Recommendation:** Run the deslop Types step. Accept: clean at the adopted profile, escape hatches not increased, witnesses recorded.
- **Fix with:** deslop
- **Effort:** M

### DSLP-4 · P2 · Tests: coverage, boundary gaps, mutation

- **Area:** deslop · tests
- **Where:** test suites and CI
- **Problem:** Coverage and mutation results are unmeasured; no deslop mutation lane exists.
- **Recommendation:** Run the deslop Tests step. Accept: no undispositioned survivor in critical code, the test cost budget holds, and the lane is green where the tools are mirrored.
- **Fix with:** deslop
- **Effort:** M

### DSLP-5 · P2 · Dead code: tools and debloat

- **Area:** deslop · dead code
- **Where:** whole repository
- **Problem:** No dead-code scan has run.
- **Recommendation:** Run the deslop Dead code step. Accept: tools clean or allowlisted with reasons; walk-backs filed as Needs owner tickets.
- **Fix with:** deslop
- **Effort:** M

