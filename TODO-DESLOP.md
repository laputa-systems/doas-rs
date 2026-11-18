Prefix: DSLP
Next: 9

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

**Installed privilege checks**

[Native x86-64 KVM run](https://github.com/laputa-systems/doas-rs/actions/runs/44399053825)
passed `DOAS_PRIV_EXEC_OK`, `DOAS_PRIV_CHECK_OK`,
`DOAS_PRIV_CRED_OK` and guest exit 0. The executable was static PIE
with SHA-256
`82b674bf6b9ccfc875f41349dbea97e372d038eafe5b9d7d018c9014142bab3b`.
The source, lock and Alpine 3.24.2 build inputs match `5cf0869`.
The separate [trial revision](https://github.com/laputa-systems/doas-rs/tree/233d2e93eee2a994b848535c1b764ad93c20aa84)
records the exact checkout and builder inputs. Run the existing
`harness/vm-priv.sh` with the Mdevd guest tree, its matching kernel and
initramfs, and the locked Doas build as shown there. The trial used
QEMU 11.0.3, the x86-64 runner's KVM device and the serial console.
It exercised restricted execution, check mode and real user transitions
inside the guest. Live password entry and the ARM64 guest remain open.

The preceding trial exited before guest boot because QEMU's optional
display model and ripgrep were absent. The harness now uses the serial
console and base grep, and prints the QEMU error if the emulator exits
before the guest markers.

**Diagnose completion**

The review at `bd3bf39` traced CLI admission, policy loading and rule order,
identity, credentials, password and timestamp handling, execution and
environment preparation, and the Linux guest boundary. Baseline Alpine CI
and the native guest receipt above passed. A disposable ARM64 Alpine 3.24.2
rebuild reproduced the clear-status error and directory diagnostic against
the binary. The policy ownership finding is a source observation. The
README describes the check-only and installed execution paths separately.
DSLP-6 through DSLP-8 record the findings. Live password entry, ARM64
installed guest verification and release security review remain separate.

## Tickets


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


### DSLP-6 · P2 · Report failures clearing cached authorization

- **Area:** CLI · timestamp
- **Where:** src/main.rs:840; src/timestamp.rs:266; docs/differences.md#d5-timestamp-group-check-hardened-to-root-only
- **Problem:** The CLI discards the error returned by timestamp clearing. On native ARM64 Alpine 3.24.2 at bd3bf39, an invalid timestamp store made doas -L exit 0 with empty stdout and stderr. The administrator cannot distinguish failed cleanup from a successful clear.
- **Recommendation:** Keep absent timestamp files idempotent. Send other clear failures through the existing CLI error path and test both results inside a disposable guest or container.
- **Fix with:** error-model
- **Effort:** S


### DSLP-7 · P3 · Preserve fragment filenames in config-check diagnostics

- **Area:** CLI · config check
- **Where:** src/main.rs:702; src/main.rs:750; tests/cli.rs
- **Problem:** The config-check command concatenates directory fragments before parsing. On ARM64 Alpine 3.24.2 a malformed first line in the second fragment was reported as line 3 in the directory. The installed loader parses each fragment with its own pathname.
- **Recommendation:** Name the fragment and its file-relative line in config-check errors while preserving byte and rule limits and alphabetical rule ordering.
- **Fix with:** error-model
- **Effort:** S


### DSLP-8 · P3 · Borrow policy rules during selection

- **Area:** policy · ownership
- **Where:** src/main.rs:206; src/policy.rs:111
- **Problem:** Authorization clones the whole rules vector before selection, then copies the selected permit into the next stage. The lookup already takes a borrowed slice and downstream stages do not read the rules vector.
- **Recommendation:** Borrow the rules through matching and keep ownership of the selected permit. Run the rule ordering, whole pipeline and guest execution checks.
- **Fix with:** typing-audit
- **Effort:** S

