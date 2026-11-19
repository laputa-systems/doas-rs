Prefix: DSLP
Next: 13

Deslop campaign backlog ([plan](https://github.com/laputa-systems/stuff/blob/main/docs/campaigns/deslop.md), tier A). One agent works this file with the `deslop` skill: take the lowest-numbered open ticket whose area does not start with `Needs owner ·`. After DSLP-5, work the open P1 and P2 findings, then fill in `## Report` below.

## Report

**Bench audit:** No benchmark harness, representative performance workload or
performance gate exists. Priorities are assumed: the main gaps are P3/P4,
with external command execution and, when needed, PAM-free password
authentication contributing to elapsed time. No claim is made that either
dominates every invocation. Ranked by risk of a missed user-visible regression:

| Outcome | Current coverage | Gap and cheapest useful measurement |
| --- | --- | --- |
| Large policy parse and check | Functional rule and fragment checks; 1 MiB per-file and 4,096-rule limits, oversize rejection | P3 DSLP-9: repeated `-C` on a representative valid policy with an asserted decision; sample CPU separately. |
| Added time before command execution, including persisted approval I/O | Guest verifies successful nopass execution; timestamp tests check validity and expiry, not cost | P4 DSLP-10: compare successful installed guest runs ending in a marker, including valid persist; trace syscall counts separately. |
| Peak memory | Input bounds and correctness tests, no footprint measurement | P4 DSLP-11: peak RSS for a successful large-policy check; profile allocations separately if needed. |
| Release binary size | README records a historical approximate size, not a gate | P4 DSLP-12: compare byte counts from identically configured pinned release builds; inspect sections if size grows. |
| Network bandwidth and sustained throughput | None | Not needed: this is a local, one-command tool with no documented network or sustained-service workload. |

The guest's oversize `timeout 10` check accepts any nonzero exit, including
timeout, so it is not a proven latency bound. No benchmark result supplies
process-tree accounting, interleaved baselines, host gating, attribution, or
a regression threshold. New measurements need pinned inputs,
completed-work and correctness checks, and separate instrumented runs; the
README describes quiet-host timing. With no harness there is no preflight,
cleanup or result provenance to audit, and no entrypoint to wrap. Live password
entry and ARM64 installed execution remain unmeasured. No new measurement was
taken in this audit.

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
wildcard diagnostics. The final Types dispositions are below. The installed
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

**Cached approval clear**

`doas -L` now reports a timestamp cleanup failure on stderr and exits 1.
The baseline reproduced exit 0 with empty output when the timestamp store
was invalid. The [native KVM proof](https://github.com/laputa-systems/doas-rs/actions/runs/44401964822)
at `0b8b07e` exercised an absent approval and an invalid store inside the
guest. The new clear marker and the three existing installed-operation
markers all passed, and the guest exited 0. The static PIE executable
digest was `338c3fb31475e5187e1b7e419d1fd04886d6ab259710de358c8e2cbacc11f995`.
The ordinary Alpine tests passed. Reproduce with the same pinned guest
as the installed-operations check and the updated harness.

**Types completion**

Check mode now requires a borrowed path. Both callers pass the path they
parsed, and the check no longer clones or unwraps the option. Fixed TTY and
logging inputs use Rust's C-string literals. A disposable compile witness
removed the path argument from the check-mode call and failed with E0061.

The same production-only Clippy probes on native ARM64 Alpine 3.24.2
reported these counts before and after:

| Probe | Before | After | Disposition |
| --- | ---: | ---: | --- |
| `redundant_clone`, `needless_pass_by_value` | 0 | 0 | Retain the two adopted checks. |
| `unwrap_used` | 11 | 2 | Remaining cases are a tokenizer byte after a successful peek and a generated timestamp name composed of a literal and digits. |
| `expect_used`, `match_wildcard_for_single_variants` | 0 | 0 | No witness for an additional check. |
| `cast_possible_truncation`, `cast_sign_loss` | 3 and 9 | 3 and 9 | Descriptor ceilings, group counts and read lengths have explicit bounds or use checked syscall results. |
| `wildcard_enum_match_arm` | 2 | 2 | Parser fallbacks handle unmatched tokens. |
| `unreachable_pub` | 100 | 100 | The binary's modules are internal. |
| `unsafe_code` | 195 | 195 | Linux libc and kernel interfaces remain in use. |

To reproduce the counts, use the pinned ARM64 Dockerfile and run
`cargo clippy --offline --locked --bin doas --message-format=json --`
with `-W` for the listed probes, including `-W unsafe-code -W unreachable-pub`.
The adopted Clippy profile and all 166 ordinary tests passed without network
access. [The native KVM trial](https://github.com/laputa-systems/doas-rs/actions/runs/44404388726)
at `91d3c40` passed all four installed-operation markers and guest exit 0.
The shipped source, harness and build inputs match that run.

**Tests completion (DSLP-4)**

The required contracts are CLI admission and exit status (`src/cli.rs`,
`src/main.rs`); config-check admission, limits and diagnostics
(`src/main.rs`, `src/config.rs`, `src/load.rs`, `tests/cli.rs`,
`tests/adversarial.rs`);
and authorization, identity transitions and approval state (`src/policy.rs`,
`src/identity.rs`, `src/exec.rs`, `src/auth.rs`, `src/timestamp.rs`). The
ordinary suite exercises malformed inputs, fragment-local diagnostics,
last-match rules, identity and command restrictions, deny by default,
credential transition checks, and absent, corrupt, expired and cleared
approvals. The KVM result above covers installed transitions and clear.

Native ARM64 Alpine at `3c29743` measured 3,113/4,323 lines and
500/1,006 branches with cargo-llvm-cov 0.9.1; coverage is a report, not
a gate. The CLI trial at `45efba88` used cargo-mutants 27.1.0 on native
x86-64 Ubuntu with `--file src/cli.rs --test-package doas
--cargo-test-arg=--bin --cargo-test-arg=doas --jobs 1 --timeout 15
--build-timeout 300` and `--no-config --gitignore true
--skip-calls-defaults=false`. Of 53 selected changes, the
[baseline](https://github.com/laputa-systems/doas-rs/actions/runs/44407296345)
caught 37, missed 7, had 4 unviable and 5 timeouts; the
[candidate](https://github.com/laputa-systems/doas-rs/actions/runs/44408131269)
caught 43, missed 1, had 4 unviable and 5 timeouts. The added cases
protect CLI argument boundaries and help behavior, not six independent
contracts. The remaining survivor changes the final target-user OR to AND:
the earlier validation already rejects empty and NUL-bearing values, so
it is equivalent for reachable values. The five option-index timeouts were
repeated at 15 seconds but remain unconfirmed hangs, not catches.

The required policy trial used cargo-mutants 27.1.0 on Linux ARM64 Alpine,
base `29ed55b`, with `RUST_TEST_THREADS=1` and `TMPDIR=$PWD/.work/tmp`:
`cargo mutants --no-config --gitignore true --file src/policy.rs --baseline
run --jobs 1 --timeout 15 --build-timeout 120 --output
/work/.work/policy-run`. The container copy had `.work/` in Git excludes.
Of 29 mutations, 22 were
caught by assertions, 3 were unviable and 4 survived; none timed out. The
caught changes cover identity, target, command and argument restrictions,
rule predicates, last-match selection and permit/deny outcomes. The four
survivors replace the results or remove the matching arms of
`matched_permit` and `matched_deny`. Both helpers have no callers; the
installed and check-mode paths call `last_match` directly. These survivors
cannot alter a current authorization decision and are leads for DSLP-5,
not equivalent mutations or accepted risks. The three unviable mutations
construct a default rule value that does not compile. The completed trial
used 104 seconds of wall time with one worker; an initial baseline attempt
used 8 seconds and stopped on a container PTY failure before any mutant,
for 112 seconds (1.87 aggregate runner-minutes) total. The retry serialized
the ordinary tests and passed its baseline.

Longer CLI timeout reruns and mutation of config loading, credentials and
approval state remain incomplete; broader module sweeps and a whole-change
lane are advisory and unrun. Live password entry and an ARM64 installed
guest remain separate environment items.

The config-check fragment regression at `0cab3038` checks the exact
fragment-relative filename and line, and filename-ordered last matching
rules including a fragment without a final newline. All 170 ordinary tests
and Clippy passed in its pinned Alpine builder. No new tests were added in
this closeout; existing evidence does not establish mutation completeness
for the unrun critical regions.

**Dead code completion (DSLP-5)**

The binary crate has no library consumer, feature flags, registrations or
platform variants: `src/main.rs` rejects non-Linux builds; Cargo.toml defines
one binary and only libc and rustix. Searches covered source, tests, harness,
docs, README and build/package manifests. The common consumer check for each
removal below was `make test` and `make lint` on the candidate copied to the
native filesystem of the ARM64 Alpine doas-dev container, with
`TMPDIR=$PWD/.work/tmp` and Cargo offline. All 168 tests and Clippy passed.
These cuts do not change a CLI, exit, policy syntax or timestamp format.
The installed guest, ARM64 privilege transition and real password entry were
not rerun; none of the removed code was reachable from installed execution.

- `matched_permit`: no caller; normal authorization and check mode select
  `last_match` in `src/main.rs`. The policy and CLI ordering tests exercise
  those decisions. Removed in d41c564.
- `matched_deny`: same entry points and tests; no caller. Removed in e05aabd.
- `ensure_dir`: no caller; timestamp creation uses `ensure_dir_in` through
  `create_placeholder` from authentication. Timestamp tests cover creation,
  expiry, corruption and directory validation. Removed in eb171b3.
- `any_stdio_is_tty`: no caller; the live session gate checks descriptors and
  controlling TTY individually. TTY session matrix tests cover the gate.
  Removed in 6ba822d.
- `refuse_interactive`: used only by tests of the obsolete stdin-only rule;
  execution calls the broader `refuse_session`. Removed with its isolated
  test in 8633c0a; the session matrix and stdin-insufficient test remain.
- `copy_winsize`: only called by its own roundtrip test, with no execution
  path creating a PTY. Removed with that test in 08e5d4e; PTY fixture tests
  for the live terminal boundary remain.
- `_start_line` in `lex_quoted`: unused parameter; `next_token` retains the
  token line and errors use the lexer's current line. Config and CLI tests
  cover quotes and diagnostics. Removed across 49006d0 and 6940678.
- `_start_line` in `lex_word_continued`: same caller and diagnostic reasoning;
  config tests cover escapes and continuations. Removed in aa88d33.

The broad module suppressions were removed. `parse_str`, `is_permitted`,
`timestamp_path` and `open_pty` are now test-only helpers; the latter sets up
PTYs for controlling-terminal and echo tests. `_guard` bindings retain locks
and terminal restoration until scope exit; `_fd_old` is read and closed in a
timestamp test. Other underscore-prefixed names are libc symbols. No
`allow(dead_code)` or `allow(unused...)` remains.

`cargo rustc --locked --bin doas -- -D dead_code` passed. The separate
`-W unreachable_pub` scan reported 96 visibility warnings: these are public
within private modules of a binary crate, not external exports. This is one
reasoned tool disposition; visibility narrowing would not remove code.
A short single-use indirection review kept `should_isolate` as the named
security decision, timestamp's parameterized helpers for isolated directory
tests, and the typed authorization pipeline for its state boundaries. No
additional cut was justified. `cargo machete` 0.10.1 found no unused
dependencies; no dependency change was needed.

## Tickets










### DSLP-8 · P3 · Borrow policy rules during selection

- **Area:** policy · ownership
- **Where:** src/main.rs:206; src/policy.rs:111
- **Problem:** Authorization clones the whole rules vector before selection, then copies the selected permit into the next stage. The lookup already takes a borrowed slice and downstream stages do not read the rules vector.
- **Recommendation:** Borrow the rules through matching and keep ownership of the selected permit. Run the rule ordering, whole pipeline and guest execution checks.
- **Fix with:** typing-audit
- **Effort:** S


### DSLP-9 · P3 · Measure large policy check cost

- **Area:** performance · policy
- **Where:** src/config.rs:4; src/policy.rs:111; tests/cli.rs:39
- **Problem:** Valid large policies are parsed and searched without a time or CPU comparison; input limits and functional tests do not reveal a slowdown.
- **Recommendation:** Compare repeated -C checks of a representative multi-fragment large policy against a reference on a quiet Linux host, asserting the expected last-match result; use CPU sampling separately to attribute changes.
- **Fix with:** none
- **Effort:** S


### DSLP-10 · P4 · Measure installed command startup and cached approval

- **Area:** performance · execution
- **Where:** src/main.rs:227; src/main.rs:854; harness/vm-guest-priv.sh:65
- **Problem:** Installed nopass and persisted-approval execution have functional coverage but no latency or syscall baseline, so extra setup or timestamp I/O may go unnoticed before the command starts.
- **Recommendation:** In a disposable Linux guest compare repeated successful setuid nopass and valid-persist runs of a trivial marker command against an interleaved reference, checking the marker; use a separate syscall-count trace to attribute timestamp I/O, excluding human password entry.
- **Fix with:** none
- **Effort:** M


### DSLP-11 · P4 · Observe peak memory for policy checks

- **Area:** performance · memory
- **Where:** src/config.rs:4; src/main.rs:204; tests/adversarial.rs:82
- **Problem:** Policy bounds and correctness checks do not measure peak memory; allocations and the rules clone can increase memory consumed by a large valid policy.
- **Recommendation:** Measure peak RSS of successful -C runs with representative large valid policies using a process resource counter, checking the decision; use an allocation profiler separately if growth needs attribution.
- **Fix with:** none
- **Effort:** S


### DSLP-12 · P4 · Track release binary size against a reference

- **Area:** performance · artifact
- **Where:** README.md:75; Cargo.toml:7; Dockerfile:1
- **Problem:** The README notes a historical approximate size and says it is logged rather than gated; it does not establish a reproducible current size comparison, so artifact growth can go unnoticed.
- **Recommendation:** Compare byte counts of pinned target release binaries built with identical inputs using stat or wc -c; inspect section sizes with size when growth needs attribution.
- **Fix with:** none
- **Effort:** S

