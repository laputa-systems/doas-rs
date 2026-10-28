# Campaign: minimal security-hardened Rust doas for Linux (aarch64 musl, Alpine edge)

Senior Rust/systems engineer. Build a production-quality, Linux-first Rust
reimplementation of OpenBSD `doas`. Real setuid-root boundary: correctness and
security are release requirements, not follow-ups. Land accepted slices on
`main`, one at a time. Continue through all feasible slices.

## Status

- Goal: working Rust `doas` binary, Alpine-edge/dev-qualified, aarch64 musl.
- Base: `3cef827` (empty repo: this doc + pinned nightly). Nothing red.
- Accepted: `S-09` (2026-10-28, safe exec with fd hygiene and transition checks green in container). Next: `S-13`. No parked slices.
- D2: syslog uses `LOG_AUTHPRIV` with ident `doas`, `LOG_PID|LOG_NDELAY`; constant `%s` formats only, no journald.
- Loop timings (aarch64, OrbStack, `doas-dev` rebuild): `docker build` 1.7s (cached toolchain), `cargo clippy` 0.91s, `cargo test` 1.74s; `cargo tree` shows only `libc`/`rustix` (+transitives). `docker run --rm` hangs on attach here; verification uses `docker create` + `docker start -a` (same image/args), no `--rm` cleanup.
- Foundation proven (2026-10-28): `alpine:edge` runs native aarch64 in Docker here.
- Resume prompt: `Execute plan.md starting at Status: next slice.`

## Charter

- Decide and keep going. Record a decision only when a later slice depends on it.
- Proceed without waiting. No approval step exists; the grant below is complete.
- Hard stops (park the slice with cause, never work around): irreversible or
  outside-repo action; a boundary below forbids it; no check can verify it.
  Pushing is always forbidden. Never install an experimental setuid binary on
  the macOS host or any machine outside a disposable container/VM.
- Fix egregiously slow or plainly broken things met along the way in their own
  commit: repair the dev loop if one slice acceptance exceeds 10 minutes;
  fix any `unsafe`, auth, or credential-transition bug found, any slice.
- Parity before optimization. Until `S-16`, log size/speed numbers, gate nothing
  except a >2x regression versus the oracle measured on the same host.
- One writer by default. Parallel lanes only for the pairs named in Sequence,
  in worktrees at `.work/wt/<lane>` (parent-created, lifecycle per
  `orchestrate`). `.work/` is ignored via `.git/info/exclude`, never tracked.
- Every commit is a Conventional Commit with the module as scope and the item
  ID in the body (e.g. `feat(cli): ...` + `S-03`). Code comments never cite
  this doc. No formatters, no pushes.

## Decisions

Owner-decided (2026-10-28, from the draft unless noted):

- O1: exactly two direct Rust dependencies: `libc`, `rustix`. No other direct
  runtime, build, or dev dependencies. Any new direct dep is a contract change
  and parks the slice instead of landing it.
- O2: Linux only. Release target is Linux aarch64 musl, qualified on Alpine
  edge in Docker. No BSD/macOS code. x86_64 is a non-goal: no qualification
  work, no release claim (owner answer 2026-10-28).
- O3: develop and qualify in Docker on latest Alpine edge (owner note,
  2026-10-28). All Linux, privileged, and setuid tests run in the container.
- O4: land accepted slices by committing to `main` locally. Never push; CI
  green is owner-run at milestones (owner answer 2026-10-28).

Prescribed (settled from the repo and sound practice; owner may overrule):

- P1: the production-readiness claim stays blocked until an independent
  security review lands or the owner explicitly lifts it. A green pipeline
  never substitutes for review of the setuid boundary.
- P2: no silent unsafe fallback anywhere. Incomplete terminal isolation is a
  blocking release issue recorded in Status, not an undocumented risk.
- P3: the oracle is built in the container from pinned sources for testing
  only, never vendored into the binary. Each deliberate difference gets one
  entry in `docs/differences.md` with rationale; unexamined diffs stay open.
- P4: red work stays on its branch. Only green slices land on `main`.
- P5: `correct` skill is disabled in this environment, so repeat-failure guard
  is manual: 3 attempts per slice, then park on the branch with cause and a
  retry condition. A second same-shaped failure in another slice means stop
  and fix the shared premise first.
- P6: failing-item rule is cause-before-retry: reproduce small, establish the
  cause with one observation, fix at the origin, keep the repro as the test.

Delegated (executor decides inside the bound, logs it in Status):

- D1: module layout may simplify the sketch in Reference if behavior and
  proofs are unchanged.
- D2: syslog facility/tag and other libc-level choices; record once used.
- D3: oracle-corpus sharding/sampling for dev speed; the full corpus still
  gates `S-14`/`S-16`.

## Baseline

- `3cef827`: only `plan.md` (the superseded 548-line draft) + pinned
  `nightly-2026-09-15`, which is installed and active. No code, no tests,
  nothing red. `cargo --version` runs in 0.04 s.
- Upstream SHAs/tags are unverified claims until `S-01` pins them. The draft's
  research notes (OpenBSD source, OpenDoas v6.8.2, Alpine aports patches,
  CVE-2019-25016, CVE-2023-28339) are inputs to `S-01`, not facts.

## Sequence

Prerequisites crossing slices are written on the item. `S-03`/`S-04`/`S-06`
may run as two lanes (disjoint files); everything else is serial.

- S-01 pins. Owns `docs/upstream.md`. No prereq. Record exact SHAs/tags for
  OpenBSD src, OpenDoas v6.8.2 + later commits/issues, aports APKBUILD +
  patches; split requirements into canonical/portability/Alpine/improvement;
  note both CVEs. Accept: `rg -c 'CVE-2019-25016|CVE-2023-28339'
  docs/upstream.md` hits both and every source has a full SHA.
- S-02 skeleton. Owns `Cargo.toml`, `Cargo.lock`, `Dockerfile`, `.github/`,
  `src/main.rs`. Needs S-01 (Alpine flags feed the image). Minimal wiring +
  state types `UntrustedInput -> ParsedPolicy -> AuthorizedRequest ->
  AuthenticatedRequest -> PreparedExecution -> Exec`. Accept: `docker build -t
  doas-dev . && docker run --rm doas-dev sh -lc 'cargo clippy --all-targets
  -- -D warnings && cargo test'` green; `cargo tree` shows only
  libc/rustix (+transitives); record both wall times in Status.
- S-03 cli. Owns `src/cli.rs`. Needs S-02. Full Linux-relevant CLI (`command`,
  `-u`, `-n`, `-s`, `-C`, `-L`; `-a` out of scope), raw bytes, option
  interactions, exit statuses, diagnostics. Accept: `cargo test cli::`.
- S-04 parser. Owns `src/config.rs`. Needs S-02. Handwritten bounded parser:
  permit/deny, nopass, persist, nolog, keepenv, setenv, users/groups/IDs, `as`,
  `cmd`, `args` (absent vs empty distinct), quoting/escapes/continuations;
  reject `args`-without-`cmd`, bad combos, partial policy; file:line errors;
  precise Permit/Deny types; NUL/non-UTF8/oversize/integer-overflow vectors.
  Accept: `cargo test config::` incl. negative vectors.
- S-06 env. Owns `src/env.rs`. Needs S-02 (parallel with S-03/S-04). HOME,
  LOGNAME, PATH, SHELL, USER, DOAS_USER, DISPLAY, TERM; keepenv/setenv with
  removals and references; clean-by-default; LD_\*/IFS/ENV/BASH_ENV, dup keys,
  bad names, non-UTF-8. Accept: `cargo test env::`.
- S-05 policy. Owns `src/policy.rs`. Needs S-04. Pure eval over parsed policy
  + resolved context: last-match-wins, deny-by-default, no shell/wildcard
  matching. Accept: `cargo test policy::` incl. rule-order confusion vectors.
- S-07 identity. Owns `src/identity.rs`. Needs S-02. passwd/group/shadow
  resolution via system interfaces; document exactly which shadow/account
  restrictions are enforced. Accept: `cargo test identity::`.
- S-10 confload. Owns `src/load.rs`. Needs S-04. `/etc/doas.conf` then
  `/etc/doas.d/*.conf` alphabetical, later-wins; ignore unrelated files;
  required main file; safe default PATH
  `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`; descriptor
  opens, owner/type/perm checks, dir checks, symlink/path-race resistance,
  `openat2` with documented fallback, never re-open by path, fail closed.
  Accept: `cargo test load::` in the container incl. symlink/perm vectors.
- S-08 auth. Owns `src/auth.rs`. Needs S-07. Shadow verification via system
  crypt (no own crypto): invoke-user auth, locked/empty/missing/unsupported
  handling, controlling-TTY required, no piped stdin, echo control on all
  exits, attempt/sensitivity limits, zeroized buffers, constant-time compare,
  no secret logging, fail closed; `nopass` only from matched policy. Accept:
  `cargo test auth::` in the container incl. PTY tests.
- S-11 timestamp. Owns `src/timestamp.rs`. Needs S-08. `/run/doas`, root-owned,
  descriptor-relative, symlink/hardlink resistant, no attacker filename parts,
  correct perms, race-safe, scoped to user+terminal, boot/monotonic/wall-clock
  handling, tested expiry, `-L` invalidation; absence/corruption means
  re-auth, never allow. Accept: `cargo test timestamp::` in the container.
- S-12 log. Owns `src/log.rs`. Needs S-02. Syslog auth/fail/exec records via
  libc with constant format strings; `nolog` never silences denials or auth
  failures; no journald. Accept: `cargo test log::` in the container.
- S-09 exec. Owns `src/exec.rs`. Needs S-07. UID/GID/groups (real/effective/
  saved), supplementary groups, NSS, capability/ambient state, ordering,
  env handoff, fd hygiene (`CLOEXEC`, `close_range`), safe `cmd` resolution
  (CVE-2019-25016: no attacker PATH for restricted rules; authorized ==
  executed), `execveat` evaluation without race claims, no shell except `-s`,
  exit/signal fidelity, post-transition state verification. No `no_new_privs`
  /seccomp/capability change without explicit applicability proof. Accept:
  root-in-container `cargo test exec::` incl. fd-leak and transition vectors.
- S-13 tty. Owns `src/tty.rs`. Needs S-09. Isolation strategy on Linux
  (CVE-2023-28339): TIOCSTI, controlling terminal, PTY lifecycle, echo,
  signals, winsize, job control, Ctrl-C/Z, termination, restoration. If not
  completable: record blocking release issue in Status, fail closed. Accept:
  `cargo test tty::` in the container.
- S-14 oracle. Owns `tests/oracle/`, `docs/differences.md`. Needs S-03..S-13
  (all behavior present). Build OpenDoas 6.8.2-r8 from S-01 pins in the
  container; differential corpus over grammar, ordering, identity, cmd/args,
  confdir order, CLI combos, env, auth paths, persistence, shell, UID/GID,
  exits, logging, parser errors; goldens committed; intentional diffs
  allowlisted once each. Accept: full corpus green or every red mapped to an
  allowlist entry or open item. Mutation rule: break the port on purpose for
  one behavior and watch its test fail.
- S-15 adversarial. Owns `tests/adversarial/`. Needs S-14. Deterministic
  seeded mutation tests + fault injection: malformed input, races, fd leaks,
  missing TTY, failed transitions, signal interruption, TIOCSTI attempts,
  crashes, partial-syscall failures. No Rust fuzzing deps. Accept: `cargo
  test --test adversarial` green in the container.
- S-16 release. Owns `README.md`, install/rollback docs, final numbers. Needs
  S-14+S-15. aarch64 release build; `ldd` inspection (no silent native deps,
  no fully-static claim unless verified); log binary size + cold overhead vs
  oracle (fix only past 2x); reproducibility check; honest maturity statement
  incl. blocked production-readiness claim (P1) and remaining risks. Accept:
  release artifacts + README install/rollback procedure verified in a fresh
  container.

## Acceptance

Each deliverable passes its named command in the Alpine edge container:

- Pinned sources: S-01 rg check.
- Skeleton + dep/lint/test gates: S-02 docker/clippy/tree commands.
- CLI, parser, policy, env, identity, confload, auth, timestamp, log, exec,
  tty: the per-module `cargo test <module>::` commands above, in-container
  where stated. Distinct success and failure conditions live in the module
  tests, not here.
- Oracle parity: S-14 full corpus; failures only via allowlist or open item.
- Adversarial: S-15 suite green.
- Release: S-16 artifacts, `ldd` output, size/speed log, fresh-container
  install/rollback run.

## Needs environment

- Independent security review (P1); owner arranges, claim stays blocked.
- First real CI green on both arches (O4); owner pushes at milestones.
- Install/rollback/root-recovery validation on real Alpine aarch64 hardware.
- Anything in S-13 that genuinely needs hardware the container lacks.

## Execution boundary and non-goals

Authorized: read upstream sources; fetch/build oracle and Alpine packages
inside `.work/` and containers; run disposable containers/VMs; commit green
slices to `main` locally; edit any repo file the active slice owns.
Forbidden: push; host setuid installs; new direct dependencies (parks slice);
`--no-verify`/skipped checks; weakening a test to fit code; silent fallbacks.
Non-goals with reason: x86_64 qualification (owner scope cut); sudo
compat/plugins/enterprise policy (not doas); PAM/systemd/journald/D-Bus/
network daemons (small bounded binary); `-a` flag (OpenBSD auth styles N/A on
Linux); recursive includes and regex policy (auditable surface); BSD/macOS;
glibc-specific code (musl-only CI keeps the boundary small; feasibility is
absence of glibc-only paths, not tested support).

## Reference

Empty tree at `3cef827`: this doc + `rust-toolchain.toml`
(`nightly-2026-09-15`, installed). Target layout: `src/cli.rs`, `config.rs`,
`policy.rs`, `identity.rs`, `auth.rs`, `timestamp.rs`, `env.rs`, `exec.rs`,
`tty.rs`, `load.rs`, `log.rs`, `sys.rs` (narrow unsafe FFI); `Dockerfile`
(Alpine edge); `tests/oracle/`, `tests/adversarial/`; `docs/upstream.md`,
`docs/differences.md`. Durable design rationale that outgrows Status goes to
`docs/`, linked here, never appended to this doc.
