# doas-rs

Rust reimplementation of OpenBSD `doas` for Linux (aarch64 musl, Alpine 3.24). Setuid-root binary; deny by default, fail closed.

## Commands

```sh
docker build -t doas-dev .
docker create --name check doas-dev sh -lc 'cargo clippy --all-targets -- -D warnings && cargo test'
docker start -a check
cargo tree  # must show only libc/rustix (+transitives)
/bin/bash harness/vm-priv.sh GUEST_ROOT KERNEL INITRAMFS DOAS_BIN
```

Note: `docker run --rm` hangs on attach in this environment; use `docker create` + `docker start -a` instead.

## Verification

- The Linux ARM64 Alpine development image ran the checkout's `make test` Cargo command twice. Both runs passed 166 tests in 5.74 s with a fresh Cargo target and 3.07 s warm. `make lint` runs the Clippy command that passed in 0.91 s there.
- Pull requests run `make test-ci`, which executes Clippy and the same test command in the development image.
- `make coverage` runs the ordinary suite with cargo-llvm-cov 0.9.1 and the pinned Rust toolchain's `llvm-tools`. It writes branch counts to `.work/coverage/report.json`.
- `tests/cli.rs` exercises help, argument checks, exit codes and rule matching through the binary. `tests/adversarial.rs` covers rejection of malformed and inaccessible policy inputs and concurrent config checks.
- `src/config.rs` and `src/policy.rs` unit tests cover the configuration grammar and authorization decisions. Tests in `src/auth.rs`, `src/timestamp.rs`, `src/exec.rs`, and `src/tty.rs` cover their local contracts.
- The separate native x86-64 KVM harness checks installed setuid execution, unprivileged config checks and credential transitions through its serial console. [Pinned guest setup](https://github.com/laputa-systems/doas-rs/blob/233d2e93eee2a994b848535c1b764ad93c20aa84/.github/workflows/native-doas-guest-trial.yml). Real password entry and ARM64 guest behavior require separate checks.
- The interface serves administrators and shell callers. This project has no library consumer in the fleet and no declared performance workload.

## Invariants

- Deny by default; absence or corruption means re-auth, never allow.
- Fail closed on every error path; no silent fallbacks.
- Exactly two direct Rust dependencies: `libc`, `rustix`.
- Linux only; release target is aarch64 musl.

## Map

- CLI parsing → `src/cli.rs`
- Config grammar → `src/config.rs`
- Policy evaluation → `src/policy.rs`
- Identity and groups → `src/identity.rs`
- Secure config loading → `src/load.rs`
- Authentication → `src/auth.rs`
- Timestamps → `src/timestamp.rs`
- Syslog → `src/log.rs`
- Execution boundary → `src/exec.rs`
- Terminal isolation → `src/tty.rs`
- Pinned sources → `docs/upstream.md`
- Intentional deltas → `docs/differences.md`
- Install and rollback → `README.md`
