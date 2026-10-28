# doas-rs

Rust reimplementation of OpenBSD `doas` for Linux (aarch64 musl, Alpine edge). Setuid-root binary; deny by default, fail closed.

## Commands

```sh
docker build -t doas-dev .
docker create --name check doas-dev sh -lc 'cargo clippy --all-targets -- -D warnings && cargo test'
docker start -a check
cargo tree  # must show only libc/rustix (+transitives)
sh harness/vm-priv.sh  # setuid privileged qualification in a disposable KVM guest
```

Note: `docker run --rm` hangs on attach in this environment; use `docker create` + `docker start -a` instead.

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
