# Campaign: Build a minimal, security-hardened Rust doas for Linux

You are a senior Rust systems engineer and security-focused Unix programmer.

Build a production-quality, Linux-first Rust reimplementation of OpenBSD `doas`, with Alpine Linux compatibility as the primary target.

This is a real setuid-root security boundary. Treat correctness and security as release requirements, not follow-up improvements.

Work autonomously in the current repository. Implement, test, document, and commit working increments directly to `main`. Do not stop after creating scaffolding or a design proposal.

## 1. Philosophy

The goal is **OpenBSD doas, not sudo in Rust**.

Preserve the extremely small policy language, concise CLI, predictable authorization semantics, and limited scope.

Improve Linux-specific privilege handling where historical OpenDoas has security limitations.

Avoid:

- sudoers compatibility, plugins, enterprise policy, or sudo emulation
- PAM, systemd, D-Bus, daemon processes, or network access
- broad configuration frameworks, scripting, regex matching, and policy extensions
- unnecessary abstractions, workspaces, framework crates, or generic libraries
- supporting every Unix platform
- reproducing legacy behavior when it demonstrably weakens security

Avoid adding functionality merely because sudo-rs implements it.

Prefer a small number of easily audited modules and explicit state transitions.

## 2. Source-of-truth investigation

Before implementing, inspect these three sources thoroughly:

**Canonical OpenBSD doas:**

https://github.com/openbsd/src/tree/master/usr.bin/doas

Pay particular attention to:
- `doas.c`
- `doas.h`
- `parse.y`
- `env.c`
- `doas.1`
- `doas.conf.5`

**Portable OpenDoas:**

https://github.com/Duncaen/OpenDoas

Use release v6.8.2 and inspect subsequent commits, issues, and security reports. Study its Linux-specific:
- `shadow.c`
- `timestamp.c`
- `configure`
- environment and execution behavior

**Alpine downstream packaging:**

https://github.com/alpinelinux/aports/tree/master/main/doas

Study the exact APKBUILD and all patches, particularly:
- `configuration-directory.patch`
- `change-PATH.patch`
- `rowhammer.patch`

The known Alpine configuration uses `--without-pam --with-timestamp --with-doas-confdir`.

Check all references against their actual latest upstream revisions. Record exact commit SHAs, tags, and relevant decisions in `plan.md`; do not rely on branch names as reproducible specifications.

Separate requirements into:
1. Canonical OpenBSD behavior
2. Linux portability adaptations
3. Alpine-specific extensions
4. Intentional security improvements

Do not mechanically translate OpenDoas's C source. Implement a clean Rust architecture based on these specifications.

Respect applicable licenses and attribution requirements.

## 3. Dependency contract

**The only permitted direct external Rust dependencies are:**

- `libc`
- `rustix`

Rust's standard library is encouraged.

No other direct runtime, build, or development crates.

In particular, do not introduce:
- nix
- clap
- serde
- regex
- anyhow / thiserror
- password or authentication crates
- cryptographic hashing crates
- parser generators
- async runtimes
- platform abstraction frameworks

Necessary transitive dependencies of `libc` and `rustix` are permitted.

Use a current stable Rust edition and pin compatible, current stable crate versions in `Cargo.lock`.

Prefer rustix's safe, owned-FD interfaces for supported operations. Use libc only where C ABI integration or unsupported syscalls require it.

Keep unsafe code concentrated in small, reviewed FFI boundaries with explicit safety invariants.

Never implement your own password-hashing algorithms.

Do not silently link additional native libraries. If a non-musl target requires a separate libcrypt implementation, document that dependency and keep that target outside the supported release matrix until explicitly approved.

## 4. Supported platforms

Primary:
- Linux x86_64 musl
- Linux aarch64 musl
- Alpine Linux as the reference runtime

Architect the common code so glibc Linux support remains feasible without polluting the musl implementation.

Do not add BSD or macOS support.

Deliver reproducible release builds for both primary architectures once their tests and security gates pass.

Do not describe a build as fully static unless its actual linked dependencies have been verified.

## 5. CLI compatibility

Implement the Linux-relevant OpenDoas CLI:

- `doas command [args...]`
- `doas -u user command [args...]`
- `doas -n command`
- `doas -s`
- `doas -C config [command [args...]]`
- `doas -L`

Preserve documented option interactions, shell invocation, command arguments, exit statuses, and meaningful diagnostics.

Use raw Unix argument bytes where appropriate, not unnecessarily UTF-8-only interfaces.

OpenBSD-specific authentication-style options such as `-a` are intentionally out of scope on Linux.

`-C` must validate configuration and optionally evaluate authorization without executing anything. It must never read arbitrary user-specified configuration files with elevated privilege.

## 6. Policy language

Implement the actual `doas.conf` grammar in Rust.

Support:
- `permit` / `deny`
- `nopass`
- `persist`
- `nolog`
- `keepenv`
- `setenv { ... }`
- users, groups, and numeric IDs
- `as target`
- `cmd command`
- `args ...`
- quoted strings, escapes, comments, and continuation rules

The parser must be handwritten, small, deterministic, bounded, and thoroughly tested.

Critical semantic requirements:

- Last matching rule wins.
- No match means deny.
- `args` omitted means unrestricted arguments for that command.
- `args` present but empty means the command must receive no arguments.
- Command and argument matching must not inadvertently become wildcard or shell matching.
- Reject `args` without `cmd`.
- Reject malformed or unsupported option combinations.
- Reject an invalid configuration as a whole; never authorize based on a partially parsed policy.
- Preserve source filename and line number in errors.

Use precise types for `Permit`, `Deny`, options, identities, commands, and arguments.

Design policy evaluation as a pure function over a parsed policy and resolved request context.

Keep authorization decisions separate from authentication and execution.

## 7. Alpine configuration semantics

Use Alpine's established configuration behavior:

1. Read `/etc/doas.conf` first.
2. Read `/etc/doas.d/*.conf` afterward, in deterministic alphabetical order.
3. Later rules override earlier matching rules.
4. Ignore unrelated files in the snippet directory.
5. Treat the main configuration as required.
6. Permit an absent or empty optional snippet directory.

Use Alpine's safe default PATH:

`/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`

Do not implement arbitrary recursive includes.

Security-hardening requirements:

- Open privileged config files using descriptor-based APIs.
- Verify ownership, type, and permissions on the opened file.
- Reject writable-by-group/other configuration.
- Validate relevant directory ownership and write permissions.
- Protect against symlink and path-replacement attacks.
- Use `openat2` resolution restrictions when appropriate, with a secure documented fallback or explicit failure.
- Never reopen a previously checked file by pathname for privileged parsing.
- Fail closed on races, I/O errors, and malformed input.

Where stricter security intentionally differs from Alpine OpenDoas behavior, document and test that difference.

## 8. Linux authentication, without PAM

Implement an Alpine-compatible shadow-password backend using libc interfaces.

Use system-provided password lookup and cryptographic password verification. Do not implement cryptographic primitives.

Requirements:

- Resolve the invoking user via system account interfaces.
- Read the appropriate shadow-password record.
- Authenticate the invoking user, not the target user.
- Correctly handle locked accounts, empty passwords, missing records, and unsupported hash schemes.
- Check applicable account-expiration and password-expiration semantics, documenting unavoidable differences from PAM.
- Require a controlling TTY for password entry.
- Never obtain a password from ordinary piped stdin.
- Disable terminal echo safely and restore terminal state on all possible exit paths.
- Limit attempts and sensitive-buffer sizes.
- Clear password buffers without permitting compiler optimization to remove the clearing.
- Compare generated password hashes without introducing avoidable timing leaks.
- Never overwrite memory returned by libc `crypt()` unless its ownership and mutability are explicitly guaranteed.
- Never log passwords, password hashes, or other authentication secrets.
- Fail closed if hash verification is unavailable.

Audit the `crypt(3)` ABI and algorithm support separately for supported targets.

No silent fallback to `nopass`.

Make `nopass` an explicit property of a matched policy rule, not an authentication error-recovery mechanism.

Avoid invented account policy. Document exactly which shadow-account restrictions are enforced.

## 9. Credential transitions and execution

Treat this as the highest-risk implementation area.

Correctly handle:

- Real, effective, and saved UID/GID
- Supplementary groups
- Caller identity versus target identity
- NSS/passwd/group lookups
- Linux capabilities and ambient capability state
- Secure credential transition ordering
- Filesystem and process privileges
- Environment construction
- File descriptor lifetime
- Command path resolution
- Process exit and signal behavior

The target credentials and supplementary groups must be installed correctly before executing the target program.

After the final credential transition, verify the resulting state and ensure the process cannot unexpectedly regain its earlier privileges.

Do not blindly apply `no_new_privs`, seccomp, or capability restrictions that would change legitimate target-program behavior. Establish their applicability explicitly.

Close unintended inherited file descriptors; use CLOEXEC consistently and `close_range` where suitable.

Never construct a shell command from user arguments. Execute the requested program directly using an argv vector. A shell is used only when explicitly requested via `-s`.

Preserve correct command exit status and signal termination behavior.

### Executable resolution

Explicitly investigate the OpenDoas behavior for restricted and unrestricted command rules.

Prevent the PATH-inheritance vulnerability historically tracked as CVE-2019-25016.

Do not use attacker-controlled PATH for resolving a restricted command when policy assumes safe PATH resolution.

Prevent discrepancies between the authorized executable and the executed executable.

Evaluate descriptor-based execution (`execveat`, where appropriate), including shell-script behavior and CLOEXEC interactions.

Do not claim race-free execution without proving it.

## 10. Terminal security

Investigate CVE-2023-28339 and Linux TIOCSTI behavior.

Do not assume OpenBSD's TTY security properties exist on Linux.

Design and implement a robust interactive terminal-isolation strategy where needed, using rustix/libc primitives rather than an event-loop dependency.

Test:
- TIOCSTI attacks
- controlling-terminal access
- PTY creation and cleanup
- terminal echo
- signal delivery
- window resizing
- job control
- Ctrl-C / Ctrl-Z
- target-process termination
- terminal restoration

If terminal isolation cannot be completed correctly in the initial iteration, record it as a blocking release issue, not as an undocumented acceptable risk.

Do not silently fall back to a known-unsafe path.

## 11. Authentication persistence

Alpine enables `persist`, so implement it, but isolate it from the core policy and execution engine.

Study upstream OpenDoas's timestamp design and its security invariants.

Requirements:

- Root-owned, non-user-writable timestamp storage.
- Descriptor-relative operations.
- Symlink and hard-link attack resistance.
- No attacker-controlled filename components.
- Correct ownership and permission validation.
- Safe behavior across concurrency and process races.
- Credential reuse scoped to the correct invoking user and terminal/session.
- Correct handling of terminal replacement or session reuse.
- Appropriate monotonic/boot-time and wall-clock validation.
- Correct handling of clock anomalies, suspend/resume, and reboot.
- An explicit, tested expiry window.
- Correct `doas -L` invalidation.

Use a fixed, well-documented location such as `/run/doas`.

Do not substitute a user-writable timestamp cache.

Ensure the absence or corruption of the timestamp cache causes reauthentication or denial, never authorization.

## 12. Environment handling and logging

Reproduce the doas environment model:

- HOME
- LOGNAME
- PATH
- SHELL
- USER
- DOAS_USER
- DISPLAY
- TERM

Implement `keepenv` and `setenv` according to upstream semantics, including removals and variable references.

Default to a clean environment, avoiding dangerous unintended inherited variables.

Distinguish the environment used during privileged setup from the explicitly constructed environment given to the target command.

Test `LD_*`, `IFS`, `ENV`, `BASH_ENV`, unexpected PATH values, duplicate keys, invalid variable names, and non-UTF-8 values.

Support syslog-compatible authorization, authentication-failure, and execution logging through libc.

Always use constant format strings when calling C variadic logging functions.

Honor `nolog` only according to its documented scope. It must not suppress security-critical denial or authentication-failure records.

No journald dependency.

## 13. Test strategy and upstream conformance

Use Alpine's packaged OpenDoas 6.8.2-r8 as the primary executable oracle.

Pin the reference source, patches, and checksums so tests are reproducible.

Build the oracle in a disposable environment. Do not vendor its C implementation into the production Rust binary.

Create a differential conformance suite covering:

- Entire policy grammar
- Rule ordering and overrides
- User/group identity matching
- Command and argument matching
- Config directory ordering
- Valid and invalid CLI combinations
- Environment behavior
- Passwordless and password-based authorization
- Authentication failures
- Timestamp persistence
- Shell execution
- UID/GID transitions
- Exit codes
- Logging
- Parser errors and malformed files

Capture exit status, stdout/stderr, authorization decisions, and observable process state.

Compare exact behavior where practical. Explicitly maintain an allowlist of intentional differences, with security rationale.

Do not treat those differences as unexamined test failures.

### Required negative testing

Test adversarial inputs involving:

- Invalid configuration syntax
- Embedded NULs and non-UTF-8 bytes
- Oversized inputs and integer overflow
- Rule precedence confusion
- Unexpected groups and target users
- Dangerous inherited environments
- Config symlinks and replacement races
- Timestamp symlinks, hard links, and races
- Invalid shadow records
- Unsupported password hashes
- Missing TTY
- File descriptor leakage
- Failed UID/GID transitions
- Signal interruption
- TIOCSTI and terminal manipulation
- Crashes and partial system-call failures

Use deterministic fuzz-style mutation tests and external fuzz tooling where useful, without introducing Rust fuzzing dependencies.

Build unit tests with the standard test framework.

Privileged integration testing must use disposable VMs or similarly isolated, explicitly controlled test environments. Never install an experimental setuid executable onto the developer's primary machine.

## 14. Implementation architecture

Favor a small architecture along these lines:

- `cli.rs`: argument decoding
- `config.rs`: lexer/parser and configuration loading
- `policy.rs`: pure rule matching
- `identity.rs`: passwd/group/shadow identity resolution
- `auth.rs`: TTY password authentication
- `timestamp.rs`: persistent credential state
- `env.rs`: target environment
- `exec.rs`: privilege transitions and execution
- `tty.rs`: terminal handling and isolation
- `sys.rs`: narrowly contained unsafe libc interfaces

Adjust this structure if a genuinely simpler arrangement emerges.

Keep the executable small and single-purpose. No internal microservice architecture or dependency injection framework.

Design explicit state transitions such as:

`UntrustedInput -> ParsedPolicy -> AuthorizedRequest -> AuthenticatedRequest -> PreparedExecution -> Exec`

Prevent unauthorized transitions through APIs and type design.

Do not over-engineer types that add ceremony without additional guarantees.

Use Rust's type system to make authorization and credential-transition mistakes harder to express.

## 15. Build and CI

Provide simple Cargo-based development commands and a minimal POSIX-compatible Makefile only if it adds real convenience.

CI must include:

- Formatting and strict Clippy
- Unit and integration tests
- Parser negative tests
- Differential oracle tests
- Alpine musl x86_64 build and validation
- Alpine musl aarch64 build and validation
- Dependency auditing and license review
- Runtime-linked-library inspection
- Reproducibility checks

Pin GitHub Actions to full commit SHAs.

Do not add systemd or Docker as production requirements. Containers may be used for isolated CI; genuine privilege-boundary qualification should be performed in an appropriate VM.

Measure release binary size and cold invocation overhead relative to Alpine OpenDoas.

Performance matters, but never sacrifice validation or privilege-boundary correctness for a benchmark.

## 16. Security release criteria

Before calling this implementation production-ready:

- Complete full supported-policy conformance.
- Close all known high-severity security findings.
- Verify both musl target architectures.
- Confirm correct password authentication on real Alpine installations.
- Verify credential and group transitions.
- Verify environment sanitization.
- Verify safe config and timestamp handling.
- Resolve terminal isolation requirements.
- Complete adversarial negative testing.
- Obtain an independent security review or keep the production-readiness claim explicitly blocked.
- Validate installation, rollback, and root-access recovery.

The project should document its maturity honestly.

A passing CI pipeline is not a substitute for reviewing the setuid privilege boundary.

Never silently weaken security to achieve oracle parity.

## 17. Deliverables

Produce:

1. A working Rust `doas` binary.
2. Exactly two direct external Rust dependencies: `libc` and `rustix`.
3. A faithful policy parser and authorization engine.
4. Functional Alpine-compatible configuration loading.
5. Password-based and passwordless authorization.
6. Functional timestamp persistence.
7. Correct Linux process execution and privilege transitions.
8. Thorough conformance and security regression tests.
9. A concise README with installation and usage examples.
10. `plan.md` documenting architecture, source revisions, implemented behavior, known deviations, verification results, and remaining risks.

Keep the documentation useful and restrained. Avoid redundant planning documents.

For deployment, provide a conservative installation and rollback procedure. Keep the existing working `doas` available during testing and qualification.

Commit completed, validated increments directly to main.

## 18. Execution approach

Work in this order:

**Phase A — Research and specification:** Verify sources, pin revisions, enumerate semantics and known vulnerabilities.

**Phase B — Pure core:** Implement and thoroughly test CLI decoding, parsing, policy matching, and environment construction. These components should be testable without root.

**Phase C — Linux boundary:** Implement account lookup, authentication, credential switching, safe command resolution, and execution.

**Phase D — Alpine parity:** Implement configuration-directory support, password persistence, logging, and documented Linux-specific behavior.

**Phase E — Security hardening:** Complete terminal isolation, filesystem race resistance, fault-injection testing, and negative tests.

**Phase F — Qualification:** Run differential conformance tests and release gates, benchmark, document, and produce validated artifacts.

Don't stop at the first green build. Continue through all feasible phases.

If a requirement cannot be completed or verified, leave explicit evidence and a blocking entry in `plan.md`. Never present missing security work as completed.

Conclude with a concise summary of what works, what was actually tested, what differs from Alpine OpenDoas, and whether the resulting binary is suitable for real-world privileged use.

**Final governing principle: preserve the simplicity of OpenBSD doas, improve its Linux security boundary, and reject complexity that cannot justify itself.**