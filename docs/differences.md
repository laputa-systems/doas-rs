# Deliberate differences from the oracle

Each entry is an intentional deviation with rationale. Unexamined
diffs stay open; these are allowlisted once each.

## D1: configuration directory always supplements the main file

Oracle with Alpine `configuration-directory.patch` (final hunk) reads
`/etc/doas.conf` (required) then `/etc/doas.d/*.conf` alphabetical,
later-wins. Earlier patch revisions did either-or. This port follows
the final both-then-append behavior. Empty `doas.d` with no `.conf`
fails closed (no silent empty policy).

## D2: safe PATH is unconditional for restricted commands

Oracle sets `PATH` to the safe value only when the matched rule names
a command, otherwise restores the invoking `PATH`. This port uses the
safe value for every restricted execution and for `PATH` references
in `setenv`. Unrestricted rules still resolve through the safe set
unless the admin explicitly opts into `keepenv`. This closes
`CVE-2019-25016` by construction: authorized equals executed, never
through attacker `PATH`.

## D3: relative paths with a slash are rejected

Oracle `execvpe` runs `bin/foo` relative to the invoking cwd when the
rule names it. This port rejects any command containing `/` that is
not absolute. Admins must write absolute paths. This removes
cwd-squatting without changing absolute-path or bare-name behavior.

## D4: descriptor-relative opens with `O_NOFOLLOW` throughout

Oracle opens config and timestamp paths by name (`fopen`, `stat`,
`open` without `O_NOFOLLOW` for some legs). This port opens parent
directories with `O_DIRECTORY|O_NOFOLLOW`, then files with
`openat(O_NOFOLLOW|O_CLOEXEC)`, checks with `fstat`, and never
re-opens by path. `openat2` with `RESOLVE_NO_SYMLINKS` was evaluated;
single-component opens with `O_NOFOLLOW` plus `fstat` give the same
guarantee here, so the fallback is the implementation.

## D5: timestamp group check hardened to root-only

Oracle checks timestamp `st_gid == getgid()`. This port requires
`st_uid == 0`, regular file, mode `0000`, and dual-clock expiry, and
scopes the name to `ppid-sid-tty-start-uid`. Group is not trusted
from the invoking user. Absence or corruption means re-auth, never
allow. `-L` clears the caller-scoped file and is idempotent.

## D6: TTY strategy is detect plus refuse, not a byte relay

Oracle shares the invoking terminal, leaving `CVE-2023-28339` open
(upstream issue `#106`). A parent-side byte relay would not close it:
bytes an attacker pushes into the invoking terminal with `TIOCSTI`
travel the relay into the privileged session exactly like keystrokes,
so a proxy is security theater here. The only userspace strategy that
closes the CVE scenario is detection plus refusal. This port reads
`legacy_tiocsti`; interactive use (terminal stdin) is refused while
`TIOCSTI` is enabled, with an actionable error, and proceeds by direct
exec once the kernel disables it. Non-interactive use is unchanged
from the oracle: pipes and files pass straight through, so pipelines
keep working. Residual, stated openly: a target program that
explicitly opens `/dev/tty` shares the invoking terminal exactly as
it does under the oracle; no new exposure, no silent fix.

## D7: `crypt` backend is system `libcrypt`

No own crypto. Password checks call system `crypt` through `libcrypt`,
which handles the modular hashes found in shadow (DES and `$6$`
sha512crypt verified by roundtrip on Linux). Hashes starting with `*`,
`!`, or empty, and missing shadow entries, fail closed. Constant-time
compare, zeroized buffers, single attempt, TTY required,
non-interactive fast fail. Calls are serialized through a
process-wide lock because `crypt` returns shared static storage.

## D8: numeric IDs bounded to `0..=65534`

Oracle `parseuid` and `parsegid` accept `0..UID_MAX-1` (`65534`) and
reject `UID_MAX` (`65535`). This port enforces the same bound in the
resolver and treats larger, negative, malformed, or unknown names as
no-match (deny by default). No panic on overflow.
