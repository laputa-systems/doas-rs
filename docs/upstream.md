# Pinned upstream sources

Oracle and packaging references for this port. SHAs verified 2026-10-28
via `git ls-remote` and the GitHub commit API.

## OpenBSD canonical source

- Mirror: `https://github.com/openbsd/src` (`usr.bin/doas/doas.c`,
  `usr.bin/doas/doas.conf.5`).
- `master` HEAD: `b077898599cb9561d1a0784b6b04bd7f32b1f82d`.
- Rowhammer hardening, also carried by Alpine below:
  `38599afa1d1d1f14a897b01350e8ce94486e1788`
  (2024-02-15, "change permit to be more bits away from deny,
  because rowhammer").

## OpenDoas (portability oracle)

- Repo: `https://github.com/Duncaen/OpenDoas`.
- `v6.8.2`: tag object `581ef0499a84898e06931aac1c47e994f68a70ac`,
  commit `7f0205fe2f06221d76243342d299851f48c2b83c`
  (2022-01-26, "Fail early if argc <= 0 or argv[0] is NULL").
  Previous tag `v6.8.1` commit `24b1a957cbe55363ca06a62b10c936e5c53e3423`;
  `v6.8` commit `31abd37c26c26892ce5e0d538c51fbc38ff3e05a`.
- Post-6.8.2 `master` HEAD: `b96106b7e34ac591ae78b1684e9be3a265122463`
  (2022-02-21, "pam: always print pam_conv messages to stderr, Fixes #95").
  `release-6.8` branch head: `7f0205fe2f06221d76243342d299851f48c2b83c`.
- Issues: `#45` (closed, "OpenDoas keeps current PATH variable",
  CVE-2019-25016); `#106` (open, "security vulnerability:
  TIOCSTI tty character injection", CVE-2023-28339).

## Alpine aports packaging

- Mirror: `https://github.com/alpinelinux/aports`, `master` HEAD at read:
  `11163576edc8df724000096fdb82eeb30df58fb0`.
- Directory `main/doas`, package `doas-6.8.2-r8`. Last touches:
  `3a55d7eb7b4b1e865bb0742590c2090e16f25fb9` (2024-10-11, config-order
  comment); `935e7613cf32d2e09462071961b534ad0226a71b` (2024-05-20,
  rowhammer backport); `40b30d19d63af675de8678549e9704e9e63c1d2f`
  (2023-05-16, read `/etc/doas.conf` then `/etc/doas.d/*.conf`);
  `04f177586bc75fcb4da2f57c6cedee4498e486a3` (2022-06-30, Alpine
  default PATH); `3e96d616928876e9ed1dabb48b8266218c611a70`
  (2022-01-26, upgrade to 6.8.2).
- File blobs at that HEAD: `APKBUILD`
  `be467c682cade4808f88990e82c2397f76894044`;
  `change-PATH.patch`
  `c0fb7a51ba39145137fa95b76f6281753fb47c29`;
  `configuration-directory.patch`
  `1ab9b968d1e3d8e2863a8b692db50df5a20b94d8`;
  `manpage-example-path.patch`
  `31048c70d6f32495740d89d52087f44f4a1acf24`;
  `rowhammer.patch` `761ffb421cb89c5b142a1b2a1bebdf753071d22e`;
  `doas.conf` `d616d35f862bff42d12cce559cd6e6110661e89e`;
  `doas.post-upgrade` `113f801d39f527e64b1fdf431dc118e29f901763`.
- Flags feeding the dev image: `./configure --prefix=/usr
  --without-pam --with-timestamp --with-doas-confdir`; safe PATH
  `/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`;
  source tarball sha512
  `4a93ff477413c859ba2702e688fa4f83248fff85e61e12336838a1e9aa1a8d9963a9782e4bc5e58e8d04b86c2c8ceb6b235ae9d3b32b3e548a2514a43653137d`.

## Requirement split

- Canonical (from OpenBSD `usr.bin/doas`): config grammar and
  last-match-wins permit/deny semantics; `permit`/`deny` with
  `nopass`, `persist`, `nolog`, `keepenv`, `setenv`; user/group/ID
  matching with `as`, `cmd`, `args`; safe default PATH.
- Portability (from OpenDoas): Linux/PAM build, `--with-timestamp`
  timestamp dir, `--without-pam` shadow path, `doas -L`
  invalidation, empty-`argv[0]` early failure.
- Alpine (from aports): `/etc/doas.conf` required, then
  `/etc/doas.d/*.conf` alphabetical later-wins; Alpine default PATH
  order; rowhammer-resistant permit return shape; doc example path
  under `/usr/share/doc/doas`.
- Improvement (new in this port): memory-safe Rust, no PAM
  dependency surface, TIOCSTI isolation strategy (see below).

## CVEs

- CVE-2019-25016: in OpenDoas 6.6 through 6.8, the invoking user's
  PATH was inherited by the executed command when the matching rule
  allowed any command. Introduced by
  `01c658f8c45cb92a343be5f32aa6da70b2032168`, reported in issue
  `#45`, fixed by `d5acd52e2a15c36a8e06f9103d35622933aa422d`
  ("correctly reset path for rules without specific command",
  2021-01-28, released in 6.8.1). Alpine tracks it in `APKBUILD`
  (`6.8-r1: CVE-2019-25016`). This port must never execute via an
  attacker-influenced PATH for restricted rules: authorized ==
  executed.
- CVE-2023-28339: OpenDoas through 6.8.2 shares the invoking
  terminal with the executed session, so where the TIOCSTI ioctl is
  available a local attacker can inject keystrokes into a
  privileged session (issue `#106`, still open upstream; no
  upstream fix release). Mitigations live outside the oracle:
  OpenBSD removed TIOCSTI in 6.0; Linux 6.2+ can disable it via
  `tty.legacy_tiocsti`. This port needs its own TTY isolation
  strategy (S-13); until then the gap stays a recorded blocking
  release issue, never a silent fallback.
