# doas-rs

Minimal security-hardened Rust reimplementation of OpenBSD `doas` for
Linux (aarch64 musl, Alpine edge). Real setuid-root boundary:
correctness and security are release requirements, not follow-ups.

> Maturity: experimental. Production use is blocked on independent
> security review. Interactive use is refused while the kernel leaves
> `TIOCSTI` enabled (`/proc/sys/dev/tty/legacy_tiocsti` reads `1`,
> `CVE-2023-28339`); set it to `0` or invoke non-interactively. No
> warranty. Use only in disposable containers or VMs. Never install an
> experimental setuid binary on a host you care about.

## Usage

`usage: doas [-Lns] [-C config] [-u user] command [args]`

Run `doas command [args]` as root (`-u user` for another target,
`-s` for a shell, `-n` to fail instead of prompting, `-L` to forget
persisted approval). `doas -C config [command [args]]` checks
policy and prints `permit` or `deny` without executing. Rules live
in `/etc/doas.conf`, then `/etc/doas.d/*.conf`; see
`docs/doas.conf.example`.

## Install (Alpine edge, aarch64)

Build the binary with the pinned toolchain (`Dockerfile`,
`rust-toolchain.toml`):

```sh
docker build -t doas-dev .
docker create --name doas-rel doas-dev cargo build --release
docker start -a doas-rel
docker cp doas-rel:/work/target/release/doas ./doas
docker rm doas-rel
```

Copy `./doas` and `docs/doas.conf.example` to the Alpine host,
then as root:

```sh
apk add --no-cache ca-certificates
install -m 4755 doas /usr/local/bin/doas
install -m 640 doas.conf.example /etc/doas.conf
mkdir -m 750 -p /etc/doas.d
mkdir -m 700 -p /run/doas
doas -C /etc/doas.conf
printf 'permit :wheel\n' > /etc/doas.conf
chmod 640 /etc/doas.conf
doas -C /etc/doas.conf id
```

Verify (measured on `alpine:edge` aarch64):

```sh
ldd /usr/local/bin/doas
# Not a valid dynamic program (fully static, musl + libcrypt.a)
ls -l /usr/local/bin/doas
# -rwsr-xr-x 825896 bytes (806.5K), sha256
# 0de3a83e83fcade1d4834b190340362fff242a218eb4c35bd2bdec7d5c58d8a8
# (identical across rebuilds)
ls -l /etc/doas.conf
ls -ld /etc/doas.d /run/doas
# drwxr-x--- /etc/doas.d, drwx------ /run/doas, both root-owned
```

Cold `doas -C` overhead matches the oracle (`OpenDoas 6.8.2`,
`--without-pam --with-timestamp`): both `real 0m 0.00s` on the same
host, well under the `2x` gate. Binary is larger than the oracle
(`806.5K` vs `77.1K`) from the Rust runtime; no action per the
size-is-logged rule.

## Rollback and root recovery

```sh
rm -f /usr/local/bin/doas
rm -rf /etc/doas.d /run/doas
cp docs/doas.conf.example /etc/doas.conf
```

If locked out, reboot from trusted media, mount the rootfs, and remove
the setuid binary and config above. Keep a root shell open while
testing policy changes.

## License

MIT License; see `LICENSE`.

## Differences from the oracle

See `docs/differences.md` for intentional, allowlisted deltas and
`docs/upstream.md` for pinned sources and CVEs.
