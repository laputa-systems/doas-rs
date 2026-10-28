# doas-rs

Minimal security-hardened Rust reimplementation of OpenBSD `doas` for
Linux (musl; install below targets Alpine edge, aarch64 or x86_64).
Real setuid-root boundary: correctness and security are release
requirements, not follow-ups.

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

## Install (Alpine edge)

Build the binary with the pinned toolchain (`Dockerfile`,
`rust-toolchain.toml`) for the host architecture:

```sh
docker build -t doas-dev .
docker create --name doas-rel doas-dev cargo build --release
docker start -a doas-rel
docker cp doas-rel:/work/target/release/doas ./doas
docker rm doas-rel
```

Copy `./doas` and `docs/doas.conf.example` to the Alpine host,
then as root with a spare root shell open and the existing privilege
tool untouched:

```sh
apk add --no-cache ca-certificates
install -m 4755 doas /usr/local/bin/doas
if test ! -e /etc/doas.conf; then
  install -m 640 doas.conf.example /etc/doas.conf
else
  echo "preserving existing /etc/doas.conf" >&2
fi
mkdir -m 750 -p /etc/doas.d
mkdir -m 700 -p /run/doas
doas -C /etc/doas.conf
# Edit /etc/doas.conf explicitly; example (does not overwrite by default):
# printf 'permit :wheel\n' > /etc/doas.conf.new && chmod 640 /etc/doas.conf.new
doas -C /etc/doas.conf id
```

Verify (example output shape, not exact bytes):

```sh
ldd /usr/local/bin/doas
# Not a valid dynamic program (fully static, musl + libcrypt.a)
ls -l /usr/local/bin/doas
# -rwsr-xr-x root-owned, setuid bit set
ls -l /etc/doas.conf
ls -ld /etc/doas.d /run/doas
# drwxr-x--- /etc/doas.d, drwx------ /run/doas, both root-owned
```

No startup/latency claim is made here: two wall-clock readings rounded
to `0.00s` cannot establish a ratio or a gate. Performance comparison
requires the median of repeated runs on a quiet host with the load
check passing before and after. The binary is larger than OpenDoas
(~800K vs ~77K) because it statically links the Rust runtime and
libcrypt; size is logged, not gated.

## Rollback and root recovery

```sh
rm -f /usr/local/bin/doas
rm -rf /run/doas
# Do not delete /etc/doas.d or overwrite /etc/doas.conf here;
# those are administrator policy. Remove only what this trial added.
```

If locked out, reboot from trusted media, mount the rootfs, and remove
only the setuid binary above. Keep a root shell open while testing
policy changes and keep the distribution privilege tool installed until
the trial is explicitly accepted.

## License

MIT License; see `LICENSE`.

## Deliberate behavior

See `docs/differences.md` for the intentional, allowlisted behavior
rules and `docs/upstream.md` for pinned sources and CVEs.
