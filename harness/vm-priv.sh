#!/bin/sh
# doas privileged guest test. Reuses the seatd/mdevd disposable-QEMU pattern:
# cached Tinyland guest-root, pinned virt kernel/initramfs, ext4 image under
# .work/, KVM, serial console markers, QMP quit, no host mutations.
#
# Usage: harness/vm-priv.sh [guest-root kernel initramfs doas-bin]
# Defaults match harness/VM.md-style cached paths and the release musl binary.
set -euo pipefail
cd "$(dirname "$0")/.."

GUEST_ROOT="${1:-/home/josh/d/tinyland/.work/guest-root}"
KERNEL="${2:-/home/josh/d/tinyland/.work/vmlinuz-virt}"
INITRAMFS="${3:-/home/josh/d/tinyland/.work/initramfs-virt}"
DOAS_BIN="${4:-target/x86_64-unknown-linux-musl/release/doas}"

for p in "$GUEST_ROOT/init" "$KERNEL" "$INITRAMFS" "$DOAS_BIN"; do
  test -e "$p" || { echo "vm-priv: missing $p" >&2; exit 1; }
done
command -v qemu-system-x86_64 >/dev/null || { echo "vm-priv: qemu missing" >&2; exit 1; }
test -c /dev/kvm || { echo "vm-priv: /dev/kvm missing (need KVM)" >&2; exit 1; }

exclude=$(git rev-parse --git-path info/exclude)
rg -qxF '.work/' "$exclude" || printf '\n.work/\n' >> "$exclude"
mkdir -p .work/tmp .work/vm-priv
export TMPDIR="$PWD/.work/tmp"
work="$PWD/.work/vm-priv"
rm -rf "$work/root"
mkdir -p "$work/root"
cp -a --reflink=auto "$GUEST_ROOT/." "$work/root/"
cp "$DOAS_BIN" "$work/root/usr/local/bin/doas"
cp harness/vm-guest-priv.sh "$work/root/usr/local/bin/vm-guest-priv"
chmod +x "$work/root/usr/local/bin/vm-guest-priv"
cat > "$work/root/init" <<'GUEST'
#!/bin/sh
mount -o remount,rw /
mkdir -p /dev/pts /dev/shm /run /tmp
mount -t devpts none /dev/pts
export PATH=/usr/local/bin:/usr/bin:/bin:/sbin
/usr/local/bin/vm-guest-priv
rc=$?
echo VM_EXIT=$rc > /dev/console
poweroff -f
GUEST
chmod +x "$work/root/init"
truncate -s 0 "$work/guest.img"
truncate -s 1G "$work/guest.img"
mkfs.ext4 -q -d "$work/root" "$work/guest.img"
qmp="$work/qmp.sock"
log="$work/console.log"
rm -f "$qmp" "$log"
pid=
wait_for_exit() {
  for _ in $(seq 1 "$1"); do
    kill -0 "$pid" 2>/dev/null || return 0
    sleep 1
  done
  ! kill -0 "$pid" 2>/dev/null
}
cleanup() {
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
    kill -TERM "$pid" 2>/dev/null || true
    if ! wait_for_exit 5; then
      kill -KILL "$pid" 2>/dev/null || true
      wait_for_exit 5 || echo "QEMU did not exit after SIGKILL: $pid" >&2
    fi
  fi
  if [ -n "$pid" ]; then wait "$pid" 2>/dev/null || true; pid=; fi
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 131' QUIT
trap 'exit 143' TERM
qemu-system-x86_64 -M q35 -m 1024 -cpu host -enable-kvm -vga none \
  -device virtio-gpu-pci -device virtio-keyboard-pci \
  -kernel "$KERNEL" -initrd "$INITRAMFS" \
  -append "console=tty0 console=ttyS0 root=/dev/vda rootfstype=ext4 rw init=/init" \
  -drive "file=$work/guest.img,format=raw,if=virtio" \
  -display none -serial "file:$log" -qmp "unix:$qmp,server=on,wait=off" \
  -no-reboot > "$work/qemu.log" 2>&1 &
pid=$!
for _ in $(seq 1 90); do
  kill -0 "$pid" 2>/dev/null || break
  sleep 1
done
if kill -0 "$pid" 2>/dev/null; then echo 'guest timed out' >&2; tail -40 "$log"; exit 1; fi
wait "$pid"; pid=
rg -q '^VM_EXIT=0' "$log" || { echo 'guest failed'; tail -40 "$log"; exit 1; }
for marker in DOAS_PRIV_EXEC_OK DOAS_PRIV_CHECK_OK DOAS_PRIV_CRED_OK; do
  rg -q "^$marker" "$log" || { echo "missing $marker" >&2; tail -40 "$log"; exit 1; }
done
echo "VM_PRIV_OK $log"
