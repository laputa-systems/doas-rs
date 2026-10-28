#!/bin/sh
# Guest side of the doas privileged qualification. Runs as pid 1 in the
# disposable guest; host /dev, /sys, networking, console and privilege tools
# are untouched. All mutations stay inside this guest.
#
# Markers go to /dev/console for the host runner to grep:
#   DOAS_PRIV_EXEC_OK   (2A executable resolution, setuid)
#   DOAS_PRIV_CHECK_OK  (2B -C unprivileged)
#   DOAS_PRIV_CRED_OK   (2C credential transitions)
set -u

out() { echo "$@" > /dev/console; }
fail() { out "DOAS_PRIV_FAIL $1"; exit 1; }

DOAS=/usr/local/bin/doas
test -x "$DOAS" || fail "doas binary missing"

# --- install setuid, base policy -------------------------------------------
chown root:root "$DOAS"
chmod 4755 "$DOAS"
test -u "$DOAS" || fail "setuid bit not set"

# Guest rootfs built via mkfs -d preserves host UIDs; policy requires
# root-owned config and parent.
chown root:root /etc
chmod 755 /etc
mkdir -p /run/doas
chmod 700 /run/doas
chown root:root /run/doas

cat > /etc/doas.conf <<'EOF'
permit nopass nobody cmd /bin/echo
permit nopass nobody cmd /bin/sh
permit nopass guest as nobody cmd /bin/echo
permit nopass nobody as guest cmd /bin/echo
EOF
chmod 640 /etc/doas.conf
chown root:root /etc/doas.conf

# --- 2A: executable resolution must fail closed under setuid ---------------
# Safe-PATH miss: bare name absent from SAFE_PATH must fail, never run cwd.
mkdir -p /tmp/hostile
printf '#!/bin/sh\necho PWNED\n' > /tmp/hostile/evil-cmd-xyz
chmod 755 /tmp/hostile/evil-cmd-xyz
if su -p -s /bin/sh nobody -c 'cd /tmp/hostile && /usr/local/bin/doas evil-cmd-xyz' 2>/dev/null; then
  fail "cwd fallback executed hostile binary"
fi
if su -p -s /bin/sh nobody -c '/usr/local/bin/doas doas-no-such-cmd-xyz-123' 2>/dev/null; then
  fail "safe-PATH miss unexpectedly succeeded"
fi
# Relative paths with slash stay rejected through the final gate.
if su -p -s /bin/sh nobody -c '/usr/local/bin/doas ./bin-evil' 2>/dev/null; then
  fail "relative ./ rejected path executed"
fi
if su -p -s /bin/sh nobody -c '/usr/local/bin/doas bin/ls' 2>/dev/null; then
  fail "relative slash path executed"
fi
# Restricted shell selection: attacker SHELL must not become the executed
# shell when policy only permits /bin/sh.
printf '#!/bin/sh\necho PWNED-SHELL\n' > /tmp/hostile/sh
chmod 755 /tmp/hostile/sh
if SHELL=/tmp/hostile/sh su -p -s /bin/sh nobody -c '/usr/local/bin/doas -s' 2>/dev/null; then
  fail "attacker SHELL bypassed policy"
fi
# Permitted restricted command still works.
su -p -s /bin/sh nobody -c '/usr/local/bin/doas /bin/echo hello' >/dev/null 2>&1 \
  || fail "permitted /bin/echo denied"
out DOAS_PRIV_EXEC_OK

# --- 2B: -C genuinely unprivileged ------------------------------------------
# A world-readable configuration succeeds for non-root.
printf 'permit nopass nobody cmd /bin/echo\n' > /tmp/ok.conf
chmod 644 /tmp/ok.conf
su -p -s /bin/sh nobody -c '/usr/local/bin/doas -C /tmp/ok.conf /bin/echo hello' >/dev/null 2>&1 \
  || fail "-C readable config denied"
# Root-only sentinel: must fail and must not disclose contents.
echo "permit nopass nobody" > /root/sentinel.conf
chmod 600 /root/sentinel.conf
chown root:root /root/sentinel.conf
echo "TOP-SECRET-SENTINEL-DO-NOT-DISCLOSE" >> /root/sentinel.conf
sent_out=$(su -p -s /bin/sh nobody -c '/usr/local/bin/doas -C /root/sentinel.conf' 2>&1 || true)
case "$sent_out" in
  *TOP-SECRET*) fail "sentinel disclosed through diagnostics" ;;
esac
if su -p -s /bin/sh nobody -c '/usr/local/bin/doas -C /root/sentinel.conf' >/dev/null 2>&1; then
  fail "root sentinel readable by non-root"
fi
# Symlink must not expand access (O_NOFOLLOW).
ln -sf /etc/doas.conf /tmp/link.conf
if su -p -s /bin/sh nobody -c '/usr/local/bin/doas -C /tmp/link.conf' >/dev/null 2>&1; then
  fail "symlink config unexpectedly readable"
fi
rm -f /tmp/link.conf
# Directory handling stays bounded; parser failure never permits.
mkdir -p /tmp/empty-d
if su -p -s /bin/sh nobody -c '/usr/local/bin/doas -C /tmp/empty-d' >/dev/null 2>&1; then
  fail "empty dir unexpectedly permitted"
fi
echo '*** not a rule ***' > /tmp/bad.conf
chmod 644 /tmp/bad.conf
if su -p -s /bin/sh nobody -c '/usr/local/bin/doas -C /tmp/bad.conf /bin/echo' 2>&1 | grep -q '^permit'; then
  fail "parser failure granted permit"
fi
# Bounded read: 2 MiB must fail fast, not hang.
head -c 2097152 /dev/zero | tr '\0' 'a' > /tmp/big.conf
chmod 644 /tmp/big.conf
if timeout 10 su -p -s /bin/sh nobody -c '/usr/local/bin/doas -C /tmp/big.conf' >/dev/null 2>&1; then
  fail "oversize config unexpectedly permitted"
fi
out DOAS_PRIV_CHECK_OK

# --- 2C: credential transitions ----------------------------------------------
# Real transitions between distinct users/groups (guest 405:100,
# nobody 65534:65534). Both directions use nopass rules above.
got=$(su -p -s /bin/sh guest -c '/usr/local/bin/doas -u nobody /bin/echo TRANSITION-OK' 2>&1 || true)
case "$got" in
  *TRANSITION-OK*) ;;
  *) fail "guest->nobody transition failed: $got" ;;
esac
got=$(su -p -s /bin/sh nobody -c '/usr/local/bin/doas -u guest /bin/echo BACK-OK' 2>&1 || true)
case "$got" in
  *BACK-OK*) ;;
  *) fail "nobody->guest transition failed: $got" ;;
esac
# Unknown target must fail closed, never fall back.
if su -p -s /bin/sh nobody -c '/usr/local/bin/doas -u no-such-user-xyz-123 /bin/echo hi' >/dev/null 2>&1; then
  fail "unknown target unexpectedly permitted"
fi
out DOAS_PRIV_CRED_OK
exit 0
