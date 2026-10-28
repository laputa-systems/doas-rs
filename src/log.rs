use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::ffi::OsStr;

fn sanitize(input: &OsStr) -> CString {
    let b = input.as_bytes();
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    let mut v = b[..end].to_vec();
    if v.len() > 1024 {
        v.truncate(1024);
    }
    CString::new(v).unwrap_or_else(|_| CString::new("?").unwrap())
}

pub fn should_log_success(nolog: bool) -> bool {
    !nolog
}

pub fn should_log_deny() -> bool {
    true
}

pub fn should_log_auth_fail() -> bool {
    true
}

fn ensure_openlog() {
    use std::sync::Once;
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let ident = CString::new("doas").unwrap();
        unsafe { libc::openlog(ident.as_ptr(), libc::LOG_PID | libc::LOG_NDELAY, libc::LOG_AUTHPRIV) };
    });
}

pub fn log_permit(user: &OsStr, cmdline: &OsStr, target: &OsStr, cwd: &OsStr, nolog: bool) {
    if !should_log_success(nolog) {
        return;
    }
    ensure_openlog();
    let u = sanitize(user);
    let c = sanitize(cmdline);
    let t = sanitize(target);
    let w = sanitize(cwd);
    let fmt = CString::new("%s ran command %s as %s from %s").unwrap();
    unsafe {
        libc::syslog(
            libc::LOG_AUTHPRIV | libc::LOG_INFO,
            fmt.as_ptr(),
            u.as_ptr(),
            c.as_ptr(),
            t.as_ptr(),
            w.as_ptr(),
        );
    }
}

pub fn log_deny(user: &OsStr, cmdline: &OsStr) {
    debug_assert!(should_log_deny());
    ensure_openlog();
    let u = sanitize(user);
    let c = sanitize(cmdline);
    let fmt = CString::new("command not permitted for %s: %s").unwrap();
    unsafe {
        libc::syslog(
            libc::LOG_AUTHPRIV | libc::LOG_NOTICE,
            fmt.as_ptr(),
            u.as_ptr(),
            c.as_ptr(),
        );
    }
}

pub fn log_auth_fail(user: &OsStr) {
    debug_assert!(should_log_auth_fail());
    ensure_openlog();
    let u = sanitize(user);
    let fmt = CString::new("failed auth for %s").unwrap();
    unsafe {
        libc::syslog(libc::LOG_AUTHPRIV | libc::LOG_NOTICE, fmt.as_ptr(), u.as_ptr());
    }
}

pub fn log_tty_required(user: &OsStr) {
    ensure_openlog();
    let u = sanitize(user);
    let fmt = CString::new("tty required for %s").unwrap();
    unsafe {
        libc::syslog(libc::LOG_AUTHPRIV | libc::LOG_NOTICE, fmt.as_ptr(), u.as_ptr());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    fn os(s: &str) -> OsString {
        OsString::from(s)
    }

    #[test]
    fn nolog_never_silences_denials_or_auth() {
        assert!(!should_log_success(true));
        assert!(should_log_success(false));
        assert!(should_log_deny());
        assert!(should_log_auth_fail());
    }

    #[test]
    fn format_strings_are_constant_safe() {
        let evil = os("%s %s %n %x");
        log_deny(evil.as_os_str(), evil.as_os_str());
        log_auth_fail(evil.as_os_str());
        log_tty_required(evil.as_os_str());
        log_permit(evil.as_os_str(), evil.as_os_str(), evil.as_os_str(), evil.as_os_str(), false);
        log_permit(evil.as_os_str(), evil.as_os_str(), evil.as_os_str(), evil.as_os_str(), true);
    }

    #[test]
    fn nul_truncated_not_rejected() {
        let bad = OsString::from_vec(vec![b'a', 0, b'b']);
        log_deny(bad.as_os_str(), bad.as_os_str());
    }

    #[test]
    fn non_utf8_logged_without_panic() {
        let raw = OsString::from_vec(vec![0xff, 0xfe, b'x']);
        log_deny(raw.as_os_str(), raw.as_os_str());
        log_auth_fail(raw.as_os_str());
    }

    #[test]
    fn empty_fields_do_not_panic() {
        log_deny(os("").as_os_str(), os("").as_os_str());
    }
}
