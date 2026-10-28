use std::ffi::CString;

pub fn tiocsti_disabled() -> bool {
    let data = std::fs::read("/proc/sys/dev/tty/legacy_tiocsti").unwrap_or_default();
    let s = String::from_utf8_lossy(&data);
    s.trim() == "0"
}

pub fn should_isolate() -> bool {
    !tiocsti_disabled()
}

pub fn stdin_is_tty() -> bool {
    unsafe { libc::isatty(0) == 1 }
}

pub fn stdout_is_tty() -> bool {
    unsafe { libc::isatty(1) == 1 }
}

pub fn stderr_is_tty() -> bool {
    unsafe { libc::isatty(2) == 1 }
}

pub fn any_stdio_is_tty() -> bool {
    stdin_is_tty() || stdout_is_tty() || stderr_is_tty()
}

pub fn has_controlling_tty() -> bool {
    let c = CString::new("/dev/tty").unwrap();
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOCTTY) };
    if fd < 0 {
        return false;
    }
    unsafe { libc::close(fd) };
    true
}

pub fn refuse_interactive(stdin_tty: bool, tiocsti_enabled: bool) -> bool {
    stdin_tty && tiocsti_enabled
}

pub fn refuse_session(
    stdin_tty: bool,
    stdout_tty: bool,
    stderr_tty: bool,
    controlling_tty: bool,
    tiocsti_enabled: bool,
) -> bool {
    (stdin_tty || stdout_tty || stderr_tty || controlling_tty) && tiocsti_enabled
}

pub fn should_refuse_current_session() -> bool {
    let tiocsti_enabled = should_isolate();
    refuse_session(
        stdin_is_tty(),
        stdout_is_tty(),
        stderr_is_tty(),
        has_controlling_tty(),
        tiocsti_enabled,
    )
}

pub fn open_pty() -> Result<(i32, i32, String), String> {
    let master = unsafe { libc::posix_openpt(libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC) };
    if master < 0 {
        return Err(format!("posix_openpt failed: {}", std::io::Error::last_os_error()));
    }
    if unsafe { libc::grantpt(master) } != 0 || unsafe { libc::unlockpt(master) } != 0 {
        unsafe { libc::close(master) };
        return Err("grantpt/unlockpt failed".to_string());
    }
    let name_ptr = unsafe { libc::ptsname(master) };
    if name_ptr.is_null() {
        unsafe { libc::close(master) };
        return Err("ptsname failed".to_string());
    }
    let name = unsafe { std::ffi::CStr::from_ptr(name_ptr) }.to_string_lossy().into_owned();
    let cname = CString::new(name.clone()).map_err(|_| "bad pty name".to_string())?;
    let slave = unsafe { libc::open(cname.as_ptr(), libc::O_RDWR | libc::O_NOCTTY | libc::O_CLOEXEC) };
    if slave < 0 {
        unsafe { libc::close(master) };
        return Err(format!("open slave failed: {}", std::io::Error::last_os_error()));
    }
    Ok((master, slave, name))
}

pub fn copy_winsize(src: i32, dst: i32) -> Result<(), String> {
    let mut ws: libc::winsize = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(src, libc::TIOCGWINSZ, &mut ws) } != 0 {
        return Err(format!("TIOCGWINSZ failed: {}", std::io::Error::last_os_error()));
    }
    if unsafe { libc::ioctl(dst, libc::TIOCSWINSZ, &ws) } != 0 {
        return Err(format!("TIOCSWINSZ failed: {}", std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tiocsti_check_does_not_panic() {
        let _ = tiocsti_disabled();
        let _ = should_isolate();
        let _ = stdin_is_tty();
    }

    #[test]
    fn refuse_gate_matrix() {
        assert!(refuse_interactive(true, true));
        assert!(!refuse_interactive(true, false));
        assert!(!refuse_interactive(false, true));
        assert!(!refuse_interactive(false, false));
    }

    #[test]
    fn refuse_session_covers_all_stdio_and_ctty() {
        assert!(refuse_session(true, false, false, false, true));
        assert!(refuse_session(false, true, false, false, true));
        assert!(refuse_session(false, false, true, false, true));
        assert!(refuse_session(false, false, false, true, true));
        assert!(!refuse_session(true, false, false, false, false));
        assert!(!refuse_session(false, true, false, false, false));
        assert!(!refuse_session(false, false, false, false, true));
        assert!(!refuse_session(false, false, false, false, false));
    }

    #[test]
    fn stdin_only_is_insufficient() {
        assert!(!refuse_interactive(false, true));
        assert!(refuse_session(false, true, false, false, true));
        assert!(refuse_session(false, false, false, true, true));
    }

    #[test]
    fn pty_lifecycle() {
        let (master, slave, name) = open_pty().expect("pty must open in container");
        assert!(master >= 0 && slave >= 0 && master != slave);
        assert!(name.starts_with("/dev/pts/"));
        unsafe { libc::close(master) };
        unsafe { libc::close(slave) };
    }

    #[test]
    fn winsize_roundtrip() {
        let (m1, s1, _) = open_pty().unwrap();
        let (m2, s2, _) = open_pty().unwrap();
        let ws = libc::winsize { ws_row: 24, ws_col: 80, ws_xpixel: 0, ws_ypixel: 0 };
        assert_eq!(unsafe { libc::ioctl(m1, libc::TIOCSWINSZ, &ws) }, 0);
        copy_winsize(m1, m2).expect("winsize copy must work between ptys");
        let mut out: libc::winsize = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::ioctl(m2, libc::TIOCGWINSZ, &mut out) }, 0);
        assert_eq!(out.ws_row, 24);
        assert_eq!(out.ws_col, 80);
        unsafe { libc::close(m1) };
        unsafe { libc::close(s1) };
        unsafe { libc::close(m2) };
        unsafe { libc::close(s2) };
    }

    #[test]
    fn child_sets_controlling_tty() {
        let (master, slave, _) = open_pty().unwrap();
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            unsafe { libc::close(master) };
            if unsafe { libc::setsid() } < 0 {
                unsafe { libc::_exit(10) };
            }
            let sid = unsafe { libc::getsid(0) };
            let mypid = unsafe { libc::getpid() };
            if sid != mypid {
                unsafe { libc::_exit(12) };
            }
            let _ = unsafe { libc::ioctl(slave, libc::TIOCSCTTY as _, 0) };
            unsafe { libc::close(slave) };
            unsafe { libc::_exit(0) };
        } else {
            unsafe { libc::close(slave) };
            let mut status = 0;
            unsafe { libc::waitpid(pid, &mut status, 0) };
            unsafe { libc::close(master) };
            assert_eq!(libc::WEXITSTATUS(status), 0);
        }
    }

    #[test]
    fn echo_control_on_pty() {
        let (master, slave, _) = open_pty().unwrap();
        let mut term: libc::termios = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::tcgetattr(slave, &mut term) }, 0);
        let orig = term;
        term.c_lflag &= !(libc::ECHO as libc::tcflag_t);
        for _ in 0..10 {
            if unsafe { libc::tcsetattr(slave, libc::TCSANOW, &term) } == 0 {
                break;
            }
            let e = std::io::Error::last_os_error();
            assert_eq!(e.raw_os_error(), Some(libc::EINTR));
        }
        let mut back: libc::termios = unsafe { std::mem::zeroed() };
        assert_eq!(unsafe { libc::tcgetattr(slave, &mut back) }, 0);
        assert_eq!(back.c_lflag & (libc::ECHO as libc::tcflag_t), 0);
        assert_eq!(unsafe { libc::tcsetattr(slave, libc::TCSANOW, &orig) }, 0);
        unsafe { libc::close(master) };
        unsafe { libc::close(slave) };
    }
}
