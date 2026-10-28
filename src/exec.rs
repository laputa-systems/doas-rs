use std::ffi::{CString, OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};

use crate::load::SAFE_PATH;

pub fn resolve_cmd(cmd: &OsStr, rule_has_cmd: bool, former_path: &OsStr) -> Result<PathBuf, String> {
    let b = cmd.as_bytes();
    if b.is_empty() || b.contains(&0) {
        return Err("invalid command".to_string());
    }
    if b.contains(&b'/') {
        if !b.starts_with(b"/") {
            return Err("relative path with slash rejected".to_string());
        }
        return Ok(PathBuf::from(OsString::from_vec(b.to_vec())));
    }
    let search_path = if rule_has_cmd {
        SAFE_PATH
    } else {
        match std::str::from_utf8(former_path.as_bytes()) {
            Ok(s) => {
                if s.is_empty() {
                    SAFE_PATH
                } else {
                    Box::leak(s.to_string().into_boxed_str()) as &str
                }
            }
            Err(_) => SAFE_PATH,
        }
    };
    for dir in search_path.split(':') {
        if dir.is_empty() || dir.contains('\0') {
            continue;
        }
        if !dir.starts_with('/') {
            continue;
        }
        let candidate = Path::new(dir).join(OsString::from_vec(b.to_vec()));
        if let Ok(c) = CString::new(candidate.to_string_lossy().as_bytes()) {
            let mut sb: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::stat(c.as_ptr(), &mut sb) } == 0
                && (sb.st_mode & libc::S_IFMT) == libc::S_IFREG
            {
                return Ok(candidate);
            }
        }
    }
    Ok(PathBuf::from(OsString::from_vec(b.to_vec())))
}

pub fn close_fds_from_3() {
    #[cfg(target_os = "linux")]
    {
        const SYS_CLOSE_RANGE: libc::c_long = 436;
        let rc = unsafe { libc::syscall(SYS_CLOSE_RANGE, 3 as libc::c_long, u32::MAX as libc::c_long, 0 as libc::c_long) };
        if rc == 0 {
            return;
        }
    }
    let max = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
    let max = if !(0..=1024 * 1024).contains(&max) { 1024 } else { max as i32 };
    for fd in 3..max {
        unsafe { libc::close(fd) };
    }
}

pub fn verify_transition(target_uid: u32, target_gid: u32) -> Result<(), String> {
    let ruid = unsafe { libc::getuid() };
    let euid = unsafe { libc::geteuid() };
    let rgid = unsafe { libc::getgid() };
    let egid = unsafe { libc::getegid() };
    if ruid != target_uid || euid != target_uid {
        return Err(format!("uid transition failed: {ruid}/{euid} != {target_uid}"));
    }
    if rgid != target_gid || egid != target_gid {
        return Err(format!("gid transition failed: {rgid}/{egid} != {target_gid}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::io::AsRawFd;

    fn os(s: &str) -> OsString {
        OsString::from(s)
    }

    #[test]
    fn absolute_cmd_bypasses_path() {
        let former = os("/tmp/evil:/usr/bin");
        let p = resolve_cmd(os("/bin/ls").as_os_str(), true, former.as_os_str()).unwrap();
        assert_eq!(p, PathBuf::from("/bin/ls"));
    }

    #[test]
    fn relative_with_slash_rejected() {
        let former = os("/usr/bin");
        assert!(resolve_cmd(os("bin/ls").as_os_str(), true, former.as_os_str()).is_err());
        assert!(resolve_cmd(os("./a").as_os_str(), true, former.as_os_str()).is_err());
    }

    #[test]
    fn cve_no_attacker_path_for_restricted() {
        let evil = os("/tmp/evil:/usr/bin");
        let p = resolve_cmd(os("ls").as_os_str(), true, evil.as_os_str()).unwrap();
        let s = p.to_string_lossy();
        assert!(!s.starts_with("/tmp/evil"), "must not use attacker PATH: {s}");
    }

    #[test]
    fn empty_and_nul_rejected() {
        let former = os("/usr/bin");
        assert!(resolve_cmd(os("").as_os_str(), true, former.as_os_str()).is_err());
        use std::os::unix::ffi::OsStringExt;
        let bad = OsString::from_vec(vec![b'a', 0]);
        assert!(resolve_cmd(bad.as_os_str(), true, former.as_os_str()).is_err());
    }

    #[test]
    fn fd_hygiene_closes_extra_fds() {
        let f1 = std::fs::File::open("/dev/null").unwrap();
        let f2 = std::fs::File::open("/dev/null").unwrap();
        let fd1 = f1.as_raw_fd();
        let fd2 = f2.as_raw_fd();
        assert!(fd1 >= 3 && fd2 >= 3);
        close_fds_from_3();
        let r1 = unsafe { libc::fcntl(fd1, libc::F_GETFD) };
        let r2 = unsafe { libc::fcntl(fd2, libc::F_GETFD) };
        assert!(r1 < 0 && r2 < 0, "fds must be closed");
        std::mem::forget(f1);
        std::mem::forget(f2);
    }

    #[test]
    fn transition_verify_detects_mismatch() {
        let me = unsafe { libc::getuid() };
        let mygid = unsafe { libc::getgid() };
        assert!(verify_transition(me, mygid).is_ok());
        assert!(verify_transition(me.wrapping_add(1), mygid).is_err());
    }

    #[test]
    fn forked_transition_to_nobody() {
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let rc_gid = unsafe { libc::setresgid(65534, 65534, 65534) };
            let rc_uid = unsafe { libc::setresuid(65534, 65534, 65534) };
            if rc_gid != 0 || rc_uid != 0 {
                unsafe { libc::_exit(42) };
            }
            match verify_transition(65534, 65534) {
                Ok(()) => unsafe { libc::_exit(0) },
                Err(_) => unsafe { libc::_exit(43) },
            }
        } else {
            let mut status = 0;
            unsafe { libc::waitpid(pid, &mut status, 0) };
            let code = libc::WEXITSTATUS(status);
            assert_eq!(code, 0, "child transition must verify");
        }
    }
}
