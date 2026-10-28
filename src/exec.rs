use std::ffi::{CString, OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::PathBuf;

use crate::load::SAFE_PATH;

pub fn select_shell(shell_env: Option<&OsStr>, target_shell: &OsStr) -> OsString {
    if let Some(s) = shell_env
        && !s.is_empty()
    {
        let b = s.as_bytes();
        if !b.contains(&0) && b.starts_with(b"/") {
            return s.to_os_string();
        }
    }
    if !target_shell.is_empty() {
        let b = target_shell.as_bytes();
        if !b.contains(&0) && b.starts_with(b"/") {
            return target_shell.to_os_string();
        }
    }
    OsString::from("/bin/sh")
}

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
    let search_bytes: &[u8] = if rule_has_cmd {
        SAFE_PATH.as_bytes()
    } else {
        let fb = former_path.as_bytes();
        if fb.is_empty() {
            SAFE_PATH.as_bytes()
        } else {
            fb
        }
    };
    for dir in search_bytes.split(|&c| c == b':') {
        if dir.is_empty() || dir.contains(&0) {
            continue;
        }
        if !dir.starts_with(b"/") {
            continue;
        }
        let mut cand = Vec::with_capacity(dir.len() + 1 + b.len());
        cand.extend_from_slice(dir);
        cand.push(b'/');
        cand.extend_from_slice(b);
        let Ok(c) = CString::new(cand.clone()) else {
            continue;
        };
        let mut sb: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::stat(c.as_ptr(), &mut sb) } != 0 {
            continue;
        }
        if (sb.st_mode & libc::S_IFMT) != libc::S_IFREG {
            continue;
        }
        if (sb.st_mode & 0o111) == 0 {
            continue;
        }
        return Ok(PathBuf::from(OsString::from_vec(cand)));
    }
    Err("command not found in PATH".to_string())
}

pub fn close_fds_from_3() {
    #[cfg(target_os = "linux")]
    {
        let rc = unsafe { libc::syscall(libc::SYS_close_range, 3 as libc::c_long, u32::MAX as libc::c_long, 0 as libc::c_long) };
        if rc == 0 {
            return;
        }
    }
    let mut ceiling: i64 = unsafe { libc::sysconf(libc::_SC_OPEN_MAX) };
    if !(0..=1024 * 1024).contains(&ceiling) {
        let mut rl: libc::rlimit = unsafe { std::mem::zeroed() };
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rl) } == 0
            && rl.rlim_cur > 0
            && rl.rlim_cur <= 1024 * 1024
        {
            ceiling = rl.rlim_cur as i64;
        } else {
            ceiling = 1024 * 1024;
        }
    }
    ceiling = ceiling.clamp(1024, 1024 * 1024);
    for fd in 3..(ceiling as i32) {
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
    let mut r = 0u32;
    let mut e = 0u32;
    let mut s = 0u32;
    if unsafe { libc::getresuid(&mut r, &mut e, &mut s) } != 0 {
        return Err("getresuid failed".to_string());
    }
    if r != target_uid || e != target_uid || s != target_uid {
        return Err(format!("saved uid transition failed: {r}/{e}/{s} != {target_uid}"));
    }
    let mut rg = 0u32;
    let mut eg = 0u32;
    let mut sg = 0u32;
    if unsafe { libc::getresgid(&mut rg, &mut eg, &mut sg) } != 0 {
        return Err("getresgid failed".to_string());
    }
    if rg != target_gid || eg != target_gid || sg != target_gid {
        return Err(format!("saved gid transition failed: {rg}/{eg}/{sg} != {target_gid}"));
    }
    let n = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if n < 0 {
        return Err("getgroups count failed".to_string());
    }
    let mut gids = vec![0 as libc::gid_t; n as usize];
    let rc = unsafe { libc::getgroups(gids.len() as libc::c_int, gids.as_mut_ptr()) };
    if rc < 0 {
        return Err("getgroups failed".to_string());
    }
    gids.truncate(rc as usize);
    if !gids.contains(&(target_gid as libc::gid_t)) {
        return Err("supplementary groups missing target gid".to_string());
    }
    if target_uid != 0 && target_gid != 0 && gids.contains(&0) {
        return Err("unexpected root group retained".to_string());
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
    fn safe_path_miss_fails_closed() {
        let former = os("/usr/bin");
        use std::os::unix::ffi::OsStringExt;
        let missing = OsString::from_vec(b"doas-no-such-cmd-xyz-123".to_vec());
        assert!(resolve_cmd(missing.as_os_str(), true, former.as_os_str()).is_err());
    }

    #[test]
    fn missing_never_falls_back_to_cwd() {
        use std::os::unix::ffi::OsStringExt;
        let tmp = std::env::temp_dir().join(format!("doas-cwd-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&tmp).unwrap();
        let evil = tmp.join("evil-cmd-xyz");
        std::fs::write(&evil, b"#!/bin/sh\necho pwned\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&evil, std::fs::Permissions::from_mode(0o755)).unwrap();
        let old = std::env::current_dir().unwrap();
        std::env::set_current_dir(&tmp).unwrap();
        let former = os("/usr/bin:/bin");
        let missing = OsString::from_vec(b"evil-cmd-xyz".to_vec());
        let r = resolve_cmd(missing.as_os_str(), true, former.as_os_str());
        std::env::set_current_dir(&old).unwrap();
        let _ = std::fs::remove_dir_all(&tmp);
        assert!(r.is_err(), "cwd executable must not satisfy safe-PATH miss");
        if let Ok(p) = r {
            assert!(!p.as_os_str().as_bytes().starts_with(b"evil"));
        }
    }

    #[test]
    fn hostile_cwd_not_used_for_bare() {
        use std::os::unix::ffi::OsStringExt;
        let former = os("");
        let missing = OsString::from_vec(b"definitely-missing-xyz".to_vec());
        let r = resolve_cmd(missing.as_os_str(), false, former.as_os_str());
        assert!(r.is_err());
    }

    #[test]
    fn non_utf8_candidate_preserves_bytes() {
        use std::os::unix::ffi::OsStringExt;
        let dir = std::env::temp_dir().join(format!("doas-nonascii-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let name_bytes = vec![0xff, 0xfe, b'x'];
        let full = dir.join(OsString::from_vec(name_bytes.clone()));
        std::fs::write(&full, b"#!/bin/sh\nexit 0\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&full, std::fs::Permissions::from_mode(0o755)).unwrap();
        let dir_os = OsString::from_vec(dir.as_os_str().as_bytes().to_vec());
        let cmd_os = OsString::from_vec(name_bytes.clone());
        let r = resolve_cmd(cmd_os.as_os_str(), false, dir_os.as_os_str());
        let _ = std::fs::remove_dir_all(&dir);
        assert!(r.is_ok(), "non-UTF8 executable in explicit PATH must resolve");
        assert_eq!(r.unwrap().as_os_str().as_bytes().to_vec(), {
            let mut v = dir.as_os_str().as_bytes().to_vec();
            v.push(b'/');
            v.extend_from_slice(&name_bytes);
            v
        });
    }

    #[test]
    fn unrestricted_relative_components_ignored() {
        let former = os(":/tmp/evil:/usr/bin");
        let p = resolve_cmd(os("sh").as_os_str(), false, former.as_os_str());
        if let Ok(path) = p {
            let s = path.to_string_lossy();
            assert!(!s.starts_with("/tmp/evil") || s.starts_with("/usr/bin") || s.starts_with("/bin"),
                "relative/empty components must be skipped: {s}");
            assert!(path.as_os_str().as_bytes().starts_with(b"/"));
        }
    }

    #[test]
    fn shell_selection_prefers_absolute_env() {
        let env_abs = os("/bin/bash");
        let target = os("/bin/sh");
        assert_eq!(
            select_shell(Some(env_abs.as_os_str()), target.as_os_str()),
            env_abs
        );
        let env_rel = os("evil");
        assert_eq!(
            select_shell(Some(env_rel.as_os_str()), target.as_os_str()),
            target
        );
        let empty = OsString::new();
        assert_eq!(
            select_shell(Some(empty.as_os_str()), target.as_os_str()),
            target
        );
        assert_eq!(
            select_shell(None, target.as_os_str()),
            target
        );
        let bad_target = os("relative");
        assert_eq!(
            select_shell(None, bad_target.as_os_str()),
            OsString::from("/bin/sh")
        );
    }

    #[test]
    fn fd_hygiene_closes_extra_fds() {
        let f1 = std::fs::File::open("/dev/null").unwrap();
        let f2 = std::fs::File::open("/dev/null").unwrap();
        let fd1 = f1.as_raw_fd();
        let fd2 = f2.as_raw_fd();
        assert!(fd1 >= 3 && fd2 >= 3);
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            close_fds_from_3();
            let r1 = unsafe { libc::fcntl(fd1, libc::F_GETFD) };
            let r2 = unsafe { libc::fcntl(fd2, libc::F_GETFD) };
            let stdio = unsafe { libc::fcntl(1, libc::F_GETFD) };
            let ok = r1 < 0 && r2 < 0 && stdio >= 0;
            unsafe { libc::_exit(if ok { 0 } else { 1 }) };
        } else {
            let mut status = 0;
            unsafe { libc::waitpid(pid, &mut status, 0) };
            assert_eq!(libc::WEXITSTATUS(status), 0, "fds must be closed");
        }
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
        if unsafe { libc::geteuid() } != 0 {
            return;
        }
        let pid = unsafe { libc::fork() };
        assert!(pid >= 0);
        if pid == 0 {
            let rc_gid = unsafe { libc::setresgid(65534, 65534, 65534) };
            if rc_gid != 0 {
                unsafe { libc::_exit(42) };
            }
            let cname = std::ffi::CString::new("nobody").unwrap();
            if unsafe { libc::initgroups(cname.as_ptr(), 65534) } != 0 {
                unsafe { libc::_exit(44) };
            }
            let rc_uid = unsafe { libc::setresuid(65534, 65534, 65534) };
            if rc_uid != 0 {
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
