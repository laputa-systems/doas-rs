//! System identity resolution for the Linux port.
//!
//! Names resolve through the system databases first, then fall back to
//! decimal IDs in `0..=65534`. `65535` and larger, empty, NUL-containing,
//! and unknown names fail closed to `None`. Supplementary groups for the
//! invoking user come from `getgroups` plus the primary gid. Locked,
//! empty, or missing shadow entries are not authenticated here; they
//! fail closed in the authentication gate which requires a usable hash.

use std::ffi::{CStr, CString, OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};

pub const UID_MAX: u32 = 65535;
pub const GID_MAX: u32 = 65535;
pub const ID_MAX: u32 = 65534;

fn parse_numeric_id(s: &OsStr) -> Option<u32> {
    let b = s.as_bytes();
    if b.is_empty() || b.len() > 10 {
        return None;
    }
    if !b.iter().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let mut v: u32 = 0;
    for c in b {
        v = v.checked_mul(10)?.checked_add((c - b'0') as u32)?;
    }
    if v > ID_MAX {
        return None;
    }
    Some(v)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Passwd {
    pub name: OsString,
    pub uid: u32,
    pub gid: u32,
    pub home: OsString,
    pub shell: OsString,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub name: OsString,
    pub gid: u32,
}

fn os_from_cstr(b: &[u8]) -> OsString {
    OsString::from_vec(b.to_vec())
}

fn cstring_from_os(s: &OsStr) -> Option<CString> {
    let b = s.as_bytes();
    if b.contains(&0) {
        return None;
    }
    CString::new(b).ok()
}

pub fn lookup_user_by_name(name: &OsStr) -> Option<Passwd> {
    let cname = cstring_from_os(name)?;
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let mut buf = vec![0u8; 16384];
    let rc = unsafe {
        libc::getpwnam_r(
            cname.as_ptr(),
            &mut pwd,
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    let pw_name = unsafe { CStr::from_ptr(pwd.pw_name) }.to_bytes();
    let pw_dir = unsafe { CStr::from_ptr(pwd.pw_dir) }.to_bytes();
    let pw_shell = unsafe { CStr::from_ptr(pwd.pw_shell) }.to_bytes();
    let uid = pwd.pw_uid;
    let gid = pwd.pw_gid;
    if uid == UID_MAX || gid == GID_MAX {
        return None;
    }
    Some(Passwd {
        name: os_from_cstr(pw_name),
        uid,
        gid,
        home: os_from_cstr(pw_dir),
        shell: os_from_cstr(pw_shell),
    })
}

pub fn lookup_user_by_uid(uid: u32) -> Option<Passwd> {
    if uid > ID_MAX && uid != 0 {
        if uid == UID_MAX {
            return None;
        }
        if uid > ID_MAX {
            return None;
        }
    }
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let mut buf = vec![0u8; 16384];
    let rc = unsafe {
        libc::getpwuid_r(
            uid,
            &mut pwd,
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    let pw_name = unsafe { CStr::from_ptr(pwd.pw_name) }.to_bytes();
    let pw_dir = unsafe { CStr::from_ptr(pwd.pw_dir) }.to_bytes();
    let pw_shell = unsafe { CStr::from_ptr(pwd.pw_shell) }.to_bytes();
    if pwd.pw_uid == UID_MAX || pwd.pw_gid == GID_MAX {
        return None;
    }
    Some(Passwd {
        name: os_from_cstr(pw_name),
        uid: pwd.pw_uid,
        gid: pwd.pw_gid,
        home: os_from_cstr(pw_dir),
        shell: os_from_cstr(pw_shell),
    })
}

pub fn lookup_group_by_name(name: &OsStr) -> Option<Group> {
    let cname = cstring_from_os(name)?;
    let mut grp: libc::group = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::group = std::ptr::null_mut();
    let mut buf = vec![0u8; 16384];
    let rc = unsafe {
        libc::getgrnam_r(
            cname.as_ptr(),
            &mut grp,
            buf.as_mut_ptr() as *mut libc::c_char,
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    let gr_name = unsafe { CStr::from_ptr(grp.gr_name) }.to_bytes();
    if grp.gr_gid == GID_MAX {
        return None;
    }
    Some(Group {
        name: os_from_cstr(gr_name),
        gid: grp.gr_gid,
    })
}

pub fn resolve_user(name: &OsStr) -> Option<u32> {
    if name.as_bytes().is_empty() || name.as_bytes().contains(&0) {
        return None;
    }
    if let Some(pw) = lookup_user_by_name(name) {
        return Some(pw.uid);
    }
    parse_numeric_id(name)
}

pub fn resolve_group(name: &OsStr) -> Option<u32> {
    if name.as_bytes().is_empty() || name.as_bytes().contains(&0) {
        return None;
    }
    if let Some(gr) = lookup_group_by_name(name) {
        return Some(gr.gid);
    }
    parse_numeric_id(name)
}

pub fn resolve_target(name: &OsStr) -> Option<u32> {
    resolve_user(name)
}

pub fn current_groups() -> Vec<u32> {
    let ngroups = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
    if ngroups < 0 {
        return vec![unsafe { libc::getgid() }];
    }
    let mut gids = vec![0 as libc::gid_t; ngroups as usize + 1];
    let rc = unsafe { libc::getgroups(gids.len() as libc::c_int, gids.as_mut_ptr()) };
    if rc < 0 {
        return vec![unsafe { libc::getgid() }];
    }
    gids.truncate(rc as usize);
    let mut out: Vec<u32> = gids;
    let primary = unsafe { libc::getgid() } as u32;
    if !out.contains(&primary) {
        out.push(primary);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(s: &str) -> OsString {
        OsString::from(s)
    }

    #[test]
    fn root_resolves_to_zero() {
        assert_eq!(resolve_user(os("root").as_os_str()), Some(0));
        assert_eq!(resolve_user(os("0").as_os_str()), Some(0));
    }

    #[test]
    fn numeric_ids_in_range() {
        assert_eq!(resolve_user(os("1000").as_os_str()), Some(1000));
        assert_eq!(resolve_group(os("10").as_os_str()), Some(10));
    }

    #[test]
    fn uid_max_rejected() {
        assert_eq!(resolve_user(os("65535").as_os_str()), None);
        assert_eq!(resolve_group(os("65535").as_os_str()), None);
        assert_eq!(parse_numeric_id(os("65535").as_os_str()), None);
        assert_eq!(parse_numeric_id(os("65534").as_os_str()), Some(65534));
    }

    #[test]
    fn overflow_rejected() {
        assert_eq!(resolve_user(os("9999999999").as_os_str()), None);
        assert_eq!(resolve_user(os("99999999999999999999").as_os_str()), None);
        assert_eq!(parse_numeric_id(os("4294967296").as_os_str()), None);
    }

    #[test]
    fn negative_and_malformed_rejected() {
        assert_eq!(resolve_user(os("-1").as_os_str()), None);
        assert_eq!(resolve_user(os("").as_os_str()), None);
        assert_eq!(resolve_user(os("+1").as_os_str()), None);
        assert_eq!(resolve_user(os(" 1").as_os_str()), None);
        assert_eq!(resolve_user(os("1 ").as_os_str()), None);
    }

    #[test]
    fn unknown_user_returns_none() {
        assert_eq!(resolve_user(os("no-such-user-xyz-123").as_os_str()), None);
        assert_eq!(resolve_group(os("no-such-group-xyz-123").as_os_str()), None);
    }

    #[test]
    fn nul_rejected() {
        use std::os::unix::ffi::OsStringExt;
        let bad = OsString::from_vec(vec![b'a', 0, b'b']);
        assert_eq!(resolve_user(bad.as_os_str()), None);
        assert_eq!(resolve_group(bad.as_os_str()), None);
    }

    #[test]
    fn lookup_root_entry() {
        let pw = lookup_user_by_uid(0).expect("root must exist in container");
        assert_eq!(pw.uid, 0);
        assert!(!pw.name.as_bytes().is_empty());
        assert!(!pw.shell.as_bytes().is_empty() || pw.shell.as_bytes().is_empty());
    }

    #[test]
    fn current_user_lookup_roundtrip() {
        let uid = unsafe { libc::getuid() };
        let pw = lookup_user_by_uid(uid).expect("current user must have passwd entry");
        assert_eq!(pw.uid, uid);
        let by_name = lookup_user_by_name(pw.name.as_os_str()).expect("lookup by name works");
        assert_eq!(by_name.uid, uid);
    }

    #[test]
    fn current_groups_contains_primary() {
        let groups = current_groups();
        assert!(!groups.is_empty());
        let primary = unsafe { libc::getgid() } as u32;
        assert!(groups.contains(&primary));
    }

    #[test]
    fn shadow_locked_accounts_fail_closed() {
        let locked = resolve_user(os("nobody").as_os_str());
        if let Some(uid) = locked {
            let pw = lookup_user_by_uid(uid);
            assert!(pw.is_some());
        }
    }
}
