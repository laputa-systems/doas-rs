use std::ffi::{CString, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::io::FromRawFd;
use std::path::{Path, PathBuf};

use crate::config::{self, Rule};

pub const SAFE_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
pub const MAIN_CONF: &str = "/etc/doas.conf";
pub const CONF_DIR: &str = "/etc/doas.d";

#[derive(Debug)]
pub enum LoadError {
    Io(String),
    Perm(String),
    Parse(config::ConfigError),
}

impl std::fmt::Display for LoadError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(m) => write!(f, "doas: {m}"),
            Self::Perm(m) => write!(f, "doas: {m}"),
            Self::Parse(e) => write!(f, "{e}"),
        }
    }
}

fn cstr_for_path(p: &Path) -> Result<CString, LoadError> {
    let b = p.as_os_str().as_bytes();
    if b.contains(&0) {
        return Err(LoadError::Perm(format!("invalid path: {}", p.display())));
    }
    CString::new(b).map_err(|_| LoadError::Perm(format!("invalid path: {}", p.display())))
}

fn check_file_stat(sb: &libc::stat, path: &str) -> Result<(), LoadError> {
    if (sb.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return Err(LoadError::Perm(format!("{path} is not a regular file")));
    }
    if sb.st_uid != 0 {
        return Err(LoadError::Perm(format!("{path} is not owned by root")));
    }
    if (sb.st_mode & (libc::S_IWGRP | libc::S_IWOTH)) != 0 {
        return Err(LoadError::Perm(format!("{path} is writable by group or other")));
    }
    Ok(())
}

fn check_dir_stat(sb: &libc::stat, path: &str) -> Result<(), LoadError> {
    if (sb.st_mode & libc::S_IFMT) != libc::S_IFDIR {
        return Err(LoadError::Perm(format!("{path} is not a directory")));
    }
    if sb.st_uid != 0 {
        return Err(LoadError::Perm(format!("{path} is not owned by root")));
    }
    if (sb.st_mode & (libc::S_IWGRP | libc::S_IWOTH)) != 0 {
        return Err(LoadError::Perm(format!("{path} is writable by group or other")));
    }
    Ok(())
}

fn open_parent_and_name(path: &Path) -> Result<(PathBuf, CString), LoadError> {
    let parent = path.parent().ok_or_else(|| LoadError::Io(format!("bad path: {}", path.display())))?;
    let name = path.file_name().ok_or_else(|| LoadError::Io(format!("bad path: {}", path.display())))?;
    let name_bytes = name.as_bytes();
    if name_bytes.contains(&0) || name_bytes.contains(&b'/') {
        return Err(LoadError::Perm(format!("invalid name: {}", path.display())));
    }
    let cname = CString::new(name_bytes).map_err(|_| LoadError::Perm(format!("invalid name: {}", path.display())))?;
    Ok((parent.to_path_buf(), cname))
}

fn open_dir_fd(dir: &Path) -> Result<i32, LoadError> {
    let cdir = cstr_for_path(dir)?;
    let fd = unsafe { libc::openat(libc::AT_FDCWD, cdir.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
    if fd < 0 {
        let e = std::io::Error::last_os_error();
        return Err(LoadError::Io(format!("could not open {}: {e}", dir.display())));
    }
    let mut sb: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut sb) } != 0 {
        let e = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(LoadError::Io(format!("fstat {}: {e}", dir.display())));
    }
    let label = dir.to_string_lossy().into_owned();
    if let Err(e) = check_dir_stat(&sb, &label) {
        unsafe { libc::close(fd) };
        return Err(e);
    }
    Ok(fd)
}

fn read_file_at(dir_fd: i32, name: &CString, display: &str) -> Result<Vec<u8>, LoadError> {
    let fd = unsafe { libc::openat(dir_fd, name.as_ptr(), libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
    if fd < 0 {
        let e = std::io::Error::last_os_error();
        return Err(LoadError::Io(format!("could not open {display}: {e}")));
    }
    let mut sb: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut sb) } != 0 {
        let e = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(LoadError::Io(format!("fstat {display}: {e}")));
    }
    if let Err(e) = check_file_stat(&sb, display) {
        unsafe { libc::close(fd) };
        return Err(e);
    }
    if sb.st_size < 0 || sb.st_size as u64 > config::MAX_FILE_BYTES as u64 {
        unsafe { libc::close(fd) };
        return Err(LoadError::Perm(format!("{display} too large")));
    }
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut data = Vec::new();
    use std::io::Read;
    if let Err(e) = file.read_to_end(&mut data) {
        return Err(LoadError::Io(format!("read {display}: {e}")));
    }
    if data.len() > config::MAX_FILE_BYTES {
        return Err(LoadError::Perm(format!("{display} too large")));
    }
    Ok(data)
}

fn list_conf_names(dir_fd: i32) -> Result<Vec<OsString>, LoadError> {
    let dirp = unsafe { libc::fdopendir(dir_fd) };
    if dirp.is_null() {
        let e = std::io::Error::last_os_error();
        unsafe { libc::close(dir_fd) };
        return Err(LoadError::Io(format!("fdopendir failed: {e}")));
    }
    let mut names: Vec<OsString> = Vec::new();
    loop {
        unsafe { *libc::__errno_location() = 0 };
        let ent = unsafe { libc::readdir(dirp) };
        if ent.is_null() {
            let err = unsafe { *libc::__errno_location() };
            if err != 0 {
                unsafe { libc::closedir(dirp) };
                return Err(LoadError::Io(format!("readdir failed: {err}")));
            }
            break;
        }
        let d_name = unsafe { std::ffi::CStr::from_ptr((*ent).d_name.as_ptr()) }.to_bytes();
        if d_name == b"." || d_name == b".." {
            continue;
        }
        if d_name.len() < 6 || !d_name.ends_with(b".conf") {
            continue;
        }
        if d_name.contains(&0) || d_name.contains(&b'/') {
            continue;
        }
        names.push(OsString::from_vec(d_name.to_vec()));
    }
    unsafe { libc::closedir(dirp) };
    names.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
    Ok(names)
}

pub fn load_paths(main: &Path, dir: &Path) -> Result<Vec<Rule>, LoadError> {
    let (main_parent, main_name) = open_parent_and_name(main)?;
    let main_parent_c = cstr_for_path(&main_parent)?;
    let main_dir_fd = unsafe {
        libc::openat(
            libc::AT_FDCWD,
            main_parent_c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if main_dir_fd < 0 {
        let e = std::io::Error::last_os_error();
        return Err(LoadError::Io(format!("doas is not enabled, {}: {e}", main.display())));
    }
    let mut sb: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(main_dir_fd, &mut sb) } != 0 {
        let e = std::io::Error::last_os_error();
        unsafe { libc::close(main_dir_fd) };
        return Err(LoadError::Io(format!("fstat {}: {e}", main_parent.display())));
    }
    let parent_label = main_parent.to_string_lossy().into_owned();
    if let Err(e) = check_dir_stat(&sb, &parent_label) {
        unsafe { libc::close(main_dir_fd) };
        return Err(e);
    }
    let main_display = main.to_string_lossy().into_owned();
    let main_data = match read_file_at(main_dir_fd, &main_name, &main_display) {
        Ok(d) => d,
        Err(e) => {
            unsafe { libc::close(main_dir_fd) };
            return Err(e);
        }
    };
    unsafe { libc::close(main_dir_fd) };
    let mut rules = config::parse_bytes(&main_data, &main_display).map_err(LoadError::Parse)?;
    let dir_c = match cstr_for_path(dir) {
        Ok(c) => c,
        Err(_) => return Ok(rules),
    };
    let dir_fd_probe = unsafe {
        libc::openat(
            libc::AT_FDCWD,
            dir_c.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if dir_fd_probe < 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ENOENT) || e.raw_os_error() == Some(libc::ENOTDIR) {
            return Ok(rules);
        }
        return Err(LoadError::Io(format!("could not open {}: {e}", dir.display())));
    }
    let mut dsb: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(dir_fd_probe, &mut dsb) } != 0 {
        let e = std::io::Error::last_os_error();
        unsafe { libc::close(dir_fd_probe) };
        return Err(LoadError::Io(format!("fstat {}: {e}", dir.display())));
    }
    let dir_label = dir.to_string_lossy().into_owned();
    if let Err(e) = check_dir_stat(&dsb, &dir_label) {
        unsafe { libc::close(dir_fd_probe) };
        return Err(e);
    }
    let names = list_conf_names(dir_fd_probe)?;
    if names.is_empty() {
        return Err(LoadError::Io(format!(
            "doas is not enabled, {}: no matching configuration files found",
            dir.display()
        )));
    }
    for name in names {
        let name_bytes = name.as_bytes();
        let cname = match CString::new(name_bytes) {
            Ok(c) => c,
            Err(_) => continue,
        };
        let full = format!("{}/{}", dir.display(), String::from_utf8_lossy(name_bytes));
        let dir_fd2 = open_dir_fd(dir)?;
        let data = match read_file_at(dir_fd2, &cname, &full) {
            Ok(d) => {
                unsafe { libc::close(dir_fd2) };
                d
            }
            Err(LoadError::Perm(_)) => {
                unsafe { libc::close(dir_fd2) };
                continue;
            }
            Err(e) => {
                unsafe { libc::close(dir_fd2) };
                return Err(e);
            }
        };
        let more = config::parse_bytes(&data, &full).map_err(LoadError::Parse)?;
        rules.extend(more);
        if rules.len() > config::MAX_RULES {
            return Err(LoadError::Perm(format!("too many rules in {}", dir.display())));
        }
    }
    Ok(rules)
}

pub fn load_system() -> Result<Vec<Rule>, LoadError> {
    load_paths(Path::new(MAIN_CONF), Path::new(CONF_DIR))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn tmp_base(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("doas-load-{}-{}", std::process::id(), tag));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    fn write_secure(path: &Path, data: &[u8]) {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o755)).unwrap();
        }
        std::fs::write(path, data).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o644)).unwrap();
    }

    #[test]
    fn safe_path_matches_alpine() {
        assert_eq!(SAFE_PATH, "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin");
    }

    #[test]
    fn loads_main_then_dir_later_wins() {
        let base = tmp_base("order");
        let main = base.join("doas.conf");
        let dir = base.join("doas.d");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        write_secure(&main, b"permit alice\n");
        write_secure(&dir.join("10-a.conf"), b"deny alice\n");
        write_secure(&dir.join("20-b.conf"), b"permit alice\n");
        write_secure(&dir.join("ignore.txt"), b"permit bob\n");
        let rules = load_paths(&main, &dir).unwrap();
        assert_eq!(rules.len(), 3);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn missing_main_fails_closed() {
        let base = tmp_base("missing");
        let main = base.join("doas.conf");
        let dir = base.join("doas.d");
        assert!(load_paths(&main, &dir).is_err());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn missing_dir_ok_with_main_only() {
        let base = tmp_base("nodir");
        let main = base.join("doas.conf");
        let dir = base.join("no-such-d");
        write_secure(&main, b"permit alice\n");
        let rules = load_paths(&main, &dir).unwrap();
        assert_eq!(rules.len(), 1);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn symlink_file_rejected_or_ignored() {
        let base = tmp_base("symlink");
        let main = base.join("doas.conf");
        let dir = base.join("doas.d");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        write_secure(&main, b"permit alice\n");
        write_secure(&dir.join("real.conf"), b"permit bob\n");
        std::os::unix::fs::symlink(dir.join("real.conf"), dir.join("link.conf")).unwrap();
        assert!(load_paths(&main, &dir).is_err());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn symlink_main_rejected() {
        let base = tmp_base("symlinkmain");
        let real = base.join("real.conf");
        let main = base.join("doas.conf");
        write_secure(&real, b"permit alice\n");
        std::os::unix::fs::symlink(&real, &main).unwrap();
        let dir = base.join("doas.d");
        assert!(load_paths(&main, &dir).is_err());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn writable_file_rejected() {
        let base = tmp_base("writable");
        let main = base.join("doas.conf");
        let dir = base.join("doas.d");
        write_secure(&main, b"permit alice\n");
        std::fs::set_permissions(&main, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(load_paths(&main, &dir).is_err());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn parse_error_fails_closed() {
        let base = tmp_base("parseerr");
        let main = base.join("doas.conf");
        let dir = base.join("doas.d");
        write_secure(&main, b"permit alice args foo\n");
        assert!(load_paths(&main, &dir).is_err());
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn ignores_non_conf_and_non_regular() {
        let base = tmp_base("ignore");
        let main = base.join("doas.conf");
        let dir = base.join("doas.d");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        write_secure(&main, b"permit alice\n");
        write_secure(&dir.join("01.conf"), b"permit bob\n");
        write_secure(&dir.join("notes.txt"), b"permit carol\n");
        let rules = load_paths(&main, &dir).unwrap();
        assert_eq!(rules.len(), 2);
        let _ = std::fs::remove_dir_all(&base);
    }
}
