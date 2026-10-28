use std::ffi::CString;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

pub const TIMESTAMP_DIR: &str = "/run/doas";
pub const TIMESTAMP_TIMEOUT_SECS: i64 = 300;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TimestampError {
    Io(String),
    Invalid,
}

impl std::fmt::Display for TimestampError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(m) => write!(f, "doas: {m}"),
            Self::Invalid => write!(f, "doas: invalid timestamp"),
        }
    }
}

fn read_proc_stat(pid: i32) -> Result<(i32, u64), TimestampError> {
    let path = format!("/proc/{pid}/stat");
    let cpath = CString::new(path.clone()).map_err(|_| TimestampError::Invalid)?;
    let fd = unsafe { libc::openat(libc::AT_FDCWD, cpath.as_ptr(), libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
    if fd < 0 {
        return Err(TimestampError::Invalid);
    }
    let mut buf = vec![0u8; 4096];
    let mut total = 0usize;
    loop {
        let n = unsafe { libc::read(fd, buf.as_mut_ptr().add(total) as *mut libc::c_void, buf.len() - total) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            unsafe { libc::close(fd) };
            return Err(TimestampError::Invalid);
        }
        if n == 0 {
            break;
        }
        total += n as usize;
        if total >= buf.len() {
            break;
        }
    }
    unsafe { libc::close(fd) };
    if total == 0 || buf[..total].contains(&0) {
        return Err(TimestampError::Invalid);
    }
    let s = match std::str::from_utf8(&buf[..total]) {
        Ok(v) => v,
        Err(_) => return Err(TimestampError::Invalid),
    };
    let close_paren = s.rfind(')').ok_or(TimestampError::Invalid)?;
    let rest = &s[close_paren + 1..];
    let fields: Vec<&str> = rest.split_whitespace().collect();
    if fields.len() < 20 {
        return Err(TimestampError::Invalid);
    }
    let tty: i32 = fields[4].parse().map_err(|_| TimestampError::Invalid)?;
    let start: u64 = fields[19].parse().map_err(|_| TimestampError::Invalid)?;
    Ok((tty, start))
}

fn timestamp_name() -> Result<String, TimestampError> {
    let ppid = unsafe { libc::getppid() };
    let sid = unsafe { libc::getsid(0) };
    if sid < 0 {
        return Err(TimestampError::Invalid);
    }
    let uid = unsafe { libc::getuid() };
    let (tty, start) = read_proc_stat(ppid).map_err(|_| TimestampError::Invalid)?;
    Ok(format!("{ppid}-{sid}-{tty}-{start}-{uid}"))
}

pub fn timestamp_path() -> Result<PathBuf, TimestampError> {
    timestamp_path_in(Path::new(TIMESTAMP_DIR))
}

pub fn timestamp_path_in(dir: &Path) -> Result<PathBuf, TimestampError> {
    let name = timestamp_name()?;
    if name.contains('/') || name.contains('\0') {
        return Err(TimestampError::Invalid);
    }
    Ok(dir.join(name))
}

fn check_dir_fd(fd: i32) -> Result<(), TimestampError> {
    let mut sb: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut sb) } != 0 {
        return Err(TimestampError::Io("fstat timestamp dir failed".to_string()));
    }
    if (sb.st_mode & libc::S_IFMT) != libc::S_IFDIR {
        return Err(TimestampError::Invalid);
    }
    if sb.st_uid != 0 {
        return Err(TimestampError::Invalid);
    }
    if (sb.st_mode & 0o777) != 0o700 {
        return Err(TimestampError::Invalid);
    }
    Ok(())
}

fn ensure_dir_in(dir: &Path) -> Result<i32, TimestampError> {
    let dir_s = dir.to_string_lossy().into_owned();
    let cdir = CString::new(dir_s).map_err(|_| TimestampError::Invalid)?;
    let fd = unsafe { libc::openat(libc::AT_FDCWD, cdir.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
    if fd >= 0 {
        if check_dir_fd(fd).is_err() {
            unsafe { libc::close(fd) };
            return Err(TimestampError::Invalid);
        }
        return Ok(fd);
    }
    let e = std::io::Error::last_os_error();
    if e.raw_os_error() != Some(libc::ENOENT) {
        return Err(TimestampError::Invalid);
    }
    if unsafe { libc::mkdir(cdir.as_ptr(), 0o700) } != 0 {
        return Err(TimestampError::Invalid);
    }
    let fd2 = unsafe { libc::openat(libc::AT_FDCWD, cdir.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
    if fd2 < 0 {
        return Err(TimestampError::Invalid);
    }
    if check_dir_fd(fd2).is_err() {
        unsafe { libc::close(fd2) };
        return Err(TimestampError::Invalid);
    }
    Ok(fd2)
}

fn ensure_dir() -> Result<i32, TimestampError> {
    ensure_dir_in(Path::new(TIMESTAMP_DIR))
}

fn clock_now() -> Result<(libc::timespec, libc::timespec), TimestampError> {
    let mut boot: libc::timespec = unsafe { std::mem::zeroed() };
    let mut wall: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut boot) } != 0 {
        return Err(TimestampError::Invalid);
    }
    if unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut wall) } != 0 {
        return Err(TimestampError::Invalid);
    }
    Ok((boot, wall))
}

fn timespec_add(a: &libc::timespec, secs: i64) -> libc::timespec {
    let mut out = *a;
    out.tv_sec += secs;
    out
}

pub fn is_valid(fd: i32, timeout_secs: i64) -> bool {
    let mut sb: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd, &mut sb) } != 0 {
        return false;
    }
    if sb.st_uid != 0 {
        return false;
    }
    if (sb.st_mode & libc::S_IFMT) != libc::S_IFREG {
        return false;
    }
    if (sb.st_mode & 0o7777) != 0 {
        return false;
    }
    if sb.st_atime == 0 || sb.st_mtime == 0 {
        return false;
    }
    let Ok((boot_now, wall_now)) = clock_now() else {
        return false;
    };
    if sb.st_atime < boot_now.tv_sec {
        return false;
    }
    if sb.st_mtime < wall_now.tv_sec {
        return false;
    }
    if sb.st_atime > boot_now.tv_sec + timeout_secs {
        return false;
    }
    if sb.st_mtime > wall_now.tv_sec + timeout_secs {
        return false;
    }
    true
}

pub fn open_existing(timeout_secs: i64) -> Result<(i32, bool), TimestampError> {
    open_existing_in(Path::new(TIMESTAMP_DIR), timeout_secs)
}

pub fn open_existing_in(dir: &Path, timeout_secs: i64) -> Result<(i32, bool), TimestampError> {
    let dir_fd = ensure_dir_in(dir)?;
    let path = timestamp_path_in(dir)?;
    let name = path.file_name().ok_or(TimestampError::Invalid)?;
    let cname = CString::new(name.as_bytes()).map_err(|_| TimestampError::Invalid)?;
    let fd = unsafe { libc::openat(dir_fd, cname.as_ptr(), libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
    if fd < 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ENOENT) {
            unsafe { libc::close(dir_fd) };
            return Ok((-1, false));
        }
        unsafe { libc::close(dir_fd) };
        return Err(TimestampError::Invalid);
    }
    unsafe { libc::close(dir_fd) };
    let valid = is_valid(fd, timeout_secs);
    Ok((fd, valid))
}

pub fn create_placeholder() -> Result<i32, TimestampError> {
    create_placeholder_in(Path::new(TIMESTAMP_DIR))
}

pub fn create_placeholder_in(dir: &Path) -> Result<i32, TimestampError> {
    let dir_fd = ensure_dir_in(dir)?;
    let pid = unsafe { libc::getpid() };
    let tid = format!("{:?}", std::thread::current().id());
    let tag: String = tid.chars().filter(|c| c.is_ascii_digit()).collect();
    let tmp_name = format!(".tmp-{pid}-{tag}");
    let ctmp = CString::new(tmp_name.clone()).unwrap();
    let fd = unsafe { libc::openat(dir_fd, ctmp.as_ptr(), libc::O_RDONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC, 0o000) };
    if fd < 0 {
        unsafe { libc::close(dir_fd) };
        return Err(TimestampError::Invalid);
    }
    let zero: libc::timespec = unsafe { std::mem::zeroed() };
    let ts = [zero, zero];
    unsafe { libc::futimens(fd, ts.as_ptr()) };
    let path = timestamp_path_in(dir)?;
    let target = path.file_name().ok_or(TimestampError::Invalid)?;
    let ctarget = CString::new(target.as_bytes()).map_err(|_| TimestampError::Invalid)?;
    if unsafe { libc::renameat(dir_fd, ctmp.as_ptr(), dir_fd, ctarget.as_ptr()) } != 0 {
        let _ = std::fs::remove_file(dir.join(&tmp_name));
        unsafe { libc::close(fd) };
        unsafe { libc::close(dir_fd) };
        return Err(TimestampError::Invalid);
    }
    unsafe { libc::close(dir_fd) };
    Ok(fd)
}

pub fn set_valid(fd: i32, timeout_secs: i64) -> Result<(), TimestampError> {
    let (boot_now, wall_now) = clock_now()?;
    let boot_exp = timespec_add(&boot_now, timeout_secs);
    let wall_exp = timespec_add(&wall_now, timeout_secs);
    let ts = [boot_exp, wall_exp];
    if unsafe { libc::futimens(fd, ts.as_ptr()) } != 0 {
        return Err(TimestampError::Invalid);
    }
    Ok(())
}

pub fn clear() -> Result<(), TimestampError> {
    clear_in(Path::new(TIMESTAMP_DIR))
}

pub fn clear_in(dir: &Path) -> Result<(), TimestampError> {
    let Ok(path) = timestamp_path_in(dir) else {
        return Ok(());
    };
    let cpath = match CString::new(path.to_string_lossy().as_bytes()) {
        Ok(c) => c,
        Err(_) => return Ok(()),
    };
    if unsafe { libc::unlinkat(libc::AT_FDCWD, cpath.as_ptr(), 0) } != 0 {
        let e = std::io::Error::last_os_error();
        if e.raw_os_error() == Some(libc::ENOENT) {
            return Ok(());
        }
        return Err(TimestampError::Io(format!("unlink failed: {e}")));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn tmp_dir(tag: &str) -> PathBuf {
        let mut p = std::env::temp_dir();
        p.push(format!("doas-ts-{}-{}", std::process::id(), tag));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o700)).unwrap();
        p
    }

    fn is_root() -> bool {
        unsafe { libc::geteuid() == 0 }
    }

    #[test]
    fn path_has_no_attacker_parts() {
        let p = timestamp_path().expect("must build path in container");
        let s = p.to_string_lossy();
        assert!(s.starts_with(TIMESTAMP_DIR));
        let name = p.file_name().unwrap().to_string_lossy();
        assert!(!name.contains('/'));
        assert!(!name.contains('\0'));
        for part in name.split('-') {
            assert!(part.chars().all(|c| c.is_ascii_digit()), "part {part} not numeric");
        }
    }

    #[test]
    fn absence_means_reauth_never_allow() {
        if !is_root() {
            return;
        }
        let dir = tmp_dir("absence");
        let (fd, valid) = open_existing_in(&dir, 300).expect("open must not fail hard");
        if fd >= 0 {
            unsafe { libc::close(fd) };
        }
        assert!(!valid);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn create_then_valid_then_expiry() {
        if !is_root() {
            return;
        }
        let dir = tmp_dir("expiry");
        let (_fd_old, v0) = open_existing_in(&dir, 300).unwrap();
        assert!(!v0);
        if _fd_old >= 0 {
            unsafe { libc::close(_fd_old) };
        }
        let fd = create_placeholder_in(&dir).expect("create must succeed as root");
        assert!(!is_valid(fd, 300));
        set_valid(fd, 2).expect("set must succeed");
        assert!(is_valid(fd, 300));
        unsafe { libc::close(fd) };
        std::thread::sleep(std::time::Duration::from_secs(3));
        let (fd2, valid2) = open_existing_in(&dir, 2).unwrap();
        if fd2 >= 0 {
            let still = is_valid(fd2, 2);
            unsafe { libc::close(fd2) };
            assert!(!still || !valid2);
        } else {
            assert!(!valid2);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn corruption_means_reauth() {
        if !is_root() {
            return;
        }
        let dir = tmp_dir("corrupt");
        let fd = create_placeholder_in(&dir).expect("create");
        unsafe { libc::close(fd) };
        let (fd2, valid) = open_existing_in(&dir, 300).unwrap();
        assert!(!valid);
        if fd2 >= 0 {
            unsafe { libc::close(fd2) };
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn future_timestamp_rejected() {
        if !is_root() {
            return;
        }
        let dir = tmp_dir("future");
        let fd = create_placeholder_in(&dir).expect("create");
        let far: libc::timespec = libc::timespec { tv_sec: 1_000_000_000, tv_nsec: 0 };
        let ts = [far, far];
        unsafe { libc::futimens(fd, ts.as_ptr()) };
        assert!(!is_valid(fd, 300));
        unsafe { libc::close(fd) };
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn clear_is_idempotent() {
        let dir = tmp_dir("clear");
        assert!(clear_in(&dir).is_ok());
        assert!(clear_in(&dir).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn dir_must_be_root_0700() {
        if !is_root() {
            return;
        }
        let dir = tmp_dir("perm");
        let dir_fd = ensure_dir_in(&dir).expect("dir must exist as root");
        unsafe { libc::close(dir_fd) };
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn filename_uses_only_numbers() {
        let name = timestamp_name().unwrap();
        assert!(!name.contains('/'));
        assert!(name.split('-').count() == 5);
    }
}
