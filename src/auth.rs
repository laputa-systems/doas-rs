use std::ffi::{CStr, CString, OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};

#[link(name = "crypt")]
unsafe extern "C" {
    fn crypt(key: *const libc::c_char, salt: *const libc::c_char) -> *mut libc::c_char;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthError {
    NoTty(String),
    Failed(String),
    NonInteractive,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoTty(m) => write!(f, "doas: {m}: a tty is required"),
            Self::Failed(m) => write!(f, "doas: {m}"),
            Self::NonInteractive => write!(f, "doas: Authentication required"),
        }
    }
}

pub fn zeroize(buf: &mut [u8]) {
    for b in buf.iter_mut() {
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn cstring_from_bytes(b: &[u8]) -> Option<CString> {
    if b.contains(&0) {
        return None;
    }
    CString::new(b).ok()
}

pub fn crypt_verify(password: &[u8], hash: &OsStr) -> bool {
    let hash_bytes = hash.as_bytes();
    if hash_bytes.is_empty() || hash_bytes.contains(&0) {
        return false;
    }
    if hash_bytes.starts_with(b"*") || hash_bytes.starts_with(b"!") {
        return false;
    }
    if password.contains(&0) {
        return false;
    }
    if password.len() > 1024 {
        return false;
    }
    let Some(pw_c) = cstring_from_bytes(password) else {
        return false;
    };
    let Some(hash_c) = cstring_from_bytes(hash_bytes) else {
        return false;
    };
    let out = unsafe { crypt(pw_c.as_ptr(), hash_c.as_ptr()) };
    if out.is_null() {
        return false;
    }
    let computed = unsafe { CStr::from_ptr(out) }.to_bytes();
    if computed.starts_with(b"*") {
        return false;
    }
    ct_eq(computed, hash_bytes)
}

pub fn get_stored_hash(username: &OsStr) -> Option<OsString> {
    let ub = username.as_bytes();
    if ub.is_empty() || ub.contains(&0) {
        return None;
    }
    let cname = cstring_from_bytes(ub)?;
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
    let pw_passwd = unsafe { CStr::from_ptr(pwd.pw_passwd) }.to_bytes();
    if pw_passwd == b"x" {
        let sp = unsafe { libc::getspnam(cname.as_ptr()) };
        if sp.is_null() {
            return None;
        }
        let sp_pwdp = unsafe { CStr::from_ptr((*sp).sp_pwdp) }.to_bytes();
        if sp_pwdp.is_empty() {
            return None;
        }
        if sp_pwdp.starts_with(b"*") || sp_pwdp.starts_with(b"!") {
            return None;
        }
        if sp_pwdp.contains(&0) {
            return None;
        }
        return Some(OsString::from_vec(sp_pwdp.to_vec()));
    }
    if pw_passwd.is_empty() {
        return None;
    }
    if pw_passwd.starts_with(b"*") || pw_passwd.starts_with(b"!") {
        return None;
    }
    if pw_passwd == b"x" {
        return None;
    }
    Some(OsString::from_vec(pw_passwd.to_vec()))
}

struct TermGuard {
    fd: i32,
    orig: libc::termios,
    active: bool,
}

impl Drop for TermGuard {
    fn drop(&mut self) {
        if self.active {
            unsafe { libc::tcsetattr(self.fd, libc::TCSANOW, &self.orig) };
        }
    }
}

fn open_tty() -> Result<i32, AuthError> {
    let c = CString::new("/dev/tty").unwrap();
    let fd = unsafe { libc::open(c.as_ptr(), libc::O_RDWR | libc::O_NOFOLLOW | libc::O_CLOEXEC) };
    if fd < 0 {
        let e = std::io::Error::last_os_error();
        return Err(AuthError::NoTty(format!("tty required ({e})")));
    }
    Ok(fd)
}

fn read_password_tty(fd: i32, prompt: &[u8]) -> Result<Vec<u8>, AuthError> {
    let mut orig: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut orig) } != 0 {
        unsafe { libc::close(fd) };
        return Err(AuthError::NoTty("tty required".to_string()));
    }
    let mut noecho = orig;
    noecho.c_lflag &= !(libc::ECHO as libc::tcflag_t);
    noecho.c_lflag |= libc::ICANON as libc::tcflag_t;
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &noecho) } != 0 {
        unsafe { libc::close(fd) };
        return Err(AuthError::NoTty("tty required".to_string()));
    }
    let _guard = TermGuard { fd, orig, active: true };
    let _ = unsafe { libc::write(fd, prompt.as_ptr() as *const libc::c_void, prompt.len()) };
    let mut buf: Vec<u8> = Vec::new();
    let mut tmp = [0u8; 256];
    loop {
        let n = unsafe { libc::read(fd, tmp.as_mut_ptr() as *mut libc::c_void, tmp.len()) };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            let _ = unsafe { libc::write(fd, b"\n".as_ptr() as *const libc::c_void, 1) };
            return Err(AuthError::Failed(format!("readpassphrase: {e}")));
        }
        if n == 0 {
            break;
        }
        let chunk = &tmp[..n as usize];
        if let Some(pos) = chunk.iter().position(|&b| b == b'\n') {
            buf.extend_from_slice(&chunk[..pos]);
            break;
        }
        buf.extend_from_slice(chunk);
        if buf.len() > 1024 {
            zeroize(&mut buf);
            let _ = unsafe { libc::write(fd, b"\n".as_ptr() as *const libc::c_void, 1) };
            return Err(AuthError::Failed("Authentication failed".to_string()));
        }
    }
    let _ = unsafe { libc::write(fd, b"\n".as_ptr() as *const libc::c_void, 1) };
    Ok(buf)
}

pub fn authenticate_user(username: &OsStr, non_interactive: bool) -> Result<(), AuthError> {
    if non_interactive {
        return Err(AuthError::NonInteractive);
    }
    let Some(hash) = get_stored_hash(username) else {
        return Err(AuthError::Failed("Authentication failed".to_string()));
    };
    let fd = open_tty()?;
    let hostname = {
        let mut h = vec![0u8; 65];
        if unsafe { libc::gethostname(h.as_mut_ptr() as *mut libc::c_char, h.len()) } != 0 {
            b"?".to_vec()
        } else {
            let len = h.iter().position(|&b| b == 0).unwrap_or(h.len());
            h.truncate(len);
            if h.is_empty() { b"?".to_vec() } else { h }
        }
    };
    let mut host32 = hostname;
    host32.truncate(32);
    let mut user32 = username.as_bytes().to_vec();
    user32.truncate(32);
    let prompt = format!(
        "\rdoas ({}@{}) password: ",
        String::from_utf8_lossy(&user32),
        String::from_utf8_lossy(&host32)
    );
    let mut pw = read_password_tty(fd, prompt.as_bytes())?;
    unsafe { libc::close(fd) };
    let ok = crypt_verify(&pw, hash.as_os_str());
    zeroize(&mut pw);
    if ok {
        Ok(())
    } else {
        Err(AuthError::Failed("Authentication failed".to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(s: &str) -> OsString {
        OsString::from(s)
    }

    #[test]
    fn locked_and_missing_fail_closed() {
        assert!(get_stored_hash(os("no-such-user-xyz-123").as_os_str()).is_none());
        assert!(get_stored_hash(os("").as_os_str()).is_none());
        use std::os::unix::ffi::OsStringExt;
        let bad = OsString::from_vec(vec![b'a', 0]);
        assert!(get_stored_hash(bad.as_os_str()).is_none());
    }

    #[test]
    fn crypt_verify_rejects_empty_and_nul() {
        assert!(!crypt_verify(b"", os("$6$salt$hash").as_os_str()));
        assert!(!crypt_verify(b"a\0b", os("$6$salt$hash").as_os_str()));
        assert!(!crypt_verify(b"pw", os("").as_os_str()));
        assert!(!crypt_verify(b"pw", os("*").as_os_str()));
        assert!(!crypt_verify(b"pw", os("!").as_os_str()));
    }

    #[test]
    fn crypt_roundtrip_with_known_hash() {
        let pw = b"test-password-123";
        let salt = CString::new("do").unwrap();
        let pw_c = CString::new(pw.as_slice()).unwrap();
        let out = unsafe { crypt(pw_c.as_ptr(), salt.as_ptr()) };
        assert!(!out.is_null());
        let hash = unsafe { CStr::from_ptr(out) }.to_bytes();
        assert!(!hash.is_empty());
        assert!(!hash.starts_with(b"*"));
        let hash_os = OsString::from_vec(hash.to_vec());
        assert!(crypt_verify(pw, hash_os.as_os_str()));
        assert!(!crypt_verify(b"wrong-password", hash_os.as_os_str()));
    }

    #[test]
    fn constant_time_compare() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
        assert!(!ct_eq(b"", b"a"));
    }

    #[test]
    fn zeroize_clears() {
        let mut b = vec![1u8, 2, 3];
        zeroize(&mut b);
        assert_eq!(b, vec![0, 0, 0]);
    }

    #[test]
    fn non_interactive_fails_fast_without_tty() {
        let r = authenticate_user(os("root").as_os_str(), true);
        assert!(matches!(r, Err(AuthError::NonInteractive)));
    }

    #[test]
    fn tty_required_when_no_tty() {
        let r = authenticate_user(os("no-such-user-xyz-123").as_os_str(), false);
        assert!(r.is_err());
        if let Err(e) = r {
            let s = format!("{e}");
            assert!(s.contains("Authentication failed") || s.contains("tty"));
            assert!(!s.contains("test-password"));
        }
    }

    #[test]
    fn no_secret_logging_in_errors() {
        let r = authenticate_user(os("root").as_os_str(), false);
        if let Err(e) = r {
            let s = format!("{e}");
            assert!(!s.contains("password"));
        }
    }
}
