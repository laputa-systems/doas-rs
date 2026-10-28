use std::path::{Path, PathBuf};
use std::process::Command;

fn our_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_doas"))
}

fn run_check(bin: &Path, cfg: &Path, extra: &[&str]) -> (i32, String) {
    let mut cmd = Command::new(bin);
    cmd.arg("-C").arg(cfg);
    for a in extra {
        cmd.arg(a);
    }
    cmd.env("DOAS_ALLOW_NONSETUID", "1");
    let out = cmd.output().expect("run check failed");
    let code = out.status.code().unwrap_or(99);
    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (code, stdout)
}

fn write_cfg(dir: &Path, name: &str, content: &str) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, content).unwrap();
    p
}

fn tmp_dir(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("doas-check-{}-{}", std::process::id(), tag));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn is_root() -> bool {
    rustix::process::getuid().as_raw() == 0
}

#[test]
fn check_permit_deny_ordering() {
    if !is_root() {
        return;
    }
    let nbin = our_bin();
    let dir = tmp_dir("ordering");
    let cfg = write_cfg(&dir, "t.conf", "permit root\ndeny root\n");
    assert_eq!(run_check(&nbin, &cfg, &["id"]), (1, "deny".to_string()));
    let cfg2 = write_cfg(&dir, "t2.conf", "deny root\npermit root\n");
    assert_eq!(run_check(&nbin, &cfg2, &["id"]), (0, "permit".to_string()));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn check_cmd_args_exact() {
    if !is_root() {
        return;
    }
    let nbin = our_bin();
    let dir = tmp_dir("cmdargs");
    let cfg = write_cfg(&dir, "t.conf", "permit root cmd /bin/echo args hello\n");
    for (args, expect) in [
        (vec!["/bin/echo", "hello"], (0, "permit")),
        (vec!["/bin/echo"], (1, "deny")),
        (vec!["/bin/echo", "hello", "x"], (1, "deny")),
    ] {
        assert_eq!(run_check(&nbin, &cfg, &args), (expect.0, expect.1.to_string()), "args {args:?}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn check_parser_errors() {
    let nbin = our_bin();
    let dir = tmp_dir("parseerr");
    for bad in [
        "permit root args foo\n",
        "permit nopass persist root\n",
        "permit\n",
    ] {
        let cfg = write_cfg(&dir, "bad.conf", bad);
        let (nc, _) = run_check(&nbin, &cfg, &[]);
        assert_ne!(nc, 0, "bad config {bad:?} must fail");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn check_nopass_marker() {
    if !is_root() {
        return;
    }
    let nbin = our_bin();
    let dir = tmp_dir("nopass");
    let cfg = write_cfg(&dir, "t.conf", "permit nopass root cmd /bin/id\n");
    assert_eq!(
        run_check(&nbin, &cfg, &["/bin/id"]),
        (0, "permit nopass".to_string())
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn mutation_guard_last_match_wins() {
    let dir = tmp_dir("mutation");
    let cfg = write_cfg(&dir, "t.conf", "permit root\ndeny root\n");
    let (nc, ns) = run_check(&our_bin(), &cfg, &["id"]);
    assert_eq!((nc, ns.as_str()), (1, "deny"), "last match must win; first-match mutation must fail here");
    let _ = std::fs::remove_dir_all(&dir);
}
