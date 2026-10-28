use std::path::{Path, PathBuf};
use std::process::Command;

fn our_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_doas"))
}

fn oracle_bin() -> PathBuf {
    use std::sync::OnceLock;
    static ONCE: OnceLock<PathBuf> = OnceLock::new();
    ONCE.get_or_init(|| {
        let out = PathBuf::from("/tmp/doas-oracle-build/OpenDoas-6.8.2/doas");
        if out.exists() {
            return out;
        }
        let status = Command::new("sh")
            .arg("-c")
            .arg(
                "set -e; apk add --no-cache bison make gcc musl-dev >/dev/null 2>&1 || true; \
                 mkdir -p /tmp/doas-oracle-build; cd /tmp/doas-oracle-build; \
                 rm -f v6.8.2.tar.gz; curl -fSL https://github.com/Duncaen/OpenDoas/archive/v6.8.2.tar.gz -o v6.8.2.tar.gz; \
                 rm -rf OpenDoas-6.8.2; tar xzf v6.8.2.tar.gz; cd OpenDoas-6.8.2; ./configure --prefix=/tmp/doas-oracle --without-pam --with-timestamp >/dev/null 2>&1; make >/dev/null 2>&1; test -x ./doas",
            )
            .status()
            .expect("oracle build shell failed");
        assert!(status.success(), "oracle build failed");
        assert!(out.exists(), "oracle binary missing after build");
        out
    }).clone()
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
    p.push(format!("doas-oracle-{}-{}", std::process::id(), tag));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn oracle_parity_permit_deny_ordering() {
    let obin = oracle_bin();
    let nbin = our_bin();
    let dir = tmp_dir("ordering");
    let cfg = write_cfg(&dir, "t.conf", "permit root\ndeny root\n");
    let (oc, os) = run_check(&obin, &cfg, &["id"]);
    let (nc, ns) = run_check(&nbin, &cfg, &["id"]);
    assert_eq!((oc, os.as_str()), (nc, ns.as_str()));
    assert_eq!((nc, ns.as_str()), (1, "deny"));
    let cfg2 = write_cfg(&dir, "t2.conf", "deny root\npermit root\n");
    let (oc2, os2) = run_check(&obin, &cfg2, &["id"]);
    let (nc2, ns2) = run_check(&nbin, &cfg2, &["id"]);
    assert_eq!((oc2, os2.as_str()), (nc2, ns2.as_str()));
    assert_eq!((nc2, ns2.as_str()), (0, "permit"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn oracle_parity_cmd_args_exact() {
    let obin = oracle_bin();
    let nbin = our_bin();
    let dir = tmp_dir("cmdargs");
    let cfg = write_cfg(&dir, "t.conf", "permit root cmd /bin/echo args hello\n");
    for (args, expect_code, expect_out) in [
        (vec!["/bin/echo", "hello"], 0, "permit"),
        (vec!["/bin/echo"], 1, "deny"),
        (vec!["/bin/echo", "hello", "x"], 1, "deny"),
    ] {
        let (oc, os) = run_check(&obin, &cfg, &args);
        let (nc, ns) = run_check(&nbin, &cfg, &args);
        assert_eq!((oc, os.as_str()), (nc, ns.as_str()), "args {args:?}");
        assert_eq!((nc, ns.as_str()), (expect_code, expect_out));
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn oracle_parity_parser_errors() {
    let obin = oracle_bin();
    let nbin = our_bin();
    let dir = tmp_dir("parseerr");
    for bad in [
        "permit root args foo\n",
        "permit nopass persist root\n",
        "permit\n",
    ] {
        let cfg = write_cfg(&dir, "bad.conf", bad);
        let (oc, _) = run_check(&obin, &cfg, &[]);
        let (nc, _) = run_check(&nbin, &cfg, &[]);
        assert_eq!(oc, nc, "bad config {bad:?} must share exit");
        assert_ne!(nc, 0);
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn oracle_parity_nopass_marker() {
    let obin = oracle_bin();
    let nbin = our_bin();
    let dir = tmp_dir("nopass");
    let cfg = write_cfg(&dir, "t.conf", "permit nopass root cmd /bin/id\n");
    let (oc, os) = run_check(&obin, &cfg, &["/bin/id"]);
    let (nc, ns) = run_check(&nbin, &cfg, &["/bin/id"]);
    assert_eq!((oc, os.as_str()), (nc, ns.as_str()));
    assert_eq!((nc, ns.as_str()), (0, "permit nopass"));
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
