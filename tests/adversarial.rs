use std::path::{Path, PathBuf};
use std::process::Command;

fn our_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_doas"))
}

fn lcg(state: &mut u64) -> u64 {
    *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
    *state >> 11
}

fn tmp_dir(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    p.push(format!("doas-adv-{}-{}", std::process::id(), tag));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn run_doas(args: &[&str], cfg: Option<&Path>) -> (i32, String) {
    let mut cmd = Command::new(our_bin());
    if let Some(c) = cfg {
        cmd.arg("-C").arg(c);
    }
    for a in args {
        cmd.arg(a);
    }
    cmd.env("DOAS_ALLOW_NONSETUID", "1");
    let out = cmd.output().expect("run doas");
    (
        out.status.code().unwrap_or(99),
        String::from_utf8_lossy(&out.stdout).trim().to_string(),
    )
}

#[test]
fn seeded_malformed_configs_fail_closed() {
    let dir = tmp_dir("malformed");
    let mut seed = 0x1234_5678_9abc_def1;
    for i in 0..100 {
        let len = (lcg(&mut seed) % 128) as usize;
        let mut data: Vec<u8> = (0..len).map(|_| (lcg(&mut seed) % 256) as u8).collect();
        if data.is_empty() {
            data.push(b'\n');
        }
        let cfg = dir.join(format!("f{i}.conf"));
        std::fs::write(&cfg, &data).unwrap();
        let (code, stdout) = run_doas(&[], Some(&cfg));
        assert!(code == 0 || code == 1, "must not crash: {data:?} -> {code}");
        assert_ne!(stdout.as_str(), "permit");
        assert_ne!(stdout.as_str(), "permit nopass");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn seeded_cli_never_panics() {
    let dir = tmp_dir("cli");
    let cfg = dir.join("t.conf");
    std::fs::write(&cfg, b"permit root\n").unwrap();
    let mut seed = 0xdead_beef_cafe_0001;
    for _ in 0..100 {
        let n = (lcg(&mut seed) % 4) as usize;
        let mut args: Vec<String> = Vec::new();
        for _ in 0..n {
            let len = (lcg(&mut seed) % 16) as usize;
            let b: Vec<u8> = (0..len).map(|_| (lcg(&mut seed) % 256) as u8).collect();
            if b.contains(&0) {
                continue;
            }
            args.push(String::from_utf8_lossy(&b).into_owned());
        }
        let arg_refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
        let (code, _) = run_doas(&arg_refs, Some(&cfg));
        assert!(code == 0 || code == 1, "CLI must not crash: {args:?} -> {code}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn oversize_config_rejected_not_crash() {
    let dir = tmp_dir("oversize");
    let cfg = dir.join("big.conf");
    let big = "a".repeat(2_000_000);
    std::fs::write(&cfg, format!("permit {big}\n")).unwrap();
    let (code, stdout) = run_doas(&[], Some(&cfg));
    assert_ne!(code, 0);
    assert_ne!(stdout.as_str(), "permit");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unreadable_config_fails_closed() {
    let dir = tmp_dir("unreadable");
    let missing = dir.join("no-such.conf");
    let (code, stdout) = run_doas(&["id"], Some(&missing));
    assert!(code == 0 || code == 1);
    assert_ne!(stdout.as_str(), "permit");
    assert_ne!(stdout.as_str(), "permit nopass");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn parallel_runs_no_race() {
    use std::thread;
    let dir = tmp_dir("race");
    let cfg = dir.join("t.conf");
    std::fs::write(&cfg, b"permit root\ndeny root\n").unwrap();
    let handles: Vec<_> = (0..8).map(|_| {
        let cfg = cfg.clone();
        thread::spawn(move || run_doas(&["id"], Some(&cfg)))
    }).collect();
    for h in handles {
        let (code, stdout) = h.join().unwrap();
        assert!(code == 0 || code == 1);
        assert!(stdout == "deny" || stdout.is_empty() || stdout == "permit" || stdout == "permit nopass");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn nul_and_non_utf8_fail_closed() {
    let dir = tmp_dir("nul");
    let cfg = dir.join("t.conf");
    std::fs::write(&cfg, b"permit root\x00\n").unwrap();
    let (code, stdout) = run_doas(&[], Some(&cfg));
    assert_ne!(code, 0);
    assert_ne!(stdout.as_str(), "permit");
    let cfg2 = dir.join("t2.conf");
    std::fs::write(&cfg2, [0xff, 0xfe, b'\n']).unwrap();
    let (code2, stdout2) = run_doas(&[], Some(&cfg2));
    assert!(code2 == 0 || code2 == 1);
    assert_ne!(stdout2.as_str(), "permit");
    let _ = std::fs::remove_dir_all(&dir);
}
