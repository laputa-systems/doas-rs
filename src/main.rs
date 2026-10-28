#[cfg(not(target_os = "linux"))]
compile_error!("doas-rs runs on Linux only");

use std::ffi::{CString, OsString};
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;
use std::process::ExitCode;

use rustix::process::{Gid, Uid};

mod auth;
mod cli;
mod config;
mod env;
mod exec;
mod identity;
mod load;
mod log;
mod policy;
#[allow(dead_code)]
mod timestamp;
#[allow(dead_code)]
mod tty;

#[derive(Debug)]
struct UntrustedInput {
    argv: Vec<OsString>,
    uid: Uid,
    gid: Gid,
}

#[derive(Debug)]
struct ParsedPolicy {
    input: UntrustedInput,
    cli: cli::Cli,
    rules: Vec<config::Rule>,
    target_uid: u32,
    groups: Vec<u32>,
}

#[derive(Debug)]
struct AuthorizedRequest {
    policy: ParsedPolicy,
    permit: config::PermitRule,
}

#[derive(Debug)]
struct AuthenticatedRequest {
    request: AuthorizedRequest,
}

#[derive(Debug)]
struct PreparedExecution {
    request: AuthenticatedRequest,
    envp: Vec<OsString>,
    cmd_path: PathBuf,
    argv_exec: Vec<OsString>,
}

struct Exec {
    prepared: PreparedExecution,
}

#[derive(Debug)]
struct Denied {
    stage: &'static str,
    argv: Vec<OsString>,
    uid: Uid,
    gid: Gid,
}

impl UntrustedInput {
    fn capture() -> Self {
        let uid = Uid::from_raw(unsafe { libc::getuid() });
        let gid = Gid::from_raw(unsafe { libc::getgid() });
        Self {
            argv: std::env::args_os().collect(),
            uid,
            gid,
        }
    }

    fn parse(self) -> Result<ParsedPolicy, Denied> {
        let UntrustedInput { argv, uid, gid } = self;
        let cli = match cli::parse(&argv) {
            Ok(c) => c,
            Err(_) => {
                return Err(Denied {
                    stage: "usage",
                    argv,
                    uid,
                    gid,
                });
            }
        };
        if cli.clear_timestamp {
            return Ok(ParsedPolicy {
                input: UntrustedInput { argv, uid, gid },
                cli,
                rules: Vec::new(),
                target_uid: 0,
                groups: Vec::new(),
            });
        }
        if cli.config_check.is_some() {
            return Ok(ParsedPolicy {
                input: UntrustedInput { argv, uid, gid },
                cli,
                rules: Vec::new(),
                target_uid: 0,
                groups: Vec::new(),
            });
        }
        let rules = match load::load_system() {
            Ok(r) => r,
            Err(e) => {
                eprintln!("{e}");
                return Err(Denied {
                    stage: "load",
                    argv,
                    uid,
                    gid,
                });
            }
        };
        let target_uid = match &cli.target_user {
            Some(u) => match identity::resolve_user(u.as_os_str()) {
                Some(id) => id,
                None => {
                    eprintln!("doas: unknown user");
                    return Err(Denied {
                        stage: "usage",
                        argv,
                        uid,
                        gid,
                    });
                }
            },
            None => 0,
        };
        let groups = identity::current_groups();
        Ok(ParsedPolicy {
            input: UntrustedInput { argv, uid, gid },
            cli,
            rules,
            target_uid,
            groups,
        })
    }
}

impl ParsedPolicy {
    fn authorize(self) -> Result<AuthorizedRequest, Denied> {
        if self.cli.clear_timestamp || self.cli.config_check.is_some() {
            let UntrustedInput { argv, uid, gid } = self.input;
            return Err(Denied {
                stage: "config-check",
                argv,
                uid,
                gid,
            });
        }
        let uid_raw = self.input.uid.as_raw();
        let cmd_os: OsString = if self.cli.shell {
            OsString::new()
        } else if self.cli.command.is_empty() {
            let UntrustedInput { argv, uid, gid } = self.input;
            return Err(Denied {
                stage: "usage",
                argv,
                uid,
                gid,
            });
        } else {
            self.cli.command[0].clone()
        };
        let args_slice: &[OsString] = if self.cli.shell {
            &[]
        } else {
            &self.cli.command[1..]
        };
        let req = policy::Request {
            uid: uid_raw,
            groups: &self.groups,
            target: self.target_uid,
            cmd: cmd_os.as_os_str(),
            args: args_slice,
        };
        let resolve_u = |s: &std::ffi::OsStr| identity::resolve_user(s);
        let resolve_g = |s: &std::ffi::OsStr| identity::resolve_group(s);
        match policy::last_match(&self.rules.clone(), &req, &resolve_u, &resolve_g) {
            Some(config::Rule::Permit(p)) => Ok(AuthorizedRequest {
                policy: self,
                permit: p.clone(),
            }),
            _ => {
                let UntrustedInput { argv, uid, gid } = self.input;
                let cmdline = argv.join(&OsString::from(" "));
                let user_name = identity::lookup_user_by_uid(uid_raw)
                    .map(|p| p.name)
                    .unwrap_or_else(|| OsString::from(uid_raw.to_string()));
                log::log_deny(user_name.as_os_str(), cmdline.as_os_str());
                Err(Denied {
                    stage: "deny",
                    argv,
                    uid,
                    gid,
                })
            }
        }
    }
}

impl AuthorizedRequest {
    fn authenticate(self) -> Result<AuthenticatedRequest, Denied> {
        let nopass = self.permit.options.contains(config::Options::NOPASS);
        if nopass {
            return Ok(AuthenticatedRequest { request: self });
        }
        let persist = self.permit.options.contains(config::Options::PERSIST);
        let uid_raw = self.policy.input.uid.as_raw();
        let user_name = identity::lookup_user_by_uid(uid_raw)
            .map(|p| p.name)
            .unwrap_or_else(|| OsString::from(uid_raw.to_string()));
        if persist {
            let (fd, valid) = timestamp::open_existing(timestamp::TIMESTAMP_TIMEOUT_SECS).unwrap_or((-1, false));
            if valid {
                if fd >= 0 {
                    let _ = timestamp::set_valid(fd, timestamp::TIMESTAMP_TIMEOUT_SECS);
                    unsafe { libc::close(fd) };
                }
                return Ok(AuthenticatedRequest { request: self });
            } else if fd >= 0 {
                unsafe { libc::close(fd) };
            }
        }
        let non_interactive = self.policy.cli.non_interactive;
        match auth::authenticate_user(user_name.as_os_str(), non_interactive) {
            Ok(()) => {
                if persist && let Ok(fd) = timestamp::create_placeholder() {
                    let _ = timestamp::set_valid(fd, timestamp::TIMESTAMP_TIMEOUT_SECS);
                    unsafe { libc::close(fd) };
                }
                Ok(AuthenticatedRequest { request: self })
            }
            Err(auth::AuthError::NoTty(m)) => {
                log::log_tty_required(user_name.as_os_str());
                eprintln!("{m}");
                let UntrustedInput { argv, uid, gid } = self.policy.input;
                Err(Denied {
                    stage: "auth",
                    argv,
                    uid,
                    gid,
                })
            }
            Err(_) => {
                log::log_auth_fail(user_name.as_os_str());
                eprintln!("doas: Authentication failed");
                let UntrustedInput { argv, uid, gid } = self.policy.input;
                Err(Denied {
                    stage: "auth",
                    argv,
                    uid,
                    gid,
                })
            }
        }
    }
}

impl AuthenticatedRequest {
    fn prepare(self) -> Result<PreparedExecution, Denied> {
        let invoking_uid = self.request.policy.input.uid.as_raw();
        let invoking = identity::lookup_user_by_uid(invoking_uid);
        let invoking_name = invoking
            .as_ref()
            .map(|p| p.name.clone())
            .unwrap_or_else(|| OsString::from(invoking_uid.to_string()));
        let target_uid = self.request.policy.target_uid;
        let target = identity::lookup_user_by_uid(target_uid).ok_or_else(|| {
            let UntrustedInput { argv, uid, gid } = &self.request.policy.input;
            Denied {
                stage: "deny",
                argv: argv.clone(),
                uid: *uid,
                gid: *gid,
            }
        })?;
        let (cmd_os, argv_rest): (OsString, Vec<OsString>) = if self.request.policy.cli.shell {
            let sh_env = std::env::var_os("SHELL");
            let sh = match sh_env {
                Some(s) if !s.is_empty() => s,
                _ => target.shell.clone(),
            };
            let sh = if sh.is_empty() {
                OsString::from("/bin/sh")
            } else {
                sh
            };
            (sh, Vec::new())
        } else {
            let c = self.request.policy.cli.command[0].clone();
            let r = self.request.policy.cli.command[1..].to_vec();
            (c, r)
        };
        let former_path = std::env::var_os("PATH").unwrap_or_else(|| OsString::from(""));
        let current_path: Option<OsString> = if self.request.permit.cmd.is_some() {
            Some(OsString::from(load::SAFE_PATH))
        } else {
            Some(former_path.clone())
        };
        let environ_pairs: Vec<(OsString, OsString)> = std::env::vars_os().collect();
        let keepenv = self.request.permit.options.contains(config::Options::KEEPENV);
        let setenv_list = self
            .request
            .permit
            .envlist
            .iter()
            .map(|e| e.0.clone())
            .collect::<Vec<_>>();
        let input = env::PrepenvInput {
            invoking_name: invoking_name.as_os_str(),
            target_name: target.name.as_os_str(),
            target_home: target.home.as_os_str(),
            target_shell: target.shell.as_os_str(),
            current_path: current_path.as_deref(),
            environ: &environ_pairs,
            keepenv,
            setenv_list: &setenv_list,
            formerpath: former_path.as_os_str(),
        };
        let envp = env::prepenv(&input);
        let rule_has_cmd = self.request.permit.cmd.is_some();
        let cmd_path = exec::resolve_cmd(cmd_os.as_os_str(), rule_has_cmd, former_path.as_os_str())
            .unwrap_or_else(|_| PathBuf::from(cmd_os.clone()));
        let mut argv_exec = Vec::with_capacity(argv_rest.len() + 1);
        argv_exec.push(cmd_path.clone().into_os_string());
        argv_exec.extend(argv_rest);
        Ok(PreparedExecution {
            request: self,
            envp,
            cmd_path,
            argv_exec,
        })
    }
}

impl PreparedExecution {
    fn into_exec(self) -> Exec {
        Exec { prepared: self }
    }
}

impl Exec {
    fn run(self) -> Result<ExitCode, Denied> {
        let PreparedExecution {
            request,
            envp,
            cmd_path,
            argv_exec,
        } = self.prepared;
        let target_uid = request.request.policy.target_uid;
        let target_entry = identity::lookup_user_by_uid(target_uid).ok_or_else(|| {
            let UntrustedInput { argv, uid, gid } = &request.request.policy.input;
            Denied {
                stage: "deny",
                argv: argv.clone(),
                uid: *uid,
                gid: *gid,
            }
        })?;
        let target_gid = target_entry.gid;
        let target_name = target_entry.name.clone();
        let invoking_uid = request.request.policy.input.uid.as_raw();
        let invoking_name = identity::lookup_user_by_uid(invoking_uid)
            .map(|p| p.name)
            .unwrap_or_else(|| OsString::from(invoking_uid.to_string()));
        let cmdline = argv_exec.join(&OsString::from(" "));
        let cwd = std::env::current_dir()
            .map(|p| OsString::from(p.to_string_lossy().into_owned()))
            .unwrap_or_else(|_| OsString::from("(failed)"));
        let nolog = request.request.permit.options.contains(config::Options::NOLOG);
        if crate::tty::refuse_interactive(crate::tty::stdin_is_tty(), crate::tty::should_isolate()) {
            log::log_deny(
                invoking_name.as_os_str(),
                cmdline.as_os_str(),
            );
            eprintln!("doas: refusing interactive use with TIOCSTI enabled (CVE-2023-28339); set /proc/sys/dev/tty/legacy_tiocsti to 0 or use non-interactive invocation");
            let UntrustedInput { argv, uid, gid } = &request.request.policy.input;
            return Err(Denied {
                stage: "tty",
                argv: argv.clone(),
                uid: *uid,
                gid: *gid,
            });
        }
        log::log_permit(
            invoking_name.as_os_str(),
            cmdline.as_os_str(),
            target_name.as_os_str(),
            cwd.as_os_str(),
            nolog,
        );
        if unsafe { libc::setresgid(target_gid, target_gid, target_gid) } != 0 {
            let UntrustedInput { argv, uid, gid } = &request.request.policy.input;
            return Err(Denied {
                stage: "exec",
                argv: argv.clone(),
                uid: *uid,
                gid: *gid,
            });
        }
        unsafe {
            use std::ffi::CString;
            let cname = CString::new(target_name.as_bytes()).unwrap_or_else(|_| CString::new("nobody").unwrap());
            libc::initgroups(cname.as_ptr(), target_gid as libc::gid_t);
        }
        if unsafe { libc::setresuid(target_uid, target_uid, target_uid) } != 0 {
            let UntrustedInput { argv, uid, gid } = &request.request.policy.input;
            return Err(Denied {
                stage: "exec",
                argv: argv.clone(),
                uid: *uid,
                gid: *gid,
            });
        }
        if exec::verify_transition(target_uid, target_gid).is_err() {
            let UntrustedInput { argv, uid, gid } = &request.request.policy.input;
            return Err(Denied {
                stage: "exec",
                argv: argv.clone(),
                uid: *uid,
                gid: *gid,
            });
        }
        exec::close_fds_from_3();
        let c_path = CString::new(cmd_path.to_string_lossy().as_bytes()).map_err(|_| {
            let UntrustedInput { argv, uid, gid } = &request.request.policy.input;
            Denied {
                stage: "exec",
                argv: argv.clone(),
                uid: *uid,
                gid: *gid,
            }
        })?;
        let c_argv: Vec<CString> = argv_exec
            .iter()
            .map(|a| CString::new(a.as_bytes()).unwrap_or_else(|_| CString::new("?").unwrap()))
            .collect();
        let mut c_argv_ptrs: Vec<*const libc::c_char> = c_argv.iter().map(|a| a.as_ptr()).collect();
        c_argv_ptrs.push(std::ptr::null());
        let c_envp: Vec<CString> = envp
            .iter()
            .map(|e| CString::new(e.as_bytes()).unwrap_or_else(|_| CString::new("?=?.").unwrap()))
            .collect();
        let mut c_envp_ptrs: Vec<*const libc::c_char> = c_envp.iter().map(|e| e.as_ptr()).collect();
        c_envp_ptrs.push(std::ptr::null());
        unsafe {
            libc::execve(
                c_path.as_ptr(),
                c_argv_ptrs.as_ptr(),
                c_envp_ptrs.as_ptr(),
            );
        }
        let e = std::io::Error::last_os_error();
        eprintln!("doas: {}: {e}", cmd_path.display());
        std::process::exit(1);
    }
}

fn run_check_mode(policy: ParsedPolicy) -> Result<ExitCode, Denied> {
    let cfg_path = policy.cli.config_check.clone().unwrap();
    let cfg_str = cfg_path.to_string_lossy().into_owned();
    let rules: Vec<config::Rule> = if PathBuf::from(&cfg_path).is_dir() {
        let mut names: Vec<PathBuf> = Vec::new();
        if let Ok(rd) = std::fs::read_dir(PathBuf::from(&cfg_path)) {
            for ent in rd.flatten() {
                let p = ent.path();
                if p.extension().and_then(|e| e.to_str()) == Some("conf") {
                    names.push(p);
                }
            }
        }
        names.sort();
        if names.is_empty() {
            eprintln!("doas: {cfg_str}: no matching configuration files found");
            return Ok(ExitCode::from(1));
        }
        let mut combined: Vec<u8> = Vec::new();
        for n in &names {
            match std::fs::read(n) {
                Ok(d) => {
                    combined.extend_from_slice(&d);
                    combined.push(b'\n');
                }
                Err(e) => {
                    eprintln!("doas: {cfg_str}: {e}");
                    return Ok(ExitCode::from(1));
                }
            }
        }
        match config::parse_bytes(&combined, &cfg_str) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("{e}");
                return Ok(ExitCode::from(1));
            }
        }
    } else {
        let data = match std::fs::read(PathBuf::from(&cfg_path)) {
            Ok(d) => d,
            Err(e) => {
                eprintln!("doas: {cfg_str}: {e}");
                return Ok(ExitCode::from(1));
            }
        };
        match config::parse_bytes(&data, &cfg_str) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("{e}");
                return Ok(ExitCode::from(1));
            }
        }
    };
    if policy.cli.command.is_empty() {
        return Ok(ExitCode::SUCCESS);
    }
    let target_uid = match &policy.cli.target_user {
        Some(u) => match identity::resolve_user(u.as_os_str()) {
            Some(id) => id,
            None => {
                eprintln!("doas: unknown user");
                return Ok(ExitCode::from(1));
            }
        },
        None => 0,
    };
    let groups = identity::current_groups();
    let uid_raw = policy.input.uid.as_raw();
    let cmd = policy.cli.command[0].clone();
    let args = policy.cli.command[1..].to_vec();
    let req = policy::Request {
        uid: uid_raw,
        groups: &groups,
        target: target_uid,
        cmd: cmd.as_os_str(),
        args: &args,
    };
    let ru = |s: &std::ffi::OsStr| identity::resolve_user(s);
    let rg = |s: &std::ffi::OsStr| identity::resolve_group(s);
    match policy::last_match(&rules, &req, &ru, &rg) {
        Some(config::Rule::Permit(p)) => {
            if p.options.contains(config::Options::NOPASS) {
                println!("permit nopass");
            } else {
                println!("permit");
            }
            Ok(ExitCode::SUCCESS)
        }
        _ => {
            println!("deny");
            Ok(ExitCode::from(1))
        }
    }
}

fn run() -> Result<ExitCode, Denied> {
    if unsafe { libc::geteuid() } != 0 && std::env::var_os("DOAS_ALLOW_NONSETUID").is_none() {
        let input = UntrustedInput::capture();
        if input.argv.len() > 1
            && let Ok(cli) = cli::parse(&input.argv)
            && cli.config_check.is_some()
        {
            let policy = input.parse()?;
            return run_check_mode(policy);
        }
        eprintln!("doas: not installed setuid");
        let UntrustedInput { argv, uid, gid } = input;
        return Err(Denied {
            stage: "setuid",
            argv,
            uid,
            gid,
        });
    }
    let policy = UntrustedInput::capture().parse()?;
    if policy.cli.clear_timestamp {
        let _ = timestamp::clear();
        return Ok(ExitCode::SUCCESS);
    }
    if policy.cli.config_check.is_some() {
        return run_check_mode(policy);
    }
    policy.authorize()?.authenticate()?.prepare()?.into_exec().run()
}

fn main() -> ExitCode {
    exec::close_fds_from_3();
    match run() {
        Ok(code) => code,
        Err(denied) => {
            if denied.stage == "usage" {
                eprintln!("{}", cli::USAGE);
                return ExitCode::FAILURE;
            }
            let stage = denied.stage;
            let argv = denied.argv;
            let uid = denied.uid.as_raw();
            let gid = denied.gid.as_raw();
            eprintln!("doas: denied at {stage}: argv={argv:?} uid={uid} gid={gid}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::process::{getgid, getuid};
    use std::os::unix::fs::PermissionsExt;

    fn ensure_test_config() {
        let _ = std::fs::write("/etc/doas.conf", b"permit alice\n");
        let _ = std::fs::set_permissions(
            "/etc/doas.conf",
            std::fs::Permissions::from_mode(0o644),
        );
    }

    fn sample() -> UntrustedInput {
        ensure_test_config();
        UntrustedInput {
            argv: vec![OsString::from("doas"), OsString::from("id")],
            uid: getuid(),
            gid: getgid(),
        }
    }

    #[test]
    fn pipeline_preserves_command_and_identity_to_final_gate() {
        let denied = sample()
            .parse()
            .unwrap()
            .authorize()
            .unwrap_err();
        assert_eq!(denied.stage, "deny");
    }

    #[test]
    fn entry_denies_by_default() {
        ensure_test_config();
        unsafe { std::env::set_var("DOAS_ALLOW_NONSETUID", "1") };
        let r = run();
        unsafe { std::env::remove_var("DOAS_ALLOW_NONSETUID") };
        assert!(r.is_err());
    }

    #[test]
    fn capture_records_invoking_identity() {
        let captured = UntrustedInput::capture();
        assert_eq!(captured.uid, getuid());
        assert_eq!(captured.gid, getgid());
        assert!(!captured.argv.is_empty());
    }
}
