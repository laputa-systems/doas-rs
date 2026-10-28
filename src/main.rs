#[cfg(not(target_os = "linux"))]
compile_error!("doas-rs runs on Linux only");

use std::ffi::OsString;
use std::process::ExitCode;

use rustix::process::{Gid, Uid, getgid, getuid};

mod cli;

struct UntrustedInput {
    argv: Vec<OsString>,
    uid: Uid,
    gid: Gid,
}

struct ParsedPolicy {
    input: UntrustedInput,
    cli: cli::Cli,
}

struct AuthorizedRequest {
    policy: ParsedPolicy,
}

struct AuthenticatedRequest {
    request: AuthorizedRequest,
}

struct PreparedExecution {
    request: AuthenticatedRequest,
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
        debug_assert_eq!(uid, getuid());
        debug_assert_eq!(gid, getgid());
        Self {
            argv: std::env::args_os().collect(),
            uid,
            gid,
        }
    }

    fn parse(self) -> Result<ParsedPolicy, Denied> {
        let UntrustedInput { argv, uid, gid } = self;
        match cli::parse(&argv) {
            Ok(cli) => Ok(ParsedPolicy {
                input: UntrustedInput {
                    argv,
                    uid,
                    gid,
                },
                cli,
            }),
            Err(_) => Err(Denied {
                stage: "usage",
                argv,
                uid,
                gid,
            }),
        }
    }
}

impl ParsedPolicy {
    fn authorize(self) -> Result<AuthorizedRequest, Denied> {
        if self.cli.config_check.is_some() {
            let UntrustedInput { argv, uid, gid } = self.input;
            return Err(Denied {
                stage: "config-check",
                argv,
                uid,
                gid,
            });
        }
        Ok(AuthorizedRequest { policy: self })
    }
}

impl AuthorizedRequest {
    fn authenticate(self) -> Result<AuthenticatedRequest, Denied> {
        Ok(AuthenticatedRequest { request: self })
    }
}

impl AuthenticatedRequest {
    fn prepare(self) -> Result<PreparedExecution, Denied> {
        Ok(PreparedExecution { request: self })
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
            request:
                AuthenticatedRequest {
                    request:
                        AuthorizedRequest {
                            policy:
                                ParsedPolicy {
                                    input: UntrustedInput { argv, uid, gid },
                                    ..
                                },
                        },
                },
        } = self.prepared;
        Err(Denied {
            stage: "exec",
            argv,
            uid,
            gid,
        })
    }
}

fn run() -> Result<ExitCode, Denied> {
    let policy = UntrustedInput::capture().parse()?;
    if policy.cli.clear_timestamp {
        return Ok(ExitCode::SUCCESS);
    }
    policy
        .authorize()?
        .authenticate()?
        .prepare()?
        .into_exec()
        .run()
}

fn main() -> ExitCode {
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

    fn sample() -> UntrustedInput {
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
            .unwrap()
            .authenticate()
            .unwrap()
            .prepare()
            .unwrap()
            .into_exec()
            .run()
            .unwrap_err();
        assert_eq!(denied.stage, "exec");
        assert_eq!(
            denied.argv,
            vec![OsString::from("doas"), OsString::from("id")]
        );
        assert_eq!(denied.uid, getuid());
        assert_eq!(denied.gid, getgid());
    }

    #[test]
    fn entry_denies_by_default() {
        assert!(run().is_err());
    }

    #[test]
    fn capture_records_invoking_identity() {
        let captured = UntrustedInput::capture();
        assert_eq!(captured.uid, getuid());
        assert_eq!(captured.gid, getgid());
        assert!(!captured.argv.is_empty());
    }
}
