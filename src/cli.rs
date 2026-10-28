use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};

pub const USAGE: &str = "usage: doas [-Lns] [-C config] [-u user] command [args]";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cli {
    pub target_user: Option<OsString>,
    pub non_interactive: bool,
    pub shell: bool,
    pub config_check: Option<OsString>,
    pub clear_timestamp: bool,
    pub command: Vec<OsString>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliError {
    pub message: String,
}

impl CliError {
    fn usage(msg: impl Into<String>) -> Self {
        Self {
            message: msg.into(),
        }
    }
}

impl std::fmt::Display for CliError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "doas: {}\n{}", self.message, USAGE)
    }
}

fn is_nul(bytes: &[u8]) -> bool {
    bytes.contains(&0)
}

pub fn parse(argv: &[OsString]) -> Result<Cli, CliError> {
    if argv.is_empty() {
        return Err(CliError::usage("executed without argv"));
    }
    let mut target_user: Option<OsString> = None;
    let mut non_interactive = false;
    let mut shell = false;
    let mut config_check: Option<OsString> = None;
    let mut clear_timestamp = false;
    let mut command: Vec<OsString> = Vec::new();
    let mut args = argv[1..].iter().peekable();
    let mut options_done = false;
    while let Some(arg) = args.next() {
        let bytes = arg.as_bytes();
        if options_done {
            command.push(arg.clone());
            continue;
        }
        if bytes == b"--" {
            options_done = true;
            continue;
        }
        if bytes.len() >= 2 && bytes[0] == b'-' && bytes != b"-" {
            let mut i = 1;
            while i < bytes.len() {
                match bytes[i] {
                    b'L' => {
                        clear_timestamp = true;
                        i += 1;
                    }
                    b'n' => {
                        non_interactive = true;
                        i += 1;
                    }
                    b's' => {
                        shell = true;
                        i += 1;
                    }
                    b'C' => {
                        let rest = &bytes[i + 1..];
                        let path = if rest.is_empty() {
                            match args.next() {
                                Some(v) => v.clone(),
                                None => {
                                    return Err(CliError::usage(
                                        "option requires an argument -- C",
                                    ));
                                }
                            }
                        } else {
                            OsString::from_vec(rest.to_vec())
                        };
                        if is_nul(path.as_bytes()) {
                            return Err(CliError::usage("invalid config path"));
                        }
                        if config_check.is_some() {
                            return Err(CliError::usage("repeated -C option"));
                        }
                        config_check = Some(path);
                        i = bytes.len();
                    }
                    b'u' => {
                        let rest = &bytes[i + 1..];
                        let user = if rest.is_empty() {
                            match args.next() {
                                Some(v) => v.clone(),
                                None => {
                                    return Err(CliError::usage(
                                        "option requires an argument -- u",
                                    ));
                                }
                            }
                        } else {
                            OsString::from_vec(rest.to_vec())
                        };
                        if user.is_empty() || is_nul(user.as_bytes()) {
                            return Err(CliError::usage("unknown user"));
                        }
                        if target_user.is_some() {
                            return Err(CliError::usage("repeated -u option"));
                        }
                        target_user = Some(user);
                        i = bytes.len();
                    }
                    _ => {
                        let bad = bytes[i] as char;
                        return Err(CliError::usage(format!(
                            "unknown option -- {bad}"
                        )));
                    }
                }
            }
            if clear_timestamp {
                return Ok(Cli {
                    target_user,
                    non_interactive,
                    shell,
                    config_check,
                    clear_timestamp: true,
                    command: Vec::new(),
                });
            }
            continue;
        } else {
            command.push(arg.clone());
            for rest in args.by_ref() {
                command.push(rest.clone());
            }
            break;
        }
    }
    if clear_timestamp {
        return Ok(Cli {
            target_user,
            non_interactive,
            shell,
            config_check,
            clear_timestamp: true,
            command: Vec::new(),
        });
    }
    if let Some(ref cfg) = config_check {
        if cfg.as_bytes().is_empty() {
            return Err(CliError::usage("invalid config path"));
        }
        if shell {
            return Err(CliError::usage("incompatible options"));
        }
        return Ok(Cli {
            target_user,
            non_interactive,
            shell: false,
            config_check,
            clear_timestamp: false,
            command,
        });
    }
    if shell {
        if !command.is_empty() {
            return Err(CliError::usage("incompatible options"));
        }
        return Ok(Cli {
            target_user,
            non_interactive,
            shell: true,
            config_check: None,
            clear_timestamp: false,
            command: Vec::new(),
        });
    }
    if command.is_empty() {
        return Err(CliError::usage("no command specified"));
    }
    for c in &command {
        if is_nul(c.as_bytes()) {
            return Err(CliError::usage("invalid argument"));
        }
    }
    if let Some(ref u) = target_user
        && (u.is_empty() || is_nul(u.as_bytes()))
    {
        return Err(CliError::usage("unknown user"));
    }
    Ok(Cli {
        target_user,
        non_interactive,
        shell: false,
        config_check: None,
        clear_timestamp: false,
        command,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(items: &[&str]) -> Vec<OsString> {
        items.iter().map(|s| OsString::from(*s)).collect()
    }

    #[test]
    fn empty_argv_fails() {
        assert!(parse(&[]).is_err());
    }

    #[test]
    fn bare_command_parses() {
        let c = parse(&v(&["doas", "id"])).unwrap();
        assert_eq!(c.command, v(&["id"]));
        assert!(!c.shell);
        assert!(!c.non_interactive);
        assert!(c.target_user.is_none());
    }

    #[test]
    fn command_args_preserved() {
        let c = parse(&v(&["doas", "echo", "a", "b"])).unwrap();
        assert_eq!(c.command, v(&["echo", "a", "b"]));
    }

    #[test]
    fn dash_u_with_separate_arg() {
        let c = parse(&v(&["doas", "-u", "root", "id"])).unwrap();
        assert_eq!(c.target_user, Some(OsString::from("root")));
        assert_eq!(c.command, v(&["id"]));
    }

    #[test]
    fn dash_u_with_attached_arg() {
        let c = parse(&v(&["doas", "-uroot", "id"])).unwrap();
        assert_eq!(c.target_user, Some(OsString::from("root")));
    }

    #[test]
    fn dash_n_flag() {
        let c = parse(&v(&["doas", "-n", "id"])).unwrap();
        assert!(c.non_interactive);
    }

    #[test]
    fn combined_flags() {
        let c = parse(&v(&["doas", "-ns",])).unwrap();
        assert!(c.non_interactive);
        assert!(c.shell);
    }

    #[test]
    fn shell_forbids_command() {
        assert!(parse(&v(&["doas", "-s", "id"])).is_err());
    }

    #[test]
    fn shell_alone_ok() {
        let c = parse(&v(&["doas", "-s"])).unwrap();
        assert!(c.shell);
        assert!(c.command.is_empty());
    }

    #[test]
    fn no_command_is_usage_error() {
        assert!(parse(&v(&["doas"])).is_err());
        assert!(parse(&v(&["doas", "-n"])).is_err());
        assert!(parse(&v(&["doas", "-u", "root"])).is_err());
    }

    #[test]
    fn config_check_without_command_ok() {
        let c = parse(&v(&["doas", "-C", "/etc/doas.conf"])).unwrap();
        assert_eq!(c.config_check, Some(OsString::from("/etc/doas.conf")));
        assert!(c.command.is_empty());
    }

    #[test]
    fn config_check_with_command_ok() {
        let c = parse(&v(&["doas", "-C", "/etc/doas.conf", "id"])).unwrap();
        assert_eq!(c.command, v(&["id"]));
    }

    #[test]
    fn config_check_attached_arg() {
        let c = parse(&v(&["doas", "-C/etc/doas.conf", "id"])).unwrap();
        assert_eq!(c.config_check, Some(OsString::from("/etc/doas.conf")));
    }

    #[test]
    fn config_check_forbids_shell() {
        assert!(parse(&v(&["doas", "-C", "f", "-s"])).is_err());
        assert!(parse(&v(&["doas", "-s", "-C", "f"])).is_err());
    }

    #[test]
    fn clear_timestamp_wins_immediately() {
        let c = parse(&v(&["doas", "-L"])).unwrap();
        assert!(c.clear_timestamp);
        let d = parse(&v(&["doas", "-L", "id"])).unwrap();
        assert!(d.clear_timestamp);
        assert!(d.command.is_empty());
    }

    #[test]
    fn unknown_option_rejected() {
        assert!(parse(&v(&["doas", "-a"])).is_err());
        assert!(parse(&v(&["doas", "-v"])).is_err());
        assert!(parse(&v(&["doas", "-Z"])).is_err());
    }

    #[test]
    fn missing_option_argument_rejected() {
        assert!(parse(&v(&["doas", "-u"])).is_err());
        assert!(parse(&v(&["doas", "-C"])).is_err());
    }

    #[test]
    fn repeated_u_rejected() {
        assert!(parse(&v(&["doas", "-u", "a", "-u", "b", "id"])).is_err());
    }

    #[test]
    fn double_dash_ends_options() {
        let c = parse(&v(&["doas", "--", "-u"])).unwrap();
        assert_eq!(c.command, v(&["-u"]));
    }

    #[test]
    fn single_dash_is_command() {
        let c = parse(&v(&["doas", "-"])).unwrap();
        assert_eq!(c.command, v(&["-"]));
    }

    #[test]
    fn posix_stop_at_first_non_option() {
        let c = parse(&v(&["doas", "echo", "-n"])).unwrap();
        assert_eq!(c.command, v(&["echo", "-n"]));
        assert!(!c.non_interactive);
    }

    #[test]
    fn non_utf8_command_preserved() {
        use std::os::unix::ffi::OsStringExt;
        let raw = vec![0xff, 0xfe, b'a'];
        let arg = OsString::from_vec(raw.clone());
        let argv = vec![OsString::from("doas"), arg.clone()];
        let c = parse(&argv).unwrap();
        assert_eq!(c.command, vec![arg]);
    }

    #[test]
    fn non_utf8_user_preserved() {
        use std::os::unix::ffi::OsStringExt;
        let raw = vec![b'r', 0xff, b't'];
        let user = OsString::from_vec(raw);
        let argv = vec![OsString::from("doas"), OsString::from("-u"), user.clone(), OsString::from("id")];
        let c = parse(&argv).unwrap();
        assert_eq!(c.target_user, Some(user));
    }

    #[test]
    fn nul_in_command_rejected() {
        use std::os::unix::ffi::OsStringExt;
        let bad = OsString::from_vec(vec![b'a', 0, b'b']);
        let argv = vec![OsString::from("doas"), bad];
        assert!(parse(&argv).is_err());
    }

    #[test]
    fn usage_message_format() {
        let e = parse(&v(&["doas"])).unwrap_err();
        let s = format!("{e}");
        assert!(s.contains("usage:"));
    }
}
