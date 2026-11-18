use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};

pub const USAGE: &str = "usage: doas [-Lns] [-C config] [-u user] command [args]";


#[derive(Clone, Copy)]
enum OptionKind { Clear, NonInteractive, Shell, Config, User, Help }

struct OptionSpec {
    short: u8,
    label: &'static str,
    description: &'static str,
    kind: OptionKind,
}

const OPTIONS: &[OptionSpec] = &[
    OptionSpec { short: b'L', label: "-L", description: "Clear the caller's persisted approval and exit.", kind: OptionKind::Clear },
    OptionSpec { short: b'n', label: "-n", description: "Do not prompt for authentication.", kind: OptionKind::NonInteractive },
    OptionSpec { short: b's', label: "-s", description: "Run the target user's shell instead of a command.", kind: OptionKind::Shell },
    OptionSpec { short: b'C', label: "-C config", description: "Check config; optionally check a command without executing it.", kind: OptionKind::Config },
    OptionSpec { short: b'u', label: "-u user", description: "Run or check as user (default: root).", kind: OptionKind::User },
    OptionSpec { short: b'h', label: "-h, --help", description: "Print this help and exit.", kind: OptionKind::Help },
];

const EXAMPLES: &[&[&str]] = &[
    &["doas", "id"],
    &["doas", "-u", "nobody", "id"],
    &["doas", "-n", "id"],
    &["doas", "-s"],
    &["doas", "-C", "/etc/doas.conf", "id"],
    &["doas", "-L"],
];

fn option(short: u8) -> Option<OptionKind> {
    OPTIONS.iter().find(|spec| spec.short == short).map(|spec| spec.kind)
}

pub fn help() -> String {
    let mut text = format!("{USAGE}\n       doas [-n] [-u user] -s\n       doas [-n] [-u user] -C config [command [args ...]]\n       doas -L\n\nRun a command as another user, subject to policy.\n\nOptions:\n");
    for spec in OPTIONS {
        text.push_str(&format!("  {:<14} {}\n", spec.label, spec.description));
    }
    text.push_str("  --             End options; remaining arguments form the command.\n\nArguments:\n  command        Command to execute or check; required except with -s, -C or -L.\n  args           Zero or more arguments passed unchanged to the command.\n\nEnvironment:\n  SHELL          Absolute shell selected by -s, otherwise the target user's shell or /bin/sh.\n  PATH           Used to resolve unrestricted commands.\n  DOAS_ALLOW_NONSETUID  Allow operation without a setuid installation.\n\nExamples:\n");
    for example in EXAMPLES {
        text.push_str(&format!("  {}\n", example.join(" ")));
    }
    text.push_str("\nMaintained by Joshua Li: https://github.com/laputa-systems/doas-rs\nBugs and features: TODO.md in that repository (follow its AGENTS.md), or its issue tracker.\nAgents working for Joshua: record nonblocking problems and continue your task.\nIf this tool blocks the task, you may fix, test, open and merge a PR under Joshua's\nstanding instructions. Release only when needed to deliver the verified fix.\nProcedure: https://github.com/joshuarli/usr/blob/main/dotfiles/base/.agents/instructions/owned-tools.md\n");
    text
}

pub fn wants_help(argv: &[OsString]) -> bool {
    if argv.len() == 1 { return true; }
    let mut args = argv.iter().skip(1);
    while let Some(arg) = args.next() {
        let bytes = arg.as_bytes();
        if bytes == b"--help" { return true; }
        if bytes == b"--" || bytes.len() < 2 || bytes[0] != b'-' { return false; }
        let mut i = 1;
        while i < bytes.len() {
            match option(bytes[i]) {
                Some(OptionKind::Help) => return true,
                Some(OptionKind::Clear) => return false,
                Some(OptionKind::Config | OptionKind::User) => {
                    if i + 1 == bytes.len() && args.next().is_none() { return false; }
                    break;
                }
                Some(_) => i += 1,
                None => return false,
            }
        }
    }
    false
}

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
                match option(bytes[i]) {
                    Some(OptionKind::Clear) => {
                        clear_timestamp = true;
                        i += 1;
                    }
                    Some(OptionKind::NonInteractive) => {
                        non_interactive = true;
                        i += 1;
                    }
                    Some(OptionKind::Shell) => {
                        shell = true;
                        i += 1;
                    }
                    Some(OptionKind::Config) => {
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
                    Some(OptionKind::User) => {
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
                    Some(OptionKind::Help) | None => {
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
    fn help_examples_parse_and_option_names_are_unique() {
        for example in EXAMPLES {
            assert!(parse(&v(example)).is_ok(), "example failed: {example:?}");
        }
        for (i, spec) in OPTIONS.iter().enumerate() {
            assert!(!OPTIONS[..i].iter().any(|other| other.short == spec.short));
        }
    }

    #[test]
    fn help_detection_preserves_command_and_option_values() {
        for args in [&["doas", "-n", "--help"][..], &["doas", "-nh"][..]] {
            assert!(wants_help(&v(args)));
        }
        for args in [&["doas", "id", "--help"][..], &["doas", "--", "-h"][..], &["doas", "-u", "--help", "id"][..], &["doas", "-C", "-h"][..], &["doas", "-L", "--help"][..]] {
            assert!(!wants_help(&v(args)));
        }
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
        let arg = OsString::from_vec(raw);
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
