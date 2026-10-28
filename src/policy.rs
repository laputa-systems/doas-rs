use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::OsStrExt;

use crate::config::{DenyRule, PermitRule, Rule};

pub struct Request<'a> {
    pub uid: u32,
    pub groups: &'a [u32],
    pub target: u32,
    pub cmd: &'a OsStr,
    pub args: &'a [OsString],
}

pub fn match_ident(
    ident: &OsStr,
    uid: u32,
    groups: &[u32],
    resolve_user: &dyn Fn(&OsStr) -> Option<u32>,
    resolve_group: &dyn Fn(&OsStr) -> Option<u32>,
) -> bool {
    let b = ident.as_bytes();
    if let Some(rest) = b.strip_prefix(b":") {
        if rest.is_empty() {
            return false;
        }
        let name = OsStr::from_bytes(rest);
        let Some(gid) = resolve_group(name) else {
            return false;
        };
        return groups.contains(&gid);
    }
    let Some(want) = resolve_user(ident) else {
        return false;
    };
    want == uid
}

pub fn match_target(
    target: Option<&OsStr>,
    want_target: u32,
    resolve_user: &dyn Fn(&OsStr) -> Option<u32>,
) -> bool {
    match target {
        None => true,
        Some(t) => match resolve_user(t) {
            Some(uid) => uid == want_target,
            None => false,
        },
    }
}

pub fn match_cmd(cmd_rule: Option<&OsStr>, cmd: &OsStr) -> bool {
    match cmd_rule {
        None => true,
        Some(want) => want.as_bytes() == cmd.as_bytes(),
    }
}

pub fn match_args(rule_args: Option<&[OsString]>, args: &[OsString]) -> bool {
    match rule_args {
        None => true,
        Some(want) => {
            if want.len() != args.len() {
                return false;
            }
            for (a, b) in want.iter().zip(args.iter()) {
                if a.as_bytes() != b.as_bytes() {
                    return false;
                }
            }
            true
        }
    }
}

fn rule_matches(
    rule: &Rule,
    req: &Request<'_>,
    resolve_user: &dyn Fn(&OsStr) -> Option<u32>,
    resolve_group: &dyn Fn(&OsStr) -> Option<u32>,
) -> bool {
    let (ident, target, cmd, cmdargs) = match rule {
        Rule::Permit(p) => (
            p.ident.as_os_str(),
            p.target.as_deref(),
            p.cmd.as_deref(),
            p.cmdargs.as_deref(),
        ),
        Rule::Deny(d) => (
            d.ident.as_os_str(),
            d.target.as_deref(),
            d.cmd.as_deref(),
            d.cmdargs.as_deref(),
        ),
    };
    if !match_ident(ident, req.uid, req.groups, resolve_user, resolve_group) {
        return false;
    }
    if !match_target(target, req.target, resolve_user) {
        return false;
    }
    if !match_cmd(cmd, req.cmd) {
        return false;
    }
    if !match_args(cmdargs, req.args) {
        return false;
    }
    true
}

pub fn last_match<'a>(
    rules: &'a [Rule],
    req: &Request<'_>,
    resolve_user: &dyn Fn(&OsStr) -> Option<u32>,
    resolve_group: &dyn Fn(&OsStr) -> Option<u32>,
) -> Option<&'a Rule> {
    let mut last: Option<&'a Rule> = None;
    for r in rules {
        if rule_matches(r, req, resolve_user, resolve_group) {
            last = Some(r);
        }
    }
    last
}

#[allow(dead_code)]
pub fn is_permitted(
    rules: &[Rule],
    req: &Request<'_>,
    resolve_user: &dyn Fn(&OsStr) -> Option<u32>,
    resolve_group: &dyn Fn(&OsStr) -> Option<u32>,
) -> bool {
    matches!(last_match(rules, req, resolve_user, resolve_group), Some(Rule::Permit(_)))
}

#[allow(dead_code)]
pub fn matched_permit<'a>(
    rules: &'a [Rule],
    req: &Request<'_>,
    resolve_user: &dyn Fn(&OsStr) -> Option<u32>,
    resolve_group: &dyn Fn(&OsStr) -> Option<u32>,
) -> Option<&'a PermitRule> {
    match last_match(rules, req, resolve_user, resolve_group) {
        Some(Rule::Permit(p)) => Some(p),
        _ => None,
    }
}

#[allow(dead_code)]
pub fn matched_deny<'a>(
    rules: &'a [Rule],
    req: &Request<'_>,
    resolve_user: &dyn Fn(&OsStr) -> Option<u32>,
    resolve_group: &dyn Fn(&OsStr) -> Option<u32>,
) -> Option<&'a DenyRule> {
    match last_match(rules, req, resolve_user, resolve_group) {
        Some(Rule::Deny(d)) => Some(d),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::parse_str;

    fn test_users(name: &OsStr) -> Option<u32> {
        if let b"alice" = name.as_bytes() {
            return Some(1000);
        }
        if let b"bob" = name.as_bytes() {
            return Some(1001);
        }
        if let b"root" = name.as_bytes() {
            return Some(0);
        }
        if let Ok(s) = std::str::from_utf8(name.as_bytes())
            && let Ok(n) = s.parse::<u32>()
            && n <= 65534
        {
            return Some(n);
        }
        None
    }

    fn test_groups(name: &OsStr) -> Option<u32> {
        if let b"wheel" = name.as_bytes() {
            return Some(10);
        }
        if let b"staff" = name.as_bytes() {
            return Some(20);
        }
        if let Ok(s) = std::str::from_utf8(name.as_bytes())
            && let Ok(n) = s.parse::<u32>()
            && n <= 65534
        {
            return Some(n);
        }
        None
    }

    fn os(s: &str) -> OsString {
        OsString::from(s)
    }

    #[test]
    fn deny_by_default_with_no_rules() {
        let rules: Vec<Rule> = vec![];
        let groups = [1000];
        let cmd = os("id");
        let args: Vec<OsString> = vec![];
        let r = Request { uid: 1000, groups: &groups, target: 0, cmd: cmd.as_os_str(), args: &args };
        assert!(!is_permitted(&rules, &r, &test_users, &test_groups));
        assert!(last_match(&rules, &r, &test_users, &test_groups).is_none());
    }

    #[test]
    fn last_match_wins_permit_then_deny() {
        let rules = parse_str("permit alice\ndeny alice\n", "t").unwrap();
        let groups = [1000];
        let cmd = os("id");
        let args: Vec<OsString> = vec![];
        let r = Request { uid: 1000, groups: &groups, target: 0, cmd: cmd.as_os_str(), args: &args };
        assert!(!is_permitted(&rules, &r, &test_users, &test_groups));
    }

    #[test]
    fn last_match_wins_deny_then_permit() {
        let rules = parse_str("deny alice\npermit alice\n", "t").unwrap();
        let groups = [1000];
        let cmd = os("id");
        let args: Vec<OsString> = vec![];
        let r = Request { uid: 1000, groups: &groups, target: 0, cmd: cmd.as_os_str(), args: &args };
        assert!(is_permitted(&rules, &r, &test_users, &test_groups));
    }

    #[test]
    fn specific_after_general_wins() {
        let rules = parse_str(
            "permit alice cmd /bin/ls\npermit alice cmd /bin/ls args -l\n",
            "t",
        )
        .unwrap();
        let groups = [1000];
        let cmd = os("/bin/ls");
        let args = vec![os("-l")];
        let no_args: Vec<OsString> = vec![];
        let r = Request { uid: 1000, groups: &groups, target: 0, cmd: cmd.as_os_str(), args: &args };
        assert!(is_permitted(&rules, &r, &test_users, &test_groups));
        let r2 = Request { uid: 1000, groups: &groups, target: 0, cmd: cmd.as_os_str(), args: &no_args };
        assert!(is_permitted(&rules, &r2, &test_users, &test_groups));
    }

    #[test]
    fn general_after_specific_overrides() {
        let rules = parse_str(
            "permit alice cmd /bin/ls args -l\ndeny alice cmd /bin/ls\n",
            "t",
        )
        .unwrap();
        let groups = [1000];
        let cmd = os("/bin/ls");
        let args = vec![os("-l")];
        let r = Request { uid: 1000, groups: &groups, target: 0, cmd: cmd.as_os_str(), args: &args };
        assert!(!is_permitted(&rules, &r, &test_users, &test_groups));
    }

    #[test]
    fn group_match_requires_membership() {
        let rules = parse_str("permit :wheel\n", "t").unwrap();
        let wheel = [1000, 10];
        let other = [1001, 20];
        let cmd = os("id");
        let args: Vec<OsString> = vec![];
        let r1 = Request { uid: 1000, groups: &wheel, target: 0, cmd: cmd.as_os_str(), args: &args };
        let r2 = Request { uid: 1001, groups: &other, target: 0, cmd: cmd.as_os_str(), args: &args };
        assert!(is_permitted(&rules, &r1, &test_users, &test_groups));
        assert!(!is_permitted(&rules, &r2, &test_users, &test_groups));
    }

    #[test]
    fn target_must_match() {
        let rules = parse_str("permit alice as root\n", "t").unwrap();
        let groups = [1000];
        let cmd = os("id");
        let args: Vec<OsString> = vec![];
        let r_ok = Request { uid: 1000, groups: &groups, target: 0, cmd: cmd.as_os_str(), args: &args };
        let r_bad = Request { uid: 1000, groups: &groups, target: 1001, cmd: cmd.as_os_str(), args: &args };
        assert!(is_permitted(&rules, &r_ok, &test_users, &test_groups));
        assert!(!is_permitted(&rules, &r_bad, &test_users, &test_groups));
    }

    #[test]
    fn no_shell_or_wildcard_expansion() {
        let rules = parse_str("permit alice cmd /bin/ls*\n", "t").unwrap();
        let groups = [1000];
        let star = os("/bin/ls*");
        let plain = os("/bin/ls");
        let args: Vec<OsString> = vec![];
        let r_star = Request { uid: 1000, groups: &groups, target: 0, cmd: star.as_os_str(), args: &args };
        let r_plain = Request { uid: 1000, groups: &groups, target: 0, cmd: plain.as_os_str(), args: &args };
        assert!(is_permitted(&rules, &r_star, &test_users, &test_groups));
        assert!(!is_permitted(&rules, &r_plain, &test_users, &test_groups));
        let rules2 = parse_str("permit alice cmd /bin/ls args\n", "t").unwrap();
        let extra = vec![os("*")];
        let r_extra = Request { uid: 1000, groups: &groups, target: 0, cmd: plain.as_os_str(), args: &extra };
        assert!(!is_permitted(&rules2, &r_extra, &test_users, &test_groups));
        let rules3 = parse_str("permit alice cmd /bin/ls\n", "t").unwrap();
        let r_any = Request { uid: 1000, groups: &groups, target: 0, cmd: plain.as_os_str(), args: &extra };
        assert!(is_permitted(&rules3, &r_any, &test_users, &test_groups));
    }

    #[test]
    fn args_exact_match_only() {
        let rules = parse_str("permit alice cmd /bin/echo args hello world\n", "t").unwrap();
        let groups = [1000];
        let cmd = os("/bin/echo");
        let good = vec![os("hello"), os("world")];
        let missing = vec![os("hello")];
        let extra = vec![os("hello"), os("world"), os("!")];
        let wrong = vec![os("hello"), os("WORLD")];
        let r_good = Request { uid: 1000, groups: &groups, target: 0, cmd: cmd.as_os_str(), args: &good };
        let r_missing = Request { uid: 1000, groups: &groups, target: 0, cmd: cmd.as_os_str(), args: &missing };
        let r_extra = Request { uid: 1000, groups: &groups, target: 0, cmd: cmd.as_os_str(), args: &extra };
        let r_wrong = Request { uid: 1000, groups: &groups, target: 0, cmd: cmd.as_os_str(), args: &wrong };
        assert!(is_permitted(&rules, &r_good, &test_users, &test_groups));
        assert!(!is_permitted(&rules, &r_missing, &test_users, &test_groups));
        assert!(!is_permitted(&rules, &r_extra, &test_users, &test_groups));
        assert!(!is_permitted(&rules, &r_wrong, &test_users, &test_groups));
    }

    #[test]
    fn args_empty_means_no_args() {
        let rules = parse_str("permit alice cmd /bin/ls args\n", "t").unwrap();
        let groups = [1000];
        let cmd = os("/bin/ls");
        let empty: Vec<OsString> = vec![];
        let one = vec![os("-l")];
        let r_empty = Request { uid: 1000, groups: &groups, target: 0, cmd: cmd.as_os_str(), args: &empty };
        let r_one = Request { uid: 1000, groups: &groups, target: 0, cmd: cmd.as_os_str(), args: &one };
        assert!(is_permitted(&rules, &r_empty, &test_users, &test_groups));
        assert!(!is_permitted(&rules, &r_one, &test_users, &test_groups));
    }

    #[test]
    fn args_absent_means_any_args() {
        let rules = parse_str("permit alice cmd /bin/ls\n", "t").unwrap();
        let groups = [1000];
        let cmd = os("/bin/ls");
        let empty: Vec<OsString> = vec![];
        let one = vec![os("-l")];
        let r_empty = Request { uid: 1000, groups: &groups, target: 0, cmd: cmd.as_os_str(), args: &empty };
        let r_one = Request { uid: 1000, groups: &groups, target: 0, cmd: cmd.as_os_str(), args: &one };
        assert!(is_permitted(&rules, &r_empty, &test_users, &test_groups));
        assert!(is_permitted(&rules, &r_one, &test_users, &test_groups));
    }

    #[test]
    fn unknown_user_never_matches() {
        let rules = parse_str("permit nobody\n", "t").unwrap();
        let groups = [1000];
        let cmd = os("id");
        let args: Vec<OsString> = vec![];
        let r = Request { uid: 1000, groups: &groups, target: 0, cmd: cmd.as_os_str(), args: &args };
        assert!(!is_permitted(&rules, &r, &test_users, &test_groups));
    }

    #[test]
    fn numeric_overflow_never_matches() {
        let rules = parse_str("permit 99999999999999999999\n", "t").unwrap();
        let groups = [1000];
        let cmd = os("id");
        let args: Vec<OsString> = vec![];
        let r = Request { uid: 1000, groups: &groups, target: 0, cmd: cmd.as_os_str(), args: &args };
        assert!(!is_permitted(&rules, &r, &test_users, &test_groups));
        let rules2 = parse_str("permit 65535\n", "t").unwrap();
        let groups2 = [65535];
        let r2 = Request { uid: 65535, groups: &groups2, target: 0, cmd: cmd.as_os_str(), args: &args };
        assert!(!is_permitted(&rules2, &r2, &test_users, &test_groups));
    }

    #[test]
    fn rule_order_confusion_vectors() {
        let rules = parse_str(
            "permit :wheel cmd /bin/ls\ndeny alice cmd /bin/ls args secret\npermit alice cmd /bin/ls args public\n",
            "t",
        )
        .unwrap();
        let groups = [1000, 10];
        let cmd = os("/bin/ls");
        let secret = vec![os("secret")];
        let public = vec![os("public")];
        let other = vec![os("other")];
        let r_secret = Request { uid: 1000, groups: &groups, target: 0, cmd: cmd.as_os_str(), args: &secret };
        let r_public = Request { uid: 1000, groups: &groups, target: 0, cmd: cmd.as_os_str(), args: &public };
        let r_other = Request { uid: 1000, groups: &groups, target: 0, cmd: cmd.as_os_str(), args: &other };
        assert!(!is_permitted(&rules, &r_secret, &test_users, &test_groups));
        assert!(is_permitted(&rules, &r_public, &test_users, &test_groups));
        assert!(is_permitted(&rules, &r_other, &test_users, &test_groups));
        let rules2 = parse_str(
            "permit :wheel cmd /bin/ls\ndeny alice cmd /bin/ls args secret\ndeny alice cmd /bin/ls args other\npermit alice cmd /bin/ls args public\n",
            "t",
        )
        .unwrap();
        let r_other2 = Request { uid: 1000, groups: &groups, target: 0, cmd: cmd.as_os_str(), args: &other };
        assert!(!is_permitted(&rules2, &r_other2, &test_users, &test_groups));
    }
}
