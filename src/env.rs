use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::os::unix::ffi::{OsStrExt, OsStringExt};

pub const MAX_NAME_LEN: usize = 1023;

fn valid_name(bytes: &[u8]) -> bool {
    !bytes.is_empty() && bytes.len() <= MAX_NAME_LEN && !bytes.contains(&0)
}

fn lookup(environ: &[(OsString, OsString)], key: &[u8]) -> Option<OsString> {
    for (k, v) in environ {
        if k.as_bytes() == key {
            return Some(v.clone());
        }
    }
    None
}

pub fn build_base(
    invoking_name: &OsStr,
    target_name: &OsStr,
    target_home: &OsStr,
    target_shell: &OsStr,
    current_path: Option<&OsStr>,
    environ: &[(OsString, OsString)],
) -> BTreeMap<OsString, OsString> {
    let mut map = BTreeMap::new();
    map.insert(
        OsString::from("DOAS_USER"),
        invoking_name.to_os_string(),
    );
    map.insert(OsString::from("HOME"), target_home.to_os_string());
    map.insert(
        OsString::from("LOGNAME"),
        target_name.to_os_string(),
    );
    if let Some(p) = current_path {
        map.insert(OsString::from("PATH"), p.to_os_string());
    }
    map.insert(OsString::from("SHELL"), target_shell.to_os_string());
    map.insert(OsString::from("USER"), target_name.to_os_string());
    for key in ["DISPLAY", "TERM"] {
        if let Some(v) = lookup(environ, key.as_bytes()) {
            map.insert(OsString::from(key), v);
        }
    }
    map
}

pub fn apply_keepenv(
    map: &mut BTreeMap<OsString, OsString>,
    environ: &[(OsString, OsString)],
) {
    for (k, v) in environ {
        let kb = k.as_bytes();
        if !valid_name(kb) {
            continue;
        }
        if kb.contains(&b'=') {
            continue;
        }
        map.entry(k.clone()).or_insert_with(|| v.clone());
    }
}

pub fn apply_setenv(
    map: &mut BTreeMap<OsString, OsString>,
    setenv_list: &[OsString],
    formerpath: &OsStr,
    environ: &[(OsString, OsString)],
) {
    for e in setenv_list {
        let eb = e.as_bytes();
        if eb.contains(&0) {
            continue;
        }
        let eq = eb.iter().position(|&b| b == b'=');
        let (name_part, has_eq, val_part) = match eq {
            Some(idx) => (&eb[..idx], true, &eb[idx + 1..]),
            None => (eb, false, &[][..]),
        };
        if name_part.len() > MAX_NAME_LEN {
            continue;
        }
        if name_part.starts_with(b"-") {
            let key_bytes = &name_part[1..];
            if valid_name(key_bytes) {
                map.remove(&OsString::from_vec(key_bytes.to_vec()));
            }
            continue;
        }
        if !valid_name(name_part) {
            continue;
        }
        let key = OsString::from_vec(name_part.to_vec());
        map.remove(&key);
        let val: Option<OsString> = if has_eq {
            if val_part.starts_with(b"$") {
                let ref_name = &val_part[1..];
                if ref_name == b"PATH" {
                    Some(formerpath.to_os_string())
                } else if ref_name.is_empty() || ref_name.contains(&0) {
                    None
                } else {
                    lookup(environ, ref_name)
                }
            } else {
                if val_part.contains(&0) {
                    None
                } else {
                    Some(OsString::from_vec(val_part.to_vec()))
                }
            }
        } else if name_part == b"PATH" {
            Some(formerpath.to_os_string())
        } else {
            lookup(environ, name_part)
        };
        if let Some(v) = val {
            if v.as_bytes().contains(&0) {
                continue;
            }
            map.insert(key, v);
        }
    }
}

pub fn flatten(map: &BTreeMap<OsString, OsString>) -> Vec<OsString> {
    let mut out = Vec::with_capacity(map.len() + 1);
    for (k, v) in map {
        let mut b = k.as_bytes().to_vec();
        b.push(b'=');
        b.extend_from_slice(v.as_bytes());
        out.push(OsString::from_vec(b));
    }
    out
}

pub struct PrepenvInput<'a> {
    pub invoking_name: &'a OsStr,
    pub target_name: &'a OsStr,
    pub target_home: &'a OsStr,
    pub target_shell: &'a OsStr,
    pub current_path: Option<&'a OsStr>,
    pub environ: &'a [(OsString, OsString)],
    pub keepenv: bool,
    pub setenv_list: &'a [OsString],
    pub formerpath: &'a OsStr,
}

pub fn prepenv(input: &PrepenvInput<'_>) -> Vec<OsString> {
    let mut map = build_base(
        input.invoking_name,
        input.target_name,
        input.target_home,
        input.target_shell,
        input.current_path,
        input.environ,
    );
    if input.keepenv {
        apply_keepenv(&mut map, input.environ);
    }
    if !input.setenv_list.is_empty() {
        apply_setenv(&mut map, input.setenv_list, input.formerpath, input.environ);
    }
    flatten(&map)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(s: &str) -> OsString {
        OsString::from(s)
    }

    fn environ_pairs(items: &[(&str, &str)]) -> Vec<(OsString, OsString)> {
        items.iter().map(|(k, v)| (os(k), os(v))).collect()
    }

    fn get(map: &BTreeMap<OsString, OsString>, k: &str) -> Option<String> {
        map.get(&os(k)).map(|v| v.to_string_lossy().into_owned())
    }

    #[test]
    fn clean_by_default_drops_attacker_vars() {
        let env = environ_pairs(&[
            ("LD_PRELOAD", "/tmp/evil.so"),
            ("IFS", "x"),
            ("ENV", "/tmp/x"),
            ("BASH_ENV", "/tmp/y"),
            ("DISPLAY", ":0"),
            ("TERM", "xterm"),
            ("MYVAR", "1"),
        ]);
        let map = build_base(
            os("alice").as_os_str(),
            os("root").as_os_str(),
            os("/root").as_os_str(),
            os("/bin/sh").as_os_str(),
            Some(os("safe").as_os_str()),
            &env,
        );
        assert_eq!(get(&map, "DOAS_USER"), Some("alice".to_string()));
        assert_eq!(get(&map, "HOME"), Some("/root".to_string()));
        assert_eq!(get(&map, "USER"), Some("root".to_string()));
        assert_eq!(get(&map, "DISPLAY"), Some(":0".to_string()));
        assert!(!map.contains_key(&os("LD_PRELOAD")));
        assert!(!map.contains_key(&os("MYVAR")));
        assert!(!map.contains_key(&os("IFS")));
    }

    #[test]
    fn keepenv_retains_all_valid_first_wins() {
        let env = environ_pairs(&[("A", "1"), ("B", "2")]);
        let mut dup = env.clone();
        dup.push((os("A"), os("dup")));
        dup.push((os(""), os("empty")));
        let mut map = build_base(
            os("a").as_os_str(),
            os("b").as_os_str(),
            os("/h").as_os_str(),
            os("/bin/sh").as_os_str(),
            Some(os("p").as_os_str()),
            &env,
        );
        apply_keepenv(&mut map, &dup);
        assert_eq!(get(&map, "A"), Some("1".to_string()));
        assert_eq!(get(&map, "B"), Some("2".to_string()));
    }

    #[test]
    fn keepenv_opt_in_keeps_dangerous() {
        let env = environ_pairs(&[("LD_PRELOAD", "/tmp/x")]);
        let mut map = build_base(
            os("a").as_os_str(),
            os("b").as_os_str(),
            os("/h").as_os_str(),
            os("/bin/sh").as_os_str(),
            Some(os("p").as_os_str()),
            &env,
        );
        apply_keepenv(&mut map, &env);
        assert_eq!(get(&map, "LD_PRELOAD"), Some("/tmp/x".to_string()));
    }

    #[test]
    fn setenv_set_and_remove() {
        let env = environ_pairs(&[("PS1", "orig"), ("SSH_AUTH_SOCK", "s")]);
        let mut map = build_base(
            os("a").as_os_str(),
            os("b").as_os_str(),
            os("/h").as_os_str(),
            os("/bin/sh").as_os_str(),
            Some(os("p").as_os_str()),
            &env,
        );
        let list = vec![os("-ENV"), os("PS1"), os("FOO=bar")];
        apply_setenv(&mut map, &list, os("former").as_os_str(), &env);
        assert!(!map.contains_key(&os("ENV")));
        assert_eq!(get(&map, "PS1"), Some("orig".to_string()));
        assert_eq!(get(&map, "FOO"), Some("bar".to_string()));
    }

    #[test]
    fn setenv_path_reference_uses_formerpath() {
        let env = environ_pairs(&[("PATH", "/attacker"), ("X", "1")]);
        let mut map = build_base(
            os("a").as_os_str(),
            os("b").as_os_str(),
            os("/h").as_os_str(),
            os("/bin/sh").as_os_str(),
            Some(os("safe").as_os_str()),
            &env,
        );
        let list = vec![os("PATH"), os("Y=$X"), os("Z=$PATH"), os("W=$MISSING")];
        apply_setenv(&mut map, &list, os("/former").as_os_str(), &env);
        assert_eq!(get(&map, "PATH"), Some("/former".to_string()));
        assert_eq!(get(&map, "Y"), Some("1".to_string()));
        assert_eq!(get(&map, "Z"), Some("/former".to_string()));
        assert!(!map.contains_key(&os("W")));
    }

    #[test]
    fn setenv_value_dollar_path() {
        let env = environ_pairs(&[("Q", "1")]);
        let mut map = build_base(
            os("a").as_os_str(),
            os("b").as_os_str(),
            os("/h").as_os_str(),
            os("/bin/sh").as_os_str(),
            Some(os("p").as_os_str()),
            &env,
        );
        apply_setenv(&mut map, &[os("R=$PATH")], os("/fp").as_os_str(), &env);
        assert_eq!(get(&map, "R"), Some("/fp".to_string()));
    }

    #[test]
    fn setenv_removal_with_value_ignored() {
        let env = environ_pairs(&[("A", "1")]);
        let mut map = build_base(
            os("a").as_os_str(),
            os("b").as_os_str(),
            os("/h").as_os_str(),
            os("/bin/sh").as_os_str(),
            Some(os("p").as_os_str()),
            &env,
        );
        map.insert(os("FOO"), os("x"));
        apply_setenv(&mut map, &[os("-FOO=bar")], os("f").as_os_str(), &env);
        assert!(!map.contains_key(&os("FOO")));
    }

    #[test]
    fn setenv_last_wins() {
        let env = environ_pairs(&[]);
        let mut map = build_base(
            os("a").as_os_str(),
            os("b").as_os_str(),
            os("/h").as_os_str(),
            os("/bin/sh").as_os_str(),
            Some(os("p").as_os_str()),
            &env,
        );
        apply_setenv(
            &mut map,
            &[os("A=1"), os("A=2")],
            os("f").as_os_str(),
            &env,
        );
        assert_eq!(get(&map, "A"), Some("2".to_string()));
    }

    #[test]
    fn dup_keys_in_environ_first_wins() {
        let env = vec![(os("D"), os("first")), (os("D"), os("second"))];
        let mut map = build_base(
            os("a").as_os_str(),
            os("b").as_os_str(),
            os("/h").as_os_str(),
            os("/bin/sh").as_os_str(),
            Some(os("p").as_os_str()),
            &[],
        );
        apply_keepenv(&mut map, &env);
        assert_eq!(get(&map, "D"), Some("first".to_string()));
    }

    #[test]
    fn bad_names_ignored() {
        let env = vec![
            (os(""), os("empty")),
            (os("A"), os("ok")),
        ];
        let mut map = build_base(
            os("a").as_os_str(),
            os("b").as_os_str(),
            os("/h").as_os_str(),
            os("/bin/sh").as_os_str(),
            Some(os("p").as_os_str()),
            &[],
        );
        apply_keepenv(&mut map, &env);
        assert!(!map.contains_key(&os("")));
        assert_eq!(get(&map, "A"), Some("ok".to_string()));
        let long = "x".repeat(2000);
        apply_setenv(
            &mut map,
            &[OsString::from(long)],
            os("f").as_os_str(),
            &[],
        );
        assert_eq!(map.len(), 7);
    }

    #[test]
    fn non_utf8_preserved() {
        use std::os::unix::ffi::OsStringExt;
        let k = OsString::from_vec(vec![0xff, 0x41]);
        let v = OsString::from_vec(vec![0xfe, 0x42]);
        let env = vec![(k.clone(), v.clone())];
        let mut map = build_base(
            os("a").as_os_str(),
            os("b").as_os_str(),
            os("/h").as_os_str(),
            os("/bin/sh").as_os_str(),
            Some(os("p").as_os_str()),
            &[],
        );
        apply_keepenv(&mut map, &env);
        assert_eq!(map.get(&k), Some(&v));
        let flat = flatten(&map);
        assert!(flat.iter().any(|e| e.as_bytes().starts_with(&[0xff, 0x41, b'='])));
    }

    #[test]
    fn flatten_format() {
        let mut map = BTreeMap::new();
        map.insert(os("A"), os("1"));
        let flat = flatten(&map);
        assert_eq!(flat, vec![os("A=1")]);
    }

    #[test]
    fn prepenv_end_to_end_matches_oracle_shape() {
        let env = environ_pairs(&[
            ("DISPLAY", ":0"),
            ("TERM", "xterm"),
            ("PS1", "p"),
            ("LD_PRELOAD", "evil"),
        ]);
        let alice = os("alice");
        let root = os("root");
        let root_home = os("/root");
        let sh = os("/bin/sh");
        let safe = os("/safe");
        let former = os("/former");
        let setenv = [os("PS1"), os("-LD_PRELOAD")];
        let input = PrepenvInput {
            invoking_name: alice.as_os_str(),
            target_name: root.as_os_str(),
            target_home: root_home.as_os_str(),
            target_shell: sh.as_os_str(),
            current_path: Some(safe.as_os_str()),
            environ: &env,
            keepenv: false,
            setenv_list: &setenv,
            formerpath: former.as_os_str(),
        };
        let out = prepenv(&input);
        let joined: Vec<String> = out.iter().map(|s| s.to_string_lossy().into_owned()).collect();
        assert!(joined.iter().any(|s| s == "DOAS_USER=alice"));
        assert!(joined.iter().any(|s| s == "PS1=p"));
        assert!(!joined.iter().any(|s| s.starts_with("LD_PRELOAD=")));
    }
}
