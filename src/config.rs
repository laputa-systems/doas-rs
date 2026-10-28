use std::ffi::OsString;
use std::os::unix::ffi::{OsStrExt, OsStringExt};

pub const MAX_TOKEN: usize = 1023;
pub const MAX_FILE_BYTES: usize = 1 << 20;
pub const MAX_RULES: usize = 4096;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError {
    pub file: String,
    pub line: usize,
    pub message: String,
}

impl ConfigError {
    fn new(file: &str, line: usize, message: impl Into<String>) -> Self {
        Self {
            file: file.to_string(),
            line,
            message: message.into(),
        }
    }
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "doas: {} at line {} in {}", self.message, self.line, self.file)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Options(pub u8);

impl Options {
    pub const NOPASS: u8 = 0x01;
    pub const PERSIST: u8 = 0x04;
    pub const NOLOG: u8 = 0x08;
    pub const KEEPENV: u8 = 0x02;

    pub fn empty() -> Self {
        Self(0)
    }

    pub fn contains(self, flag: u8) -> bool {
        self.0 & flag != 0
    }

    pub fn insert(&mut self, flag: u8) {
        self.0 |= flag;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnvEntry(pub OsString);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermitRule {
    pub options: Options,
    pub envlist: Vec<EnvEntry>,
    pub has_setenv: bool,
    pub ident: OsString,
    pub target: Option<OsString>,
    pub cmd: Option<OsString>,
    pub cmdargs: Option<Vec<OsString>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DenyRule {
    pub ident: OsString,
    pub target: Option<OsString>,
    pub cmd: Option<OsString>,
    pub cmdargs: Option<Vec<OsString>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rule {
    Permit(PermitRule),
    Deny(DenyRule),
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Permit,
    Deny,
    As,
    Cmd,
    Args,
    Nopass,
    Nolog,
    Persist,
    Keepenv,
    Setenv,
    LBrace,
    RBrace,
    Newline,
    Str(OsString),
    Eof,
}

struct Lexer<'a> {
    data: &'a [u8],
    pos: usize,
    line: usize,
    col: usize,
    file: String,
}

impl<'a> Lexer<'a> {
    fn new(data: &'a [u8], file: &str) -> Self {
        Self {
            data,
            pos: 0,
            line: 1,
            col: 0,
            file: file.to_string(),
        }
    }

    fn peek(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    fn next_byte(&mut self) -> Option<u8> {
        let b = self.data.get(self.pos).copied()?;
        self.pos += 1;
        if b == b'\n' {
            self.line += 1;
            self.col = 0;
        } else {
            self.col += 1;
        }
        Some(b)
    }

    fn error(&self, msg: impl Into<String>) -> ConfigError {
        ConfigError::new(&self.file, self.line, msg)
    }

    fn lex_word(&mut self, first: u8, first_escape: bool, first_quoted: bool) -> Result<(OsString, bool), ConfigError> {
        let mut buf: Vec<u8> = Vec::new();
        let mut nonkw = first_quoted || first_escape;
        if first == b'"' || first == b'\\' {
            if first == b'\\' && !first_escape {
                nonkw = true;
            }
        } else {
            buf.push(first);
            if first_escape {
                nonkw = true;
            }
        }
        let mut quotes = first_quoted;
        let mut escape = false;
        if first == b'\\' && !first_quoted {
            escape = true;
        }
        loop {
            let c = match self.peek() {
                Some(b) => b,
                None => {
                    if escape {
                        return Err(self.error("unterminated escape"));
                    }
                    if quotes {
                        return Err(self.error("unterminated quotes"));
                    }
                    break;
                }
            };
            match c {
                0 => {
                    return Err(self.error("unallowed character NUL"));
                }
                b'\\' => {
                    self.next_byte();
                    escape = !escape;
                    if escape {
                        continue;
                    }
                    nonkw = true;
                    if buf.len() >= MAX_TOKEN {
                        return Err(self.error("too long line"));
                    }
                    buf.push(b'\\');
                    escape = false;
                }
                b'\n' => {
                    if quotes {
                        return Err(self.error("unterminated quotes"));
                    }
                    if escape {
                        self.next_byte();
                        nonkw = true;
                        escape = false;
                        continue;
                    }
                    break;
                }
                b'{' | b'}' | b'#' | b' ' | b'\t' => {
                    if !escape && !quotes {
                        break;
                    }
                    self.next_byte();
                    if buf.len() >= MAX_TOKEN {
                        return Err(self.error("too long line"));
                    }
                    buf.push(c);
                    escape = false;
                }
                b'"' => {
                    self.next_byte();
                    if !escape {
                        quotes = !quotes;
                        nonkw = true;
                        continue;
                    }
                    if buf.len() >= MAX_TOKEN {
                        return Err(self.error("too long line"));
                    }
                    buf.push(b'"');
                    escape = false;
                }
                _ => {
                    self.next_byte();
                    if buf.len() >= MAX_TOKEN {
                        return Err(self.error("too long line"));
                    }
                    buf.push(c);
                    if escape {
                        nonkw = true;
                    }
                    escape = false;
                }
            }
        }
        if buf.is_empty() && !nonkw {
            return Err(self.error("internal lexer state"));
        }
        Ok((OsString::from_vec(buf), nonkw))
    }

    fn next_token(&mut self) -> Result<(Tok, usize), ConfigError> {
        loop {
            let c = match self.peek() {
                Some(b) => b,
                None => return Ok((Tok::Eof, self.line)),
            };
            match c {
                b' ' | b'\t' => {
                    self.next_byte();
                    continue;
                }
                b'\n' => {
                    let ln = self.line;
                    self.next_byte();
                    return Ok((Tok::Newline, ln));
                }
                b'#' => {
                    self.next_byte();
                    loop {
                        match self.peek() {
                            Some(b'\n') | None => break,
                            Some(_) => {
                                self.next_byte();
                            }
                        }
                    }
                    continue;
                }
                b'{' => {
                    let ln = self.line;
                    self.next_byte();
                    return Ok((Tok::LBrace, ln));
                }
                b'}' => {
                    let ln = self.line;
                    self.next_byte();
                    return Ok((Tok::RBrace, ln));
                }
                0 => {
                    return Err(self.error("unallowed character NUL"));
                }
                b'"' => {
                    let ln = self.line;
                    self.next_byte();
                    let (s, nonkw) = self.lex_quoted(ln)?;
                    return Ok((self.classify(s, nonkw), ln));
                }
                b'\\' => {
                    let ln = self.line;
                    self.next_byte();
                    match self.peek() {
                        Some(b'\n') => {
                            self.next_byte();
                            continue;
                        }
                        Some(_) => {
                            let (s, nonkw) = self.lex_word_continued(ln)?;
                            return Ok((self.classify(s, nonkw), ln));
                        }
                        None => {
                            return Err(self.error("unterminated escape"));
                        }
                    }
                }
                _ => {
                    let ln = self.line;
                    let b = self.next_byte().unwrap();
                    if b == b'\n' {
                        return Ok((Tok::Newline, ln));
                    }
                    let (s, nonkw) = self.lex_word(b, false, false)?;
                    if s.as_bytes().is_empty() {
                        continue;
                    }
                    return Ok((self.classify(s, nonkw), ln));
                }
            }
        }
    }

    fn lex_quoted(&mut self, _start_line: usize) -> Result<(OsString, bool), ConfigError> {
        let mut buf: Vec<u8> = Vec::new();
        let mut escape = false;
        loop {
            let c = match self.peek() {
                Some(b) => b,
                None => return Err(self.error("unterminated quotes")),
            };
            match c {
                0 => return Err(self.error("unallowed character NUL")),
                b'\n' => return Err(self.error("unterminated quotes")),
                b'\\' => {
                    self.next_byte();
                    escape = !escape;
                    if escape {
                        continue;
                    }
                    if buf.len() >= MAX_TOKEN {
                        return Err(self.error("too long line"));
                    }
                    buf.push(b'\\');
                    escape = false;
                }
                b'"' => {
                    self.next_byte();
                    if !escape {
                        break;
                    }
                    if buf.len() >= MAX_TOKEN {
                        return Err(self.error("too long line"));
                    }
                    buf.push(b'"');
                    escape = false;
                }
                _ => {
                    self.next_byte();
                    if buf.len() >= MAX_TOKEN {
                        return Err(self.error("too long line"));
                    }
                    buf.push(c);
                    if escape {
                        escape = false;
                    }
                }
            }
        }
        Ok((OsString::from_vec(buf), true))
    }

    fn lex_word_continued(&mut self, _start_line: usize) -> Result<(OsString, bool), ConfigError> {
        let mut buf: Vec<u8> = Vec::new();
        let mut escape = true;
        let mut quotes = false;
        loop {
            let c = match self.peek() {
                Some(b) => b,
                None => {
                    if escape {
                        return Err(self.error("unterminated escape"));
                    }
                    if quotes {
                        return Err(self.error("unterminated quotes"));
                    }
                    break;
                }
            };
            match c {
                0 => return Err(self.error("unallowed character NUL")),
                b'\n' => {
                    if quotes {
                        return Err(self.error("unterminated quotes"));
                    }
                    if escape {
                        self.next_byte();
                        escape = false;
                        continue;
                    }
                    break;
                }
                b'\\' => {
                    self.next_byte();
                    escape = !escape;
                    if escape {
                        continue;
                    }
                    if buf.len() >= MAX_TOKEN {
                        return Err(self.error("too long line"));
                    }
                    buf.push(b'\\');
                    escape = false;
                }
                b'{' | b'}' | b'#' | b' ' | b'\t' => {
                    if !escape && !quotes {
                        break;
                    }
                    self.next_byte();
                    if buf.len() >= MAX_TOKEN {
                        return Err(self.error("too long line"));
                    }
                    buf.push(c);
                    escape = false;
                }
                b'"' => {
                    self.next_byte();
                    if !escape {
                        quotes = !quotes;
                        continue;
                    }
                    if buf.len() >= MAX_TOKEN {
                        return Err(self.error("too long line"));
                    }
                    buf.push(b'"');
                    escape = false;
                }
                _ => {
                    self.next_byte();
                    if buf.len() >= MAX_TOKEN {
                        return Err(self.error("too long line"));
                    }
                    buf.push(c);
                    escape = false;
                }
            }
        }
        Ok((OsString::from_vec(buf), true))
    }

    fn classify(&self, s: OsString, nonkw: bool) -> Tok {
        if nonkw {
            return Tok::Str(s);
        }
        let b = s.as_bytes();
        match b {
            b"permit" => Tok::Permit,
            b"deny" => Tok::Deny,
            b"as" => Tok::As,
            b"cmd" => Tok::Cmd,
            b"args" => Tok::Args,
            b"nopass" => Tok::Nopass,
            b"nolog" => Tok::Nolog,
            b"persist" => Tok::Persist,
            b"keepenv" => Tok::Keepenv,
            b"setenv" => Tok::Setenv,
            _ => Tok::Str(s),
        }
    }
}

fn tokenize(data: &[u8], file: &str) -> Result<Vec<(Tok, usize)>, ConfigError> {
    if data.len() > MAX_FILE_BYTES {
        return Err(ConfigError::new(file, 1, "config file too large"));
    }
    if data.contains(&0) {
        let mut lex = Lexer::new(data, file);
        let mut out = Vec::new();
        loop {
            let (t, ln) = lex.next_token()?;
            let done = t == Tok::Eof;
            out.push((t, ln));
            if done {
                break;
            }
            if out.len() > 1_000_000 {
                return Err(ConfigError::new(file, 1, "config file too large"));
            }
        }
        return Ok(out);
    }
    let mut lex = Lexer::new(data, file);
    let mut out = Vec::new();
    loop {
        let (t, ln) = lex.next_token()?;
        let done = t == Tok::Eof;
        out.push((t, ln));
        if done {
            break;
        }
        if out.len() > 1_000_000 {
            return Err(ConfigError::new(file, 1, "config file too large"));
        }
    }
    Ok(out)
}

pub fn parse_bytes(data: &[u8], file: &str) -> Result<Vec<Rule>, ConfigError> {    let toks = tokenize(data, file)?;
    let mut rules: Vec<Rule> = Vec::new();
    let mut i = 0;
    while i < toks.len() {
        match &toks[i].0 {
            Tok::Eof => break,
            Tok::Newline => {
                i += 1;
                continue;
            }
            Tok::Permit | Tok::Deny => {
                let start_line = toks[i].1;
                let is_permit = toks[i].0 == Tok::Permit;
                i += 1;
                let mut options = Options::empty();
                let mut envlist: Vec<EnvEntry> = Vec::new();
                let mut has_setenv = false;
                if is_permit {
                    loop {
                        if i >= toks.len() {
                            break;
                        }
                        match &toks[i].0 {
                            Tok::Nopass => {
                                options.insert(Options::NOPASS);
                                i += 1;
                            }
                            Tok::Nolog => {
                                options.insert(Options::NOLOG);
                                i += 1;
                            }
                            Tok::Persist => {
                                options.insert(Options::PERSIST);
                                i += 1;
                            }
                            Tok::Keepenv => {
                                options.insert(Options::KEEPENV);
                                i += 1;
                            }
                            Tok::Setenv => {
                                if has_setenv {
                                    return Err(ConfigError::new(
                                        file,
                                        toks[i].1,
                                        "can't have two setenv sections",
                                    ));
                                }
                                i += 1;
                                match toks.get(i).map(|t| &t.0) {
                                    Some(Tok::LBrace) => i += 1,
                                    _ => {
                                        return Err(ConfigError::new(
                                            file,
                                            toks.get(i).map(|t| t.1).unwrap_or(start_line),
                                            "expected '{' after setenv",
                                        ));
                                    }
                                }
                                loop {
                                    match toks.get(i).map(|t| &t.0) {
                                        Some(Tok::RBrace) => {
                                            i += 1;
                                            break;
                                        }
                                        Some(Tok::Str(s)) => {
                                            if s.as_bytes().contains(&0) {
                                                return Err(ConfigError::new(
                                                    file,
                                                    toks[i].1,
                                                    "unallowed character NUL",
                                                ));
                                            }
                                            envlist.push(EnvEntry(s.clone()));
                                            i += 1;
                                        }
                                        Some(Tok::Newline) => {
                                            return Err(ConfigError::new(
                                                file,
                                                toks[i].1,
                                                "unterminated setenv block",
                                            ));
                                        }
                                        Some(Tok::Eof) => {
                                            return Err(ConfigError::new(
                                                file,
                                                toks[i].1,
                                                "unterminated setenv block",
                                            ));
                                        }
                                        Some(_) => {
                                            return Err(ConfigError::new(
                                                file,
                                                toks[i].1,
                                                "expected string or '}' in setenv",
                                            ));
                                        }
                                        None => {
                                            return Err(ConfigError::new(
                                                file,
                                                start_line,
                                                "unterminated setenv block",
                                            ));
                                        }
                                    }
                                }
                                has_setenv = true;
                            }
                            _ => break,
                        }
                    }
                    if options.contains(Options::NOPASS) && options.contains(Options::PERSIST) {
                        return Err(ConfigError::new(
                            file,
                            start_line,
                            "can't combine nopass and persist",
                        ));
                    }
                } else if matches!(
                    toks.get(i).map(|t| &t.0),
                    Some(Tok::Nopass)
                        | Some(Tok::Nolog)
                        | Some(Tok::Persist)
                        | Some(Tok::Keepenv)
                        | Some(Tok::Setenv)
                ) {
                    return Err(ConfigError::new(
                        file,
                        toks[i].1,
                        "deny takes no options",
                    ));
                }
                let ident = match toks.get(i).map(|t| &t.0) {
                    Some(Tok::Str(s)) => {
                        if s.as_bytes().is_empty() {
                            return Err(ConfigError::new(file, toks[i].1, "empty identity"));
                        }
                        if s.as_bytes().contains(&0) {
                            return Err(ConfigError::new(
                                file,
                                toks[i].1,
                                "unallowed character NUL",
                            ));
                        }
                        let v = s.clone();
                        i += 1;
                        v
                    }
                    _ => {
                        return Err(ConfigError::new(
                            file,
                            toks.get(i).map(|t| t.1).unwrap_or(start_line),
                            "expected user or group identity",
                        ));
                    }
                };
                let target = if matches!(toks.get(i).map(|t| &t.0), Some(Tok::As)) {
                    i += 1;
                    match toks.get(i).map(|t| &t.0) {
                        Some(Tok::Str(s)) => {
                            if s.as_bytes().is_empty() {
                                return Err(ConfigError::new(file, toks[i].1, "empty target"));
                            }
                            let v = s.clone();
                            i += 1;
                            Some(v)
                        }
                        _ => {
                            return Err(ConfigError::new(
                                file,
                                toks.get(i).map(|t| t.1).unwrap_or(start_line),
                                "expected target after 'as'",
                            ));
                        }
                    }
                } else {
                    None
                };
                let (cmd, cmdargs) = if matches!(toks.get(i).map(|t| &t.0), Some(Tok::Cmd)) {
                    i += 1;
                    let c = match toks.get(i).map(|t| &t.0) {
                        Some(Tok::Str(s)) => {
                            if s.as_bytes().is_empty() {
                                return Err(ConfigError::new(file, toks[i].1, "empty command"));
                            }
                            let v = s.clone();
                            i += 1;
                            v
                        }
                        _ => {
                            return Err(ConfigError::new(
                                file,
                                toks.get(i).map(|t| t.1).unwrap_or(start_line),
                                "expected command after 'cmd'",
                            ));
                        }
                    };
                    if matches!(toks.get(i).map(|t| &t.0), Some(Tok::Args)) {
                        i += 1;
                        let mut args: Vec<OsString> = Vec::new();
                        while let Some(Tok::Str(s)) = toks.get(i).map(|t| &t.0) {
                            args.push(s.clone());
                            i += 1;
                        }
                        (Some(c), Some(args))
                    } else {
                        (Some(c), None)
                    }
                } else {
                    if matches!(toks.get(i).map(|t| &t.0), Some(Tok::Args)) {
                        return Err(ConfigError::new(
                            file,
                            toks[i].1,
                            "args without cmd",
                        ));
                    }
                    (None, None)
                };
                match toks.get(i).map(|t| &t.0) {
                    Some(Tok::Newline) | Some(Tok::Eof) => {
                        if toks.get(i).map(|t| &t.0) == Some(&Tok::Newline) {
                            i += 1;
                        }
                    }
                    _ => {
                        return Err(ConfigError::new(
                            file,
                            toks.get(i).map(|t| t.1).unwrap_or(start_line),
                            "unexpected token at end of rule",
                        ));
                    }
                }
                if rules.len() >= MAX_RULES {
                    return Err(ConfigError::new(file, start_line, "too many rules"));
                }
                if is_permit {
                    rules.push(Rule::Permit(PermitRule {
                        options,
                        envlist,
                        has_setenv,
                        ident,
                        target,
                        cmd,
                        cmdargs,
                    }));
                } else {
                    rules.push(Rule::Deny(DenyRule {
                        ident,
                        target,
                        cmd,
                        cmdargs,
                    }));
                }
            }
            _ => {
                return Err(ConfigError::new(
                    file,
                    toks[i].1,
                    "expected 'permit' or 'deny'",
                ));
            }
        }
    }
    Ok(rules)
}

#[allow(dead_code)]
pub fn parse_str(s: &str, file: &str) -> Result<Vec<Rule>, ConfigError> {
    parse_bytes(s.as_bytes(), file)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Result<Vec<Rule>, ConfigError> {
        parse_str(s, "test.conf")
    }

    #[test]
    fn empty_and_comments_yield_no_rules() {
        assert_eq!(p("").unwrap(), vec![]);
        assert_eq!(p("# comment\n\n # other\n").unwrap(), vec![]);
    }

    #[test]
    fn simple_permit_parses() {
        let r = p("permit alice\n").unwrap();
        assert_eq!(r.len(), 1);
        match &r[0] {
            Rule::Permit(pr) => {
                assert_eq!(pr.ident, OsString::from("alice"));
                assert!(pr.target.is_none());
                assert!(pr.cmd.is_none());
                assert!(pr.cmdargs.is_none());
            }
            _ => panic!("expected permit"),
        }
    }

    #[test]
    fn last_match_wins_shape_preserved() {
        let r = p("permit alice\ndeny alice\n").unwrap();
        assert_eq!(r.len(), 2);
        assert!(matches!(r[0], Rule::Permit(_)));
        assert!(matches!(r[1], Rule::Deny(_)));
    }

    #[test]
    fn options_parse() {
        let r = p("permit nopass nolog keepenv alice\n").unwrap();
        match &r[0] {
            Rule::Permit(pr) => {
                assert!(pr.options.contains(Options::NOPASS));
                assert!(pr.options.contains(Options::KEEPENV));
                assert!(pr.options.contains(Options::NOLOG));
            }
            _ => panic!(),
        }
        let q = p("permit persist alice\n").unwrap();
        match &q[0] {
            Rule::Permit(pr) => assert!(pr.options.contains(Options::PERSIST)),
            _ => panic!(),
        }
    }

    #[test]
    fn nopass_persist_rejected() {
        assert!(p("permit nopass persist alice\n").is_err());
        assert!(p("permit persist nopass alice\n").is_err());
    }

    #[test]
    fn two_setenv_rejected() {
        assert!(p("permit setenv { A } setenv { B } alice\n").is_err());
    }

    #[test]
    fn deny_with_options_rejected() {
        assert!(p("deny nopass alice\n").is_err());
        assert!(p("deny keepenv alice\n").is_err());
        assert!(p("deny nolog alice\n").is_err());
    }

    #[test]
    fn setenv_parses_with_entries() {
        let r = p("permit setenv { -ENV PS1 FOO=bar } alice\n").unwrap();
        match &r[0] {
            Rule::Permit(pr) => {
                assert_eq!(pr.envlist.len(), 3);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn setenv_empty_allowed() {
        let r = p("permit setenv { } alice\n").unwrap();
        assert!(matches!(r[0], Rule::Permit(_)));
    }

    #[test]
    fn as_target_parses() {
        let r = p("permit alice as root\n").unwrap();
        match &r[0] {
            Rule::Permit(pr) => assert_eq!(pr.target, Some(OsString::from("root"))),
            _ => panic!(),
        }
    }

    #[test]
    fn as_without_target_rejected() {
        assert!(p("permit alice as\n").is_err());
        assert!(p("permit alice as cmd /bin/ls\n").is_err());
    }

    #[test]
    fn cmd_parses() {
        let r = p("permit alice cmd /bin/ls\n").unwrap();
        match &r[0] {
            Rule::Permit(pr) => {
                assert_eq!(pr.cmd, Some(OsString::from("/bin/ls")));
                assert!(pr.cmdargs.is_none());
            }
            _ => panic!(),
        }
    }

    #[test]
    fn args_absent_vs_empty_distinct() {
        let a = p("permit alice cmd /bin/ls\n").unwrap();
        let b = p("permit alice cmd /bin/ls args\n").unwrap();
        let c = p("permit alice cmd /bin/ls args foo\n").unwrap();
        match &a[0] {
            Rule::Permit(pr) => assert!(pr.cmdargs.is_none()),
            _ => panic!(),
        }
        match &b[0] {
            Rule::Permit(pr) => assert_eq!(pr.cmdargs, Some(vec![])),
            _ => panic!(),
        }
        match &c[0] {
            Rule::Permit(pr) => assert_eq!(pr.cmdargs, Some(vec![OsString::from("foo")])),
            _ => panic!(),
        }
    }

    #[test]
    fn args_without_cmd_rejected() {
        assert!(p("permit alice args foo\n").is_err());
        assert!(p("deny alice args\n").is_err());
    }

    #[test]
    fn cmd_without_command_rejected() {
        assert!(p("permit alice cmd\n").is_err());
        assert!(p("permit alice cmd args foo\n").is_err());
    }

    #[test]
    fn quoting_prevents_keyword() {
        let r = p("permit \"permit\"\n").unwrap();
        match &r[0] {
            Rule::Permit(pr) => assert_eq!(pr.ident, OsString::from("permit")),
            _ => panic!(),
        }
        assert!(p("permit permit\n").is_err());
    }

    #[test]
    fn quoted_empty_arg_preserved() {
        let r = p("permit alice cmd /bin/echo args \"\"\n").unwrap();
        match &r[0] {
            Rule::Permit(pr) => assert_eq!(pr.cmdargs, Some(vec![OsString::from("")])),
            _ => panic!(),
        }
    }

    #[test]
    fn escapes_and_continuations() {
        let r = p("permit alice cmd /bin/ls args foo\\\nbar\n").unwrap();
        match &r[0] {
            Rule::Permit(pr) => {
                assert_eq!(pr.cmdargs, Some(vec![OsString::from("foobar")]));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn comment_does_not_continue() {
        let r = p("permit alice # comment \\\npermit bob\n").unwrap();
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn group_ident_parses() {
        let r = p("permit :wheel cmd /bin/ls\n").unwrap();
        match &r[0] {
            Rule::Permit(pr) => assert_eq!(pr.ident, OsString::from(":wheel")),
            _ => panic!(),
        }
    }

    #[test]
    fn numeric_ids_accepted_without_overflow_panic() {
        let r = p("permit 0 as 0 cmd /bin/ls args 9999999999999999999999\n").unwrap();
        assert_eq!(r.len(), 1);
        let r2 = p("permit 65535 as 65536\n").unwrap();
        assert_eq!(r2.len(), 1);
    }

    #[test]
    fn nul_rejected() {
        let data = b"permit alice\x00\n";
        assert!(parse_bytes(data, "test.conf").is_err());
        let data2 = b"permit alice # ok \x00 comment\npermit bob\n";
        assert!(parse_bytes(data2, "test.conf").is_ok());
    }

    #[test]
    fn oversize_token_rejected() {
        let big = "a".repeat(2000);
        let s = format!("permit {big}\n");
        assert!(parse_str(&s, "test.conf").is_err());
    }

    #[test]
    fn file_line_errors_reported() {
        let e = p("permit alice\nbad line here\n").unwrap_err();
        assert_eq!(e.line, 2);
        assert!(format!("{e}").contains("test.conf"));
    }

    #[test]
    fn partial_policy_rejected() {
        assert!(p("permit\n").is_err());
        assert!(p("deny\n").is_err());
        assert!(p("permit alice as\n").is_err());
    }

    #[test]
    fn non_utf8_preserved() {
        use std::os::unix::ffi::OsStringExt;
        let mut data = b"permit ".to_vec();
        data.extend_from_slice(&[0xff, 0xfe]);
        data.extend_from_slice(b"\n");
        let r = parse_bytes(&data, "test.conf").unwrap();
        match &r[0] {
            Rule::Permit(pr) => assert_eq!(pr.ident, OsString::from_vec(vec![0xff, 0xfe])),
            _ => panic!(),
        }
    }

    #[test]
    fn full_example_from_manpage() {
        let s = "permit persist setenv { PKG_CACHE PKG_PATH } aja cmd pkg_add\npermit setenv { -ENV PS1 SSH_AUTH_SOCK } :wheel\npermit nopass tedu as root cmd /usr/sbin/procmap\npermit nopass keepenv setenv { PATH } root as root\n";
        let r = p(s).unwrap();
        assert_eq!(r.len(), 4);
    }
}
