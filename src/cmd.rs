//! Layer 2 — cmd.exe re-parse (R2.x). What `/c` does to the string it got.

use crate::model::Env;

/// Result of the `/c` quote decision plus a metachar hazard scan.
#[derive(Debug)]
pub struct CmdLine {
    /// The command string after cmd's outer-quote decision — what cmd then
    /// tokenizes and executes.
    pub effective: String,
    /// True if cmd kept every quote (the R2.1 five-condition branch).
    pub quotes_preserved: bool,
    /// (rule, message) hazards found in `effective`.
    pub hazards: Vec<(&'static str, String)>,
}

/// cmd /? semantics (R2.1–R2.3):
/// preserve all quotes iff `/S` absent AND exactly two `"` in S AND no
/// `&<>()@^|` between them AND whitespace between them AND the quoted text
/// names an executable file. Otherwise, if S starts with `"`, strip the first
/// `"` and the LAST `"` (pairing ignored).
///
/// `quoted_is_exe` is the caller's filesystem probe for condition 5 — the
/// decision is environment-dependent (R2.4), so we take it as an input.
pub fn apply_c_quotes(s: &str, s_flag: bool, quoted_is_exe: bool) -> (String, bool) {
    let n_quotes = s.matches('"').count();
    if !s_flag && n_quotes == 2 && quoted_is_exe {
        if let (Some(a), Some(b)) = (s.find('"'), s.rfind('"')) {
            let inner = &s[a + 1..b];
            let no_meta = !inner
                .bytes()
                .any(|c| matches!(c, b'&' | b'<' | b'>' | b'(' | b')' | b'@' | b'^' | b'|'));
            let has_space = inner.bytes().any(|c| matches!(c, b' ' | b'\t'));
            if a == 0 && no_meta && has_space {
                return (s.to_string(), true); // preserve — quoted exe path w/ spaces
            }
        }
    }
    // else-branch: strip first and last '"' iff S begins with one.
    if s.starts_with('"') {
        let mut chars: Vec<char> = s.chars().collect();
        // remove first
        chars.remove(0);
        if let Some(last) = chars.iter().rposition(|&c| c == '"') {
            chars.remove(last);
        }
        return (chars.into_iter().collect(), false);
    }
    (s.to_string(), false)
}

/// Metachar / expansion hazards in the effective command string (R2.5–R2.9).
/// Quote state only protects `& | < > ( ) ^` — `%` expands even inside quotes.
pub fn scan_hazards(effective: &str, env: &Env) -> Vec<(&'static str, String)> {
    let mut hazards = Vec::new();
    let bytes: Vec<char> = effective.chars().collect();
    let mut in_q = false;
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        match c {
            '"' => in_q = !in_q,
            '\r' | '\n' => hazards.push((
                "R2.8",
                format!("newline at char {i} splits commands — injection surface"),
            )),
            '&' | '|' | '<' | '>' if !in_q => hazards.push((
                "R2.9",
                format!("unquoted '{c}' at char {i} is a command separator/redirect"),
            )),
            '^' if !in_q => hazards.push((
                "R2.5",
                format!("'^' at char {i} escapes the next char for cmd (quoting won't protect it inside quotes it is literal)"),
            )),
            '%' => {
                // After real expansion, a surviving %VAR% is an UNKNOWN var —
                // cmd leaves it literal.
                if let Some(end) = bytes[i + 1..].iter().position(|&c| c == '%') {
                    if end > 0 {
                        let name: String = bytes[i + 1..i + 1 + end].iter().collect();
                        hazards.push((
                            "R2.6",
                            format!("'%{name}%' at char {i} is an undefined variable — stays literal in the command"),
                        ));
                        i += end;
                    }
                }
            }
            '!' if env.delayed_expansion => {
                if let Some(end) = bytes[i + 1..].iter().position(|&c| c == '!') {
                    if end > 0 {
                        hazards.push((
                            "R2.7",
                            format!("delayed expansion is on — '!…!' at char {i} expands"),
                        ));
                        i += end;
                    }
                }
            }
            _ => {}
        }
        i += 1;
    }
    hazards
}

/// %VAR% expansion on a `/c` line (R2.6): happens ONCE, at parse time, even
/// inside quotes. Variable names are case-insensitive. Unknown names stay
/// literal; `%%` stays `%%`; dynamic vars (%RANDOM%/%CD% etc.) expand from
/// the machine, not from args.
///
/// Returns the expanded string plus notes. Expansion can INJECT metachars —
/// an `&` inside %X%'s value becomes a live separator.
pub fn expand_percent(s: &str, env: &Env) -> (String, Vec<(&'static str, String)>) {
    let bytes: Vec<char> = s.chars().collect();
    let mut out = String::new();
    let mut notes = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != '%' {
            out.push(bytes[i]);
            i += 1;
            continue;
        }
        // `%%` is a literal escape only inside batch files; on a /c line it
        // stays %%. Either way: don't treat it as a var opener.
        if matches!(bytes.get(i + 1), Some('%')) {
            out.push_str("%%");
            i += 2;
            continue;
        }
        let Some(end) = bytes[i + 1..].iter().position(|&c| c == '%') else {
            out.push('%');
            i += 1;
            continue;
        };
        let name: String = bytes[i + 1..i + 1 + end].iter().collect();
        i += end + 2;
        if name.is_empty() {
            out.push_str("%%");
            continue;
        }
        let key = name.to_ascii_uppercase();
        // dynamic pseudo-vars
        if matches!(
            key.as_str(),
            "RANDOM" | "TIME" | "DATE" | "CD" | "ERRORLEVEL" | "CMDEXTVERSION" | "CMDCMDLINE"
        ) {
            let val = if key == "CD" {
                env.cwd.clone()
            } else {
                format!("<{key}>")
            };
            notes.push((
                "R2.6-dynamic",
                format!("'%{name}%' is a dynamic cmd pseudo-var → {val}"),
            ));
            out.push_str(&val);
            continue;
        }
        match env.vars.get(&key) {
            Some(val) => {
                let injected = val
                    .chars()
                    .any(|c| ['&', '|', '<', '>', '\r', '\n'].contains(&c));
                notes.push(("R2.6", format!("'%{name}%' expands to {val:?}")));
                if injected {
                    notes.push(("R2.6-inject", format!("EXPANSION INJECTS metachars — %{name}% value {val:?} contains command separators")));
                }
                out.push_str(val);
            }
            None => {
                out.push('%');
                out.push_str(&name);
                out.push('%');
            }
        }
    }
    (out, notes)
}
