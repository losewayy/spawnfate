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
            let no_meta = !inner.bytes().any(|c| matches!(c, b'&' | b'<' | b'>' | b'(' | b')' | b'@' | b'^' | b'|'));
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
                // %var% expands at /c parse time even inside quotes (R2.6).
                if let Some(end) = bytes[i + 1..].iter().position(|&c| c == '%') {
                    if end > 0 {
                        let name: String = bytes[i + 1..i + 1 + end].iter().collect();
                        hazards.push((
                            "R2.6",
                            format!("'%{name}%' at char {i} expands an env var at parse time — quoting does not protect it"),
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
