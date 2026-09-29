//! Layer 4 — the target program's own argv split. Same string, different
//! parsers, different answers (spec L4 table).
//!
//! Divergence example for `"a""b c"`, measured against real binaries
//! (MSVC CRT / shell32 / go1.27.1 / a Rust binary — see the L4 table in
//! docs/spec-v0.md):
//!   Msvcrt, Rust → ["a\"b c"]      Cltavw, Go → ["a\"b","c"]

use crate::model::TargetParser;

pub fn split(cmdline: &str, parser: TargetParser) -> Vec<String> {
    match parser {
        TargetParser::Batch => split_batch(cmdline),
        _ => split_argv(cmdline, parser),
    }
}

/// MSVCRT / CLTAVW / Go share the backslash-quoting skeleton and differ only
/// in the `""`-inside-quotes rule (R1.4): MSVCRT keeps quote mode, CLTAVW and
/// Go leave it.
fn split_argv(s: &str, parser: TargetParser) -> Vec<String> {
    let chars: Vec<char> = s.chars().collect();
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_q = false;
    let mut token_started = false;
    let mut slashes = 0usize;
    let mut i = 0;
    // argv[0] special case: quote-toggle only, no backslash processing.
    let mut arg0 = parser != TargetParser::Go; // Go has no argv0 quirk
    while i < chars.len() {
        let c = chars[i];
        if arg0 {
            match c {
                '"' => in_q = !in_q,
                ' ' | '\t' if !in_q => {
                    out.push(cur.clone());
                    arg0 = false;
                    token_started = false;
                    cur.clear();
                    in_q = false;
                    // skip run of separators
                    while matches!(chars.get(i + 1), Some(' ' | '\t')) {
                        i += 1;
                    }
                }
                _ => cur.push(c),
            }
            i += 1;
            continue;
        }
        match c {
            '\\' => slashes += 1,
            '"' => {
                token_started = true;
                cur.push_str(&"\\".repeat(slashes / 2));
                if slashes % 2 == 1 {
                    cur.push('"'); // \" → literal quote
                } else {
                    match parser {
                        // post-2008: inside quotes, "" → literal " and stay in
                        TargetParser::Msvcrt if in_q && matches!(chars.get(i + 1), Some('"')) => {
                            cur.push('"');
                            i += 1;
                        }
                        // CommandLineToArgvW and Go: "" emits a literal " AND
                        // exits quote mode. Measured, not remembered: shell32
                        // on Windows 10.0.29671 reads `"a""b c"` as
                        // ["a\"b","c"] — the old model said ["ab c"], which is
                        // what a pre-2008 CRT does, not what CLTAVW does.
                        TargetParser::Go | TargetParser::Cltavw
                            if in_q && matches!(chars.get(i + 1), Some('"')) =>
                        {
                            cur.push('"');
                            in_q = false;
                            i += 1;
                        }
                        _ => in_q = !in_q,
                    }
                }
                slashes = 0;
            }
            ' ' | '\t' if !in_q => {
                cur.push_str(&"\\".repeat(slashes));
                slashes = 0;
                out.push(std::mem::take(&mut cur));
                token_started = false;
                while matches!(chars.get(i + 1), Some(' ' | '\t')) {
                    i += 1;
                }
            }
            _ => {
                cur.push_str(&"\\".repeat(slashes));
                slashes = 0;
                token_started = true;
                cur.push(c);
            }
        }
        i += 1;
    }
    cur.push_str(&"\\".repeat(slashes));
    if token_started || !cur.is_empty() {
        out.push(cur);
    }
    out
}

/// Batch %1..%9 tokenization (R2.10): delimiters `, ; = space tab` (VT/FF too),
/// quotes toggle grouping but are KEPT inside the token.
fn split_batch(s: &str) -> Vec<String> {
    let chars: Vec<char> = s.chars().collect();
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_q = false;
    let mut started = false;
    for &c in &chars {
        match c {
            '"' => {
                started = true;
                in_q = !in_q;
                cur.push('"'); // batch keeps the quote characters
            }
            ' ' | '\t' | ',' | ';' | '=' | '\x0b' | '\x0c' if !in_q => {
                if started {
                    out.push(std::mem::take(&mut cur));
                    started = false;
                }
            }
            _ => {
                started = true;
                cur.push(c);
            }
        }
    }
    if started {
        out.push(cur);
    }
    out
}
