//! Layer 1 — argv → command-line serialization (R1.x).

/// MSVCRT-compatible producer quoting (R1.3 / libuv `quote_cmd_arg`, R1.6):
/// quote iff empty or contains space/tab/`"`; inside a quoted arg every `"`
/// becomes `\"`, and backslash runs before a `"` or the closing quote double.
pub fn msvcrt_quote(arg: &str) -> String {
    if !arg.is_empty() && !arg.bytes().any(|b| matches!(b, b' ' | b'\t' | b'"')) {
        return arg.to_string();
    }
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let mut slashes = 0usize;
    for c in arg.chars() {
        match c {
            '\\' => slashes += 1,
            '"' => {
                out.push_str(&"\\".repeat(slashes * 2 + 1));
                out.push('"');
                slashes = 0;
            }
            _ => {
                out.push_str(&"\\".repeat(slashes));
                slashes = 0;
                out.push(c);
            }
        }
    }
    out.push_str(&"\\".repeat(slashes * 2)); // trailing backslashes double
    out.push('"');
    out
}

/// Join a serialized argv into the single command line (R1.7: single spaces,
/// args[0] is normally the as-typed file name).
pub fn join_quoted<'a>(args: impl Iterator<Item = &'a str>) -> String {
    args.map(msvcrt_quote).collect::<Vec<_>>().join(" ")
}

/// What `spawn(file, args)` produces under each shell mode (R1.9–R1.10).
/// Returns `(effective_file, command_line_tail)` — the tail being what follows
/// the executable token in the child's command line.
pub enum NodeLine {
    /// No shell: serialized argv, `argv[0]` = as-typed file.
    Direct(String),
    /// `shell: cmd` — everything joins RAW (no escaping!), then gets wrapped
    /// as one verbatim token: `cmd /d /s /c "<raw>"`.
    CmdWrapped { raw_join: String, full_tail: String },
    /// `shell: <other>` — POSIX-style `-c` handoff.
    ShellDashC { shell: String, raw_join: String },
}

pub fn node_command_line(file: &str, args: &[String], shell: &crate::model::Shell) -> NodeLine {
    use crate::model::Shell;
    match shell {
        Shell::None => {
            let all: Vec<String> = std::iter::once(file.to_string())
                .chain(args.iter().cloned())
                .collect();
            NodeLine::Direct(join_quoted(all.iter().map(String::as_str)))
        }
        Shell::Cmd => {
            let raw = std::iter::once(file)
                .chain(args.iter().map(String::as_str))
                .collect::<Vec<_>>()
                .join(" ");
            NodeLine::CmdWrapped {
                raw_join: raw.clone(),
                // /d /s /c "<raw>" — Node wraps the whole thing in ONE quote
                // pair and marks it verbatim (R1.9).
                full_tail: format!("/d /s /c \"{raw}\""),
            }
        }
        Shell::Other(path) => NodeLine::ShellDashC {
            shell: path.clone(),
            raw_join: std::iter::once(file)
                .chain(args.iter().map(String::as_str))
                .collect::<Vec<_>>()
                .join(" "),
        },
    }
}
