//! spawnfate — predict the fate of a Windows command line before you spawn it.
//!
//! Pipeline: **L0** name resolution (three different resolvers!) →
//! **L1** argv→command-line serialization → **L2** cmd.exe re-parse →
//! **L4** the target's own argv split. Rule ids (R*.x) → docs/spec-v0.md.

pub mod argv;
pub mod cmd;
pub mod corpus;
pub mod fs;
pub mod model;
pub mod resolve;
pub mod selftest;
pub mod serialize;

use argv::split;
use cmd::{apply_c_quotes, scan_hazards};
use fs::Fs;
use model::*;
use resolve::{is_batch_literal, resolve_cmd, resolve_createprocess, resolve_libuv};
use serialize::{node_command_line, NodeLine};

/// Predict `input`'s fate under `env`, with `fs` as the filesystem oracle and
/// `target` as the assumed argv parser of the spawned program (L4).
pub fn analyze(input: &SpawnInput, env: &Env, fs: &dyn Fs, target: TargetParser) -> Report {
    let mut notes: Vec<Note> = Vec::new();
    let mut resolved = None;
    let mut command_line = None;
    let mut cmd_effective = None;
    let verdict;

    match input.producer {
        Producer::Node => match &input.shell {
            Shell::None => {
                // R1.11: literal .bat/.cmd on the file string → EINVAL, thrown
                // before any resolution attempt.
                if env.node_bat_guard && is_batch_literal(&input.file) {
                    notes.push(Note {
                        layer: Layer::Serialize,
                        severity: Severity::Fatal,
                        rule: "R1.11",
                        message: format!(
                            "file \"{}\" ends in .bat/.cmd and no shell is set — Node >=18.20.2 throws EINVAL synchronously (CVE-2024-27980)",
                            input.file
                        ),
                    });
                    verdict = Verdict::Dies {
                        layer: Layer::Serialize,
                        error: Error::EinvalBatch,
                    };
                    return Report { resolved, command_line, cmd_effective, notes, verdict };
                }
                // R1.14: libuv's resolver — .com/.exe only, never the bare
                // name, never PATHEXT.
                let res = resolve_libuv(&input.file, env, fs);
                for s in &res.shadowed {
                    notes.push(Note {
                        layer: Layer::Resolve,
                        severity: Severity::Info,
                        rule: "R1.14/R1.15",
                        message: format!(
                            "\"{s}\" exists but is invisible to libuv's resolver (no extension, not .com/.exe) — it is NOT a candidate",
                        ),
                    });
                }
                match res.found {
                    None => {
                        notes.push(Note {
                            layer: Layer::Resolve,
                            severity: Severity::Fatal,
                            rule: "R1.14",
                            message: format!(
                                "libuv tried {} candidate(s), none exist — spawn fails ENOENT",
                                res.tried.len()
                            ),
                        });
                        verdict = Verdict::Dies {
                            layer: Layer::Resolve,
                            error: Error::FileNotFound,
                        };
                        return Report { resolved, command_line, cmd_effective, notes, verdict };
                    }
                    Some(path) => {
                        resolved = Some(path.clone());
                        let l = path.to_ascii_lowercase();
                        if !(fs.is_pe(&path) || l.ends_with(".bat") || l.ends_with(".cmd")) {
                            // R0.5: exists but cannot load → 193, not ENOENT.
                            notes.push(Note {
                                layer: Layer::Exec,
                                severity: Severity::Fatal,
                                rule: "R0.5",
                                message: format!(
                                    "\"{path}\" is not a PE image and not a batch file — CreateProcess fails ERROR_BAD_EXE_FORMAT (193), not ENOENT"
                                ),
                            });
                            verdict = Verdict::Dies {
                                layer: Layer::Exec,
                                error: Error::BadExeFormat,
                            };
                            return Report { resolved, command_line, cmd_effective, notes, verdict };
                        }
                        notes.push(Note {
                            layer: Layer::Resolve,
                            severity: Severity::Info,
                            rule: "R1.14",
                            message: format!("resolved → {path}"),
                        });
                    }
                }
                // R1.7: serialized argv, argv0 = as-typed file.
                let cl = match node_command_line(&input.file, &input.args, &input.shell) {
                    NodeLine::Direct(c) => c,
                    _ => unreachable!(),
                };
                command_line = Some(cl.clone());
                notes.push(Note {
                    layer: Layer::Serialize,
                    severity: Severity::Info,
                    rule: "R1.3/R1.6",
                    message: format!("command line → {cl}"),
                });
                // R0.4: a resolved .bat/.cmd silently becomes System32 cmd.exe —
                // the args get re-tokenized by cmd's OWN grammar, not argv.
                let is_batch = resolved
                    .as_deref()
                    .map(|p| {
                        let l = p.to_ascii_lowercase();
                        l.ends_with(".bat") || l.ends_with(".cmd")
                    })
                    .unwrap_or(false);
                if is_batch {
                    notes.push(Note {
                        layer: Layer::Resolve,
                        severity: Severity::Warn,
                        rule: "R0.4",
                        message: "resolved file is a batch script — CreateProcess substitutes System32\\cmd.exe; args are re-tokenized under batch rules (R2.10), not argv".into(),
                    });
                    // argv0 may be quoted — find its end quote-aware (byte-safe).
                    let tail = if let Some(s) = cl.strip_prefix('"') {
                        s.find('"').map(|p| &cl[p + 2..]).unwrap_or("")
                    } else {
                        cl.find(|c: char| c == ' ' || c == '\t')
                            .map(|p| &cl[p..])
                            .unwrap_or("")
                    };
                    let tail = tail.trim_start().to_string();
                    let argv = split(&tail, TargetParser::Batch);
                    let mut full = vec![input.file.clone()];
                    full.extend(argv);
                    verdict = Verdict::Runs { argv: full };
                    return Report { resolved, command_line, cmd_effective, notes, verdict };
                }
                let argv = split(&cl, target);
                // Round-trip check: argv[1..] must equal input.args under the
                // assumed parser — mismatch means silent mangling.
                let readback: Vec<String> = argv.iter().skip(1).cloned().collect();
                if readback != input.args {
                    notes.push(Note {
                        layer: Layer::TargetParse,
                        severity: Severity::Warn,
                        rule: "R1.5",
                        message: format!(
                            "argv read-back differs under {target:?}: {readback:?} — serialization does not round-trip for this parser"
                        ),
                    });
                }
                verdict = Verdict::Runs { argv };
            }
            Shell::Cmd => {
                // R1.9: raw join, verbatim /d /s /c "<raw>".
                let (raw, tail) = match node_command_line(&input.file, &input.args, &input.shell) {
                    NodeLine::CmdWrapped { raw_join, full_tail } => (raw_join, full_tail),
                    _ => unreachable!(),
                };
                notes.push(Note {
                    layer: Layer::Serialize,
                    severity: Severity::Warn,
                    rule: "R1.9",
                    message: "shell:true joins args RAW — no escaping — then wraps in one quote pair (DEP0190 territory)".into(),
                });
                resolved = Some(env.comspec.clone());
                command_line = Some(format!("\"{}\" {}", env.comspec, tail));
                // The string cmd receives as S is `"<raw>"`; /s forces the
                // strip-first-and-last-quote branch (R2.3).
                let s_inner = format!("\"{raw}\"");
                let (eff, preserved) = apply_c_quotes(&s_inner, true, false);
                cmd_effective = Some(eff.clone());
                notes.push(Note {
                    layer: Layer::CmdParse,
                    severity: Severity::Info,
                    rule: "R2.3",
                    message: format!(
                        "cmd /s strips the outer quote pair → effective command: {eff} {}",
                        if preserved { "(quotes preserved)" } else { "" }
                    ),
                });
                for (rule, msg) in scan_hazards(&eff, env) {
                    notes.push(Note {
                        layer: Layer::CmdParse,
                        severity: Severity::Warn,
                        rule,
                        message: msg,
                    });
                }
                // Inside the effective line, cmd re-resolves the first token
                // with ITS OWN table (R1.16) — PATHEXT included. But cmd
                // builtins never hit the filesystem at all.
                let first = first_cmd_token(&eff);
                if is_cmd_builtin(&first) {
                    notes.push(Note {
                        layer: Layer::Resolve,
                        severity: Severity::Info,
                        rule: "cmd-builtin",
                        message: format!("\"{first}\" is a cmd builtin — no file resolution happens"),
                    });
                    resolved = Some(format!("(cmd builtin) {first}"));
                    verdict = Verdict::Runs {
                        argv: vec![first],
                    };
                    return Report { resolved, command_line, cmd_effective, notes, verdict };
                }
                let res = resolve_cmd(&first, env, fs);
                match &res.found {
                    Some(found) => {
                        resolved = Some(found.clone());
                        notes.push(Note {
                            layer: Layer::Resolve,
                            severity: Severity::Info,
                            rule: "R1.16",
                            message: format!("cmd re-resolves \"{first}\" → {found}"),
                        });
                        let l = found.to_ascii_lowercase();
                        let is_batch = l.ends_with(".bat") || l.ends_with(".cmd");
                        if !is_batch && !fs.is_pe(found) {
                            notes.push(Note {
                                layer: Layer::Exec,
                                severity: Severity::Warn,
                                rule: "R1.16/R0.5",
                                message: format!("\"{found}\" is not a PE and has no extension — cmd will try to interpret it as batch text [UNC: exact failure mode is a corpus test item]"),
                            });
                        }
                        let rest = eff[first.len()..].trim_start().to_string();
                        let argv = if is_batch {
                            split(&rest, TargetParser::Batch)
                        } else {
                            split(&rest, target)
                        };
                        let mut final_argv = vec![first.clone()];
                        final_argv.extend(argv);
                        verdict = Verdict::Runs { argv: final_argv };
                    }
                    None => {
                        notes.push(Note {
                            layer: Layer::Resolve,
                            severity: Severity::Fatal,
                            rule: "R1.16",
                            message: format!("\"{first}\" is not recognized — cmd's resolver probed {} candidate(s)", res.tried.len()),
                        });
                        verdict = Verdict::Dies {
                            layer: Layer::Resolve,
                            error: Error::FileNotFound,
                        };
                    }
                }
            }
            Shell::Other(sh) => {
                let _raw = match node_command_line(&input.file, &input.args, &input.shell) {
                    NodeLine::ShellDashC { raw_join, .. } => raw_join,
                    _ => unreachable!(),
                };
                notes.push(Note {
                    layer: Layer::Serialize,
                    severity: Severity::Warn,
                    rule: "R1.10",
                    message: format!("shell \"{sh}\" gets POSIX-style -c handoff with a raw join — its own parser decides the fate"),
                });
                resolved = Some(sh.clone());
                verdict = Verdict::Runs {
                    argv: vec![input.file.clone()],
                };
            }
        },
        Producer::RawCommandLine => {
            // The input.file IS the whole command line (lpCommandLine),
            // lpApplicationName = NULL (R0.1–R0.2).
            let line = &input.file;
            command_line = Some(line.clone());
            let (first, quoted) = first_token_r02(line);
            notes.push(Note {
                layer: Layer::Resolve,
                severity: if quoted { Severity::Info } else { Severity::Warn },
                rule: "R0.2",
                message: if quoted {
                    format!("first token (quoted) → \"{first}\"")
                } else {
                    format!("unquoted first token \"{first}\" — CreateProcess re-tries with NUL at each space; a space-bearing path must be quoted")
                },
            });
            let res = resolve_createprocess(&first, env, fs);
            match res.found {
                Some(path) => {
                    resolved = Some(path.clone());
                    let l = path.to_ascii_lowercase();
                    if l.ends_with(".bat") || l.ends_with(".cmd") {
                        // R0.4: implicit cmd.exe from System32.
                        notes.push(Note {
                            layer: Layer::Resolve,
                            severity: Severity::Warn,
                            rule: "R0.4",
                            message: format!("\"{path}\" is a batch file — CreateProcess silently substitutes System32\\cmd.exe and hands it the line [UNC: exact line reconstruction is a corpus test item]"),
                        });
                    } else if !fs.is_pe(&path) {
                        verdict = Verdict::Dies {
                            layer: Layer::Exec,
                            error: Error::BadExeFormat,
                        };
                        return Report { resolved, command_line, cmd_effective, notes, verdict };
                    }
                    let argv = split(line, target);
                    verdict = Verdict::Runs { argv };
                }
                None => {
                    verdict = Verdict::Dies {
                        layer: Layer::Resolve,
                        error: Error::FileNotFound,
                    };
                }
            }
        }
    }

    Report {
        resolved,
        command_line,
        cmd_effective,
        notes,
        verdict,
    }
}

/// cmd.exe internal commands — resolved in-process, never probed on disk.
fn is_cmd_builtin(name: &str) -> bool {
    const BUILTINS: &[&str] = &[
        "assoc", "break", "call", "cd", "chcp", "chdir", "cls", "color", "copy", "date", "del",
        "dir", "echo", "endlocal", "erase", "exit", "for", "ftype", "goto", "if", "md", "mkdir",
        "mklink", "move", "path", "pause", "popd", "prompt", "pushd", "rd", "rem", "ren",
        "rename", "rmdir", "set", "setlocal", "shift", "start", "time", "title", "type", "ver",
        "verify", "vol",
    ];
    BUILTINS.contains(&name.to_ascii_lowercase().as_str())
}

/// First whitespace token after cmd's own quote handling — the program cmd
/// will try to resolve.
fn first_cmd_token(s: &str) -> String {
    let t = s.trim_start();
    let chars: Vec<char> = t.chars().collect();
    if chars.first() == Some(&'"') {
        let mut out = String::new();
        let mut i = 1;
        while i < chars.len() && chars[i] != '"' {
            out.push(chars[i]);
            i += 1;
        }
        return out;
    }
    // stop at whitespace or a separator metachar
    chars
        .iter()
        .take_while(|&&c| !matches!(c, ' ' | '\t' | '&' | '|' | '<' | '>'))
        .collect()
}

/// First token under CreateProcess rules: quoted → quoted span; else first
/// whitespace-delimited run (R0.2).
fn first_token_r02(line: &str) -> (String, bool) {
    let t = line.trim_start();
    if t.starts_with('"') {
        let inner: String = t[1..].chars().take_while(|&c| c != '"').collect();
        (inner, true)
    } else {
        (t.split_whitespace().next().unwrap_or("").to_string(), false)
    }
}
