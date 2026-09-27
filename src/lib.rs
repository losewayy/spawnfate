//! spawnfate — predict the fate of a Windows command line before you spawn it.
//!
//! Pipeline: **L0** name resolution (three different resolvers!) →
//! **L1** argv→command-line serialization → **L2** cmd.exe re-parse →
//! **L4** the target's own argv split. Rule ids (R*.x) → docs/spec-v0.md.

pub mod argv;
pub mod cmd;
pub mod corpus;
pub mod explain;
pub mod fs;
pub mod model;
pub mod resolve;
pub mod mcp;
pub mod selftest;
pub mod serialize;

use argv::split;
use cmd::{apply_c_quotes, expand_percent, scan_hazards};
use fs::{canon, is_device_name, Fs};
use model::*;
use resolve::{is_batch_literal, resolve_cmd, resolve_createprocess, resolve_libuv};
use serialize::{node_command_line, NodeLine};

/// Predict `input`'s fate under `env`, with `fs` as the filesystem oracle and
/// `target` as the assumed argv parser of the spawned program (L4).
pub fn analyze(input: &SpawnInput, env: &Env, fs: &dyn Fs, target: TargetParser) -> Report {
    let mut notes: Vec<Note> = Vec::new();
    let mut suggestions: Vec<Suggestion> = Vec::new();
    let mut resolved = None;
    let mut command_line = None;
    let mut cmd_effective = None;
    let verdict;

    // R0.10: libuv chdirs before it execs, so a working directory that does
    // not exist kills the spawn before any name is resolved. The producer does
    // not matter — every path goes through CreateProcess with this cwd.
    if env.cwd_missing {
        notes.push(Note {
            layer: Layer::Resolve,
            severity: Severity::Fatal,
            rule: "R0.10",
            message: format!(
                "working directory \"{}\" does not exist — libuv chdirs before it execs, so the spawn fails ENOENT before resolution is attempted",
                env.cwd
            ),
        });
        suggestions.push(Suggestion {
            id: "cwd-must-exist",
            text: "create the directory that is passed as the working directory, or drop the cwd option".into(),
        });
        return Report {
            resolved: None,
            command_line: None,
            cmd_effective: None,
            notes,
            verdict: Verdict::Dies {
                layer: Layer::Resolve,
                error: Error::FileNotFound,
            },
            suggestions,
        };
    }

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
                    let raw = input.file.to_ascii_lowercase();
                    if !raw.ends_with(".bat") && !raw.ends_with(".cmd") {
                        notes.push(Note {
                            layer: Layer::Serialize,
                            severity: Severity::Warn,
                            rule: "R0.7",
                            message: "trailing-dot disguise neutralized — the EINVAL guard checks the canonicalized name (CVE-2024-43402 fix)".into(),
                        });
                    }
                    suggestions.push(Suggestion {
                        id: "route-via-comspec",
                        text: "route the batch file through %ComSpec%: spawn(env.ComSpec, ['/d','/s','/c', cmdEscapedLine]) — or set {shell:true} accepting the raw-join caveats (R1.9)".into(),
                    });
                    verdict = Verdict::Dies {
                        layer: Layer::Serialize,
                        error: Error::EinvalBatch,
                    };
                    return Report { resolved, command_line, cmd_effective, notes, verdict, suggestions };
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
                        suggestions.push(Suggestion {
                            id: "self-resolve-pathext",
                            text: "libuv's table only tries .com/.exe — resolve the name yourself (PATH+PATHEXT walk incl. .cmd), then spawn the resolved .exe directly or route .cmd via ComSpec".into(),
                        });
                        verdict = Verdict::Dies {
                            layer: Layer::Resolve,
                            error: Error::FileNotFound,
                        };
                        return Report { resolved, command_line, cmd_effective, notes, verdict, suggestions };
                    }
                    Some(path) => {
                        resolved = Some(path.clone());
                        flag_resolved(&path, fs, &mut notes);
                        let l = path.to_ascii_lowercase();
                        if fs.is_reparse(&path) {
                            // R0.9: reparse stub — the OS loader resolves the
                            // alias target; spawnability is unknowable here.
                            notes.push(Note {
                                layer: Layer::Exec,
                                severity: Severity::Warn,
                                rule: "R0.9",
                                message: format!("{path:?} is a reparse stub — if it is an App Execution Alias the OS resolves the alias target at load; spawnability is unknowable from the file alone [UNC]"),
                            });
                            suggestions.push(Suggestion {
                                id: "app-alias-stub",
                                text: "App Execution Alias: disable it in Settings → Apps → App execution aliases, or point at the real install".into(),
                            });
                        } else if !(fs.is_pe(&path) || l.ends_with(".bat") || l.ends_with(".cmd")) {
                            // R0.5: exists but cannot load → 193, not ENOENT.
                            notes.push(Note {
                                layer: Layer::Exec,
                                severity: Severity::Fatal,
                                rule: "R0.5",
                                message: format!(
                                    "\"{path}\" is not a PE image and not a batch file — CreateProcess fails ERROR_BAD_EXE_FORMAT (193), not ENOENT"
                                ),
                            });
                            suggestions.push(Suggestion {
                                id: "not-a-pe",
                                text: "the resolved file exists but isn't a PE — likely a POSIX shim or data file. Check `where <name>` and point at the real executable".into(),
                            });
                            verdict = Verdict::Dies {
                                layer: Layer::Exec,
                                error: Error::BadExeFormat,
                            };
                            return Report { resolved, command_line, cmd_effective, notes, verdict, suggestions };
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
                    .map(|p| canon(p).ends_with(".bat") || canon(p).ends_with(".cmd"))
                    .unwrap_or(false);
                // CVE-2024-43402: trailing dots/spaces defeat a naive
                // ends-with extension check while the OS still canonicalizes
                // to the batch file. If the raw resolved name doesn't LOOK
                // batch but canon says it is — the guard was bypassed.
                if is_batch {
                    let raw = resolved.as_deref().unwrap_or("");
                    let raw_l = raw.to_ascii_lowercase();
                    if !raw_l.ends_with(".bat") && !raw_l.ends_with(".cmd") {
                        notes.push(Note {
                            layer: Layer::Resolve,
                            severity: Severity::Fatal,
                            rule: "R0.7",
                            message: format!("{raw:?} canonicalizes to a batch file but doesn't end in .bat/.cmd — extension guards (EINVAL, BatBadBut) were bypassed — CVE-2024-43402 class"),
                        });
                    }
                }
                if is_batch {
                    // BatBadBut (R2.11): a '"' in any arg cannot be serialized
                    // safely for a batch target — no escaping exists.
                    if let Some(bad) = input.args.iter().find(|a| a.contains('"')) {
                        notes.push(Note {
                            layer: Layer::Serialize,
                            severity: Severity::Fatal,
                            rule: "R2.11",
                            message: format!("arg {bad:?} contains a double-quote — inescapable inside cmd's batch quoting (CVE-2024-24576 class)"),
                        });
                        suggestions.push(Suggestion {
                            id: "batbadbut",
                            text: "pass the value via an environment variable or a temp file, or replace the batch target with a real binary".into(),
                        });
                        verdict = Verdict::UnsafeUnserializable;
                        return Report { resolved, command_line, cmd_effective, notes, verdict, suggestions };
                    }
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
                    return Report { resolved, command_line, cmd_effective, notes, verdict, suggestions };
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
                suggestions.push(Suggestion {
                    id: "avoid-raw-join",
                    text: "prefer explicit ComSpec routing with per-arg cmd escaping over {shell:true}'s raw join".into(),
                });
                resolved = Some(env.comspec.clone());
                command_line = Some(format!("\"{}\" {}", env.comspec, tail));
                // The string cmd receives as S is `"<raw>"`; /s forces the
                // strip-first-and-last-quote branch (R2.3).
                let s_inner = format!("\"{raw}\"");
                let (stripped, preserved) = apply_c_quotes(&s_inner, true, false);
                // R2.6: %VAR% expands once at /c parse time, even inside
                // quotes — and can inject live metachars.
                let (eff, exp_notes) = expand_percent(&stripped, env);
                if eff != stripped {
                    notes.push(Note {
                        layer: Layer::CmdParse,
                        severity: Severity::Warn,
                        rule: "R2.6",
                        message: format!("after %VAR% expansion → {eff}"),
                    });
                }
                for (rule, msg) in exp_notes {
                    let sev = if rule.ends_with("inject") { Severity::Fatal } else { Severity::Warn };
                    notes.push(Note { layer: Layer::CmdParse, severity: sev, rule, message: msg });
                }
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
                    return Report { resolved, command_line, cmd_effective, notes, verdict, suggestions };
                }
                let res = resolve_cmd(&first, env, fs);
                match &res.found {
                    Some(found) => {
                        resolved = Some(found.clone());
                        flag_resolved(found, fs, &mut notes);
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
                        if is_batch {
                            if let Some(bad) = input.args.iter().find(|a| a.contains('"')) {
                                notes.push(Note {
                                    layer: Layer::Serialize,
                                    severity: Severity::Fatal,
                                    rule: "R2.11",
                                    message: format!("arg {bad:?} contains a double-quote — inescapable under batch re-tokenization (CVE-2024-24576 class)"),
                                });
                                suggestions.push(Suggestion {
                                    id: "batbadbut",
                                    text: "pass the value via an environment variable or a temp file, or replace the batch target with a real binary".into(),
                                });
                                verdict = Verdict::UnsafeUnserializable;
                                return Report { resolved, command_line, cmd_effective, notes, verdict, suggestions };
                            }
                        }
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
                    flag_resolved(&path, fs, &mut notes);
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
                        return Report { resolved, command_line, cmd_effective, notes, verdict, suggestions };
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
        suggestions,
    }
}


/// Post-resolution reality checks: device names and reparse stubs.
fn flag_resolved(found: &str, fs: &dyn Fs, notes: &mut Vec<Note>) {
    if is_device_name(found) {
        notes.push(Note {
            layer: Layer::Resolve,
            severity: Severity::Warn,
            rule: "R0.8",
            message: format!("DOS device name {found:?} — it exists via the device namespace but nothing matching it is a spawnable PE"),
        });
    }
    if fs.is_reparse(found) {
        notes.push(Note {
            layer: Layer::Exec,
            severity: Severity::Warn,
            rule: "R0.9",
            message: format!("{found:?} is a reparse point — under WindowsApps that means an App Execution Alias: spawning may open the Store, not a binary"),
        });
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

/// Build Env from the live process environment.
pub fn real_env_public() -> Env {
    let get = |k: &str| std::env::var(k).unwrap_or_default();
    Env {
        cwd: std::env::current_dir().map(|p| p.display().to_string()).unwrap_or_default(),
        path: get("PATH").split(';').filter(|s| !s.is_empty()).map(str::to_string).collect(),
        pathext: get("PATHEXT").split(';').filter(|s| !s.is_empty()).map(|s| s.to_ascii_uppercase()).collect(),
        comspec: if get("ComSpec").is_empty() { r"C:\Windows\System32\cmd.exe".into() } else { get("ComSpec") },
        app_dir: std::env::current_exe().ok().and_then(|p| p.parent().map(|d| d.display().to_string())).unwrap_or_default(),
        system32: r"C:\Windows\System32".into(),
        windows_dir: if get("WINDIR").is_empty() { r"C:\Windows".into() } else { get("WINDIR") },
        node_bat_guard: node_bat_guard_public(),
        vars: std::env::vars().map(|(k, v)| (k.to_ascii_uppercase(), v)).collect(),
        ..Env::default()
    }
}

/// The EINVAL-on-batch gate exists on Node >= 18.20.2 / 20.12.2 / 21.7.3 / 22.
pub fn node_bat_guard_public() -> bool {
    let Ok(out) = std::process::Command::new("node").arg("-v").output() else {
        return true;
    };
    let v = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let Some(rest) = v.strip_prefix('v') else { return true };
    let mut parts = rest.split('.').filter_map(|s| s.parse::<u32>().ok());
    match (parts.next(), parts.next(), parts.next()) {
        (Some(maj), Some(min), Some(patch)) =>
            maj >= 22
                || (maj == 21 && min >= 7 && patch >= 3)
                || (maj == 20 && min >= 12 && patch >= 2)
                || (maj == 18 && min >= 20 && patch >= 2),
        _ => true,
    }
}
