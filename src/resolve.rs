//! Layer 0 — name → file resolution.
//!
//! The tool's headline fact: there are THREE different resolvers in play and
//! they disagree (spec §"设计公理 3"). `spawn('npx')` dies not because Windows
//! can't find `npx.cmd` but because libuv's candidate table never includes it.

use crate::fs::{canon, canon_path, join, Fs};
use crate::model::Env;

/// What one resolver concluded.
#[derive(Debug)]
pub struct Resolution {
    /// The winning candidate, if any.
    pub found: Option<String>,
    /// Every candidate path probed, in order — shown verbatim in the report.
    pub tried: Vec<String>,
    /// Candidates that existed but would fail at exec (non-PE, wrong kind).
    /// Present so we can say "it *saw* the shim and skipped it".
    pub shadowed: Vec<String>,
}

fn has_dir_sep(name: &str) -> bool {
    name.contains('/') || name.contains('\\') || name.contains(':')
}

/// Does the final path component carry a (nonempty) extension?
/// `npx` no · `npx.cmd` yes · `dir.with.dot\npx` still no.
fn has_ext(name: &str) -> bool {
    let base = name.rsplit(['\\', '/']).next().unwrap_or(name);
    match base.rfind('.') {
        Some(i) => i > 0 && i < base.len() - 1,
        None => false,
    }
}

fn probe(dirs: &[String], candidates: Vec<String>, fs: &dyn Fs) -> Resolution {
    // cmd and CreateProcess stop at the FIRST EXISTING file — they do not
    // verify executability during the search. A non-PE hit is "found" here;
    // its fate (BadExeFormat / cmd batch-text interpretation) is decided by
    // the analyzer, not the resolver.
    let mut tried = Vec::new();
    for dir in dirs {
        for cand in &candidates {
            let full = join(dir, cand);
            tried.push(full.clone());
            if fs.file_exists(&full) {
                return Resolution {
                    found: Some(full),
                    tried,
                    shadowed: vec![],
                };
            }
        }
    }
    Resolution {
        found: None,
        tried,
        shadowed: vec![],
    }
}

/// **libuv `search_path`** — what Node `spawn` actually runs (R1.14).
///
/// - name with a dir separator → CWD-relative only, literal probe
/// - bare name → CWD first, then PATH in order
/// - no ext → tries ONLY `.com` / `.exe` (never the bare name, never `.cmd`)
/// - has ext → literal first, then `.com` / `.exe`
/// - PATHEXT ignored entirely; first existing file wins (no exec check in
///   libuv — a non-PE hit still returns found and dies later at exec)
pub fn resolve_libuv(name: &str, env: &Env, fs: &dyn Fs) -> Resolution {
    if has_dir_sep(name) {
        // Qualified path — absolute or relative-to-CWD. libuv still applies
        // the extension candidates to it: spawn('./prog') finds ./prog.exe.
        let path = if name.contains(':') || name.starts_with(['\\', '/']) {
            name.to_string()
        } else {
            join(&env.cwd, name)
        };
        let candidates: Vec<String> = if has_ext(name) {
            vec![path.clone(), format!("{path}.com"), format!("{path}.exe")]
        } else {
            vec![format!("{path}.com"), format!("{path}.exe")]
        };
        let mut tried = Vec::new();
        for c in &candidates {
            tried.push(c.clone());
            if fs.file_exists(c) {
                return Resolution {
                    found: Some(canon_path(c)),
                    tried,
                    shadowed: vec![],
                };
            }
        }
        return Resolution {
            found: None,
            tried,
            shadowed: vec![],
        };
    }
    let dirs: Vec<String> = std::iter::once(env.cwd.clone())
        .chain(env.path.iter().cloned())
        .collect();
    // libuv does NOT skip non-PE hits — first existing file wins. Emulate that
    // by probing existence directly rather than via `probe`'s PE filter.
    let mut tried = Vec::new();
    let mut shadowed = Vec::new();
    for dir in &dirs {
        let candidates: Vec<String> = if has_ext(name) {
            vec![name.into(), format!("{name}.com"), format!("{name}.exe")]
        } else {
            vec![format!("{name}.com"), format!("{name}.exe")]
        };
        for cand in &candidates {
            let full = join(dir, cand);
            tried.push(full.clone());
            if fs.file_exists(&full) {
                return Resolution {
                    found: Some(full),
                    tried,
                    shadowed,
                };
            }
        }
        // Record the extensionless shim it *didn't* even look at — the report
        // should say "npx existed and was invisible to this resolver".
        let bare = join(dir, name);
        if !has_ext(name) && fs.file_exists(&bare) && !tried.contains(&bare) {
            shadowed.push(bare);
        }
    }
    Resolution {
        found: None,
        tried,
        shadowed,
    }
}

/// **cmd.exe's own resolver** — for `cmd /c foo` and inside batch files (R1.16).
/// Tries the bare name AND every PATHEXT extension, CWD first.
pub fn resolve_cmd(name: &str, env: &Env, fs: &dyn Fs) -> Resolution {
    if has_dir_sep(name) {
        let path = if name.contains(':') || name.starts_with(['\\', '/']) {
            name.to_string()
        } else {
            join(&env.cwd, name)
        };
        let found = fs.file_exists(&path).then(|| path.clone());
        return Resolution {
            found,
            tried: vec![path],
            shadowed: vec![],
        };
    }
    let dirs: Vec<String> = if env.no_cd_in_exe_path {
        env.path.clone()
    } else {
        std::iter::once(env.cwd.clone())
            .chain(env.path.iter().cloned())
            .collect()
    };
    let candidates: Vec<String> = if has_ext(name) {
        vec![name.to_string()]
    } else {
        std::iter::once(name.to_string())
            .chain(
                env.pathext
                    .iter()
                    .map(|e| format!("{name}{}", e.to_ascii_lowercase())),
            )
            .collect()
    };
    probe(&dirs, candidates, fs)
}

/// **CreateProcess built-in search** — only when `lpApplicationName == NULL`
/// (R0.3). App dir precedes CWD (a different order than both others), and only
/// `.exe` is ever appended.
pub fn resolve_createprocess(name: &str, env: &Env, fs: &dyn Fs) -> Resolution {
    if has_dir_sep(name) {
        let found = fs.file_exists(name).then(|| name.to_string());
        return Resolution {
            found,
            tried: vec![name.to_string()],
            shadowed: vec![],
        };
    }
    let dirs: Vec<String> = [
        env.app_dir.clone(),
        env.cwd.clone(),
        env.system32.clone(),
        env.system32.clone(), // 16-bit System dir lives under System32 nowadays
        env.windows_dir.clone(),
    ]
    .into_iter()
    .chain(env.path.iter().cloned())
    .collect();
    let candidates = if has_ext(name) {
        vec![name.to_string()]
    } else {
        vec![name.to_string(), format!("{name}.exe")]
    };
    probe(&dirs, candidates, fs)
}

/// Does this name bypass the PATH walk entirely? Dir-separator names are
/// joined against the cwd and handed to CreateProcess unconditionally —
/// `which` is never consulted for them.
pub fn resolve_which_hits_directly(name: &str) -> bool {
    has_dir_sep(name)
}

/// **`which`-style resolution** — what the `which` crate does (used by
/// `deno_task_shell`, closest kin to Go's `exec.LookPath`) (R1.18):
///
/// - PATH dirs only — the working directory is NOT searched (unlike cmd)
/// - name with a dir separator → never probed here at all; the caller hands
///   the joined path to CreateProcess unconditionally
/// - bare name, per dir: probe `name` first — but an extensionless hit only
///   wins when `GetBinaryTypeW` accepts it (a real PE); a text shim is
///   *skipped*, not run — then `name` + each PATHEXT suffix, in order
/// - name already carrying an extension → literal probe, existence wins
///   (any extension counts as "executable" at this stage — a `.sh` resolves
///   and then dies at CreateProcess)
pub fn resolve_which(name: &str, env: &Env, fs: &dyn Fs) -> Resolution {
    let name_has_ext = has_ext(name);
    let mut tried = Vec::new();
    let mut shadowed = Vec::new();
    for dir in &env.path {
        let bare = join(dir, name);
        tried.push(bare.clone());
        if fs.file_exists(&bare) {
            // Extensionless candidates must survive GetBinaryTypeW; anything
            // with an extension wins on existence alone.
            if name_has_ext || fs.is_pe(&bare) {
                return Resolution {
                    found: Some(bare),
                    tried,
                    shadowed,
                };
            }
            shadowed.push(bare);
        }
        if !name_has_ext {
            for e in &env.pathext {
                let full = join(dir, &format!("{name}{e}"));
                tried.push(full.clone());
                if fs.file_exists(&full) {
                    return Resolution {
                        found: Some(full),
                        tried,
                        shadowed,
                    };
                }
            }
        }
    }
    Resolution {
        found: None,
        tried,
        shadowed,
    }
}

/// The basename check for Node's EINVAL gate — case-insensitive `.bat`/`.cmd`
/// on the literal file string, before any resolution (R1.11–R1.12).
pub fn is_batch_literal(file: &str) -> bool {
    let base = canon(file);
    base.ends_with(".bat") || base.ends_with(".cmd")
}
