//! spawnprobe — ground-truth runner for `Producer::WinSpawn` corpus cases.
//!
//! Reproduces what deno_task_shell / Go os/exec actually do: a `which`-style
//! PATH+PATHEXT walk (PATH only — the working directory is NOT searched),
//! then `std::process::Command` on the resolved path with verbatim argv.
//! selftest feeds it the same env the analyzer saw and compares outcomes.

use spawnfate::fs::{Fs, RealFs};
use std::path::{Path, PathBuf};
use std::process::Command;

fn has_dir_sep(name: &str) -> bool {
    name.contains('/') || name.contains('\\') || name.contains(':')
}

fn has_ext(name: &str) -> bool {
    let base = name.rsplit(['\\', '/']).next().unwrap_or(name);
    match base.rfind('.') {
        Some(i) => i > 0 && i < base.len() - 1,
        None => false,
    }
}

/// `which`-style walk: PATH dirs only, bare name then name+PATHEXT suffixes.
/// Extensionless candidates must pass GetBinaryTypeW — RealFs::is_pe is the
/// same test (MZ + PE signature), so a text shim is skipped, not run.
fn which_resolve(name: &str, cwd: &str, path: &[String], pathext: &[String]) -> Option<PathBuf> {
    let fs = RealFs;
    if has_dir_sep(name) {
        let p = if name.contains(':') || name.starts_with(['\\', '/']) {
            PathBuf::from(name)
        } else {
            Path::new(cwd).join(name)
        };
        return Some(p);
    }
    let name_has_ext = has_ext(name);
    for dir in path {
        let bare = Path::new(dir).join(name);
        if bare.is_file() && (name_has_ext || fs.is_pe(bare.to_str().unwrap_or_default())) {
            return Some(bare);
        }
        if !name_has_ext {
            for e in pathext {
                let full = Path::new(dir).join(format!("{name}{e}"));
                if full.is_file() {
                    return Some(full);
                }
            }
        }
    }
    None
}

fn main() {
    // spawnprobe <file> <args-json>   env: SF_CWD, SF_PATH (;-joined), SF_PATHEXT
    let file = std::env::args().nth(1).unwrap_or_default();
    let args_json = std::env::args().nth(2).unwrap_or_else(|| "[]".into());
    let args: Vec<String> = serde_json::from_str(&args_json).unwrap_or_default();

    let cwd = std::env::var("SF_CWD").unwrap_or_default();
    let path: Vec<String> = std::env::var("SF_PATH")
        .unwrap_or_default()
        .split(';')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();
    let pathext: Vec<String> = std::env::var("SF_PATHEXT")
        .unwrap_or_default()
        .split(';')
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .collect();

    let Some(resolved) = which_resolve(&file, &cwd, &path, &pathext) else {
        println!("ERR resolve");
        return;
    };

    match Command::new(&resolved)
        .current_dir(&cwd)
        .args(&args)
        .env("PATH", std::env::var("SF_PATH").unwrap_or_default())
        .env("PATHEXT", std::env::var("SF_PATHEXT").unwrap_or_default())
        .env("ComSpec", std::env::var("ComSpec").unwrap_or_default())
        .env("SystemRoot", r"C:\Windows")
        .output()
    {
        Ok(out) => {
            let code = out.status.code().unwrap_or(-1);
            println!("EXIT {code}");
            let text = String::from_utf8_lossy(&out.stdout);
            if !text.trim().is_empty() {
                println!(
                    "CHILDOUT {}",
                    serde_json::to_string(&text.to_string()).unwrap()
                );
            }
        }
        Err(e) => {
            let code = e
                .raw_os_error()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "?".into());
            println!("ERR {code} {e}");
        }
    }
}
