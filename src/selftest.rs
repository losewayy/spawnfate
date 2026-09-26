//! `--selftest`: the corpus proves itself against reality.
//!
//! For every node-producer case, materialize the declared filesystem into a
//! temp dir, run a real `node` spawn with the remapped PATH/cwd, and compare
//! what actually happened with what we predicted. This is the property that
//! turns "a pile of rules" into "a verified model of Windows".

use crate::corpus::{self, Case};
use crate::model::{Env, Error, Layer, Verdict};
use std::path::{Path, PathBuf};
use std::process::Command;

const HARNESS: &str = r#"
const { spawn } = require('child_process');
const [file, argsJ, optsJ] = process.argv.slice(2);
const opts = JSON.parse(optsJ);
opts.cwd = process.env.SF_CWD;
opts.env = {
  PATH: process.env.SF_PATH,
  PATHEXT: process.env.SF_PATHEXT,
  ComSpec: process.env.ComSpec || 'C:\\Windows\\System32\\cmd.exe',
  SystemRoot: process.env.SystemRoot || 'C:\\Windows',
};
let cp;
try {
  cp = spawn(file, JSON.parse(argsJ), opts);
} catch (e) {
  // EINVAL-on-batch throws SYNCHRONOUSLY (CVE-2024-27980) — not an event.
  console.log('ERR ' + (e.code || e.errno || e.message));
  process.exit(0);
}
cp.on('error', e => { console.log('ERR ' + (e.code || e.errno || e.message)); process.exit(0); });
let out = '';
if (cp.stdout) cp.stdout.on('data', d => out += d);
cp.on('exit', (c, s) => console.log('EXIT ' + c + ' sig=' + s));
setTimeout(() => { console.log('TIMEOUT'); process.exit(42); }, 8000).unref();
"#;

fn remap(path: &str, root: &Path) -> String {
    let bytes = path.as_bytes();
    if bytes.len() > 2 && bytes[1] == b':' && (bytes[2] == b'\\' || bytes[2] == b'/') {
        root.join(&path[3..]).display().to_string()
    } else {
        path.to_string()
    }
}

/// Write the declared virtual filesystem under `root`, plus the cwd and PATH
/// dirs themselves — a missing cwd makes real spawn fail ENOENT before
/// resolution is even attempted.
fn materialize(case: &Case, env: &Env, root: &Path) {
    std::fs::create_dir_all(remap(&env.cwd, root)).unwrap();
    for d in &env.path {
        std::fs::create_dir_all(remap(d, root)).unwrap();
    }
    let Some(spec) = &case.env else { return };
    for f in &spec.files {
        let dst = PathBuf::from(remap(&f.path, root));
        if let Some(d) = dst.parent() {
            std::fs::create_dir_all(d).unwrap();
        }
        let lower = f.path.to_ascii_lowercase();
        if f.pe {
            // A real PE: clone the smallest real exe we have.
            let donor = Path::new(r"C:\Windows\System32\hostname.exe");
            if donor.exists() {
                std::fs::copy(donor, &dst).unwrap();
            } else {
                std::fs::write(&dst, "MZ").unwrap();
            }
        } else if lower.ends_with(".cmd") || lower.ends_with(".bat") {
            std::fs::write(&dst, "@exit /b 0\r\n").unwrap();
        } else {
            std::fs::write(&dst, "not a PE\n").unwrap();
        }
    }
}

#[derive(Debug, PartialEq)]
enum Observed {
    Exit(Option<i32>),
    Err(String),
    Timeout,
}

fn spawn_real(case: &Case, env: &Env, root: &Path, harness: &Path) -> Observed {
    let file = remap(&case.input.file, root);
    let args = serde_json::to_string(&case.input.args).unwrap();
    let opts = match case.input.shell.as_str() {
        "none" => "{}".to_string(),
        "cmd" => "{\"shell\":true}".to_string(),
        p => format!("{{\"shell\":{}}}", serde_json::to_string(p).unwrap()),
    };
    let out = Command::new("node")
        .arg(harness)
        .arg(&file)
        .arg(&args)
        .arg(&opts)
        .env("SF_CWD", remap(&env.cwd, root))
        .env("SF_PATH", env.path.iter().map(|p| remap(p, root)).collect::<Vec<_>>().join(";"))
        .env("SF_PATHEXT", env.pathext.join(";"))
        .env("ComSpec", env.comspec.clone())
        .env("SystemRoot", r"C:\Windows")
        .output()
        .expect("failed to run node harness");
    let text = String::from_utf8_lossy(&out.stdout);
    if let Some(line) = text.lines().find(|l| l.starts_with("ERR ")) {
        return Observed::Err(line[4..].trim().to_string());
    }
    if let Some(line) = text.lines().find(|l| l.starts_with("EXIT ")) {
        let code = line[5..]
            .split_whitespace()
            .next()
            .and_then(|s| s.parse::<i32>().ok());
        return Observed::Exit(code);
    }
    if text.contains("TIMEOUT") {
        return Observed::Timeout;
    }
    Observed::Err(format!("unparsed: {text}"))
}

/// Compare predicted verdict with observed spawn result. Returns Ok/Fail note.
fn compare(case: &Case, verdict: &Verdict, obs: &Observed) -> Result<(), String> {
    let shell = case.input.shell != "none";
    match (verdict, obs) {
        (Verdict::Runs { .. }, Observed::Exit(_)) => Ok(()),
        // Inside cmd, a resolution failure surfaces as exit≠0, not a spawn err.
        (Verdict::Dies { layer: Layer::Resolve, .. }, Observed::Exit(Some(c)))
            if shell && *c != 0 => Ok(()),
        (Verdict::Dies { error: Error::FileNotFound, .. }, Observed::Err(e))
            if e.contains("ENOENT") => Ok(()),
        (Verdict::Dies { error: Error::EinvalBatch, .. }, Observed::Err(e))
            if e.contains("EINVAL") => Ok(()),
        // ERROR_BAD_EXE_FORMAT surfaces in Node as `EFTYPE`
        // (libuv maps 193 → UV_EFTYPE) — measured on Node v24.
        (Verdict::Dies { error: Error::BadExeFormat, .. }, Observed::Err(e))
            if e.contains("EFTYPE") || e.contains("UNKNOWN") || e.contains("193") => Ok(()),
        (Verdict::Runs { .. }, Observed::Err(e)) => {
            Err(format!("predicted runs, observed spawn error {e}"))
        }
        (Verdict::Dies { error, layer }, Observed::Exit(Some(c))) => {
            Err(format!("predicted dies@{layer:?}/{error:?}, observed exit {c}"))
        }
        (a, b) => Err(format!("predicted {a:?}, observed {b:?}")),
    }
}

pub fn run(corpus_dir: &Path) -> i32 {
    // Prereq: node must exist to be the ground-truth spawner.
    if Command::new("node").arg("-v").output().is_err() {
        eprintln!("selftest: `node` not on PATH — skipped (prediction-only corpus still runs in `cargo test`)");
        return 0;
    }
    let corpora = corpus::load(corpus_dir);
    let cases: Vec<&Case> = corpora
        .iter()
        .flat_map(|(_, c)| c.cases.iter())
        .filter(|c| c.selftest && c.input.producer == "node")
        .collect();

    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let root = std::env::temp_dir().join(format!("spawnfate-st-{stamp}"));
    let harness = root.join("harness.js");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(&harness, HARNESS).unwrap();

    let mut pass = 0;
    let mut fail = 0;
    for case in cases {
        let case_root = root.join(&case.id);
        std::fs::create_dir_all(&case_root).unwrap();
        let (_input, env, vfs, target) = corpus::build(case);
        materialize(case, &env, &case_root);
        // node_bat_guard is a property of this machine's node — honor it.
        let env = Env { node_bat_guard: true, ..env };
        let report = crate::analyze(&_input, &env, &vfs, target);
        let obs = spawn_real(case, &env, &case_root, &harness);
        match compare(case, &report.verdict, &obs) {
            Ok(()) => {
                pass += 1;
                println!("  ok   {}", case.id);
            }
            Err(d) => {
                fail += 1;
                println!("  FAIL {} — {d}", case.id);
            }
        }
    }
    let _ = std::fs::remove_dir_all(&root);
    println!("selftest: {pass} verified against real spawn, {fail} diverged");
    if fail > 0 { 1 } else { 0 }
}
