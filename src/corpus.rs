//! Corpus schema + case evaluation. The YAML files under corpus/ are the
//! language-agnostic golden set — any reimplementation can run them.

use crate::fs::VirtualFs;
use crate::model::*;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Corpus {
    pub cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
pub struct Case {
    pub id: String,
    pub title: Option<String>,
    pub rules: Option<Vec<String>>,
    pub source: Option<String>,
    pub env: Option<EnvSpec>,
    pub input: InputSpec,
    pub target: Option<String>,
    pub expect: Expect,
    /// `selftest: false` opts a case out of real-spawn verification
    /// (e.g. cases whose fate is intentionally uncertain).
    #[serde(default = "yes")]
    pub selftest: bool,
}

fn yes() -> bool {
    true
}

#[derive(Debug, Deserialize, Default)]
pub struct EnvSpec {
    pub cwd: Option<String>,
    pub path: Option<Vec<String>>,
    pub pathext: Option<Vec<String>>,
    pub comspec: Option<String>,
    pub app_dir: Option<String>,
    pub system32: Option<String>,
    pub windows_dir: Option<String>,
    pub no_cd_in_exe_path: Option<bool>,
    pub delayed_expansion: Option<bool>,
    pub node_bat_guard: Option<bool>,
    #[serde(default)]
    pub files: Vec<FileSpec>,
}

#[derive(Debug, Deserialize)]
pub struct FileSpec {
    pub path: String,
    #[serde(default)]
    pub pe: bool,
}

#[derive(Debug, Deserialize)]
pub struct InputSpec {
    pub producer: String,
    pub file: String,
    #[serde(default)]
    pub args: Vec<String>,
    pub shell: String,
}

#[derive(Debug, Deserialize, Default)]
pub struct Expect {
    pub verdict: Option<String>,
    pub error: Option<String>,
    pub layer: Option<String>,
    pub resolved_contains: Option<String>,
    pub argv: Option<Vec<String>>,
    pub command_line: Option<String>,
    pub cmd_effective: Option<String>,
    pub notes_contain: Option<Vec<String>>,
    pub notes_rule: Option<Vec<String>>,
    pub notes_absent: Option<Vec<String>>,
}

pub fn load(dir: &std::path::Path) -> Vec<(std::path::PathBuf, Corpus)> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().map(|e| e == "yaml" || e == "yml") != Some(true) {
            continue;
        }
        let text = std::fs::read_to_string(&path).unwrap();
        let corpus: Corpus = serde_norway::from_str(&text)
            .unwrap_or_else(|e| panic!("{}: YAML parse: {e}", path.display()));
        out.push((path, corpus));
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

/// Realize a case into concrete inputs.
pub fn build(case: &Case) -> (SpawnInput, Env, VirtualFs, TargetParser) {
    let mut env = Env::default();
    let mut fs = VirtualFs::new();
    if let Some(e) = &case.env {
        if let Some(v) = &e.cwd { env.cwd = v.clone(); }
        if let Some(v) = &e.path { env.path = v.clone(); }
        if let Some(v) = &e.pathext { env.pathext = v.clone(); }
        if let Some(v) = &e.comspec { env.comspec = v.clone(); }
        if let Some(v) = &e.app_dir { env.app_dir = v.clone(); }
        if let Some(v) = &e.system32 { env.system32 = v.clone(); }
        if let Some(v) = &e.windows_dir { env.windows_dir = v.clone(); }
        if let Some(v) = e.no_cd_in_exe_path { env.no_cd_in_exe_path = v; }
        if let Some(v) = e.delayed_expansion { env.delayed_expansion = v; }
        if let Some(v) = e.node_bat_guard { env.node_bat_guard = v; }
        for f in &e.files {
            fs = fs.file(&f.path, f.pe);
        }
    }
    let shell = match case.input.shell.as_str() {
        "none" => Shell::None,
        "cmd" => Shell::Cmd,
        p => Shell::Other(p.to_string()),
    };
    let producer = match case.input.producer.as_str() {
        "node" => Producer::Node,
        "raw" => Producer::RawCommandLine,
        other => panic!("{}: unknown producer {other}", case.id),
    };
    let input = SpawnInput {
        file: case.input.file.clone(),
        args: case.input.args.clone(),
        shell,
        producer,
    };
    let target = parse_target(case.target.as_deref());
    (input, env, fs, target)
}

pub fn parse_target(s: Option<&str>) -> TargetParser {
    match s.unwrap_or("msvcrt") {
        "msvcrt" => TargetParser::Msvcrt,
        "cltavw" => TargetParser::Cltavw,
        "go" => TargetParser::Go,
        "batch" => TargetParser::Batch,
        other => panic!("unknown target parser {other}"),
    }
}

/// Check a case's `expect` block against a report; returns failure strings.
pub fn check(case: &Case, r: &Report) -> Vec<String> {
    let ex = &case.expect;
    let mut fails = Vec::new();
    macro_rules! bad {
        ($cond:expr, $($m:tt)*) => {
            if !$cond { fails.push(format!("{}: {}", case.id, format!($($m)*))); }
        };
    }
    if let Some(v) = &ex.verdict {
        match v.as_str() {
            "runs" => bad!(matches!(r.verdict, Verdict::Runs { .. }), "expected runs, got {:?}", r.verdict),
            "dies" => bad!(matches!(r.verdict, Verdict::Dies { .. }), "expected dies, got {:?}", r.verdict),
            "unsafe" => bad!(r.verdict == Verdict::UnsafeUnserializable, "expected unsafe, got {:?}", r.verdict),
            other => fails.push(format!("{}: bad verdict key {other}", case.id)),
        }
        if let Some(e) = &ex.error {
            let want = match e.as_str() {
                "FileNotFound" | "ENOENT" => Error::FileNotFound,
                "EinvalBatch" | "EINVAL" => Error::EinvalBatch,
                "BadExeFormat" | "193" => Error::BadExeFormat,
                other => { fails.push(format!("{}: bad error key {other}", case.id)); return fails; }
            };
            match &r.verdict {
                Verdict::Dies { error, .. } => bad!(*error == want, "expected error {want:?}, got {error:?}"),
                other => fails.push(format!("{}: expected dies {want:?}, got {other:?}", case.id)),
            }
        }
        if let Some(l) = &ex.layer {
            let want = match l.as_str() {
                "Resolve" => Layer::Resolve, "Serialize" => Layer::Serialize,
                "CmdParse" => Layer::CmdParse, "Exec" => Layer::Exec,
                "TargetParse" => Layer::TargetParse,
                other => { fails.push(format!("{}: bad layer key {other}", case.id)); return fails; }
            };
            match &r.verdict {
                Verdict::Dies { layer, .. } => bad!(*layer == want, "expected dies@{want:?}, got {layer:?}"),
                other => fails.push(format!("{}: expected dies@{want:?}, got {other:?}", case.id)),
            }
        }
    }
    if let Some(v) = &ex.argv {
        match &r.verdict {
            Verdict::Runs { argv } => bad!(argv == v, "argv mismatch: want {v:?}, got {argv:?}"),
            other => fails.push(format!("{}: expected argv, got {other:?}", case.id)),
        }
    }
    if let Some(v) = &ex.resolved_contains {
        let got = r.resolved.clone().unwrap_or_default();
        bad!(got.to_ascii_lowercase().contains(&v.to_ascii_lowercase()), "resolved {got:?} lacks {v:?}");
    }
    if let Some(v) = &ex.command_line {
        bad!(r.command_line.as_deref() == Some(v.as_str()), "command_line want {v:?}, got {:?}", r.command_line);
    }
    if let Some(v) = &ex.cmd_effective {
        bad!(r.cmd_effective.as_deref() == Some(v.as_str()), "cmd_effective want {v:?}, got {:?}", r.cmd_effective);
    }
    for needle in ex.notes_contain.iter().flatten() {
        bad!(r.notes.iter().any(|n| n.message.contains(needle.as_str())), "no note containing {needle:?}");
    }
    for rule in ex.notes_rule.iter().flatten() {
        bad!(r.notes.iter().any(|n| n.rule == rule), "no note with rule {rule}");
    }
    for rule in ex.notes_absent.iter().flatten() {
        bad!(!r.notes.iter().any(|n| n.rule == rule), "unexpected note with rule {rule}");
    }
    fails
}
