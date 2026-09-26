//! Core types shared across the fate-prediction pipeline.
//! Rule references (R*.x) point to docs/spec-v0.md.

use serde::Serialize;
use std::collections::BTreeMap;

/// Who produced the call — each runtime serializes and resolves differently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Producer {
    /// Node.js `child_process.spawn` (libuv semantics).
    Node,
    /// Raw `CreateProcessW` with `lpApplicationName = NULL` — the command line
    /// is already serialized and the first token is the module name.
    RawCommandLine,
}

/// The `shell` option as Node understands it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum Shell {
    None,
    /// `shell: true` — routed through `%ComSpec%` (cmd.exe) verbatim.
    Cmd,
    /// `shell: "path"` — joined command handed to `<shell> -c`.
    Other(String),
}

/// A structured spawn call, before anything touches the OS.
#[derive(Debug, Clone, Serialize)]
pub struct SpawnInput {
    pub file: String,
    pub args: Vec<String>,
    pub shell: Shell,
    pub producer: Producer,
}

/// Everything about the machine state that changes the answer.
/// The same call resolves differently under a different PATH — an honest
/// predictor takes the environment as an input, not a global.
#[derive(Debug, Clone, Serialize)]
pub struct Env {
    pub cwd: String,
    /// PATH entries, in order.
    pub path: Vec<String>,
    /// PATHEXT extensions (uppercase, with dot). cmd-resolver only.
    pub pathext: Vec<String>,
    pub comspec: String,
    pub app_dir: String,
    pub system32: String,
    pub windows_dir: String,
    /// cmd `NoCurrentDirectoryInExePath` — drops CWD from cmd's own search.
    pub no_cd_in_exe_path: bool,
    /// cmd delayed expansion (`/V:ON` or registry-enabled).
    pub delayed_expansion: bool,
    /// General environment variables (UPPERCASE keys — cmd var names are
    /// case-insensitive). Drives real `%VAR%` expansion.
    pub vars: BTreeMap<String, String>,
    /// Node >= 18.20.2/20.12.2/21.7.3/22 — the CVE-2024-27980 EINVAL gate (R1.11).
    pub node_bat_guard: bool,
}

impl Default for Env {
    fn default() -> Self {
        Self {
            cwd: r"C:\work".into(),
            path: vec![
                r"C:\Windows\System32".into(),
                r"C:\Program Files\nodejs".into(),
            ],
            pathext: [
                ".COM", ".EXE", ".BAT", ".CMD", ".VBS", ".VBE", ".JS", ".JSE", ".WSF", ".WSH",
                ".MSC",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect(),
            comspec: r"C:\Windows\System32\cmd.exe".into(),
            app_dir: r"C:\Program Files\app".into(),
            system32: r"C:\Windows\System32".into(),
            windows_dir: r"C:\Windows".into(),
            no_cd_in_exe_path: false,
            delayed_expansion: false,
            vars: BTreeMap::new(),
            node_bat_guard: true,
        }
    }
}

/// Which layer of the pipeline a note/verdict belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Layer {
    /// Name → file resolution (three different resolvers live here).
    Resolve,
    /// argv → command-line serialization.
    Serialize,
    /// cmd.exe re-parse of the command line.
    CmdParse,
    /// The spawned image could not start (CreateProcess error path).
    Exec,
    /// The target program's own argv split.
    TargetParse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Severity {
    Info,
    Warn,
    Fatal,
}

/// One finding in the trace.
#[derive(Debug, Clone, Serialize)]
pub struct Note {
    pub layer: Layer,
    pub severity: Severity,
    /// Stable rule id, e.g. "R1.14" — grep-able into the spec.
    pub rule: &'static str,
    pub message: String,
}

/// How the story ends.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum Error {
    /// `ERROR_FILE_NOT_FOUND` — nothing matched in the resolver's table.
    FileNotFound,
    /// CVE-2024-27980 class: Node refuses to bare-spawn a batch file.
    EinvalBatch,
    /// `ERROR_BAD_EXE_FORMAT` (193) — file exists but is not a PE/batch.
    BadExeFormat,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum Verdict {
    /// Every layer survived; `argv` is what the target program reads back.
    Runs { argv: Vec<String> },
    /// Died at a layer before the target's code ran.
    Dies { layer: Layer, error: Error },
    /// The argv cannot be represented safely at all (BatBadBut class):
    /// quoting it honestly would still mangle under the target's parser.
    UnsafeUnserializable,
}

/// Which argv dialect the target program speaks (L4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum TargetParser {
    /// MSVC-built C/C++, Node, Python 3, .NET — post-2008 MSVCRT rules
    /// including the `""` → `"` literal inside quotes.
    Msvcrt,
    /// `CommandLineToArgvW` — pre-2008 rules: `""` contributes nothing.
    Cltavw,
    /// Go's own parser — `""` emits a literal `"` AND leaves quote mode.
    Go,
    /// cmd.exe batch %1..%9 — different delimiter set, quotes retained.
    Batch,
}

/// A concrete remediation — what the README calls the prescription.
#[derive(Debug, Clone, Serialize)]
pub struct Suggestion {
    /// Stable id for corpus assertions.
    pub id: &'static str,
    pub text: String,
}

/// The full answer.
#[derive(Debug, Serialize)]
pub struct Report {
    /// What the resolved executable was (if resolution got that far).
    pub resolved: Option<String>,
    /// The command line as serialized for the child (if produced).
    pub command_line: Option<String>,
    /// After any cmd.exe re-parse — what cmd actually runs.
    pub cmd_effective: Option<String>,
    pub notes: Vec<Note>,
    pub verdict: Verdict,
    /// Actionable fixes, ordered by preference. Empty when none applies.
    pub suggestions: Vec<Suggestion>,
}
