//! MCP server — `spawnfate mcp` exposes the predictor to AI agents over
//! stdio (newline-delimited JSON-RPC 2.0, per the MCP stdio transport).
//!
//! Tools: `analyze_spawn` — the same layered prediction as the CLI, with an
//! optional synthetic environment so an agent can ask "what would happen on
//! a machine where PATH looked like this?"

use crate::fs::{RealFs, VirtualFs};
use crate::model::*;
use serde_json::{json, Value};
use std::io::{BufRead, Write};

fn tools() -> Value {
    json!([{
        "name": "analyze_spawn",
        "description": concat!(
            "Predict the fate of a Windows process spawn BEFORE executing it. ",
            "Simulates name resolution (libuv/Node vs cmd.exe vs CreateProcess — ",
            "three different resolvers), argv→command-line serialization, cmd.exe ",
            "re-parsing, and the target program's argv parser. Reports where the ",
            "call dies or gets mangled (ENOENT/EINVAL/EFTYPE classes), the warnings ",
            "along the way, and concrete prescriptions. Use BEFORE running any ",
            "spawn()/subprocess/system() call on Windows — especially with bare ",
            "command names, .cmd/.bat files, shell:true, or args containing spaces, ",
            "quotes, %, !, or &."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "file": {
                    "type": "string",
                    "description": "Program to spawn — bare name ('npx') or a path"
                },
                "args": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Arguments as an argv vector (pre-serialization)"
                },
                "shell": {
                    "type": "string",
                    "enum": ["none", "cmd"],
                    "description": "none = direct spawn (Node default); cmd = Node's {shell:true} → cmd.exe re-parse"
                },
                "target": {
                    "type": "string",
                    "enum": ["msvcrt", "cltavw", "go", "batch"],
                    "description": "The spawned program's argv parser dialect (default msvcrt)"
                },
                "env": {
                    "type": "object",
                    "description": "Optional synthetic environment to analyze against instead of this machine's real one",
                    "properties": {
                        "cwd": { "type": "string" },
                        "path": { "type": "array", "items": { "type": "string" } },
                        "pathext": { "type": "array", "items": { "type": "string" } },
                        "files": {
                            "type": "array",
                            "items": {
                                "oneOf": [
                                    { "type": "string" },
                                    {
                                        "type": "object",
                                        "properties": {
                                            "path": { "type": "string" },
                                            "pe": { "type": "boolean" }
                                        },
                                        "required": ["path"]
                                    }
                                ]
                            },
                            "description": "Pretend these paths exist (synthetic fs). A string item means the file exists and is a PE image when the extension says so (.exe/.com); an object sets \"pe\" explicitly, for an extensionless image or a .exe that is not one"
                        },
                        "vars": { "type": "object" }
                    }
                }
            },
            "required": ["file"]
        }
    }])
}

struct Args {
    file: String,
    args: Vec<String>,
    shell: Shell,
    target: TargetParser,
    env: Option<Env>,
    /// Synthetic files as (path, is a PE image).
    files: Vec<(String, bool)>,
}

/// The string form of `env.files` carries no PE flag, so the flag is inferred
/// from the extension — that is what callers got before the object form
/// existed. An object item may override it, which is required for an
/// extensionless real image (a `.cmd` shim and a stripped binary look alike)
/// and for a `.exe` that is not one.
fn infer_pe(path: &str) -> bool {
    let lower = path.to_ascii_lowercase();
    lower.ends_with(".exe") || lower.ends_with(".com")
}

fn parse_args(v: &Value) -> Result<Args, String> {
    let get = |k: &str| v.get(k);
    let file = get("file")
        .and_then(Value::as_str)
        .ok_or("missing required param 'file'")?
        .to_string();
    let args = get("args")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).map(str::to_string).collect())
        .unwrap_or_default();
    let shell = match get("shell").and_then(Value::as_str).unwrap_or("none") {
        "cmd" => Shell::Cmd,
        "none" => Shell::None,
        other => Shell::Other(other.to_string()),
    };
    let target = crate::corpus::parse_target(get("target").and_then(Value::as_str));
    let (env, files) = if let Some(e) = get("env") {
        let mut env = Env::default();
        let mut files = Vec::new();
        if let Some(v) = e.get("cwd").and_then(Value::as_str) { env.cwd = v.into(); }
        if let Some(a) = e.get("path").and_then(Value::as_array) {
            env.path = a.iter().filter_map(Value::as_str).map(str::to_string).collect();
        }
        if let Some(a) = e.get("pathext").and_then(Value::as_array) {
            env.pathext = a.iter().filter_map(Value::as_str).map(str::to_string).collect();
        }
        if let Some(a) = e.get("files").and_then(Value::as_array) {
            files = a
                .iter()
                .map(|item| match item {
                    Value::String(path) => Ok((path.clone(), infer_pe(path))),
                    Value::Object(o) => {
                        let path = o
                            .get("path")
                            .and_then(Value::as_str)
                            .ok_or_else(|| "env.files[]: an object item needs a \"path\"".to_string())?;
                        let pe = match o.get("pe") {
                            None => infer_pe(path),
                            Some(Value::Bool(b)) => *b,
                            Some(_) => return Err("env.files[]: \"pe\" must be a boolean".to_string()),
                        };
                        Ok((path.to_string(), pe))
                    }
                    other => Err(format!(
                        "env.files[]: expected a path string or {{\"path\": ..., \"pe\": ...}}, got {other}"
                    )),
                })
                .collect::<Result<Vec<_>, String>>()?;
        }
        if let Some(m) = e.get("vars").and_then(Value::as_object) {
            for (k, val) in m {
                if let Some(v) = val.as_str() {
                    env.vars.insert(k.to_ascii_uppercase(), v.to_string());
                }
            }
        }
        (Some(env), files)
    } else {
        (None, vec![])
    };
    Ok(Args { file, args, shell, target, env, files })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn files_accept_a_string_or_an_object() {
        let args = parse_args(&json!({
            "file": "npx",
            "env": { "files": ["C:\\tools\\node.exe", { "path": "C:\\tools\\npx", "pe": false }] }
        }))
        .expect("parse");
        assert_eq!(
            args.files,
            vec![
                ("C:\\tools\\node.exe".to_string(), true),
                ("C:\\tools\\npx".to_string(), false),
            ]
        );
    }

    /// What the extension guess gets wrong, and why the object form exists:
    /// a real image with no `.exe` suffix, and a `.exe` that is not one.
    #[test]
    fn the_pe_flag_overrides_the_extension_guess() {
        let args = parse_args(&json!({
            "file": "mod",
            "env": { "files": [
                { "path": "C:\\tools\\shim" },
                { "path": "C:\\tools\\mod.exe", "pe": false }
            ] }
        }))
        .expect("parse");
        assert_eq!(
            args.files,
            vec![
                ("C:\\tools\\shim".to_string(), false),
                ("C:\\tools\\mod.exe".to_string(), false),
            ]
        );
    }

    /// A shapless item used to be dropped on the floor, which turned a bad
    /// request into a confident verdict about a machine with no files at all.
    #[test]
    fn shapeless_file_items_are_rejected() {
        let no_path = parse_args(&json!({ "file": "x", "env": { "files": [{ "pe": true }] } }));
        match no_path {
            Err(e) => assert!(e.contains("path"), "{e}"),
            Ok(_) => panic!("an object without a path must not be accepted"),
        }

        let not_an_item = parse_args(&json!({ "file": "x", "env": { "files": [42] } }));
        match not_an_item {
            Err(e) => assert!(e.contains("env.files"), "{e}"),
            Ok(_) => panic!("a non-string, non-object item must not be accepted"),
        }
    }
}

fn human_summary(r: &Report) -> String {
    let mut s = String::new();
    for n in &r.notes {
        s.push_str(&format!("[{:?}] {:?} {}: {}\n", n.severity, n.layer, n.rule, n.message));
    }
    match &r.verdict {
        Verdict::Runs { argv } => s.push_str(&format!("RUNS — argv {argv:?}\n")),
        Verdict::Dies { layer, error } => s.push_str(&format!("DIES at {layer:?}: {error:?}\n")),
        Verdict::UnsafeUnserializable => s.push_str("UNSAFE — argv cannot be serialized\n"),
    }
    for sg in &r.suggestions {
        s.push_str(&format!("fix({}): {}\n", sg.id, sg.text));
    }
    s
}

fn respond(id: &Value, result: Value) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "result": result})
}

fn rpc_err(id: &Value, code: i64, msg: &str) -> Value {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": msg}})
}

pub fn run() -> i32 {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() { continue; }
        let req: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                let _ = writeln!(out, "{}", rpc_err(&Value::Null, -32700, &e.to_string()));
                let _ = out.flush();
                continue;
            }
        };
        let id = req.get("id").cloned().unwrap_or(Value::Null);
        let method = req.get("method").and_then(Value::as_str).unwrap_or("");
        let is_notif = req.get("id").is_none();
        let resp = match method {
            "initialize" => Some(respond(&id, json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "spawnfate", "version": env!("CARGO_PKG_VERSION")},
            }))),
            "notifications/initialized" | "initialized" => None,
            "ping" => Some(respond(&id, json!({}))),
            "tools/list" => Some(respond(&id, json!({"tools": tools()}))),
            "tools/call" => {
                let params = req.get("params").cloned().unwrap_or(json!({}));
                let name = params.get("name").and_then(Value::as_str).unwrap_or("");
                if name != "analyze_spawn" {
                    Some(rpc_err(&id, -32602, &format!("unknown tool {name}")))
                } else {
                    match parse_args(&params["arguments"]) {
                        Ok(a) => {
                            let input = SpawnInput {
                                file: a.file, args: a.args, shell: a.shell,
                                producer: Producer::Node,
                            };
                            let report = if let Some(env) = &a.env {
                                let mut fs = VirtualFs::new();
                                for (path, pe) in &a.files { fs = fs.file(path, *pe); }
                                crate::analyze(&input, env, &fs, a.target)
                            } else {
                                crate::analyze(&input, &crate::real_env_public(), &RealFs, a.target)
                            };
                            Some(respond(&id, json!({"content": [
                                {"type": "text", "text": human_summary(&report)},
                                {"type": "text", "text": serde_json::to_string_pretty(&report).unwrap()},
                            ]})))
                        }
                        Err(e) => Some(rpc_err(&id, -32602, &e)),
                    }
                }
            }
            _ if is_notif => None,
            _ => Some(rpc_err(&id, -32601, &format!("method not found: {method}"))),
        };
        if let Some(r) = resp {
            let _ = writeln!(out, "{r}");
            let _ = out.flush();
        }
    }
    0
}
