//! spawnfate — predict the fate of a Windows command line before you spawn it.

use clap::{Parser, Subcommand, ValueEnum};
use spawnfate::fs::RealFs;
use spawnfate::model::*;

#[derive(Parser)]
#[command(version, about = "Predict what happens to a Windows command line before you spawn it")]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,

    /// Program to spawn, e.g. `npx` or `C:\tools\thing.exe`
    file: Option<String>,
    /// Arguments for the program
    #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
    args: Vec<String>,

    /// Simulate Node `shell: true` (routes through cmd.exe verbatim)
    #[arg(short, long)]
    shell: bool,

    /// Assume the target program's argv parser (L4)
    #[arg(short, long, value_enum, default_value = "msvcrt")]
    target: Target,

    /// Emit the report as JSON
    #[arg(long, global = true)]
    json: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Analyze a raw command line as CreateProcess sees it
    /// (lpApplicationName = NULL — first token is the module name).
    Raw { line: String },
    /// Read an error message back to the layer that produced it.
    /// Paste `spawn npx ENOENT`, a Python traceback, or a Rust io error;
    /// `-` reads stdin.
    Explain { text: String },
    /// Materialize the corpus's declared filesystems and compare each
    /// prediction against a real `node` spawn — the proof mode.
    Selftest,
    /// Run as an MCP server over stdio (agents call the analyze_spawn tool)
    Mcp,
}

#[derive(Clone, Copy, ValueEnum)]
enum Target {
    /// MSVC/Node/Python3/.NET — post-2008 MSVCRT rules
    Msvcrt,
    /// CommandLineToArgvW — pre-2008 rules
    Cltavw,
    /// Go's own parser — `""` exits quotes AND emits a literal quote
    Go,
    /// cmd.exe batch %1..%9 — different delimiters, quotes kept
    Batch,
}

impl From<Target> for TargetParser {
    fn from(t: Target) -> Self {
        match t {
            Target::Msvcrt => TargetParser::Msvcrt,
            Target::Cltavw => TargetParser::Cltavw,
            Target::Go => TargetParser::Go,
            Target::Batch => TargetParser::Batch,
        }
    }
}

fn main() {
    let cli = Cli::parse();
    match cli.cmd {
        Some(Cmd::Selftest) => {
            let dir = std::path::Path::new("corpus");
            let dir = if dir.exists() {
                dir.to_path_buf()
            } else {
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus")
            };
            std::process::exit(spawnfate::selftest::run(&dir));
        }
        Some(Cmd::Mcp) => {
            std::process::exit(spawnfate::mcp::run());
        }
        Some(Cmd::Raw { line }) => {
            let input = SpawnInput {
                file: line,
                args: vec![],
                shell: Shell::None,
                producer: Producer::RawCommandLine,
            };
            run(&input, cli.target.into(), cli.json);
        }
        Some(Cmd::Explain { text }) => {
            let text = if text == "-" { read_stdin() } else { text };
            print_explain(&text, cli.json);
        }
        None => {
            let Some(file) = cli.file else {
                eprintln!("missing <file> — see --help");
                std::process::exit(2);
            };
            let input = SpawnInput {
                file,
                args: cli.args,
                shell: if cli.shell { Shell::Cmd } else { Shell::None },
                producer: Producer::Node,
            };
            run(&input, cli.target.into(), cli.json);
        }
    }
}

fn run(input: &SpawnInput, target: TargetParser, json: bool) {
    let env = real_env();
    let report = spawnfate::analyze(input, &env, &RealFs, target);
    if json {
        println!("{}", serde_json::to_string_pretty(&report).unwrap());
    } else {
        print_report(&report);
    }
    std::process::exit(match report.verdict {
        Verdict::Runs { .. } => 0,
        Verdict::Dies { .. } => 1,
        Verdict::UnsafeUnserializable => 3,
    });
}

fn real_env() -> Env {
    spawnfate::real_env_public()
}

fn print_report(r: &Report) {
    println!("== resolution ==");
    match &r.resolved {
        Some(p) => println!("  resolved: {p}"),
        None => println!("  resolved: (none)"),
    }
    if let Some(cl) = &r.command_line {
        println!("== serialized command line ==\n  {cl}");
    }
    if let Some(eff) = &r.cmd_effective {
        println!("== after cmd re-parse ==\n  {eff}");
    }
    println!("== findings ==");
    for n in &r.notes {
        let tag = match n.severity {
            Severity::Info => "info",
            Severity::Warn => "warn",
            Severity::Fatal => "FATAL",
        };
        println!("  [{tag}] {:?} {}: {}", n.layer, n.rule, n.message);
    }
    if !r.suggestions.is_empty() {
        println!("== prescription ==");
        for sg in &r.suggestions {
            println!("  → {}", sg.text);
        }
    }
    println!("== verdict ==");
    match &r.verdict {
        Verdict::Runs { argv } => {
            println!("  RUNS — target argv:");
            for (i, a) in argv.iter().enumerate() {
                println!("    [{i}] {a}");
            }
        }
        Verdict::Dies { layer, error } => println!("  DIES at {layer:?}: {error:?}"),
        Verdict::UnsafeUnserializable => {
            println!("  UNSAFE — argv cannot be serialized without mangling")
        }
    }
}

fn read_stdin() -> String {
    use std::io::Read;
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s).expect("read stdin");
    s
}

/// Print an error-surface reading.
///
/// Exit code: `0` when a known surface matched, `4` when nothing did — the
/// text is not modelled yet. Either way this is a differential; `spawnfate
/// <file> <args>` is the authoritative answer, and every hit prints it.
fn print_explain(text: &str, json: bool) {
    let hits = spawnfate::explain::explain(text);
    if json {
        println!("{}", serde_json::to_string_pretty(&hits).unwrap());
    } else if hits.is_empty() {
        println!("== reading ==");
        println!(
            "  no known error surface in {} byte(s) of input",
            text.len()
        );
        println!("  modelled: Win32 2 / 193, Node ENOENT / EINVAL / EFTYPE, cmd's own complaint");
        println!("  with the exact call, ask for a verdict instead:");
        println!("    spawnfate <file> <args>");
    } else {
        for hit in &hits {
            let s = hit.signature;
            println!("== reading ==\n  {} (on \"{}\")", s.id, hit.evidence);
            println!("  layer: {:?}", s.layer);
            println!("  rules: {}", s.rules.join(", "));
            println!("  case:  {} (corpus/core.yaml)", s.case);
            println!("  means: {}", s.diagnosis);
            println!("== prescription ==");
            for f in s.fixes {
                println!("  → [{}] {}", f.id, f.text);
            }
            println!("== definite answer ==\n  {}", s.verify);
        }
    }
    std::process::exit(if hits.is_empty() { 4 } else { 0 });
}
