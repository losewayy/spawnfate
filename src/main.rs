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
    #[arg(long)]
    json: bool,
}

#[derive(Subcommand)]
enum Cmd {
    /// Analyze a raw command line as CreateProcess sees it
    /// (lpApplicationName = NULL — first token is the module name).
    Raw { line: String },
    /// Materialize the corpus's declared filesystems and compare each
    /// prediction against a real `node` spawn — the proof mode.
    Selftest,
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
        Some(Cmd::Raw { line }) => {
            let input = SpawnInput {
                file: line,
                args: vec![],
                shell: Shell::None,
                producer: Producer::RawCommandLine,
            };
            run(&input, cli.target.into(), cli.json);
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
    let get = |k: &str| std::env::var(k).unwrap_or_default();
    Env {
        cwd: std::env::current_dir()
            .map(|p| p.display().to_string())
            .unwrap_or_default(),
        path: get("PATH")
            .split(';')
            .filter(|s| !s.is_empty())
            .map(str::to_string)
            .collect(),
        pathext: get("PATHEXT")
            .split(';')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_ascii_uppercase())
            .collect(),
        comspec: if get("ComSpec").is_empty() {
            r"C:\Windows\System32\cmd.exe".into()
        } else {
            get("ComSpec")
        },
        app_dir: std::env::current_exe()
            .ok()
            .and_then(|p| p.parent().map(|d| d.display().to_string()))
            .unwrap_or_default(),
        system32: r"C:\Windows\System32".into(),
        windows_dir: if get("WINDIR").is_empty() {
            r"C:\Windows".into()
        } else {
            get("WINDIR")
        },
        node_bat_guard: node_bat_guard(),
        ..Env::default()
    }
}

/// The EINVAL-on-batch gate exists on Node >= 18.20.2 / 20.12.2 / 21.7.3 / 22.
/// Query the real node on PATH if present.
fn node_bat_guard() -> bool {
    let Ok(out) = std::process::Command::new("node").arg("-v").output() else {
        return true; // assume modern
    };
    let v = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let Some(rest) = v.strip_prefix('v') else { return true };
    let mut parts = rest.split('.').filter_map(|s| s.parse::<u32>().ok());
    match (parts.next(), parts.next(), parts.next()) {
        (Some(maj), Some(min), Some(patch)) => {
            maj >= 22
                || (maj == 21 && min >= 7 && patch >= 3)
                || (maj == 20 && min >= 12 && patch >= 2)
                || (maj == 18 && min >= 20 && patch >= 2)
        }
        _ => true,
    }
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
