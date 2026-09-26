//! Calibrated cases — each maps to a spec rule and a real-world bug we've hit.

use spawnfate::argv::split;
use spawnfate::fs::VirtualFs;
use spawnfate::model::*;
use spawnfate::{analyze, serialize};

fn env() -> Env {
    Env {
        cwd: r"C:\work".into(),
        path: vec![r"C:\tools\nodejs".into()],
        comspec: r"C:\Windows\System32\cmd.exe".into(),
        ..Env::default()
    }
}

/// The scoop-style PATH layout that bites everyone:
/// `npx` (bash shim, extensionless) + `npx.cmd` + `node.exe` side by side.
fn fs() -> VirtualFs {
    VirtualFs::new()
        .file(r"C:\tools\nodejs\npx", false) // bash shim — not a PE!
        .file(r"C:\tools\nodejs\npx.cmd", false)
        .file(r"C:\tools\nodejs\node.exe", true)
        .file(r"C:\tools\nodejs\npx.sh", false)
        .file(r"C:\Windows\System32\cmd.exe", true)
}

fn node(file: &str, args: &[&str], shell: Shell) -> SpawnInput {
    SpawnInput {
        file: file.into(),
        args: args.iter().map(|s| s.to_string()).collect(),
        shell,
        producer: Producer::Node,
    }
}

/// R1.14/R1.15: `spawn('npx')` → ENOENT. The .cmd exists, the shim exists —
/// libuv's candidate table contains neither. (kimi-code #3236)
#[test]
fn bare_npx_dies_enoent() {
    let r = analyze(&node("npx", &["-v"], Shell::None), &env(), &fs(), TargetParser::Msvcrt);
    assert!(matches!(
        r.verdict,
        Verdict::Dies {
            layer: Layer::Resolve,
            error: Error::FileNotFound
        }
    ));
    // The shadowed note must name the invisible shim.
    assert!(r
        .notes
        .iter()
        .any(|n| n.message.contains(r"C:\tools\nodejs\npx") && n.rule.contains("R1.14")));
}

/// R1.11: `spawn('npx.cmd')` → synchronous EINVAL (CVE-2024-27980).
#[test]
fn explicit_cmd_dies_einval() {
    let r = analyze(
        &node("npx.cmd", &[], Shell::None),
        &env(),
        &fs(),
        TargetParser::Msvcrt,
    );
    assert!(matches!(
        r.verdict,
        Verdict::Dies {
            error: Error::EinvalBatch,
            ..
        }
    ));
    // ...and the gate can be switched off for old-Node simulation.
    let mut old = env();
    old.node_bat_guard = false;
    let r2 = analyze(
        &node("npx.cmd", &[], Shell::None),
        &old,
        &fs(),
        TargetParser::Msvcrt,
    );
    assert!(!matches!(r2.verdict, Verdict::Dies { error: Error::EinvalBatch, .. }));
}

/// R1.16/R2.3: `shell:true` re-routes through cmd's own resolver — which DOES
/// see PATHEXT. On this PATH it finds the extensionless bash shim first and
/// warns (R0.5/UNC territory).
#[test]
fn shell_true_routes_through_cmd() {
    let r = analyze(
        &node("npx", &["-v"], Shell::Cmd),
        &env(),
        &fs(),
        TargetParser::Msvcrt,
    );
    assert_eq!(r.cmd_effective.as_deref(), Some("npx -v"));
    // cmd resolves the bare shim before npx.cmd (bare name precedes PATHEXT).
    assert_eq!(r.resolved.as_deref(), Some(r"C:\tools\nodejs\npx"));
    assert!(r.notes.iter().any(|n| n.message.contains("batch text")));
}

/// R1.3/R1.6 round-trip: trailing-backslash args are the classic mangling.
#[test]
fn trailing_backslash_round_trips() {
    let cl = serialize::join_quoted(["prog", r"C:\My Dir\"].into_iter());
    assert_eq!(cl, r#"prog "C:\My Dir\\""#);
    let argv = split(&cl, TargetParser::Msvcrt);
    assert_eq!(argv, vec!["prog", r"C:\My Dir\"]);
}

/// Same string, different parsers — the L4 divergence matrix (spec L4).
#[test]
fn parsers_disagree_on_double_quote() {
    let s = r#"exe "a""b c""#;
    assert_eq!(split(s, TargetParser::Msvcrt), vec!["exe", "a\"b c"]);
    assert_eq!(split(s, TargetParser::Cltavw), vec!["exe", "ab c"]);
    assert_eq!(split(s, TargetParser::Go), vec!["exe", "a\"b", "c"]);
}

/// Batch delimiters differ from argv entirely (R2.10) and quotes are kept.
#[test]
fn batch_has_its_own_delimiters() {
    assert_eq!(
        split("a,b;c=d", TargetParser::Batch),
        vec!["a", "b", "c", "d"]
    );
    assert_eq!(
        split(r#""a b" c"#, TargetParser::Batch),
        vec![r#""a b""#, "c"]
    );
}

/// R2.6: %var% expands at /c parse time even inside quotes — flag it.
#[test]
fn shell_true_flags_percent_expansion() {
    let r = analyze(
        &node("echo", &["%PATH%"], Shell::Cmd),
        &env(),
        &fs(),
        TargetParser::Msvcrt,
    );
    assert!(r.notes.iter().any(|n| n.rule == "R2.6"));
}

/// R2.9: a metachar in an arg is inert in a direct spawn but live through
/// shell:true — the injection surface.
#[test]
fn shell_true_flags_metachar_injection() {
    let r = analyze(
        &node("echo", &["ok", "&", "calc"], Shell::Cmd),
        &env(),
        &fs(),
        TargetParser::Msvcrt,
    );
    assert!(r.notes.iter().any(|n| n.rule == "R2.9"));
}

/// spawn('npx.sh') — literal-with-ext IS probed by libuv, found, then dies
/// ERROR_BAD_EXE_FORMAT at exec (R0.5) — not ENOENT.
#[test]
fn sh_extension_found_then_193() {
    let r = analyze(
        &node("npx.sh", &[], Shell::None),
        &env(),
        &fs(),
        TargetParser::Msvcrt,
    );
    assert!(matches!(
        r.verdict,
        Verdict::Dies {
            layer: Layer::Exec,
            error: Error::BadExeFormat
        }
    ));
}

/// R0.4: raw command line resolving to a .bat silently becomes cmd.exe.
#[test]
fn raw_line_to_batch_becomes_implicit_cmd() {
    let input = SpawnInput {
        file: r"setup.cmd /q".into(),
        args: vec![],
        shell: Shell::None,
        producer: Producer::RawCommandLine,
    };
    let fs = VirtualFs::new().file(r"C:\tools\nodejs\setup.cmd", false);
    let r = analyze(&input, &env(), &fs, TargetParser::Msvcrt);
    assert_eq!(r.resolved.as_deref(), Some(r"C:\tools\nodejs\setup.cmd"));
    assert!(r.notes.iter().any(|n| n.rule == "R0.4"));
}
