//! Error-surface reading: map what the caller *printed* back to the layer that
//! produced it.
//!
//! The prediction path ([`crate::analyze`]) needs the argv. Someone who
//! searched their way here rarely has it — they have `Error: spawn npx ENOENT`,
//! a Python traceback, or a Rust `io` error. This module maps such a surface
//! onto the layer, the rule ids (docs/spec-v0.md), and the corpus case that
//! demonstrates it.
//!
//! It is a differential, not a verdict. The error text alone cannot say whether
//! a name was missing, shadowed, or invisible to the resolver — it names the
//! layer and the candidates. Every hit therefore prints the command that would
//! settle it; `spawnfate <file> <args>` stays authoritative.
//!
//! Matching runs on a normalized form of the text (lower-cased, with ASCII
//! whitespace, `_` and `-` removed) so that `ERROR_BAD_EXE_FORMAT`,
//! `error_bad_exe_format` and `error bad exe format` all hit the same needle.

use crate::model::Layer;
use serde::Serialize;

/// One remediation, with a stable id.
#[derive(Debug, Serialize)]
pub struct Fix {
    /// Stable id, namespaced `explain.` so it cannot collide with the
    /// engine's suggestion ids.
    pub id: &'static str,
    pub text: &'static str,
}

/// One error surface, and what it implies.
#[derive(Debug, Serialize)]
pub struct Signature {
    /// Stable id, printed with every hit and asserted by the tests.
    pub id: &'static str,
    /// Normalized needles that must all be present.
    pub all_of: &'static [&'static str],
    /// Normalized needles of which at least one must be present.
    pub any_of: &'static [&'static str],
    /// The layer this surface points at.
    pub layer: Layer,
    /// docs/spec-v0.md rule ids the reading rests on.
    pub rules: &'static [&'static str],
    /// corpus/core.yaml case that demonstrates the layer.
    pub case: &'static str,
    /// What the error means, in the terms of the pipeline.
    pub diagnosis: &'static str,
    /// Ordered fixes.
    pub fixes: &'static [Fix],
    /// The command that turns this reading into a verdict.
    pub verify: &'static str,
}

/// A signature that fired, and the needle that fired it.
#[derive(Debug, Serialize)]
pub struct Hit {
    pub signature: &'static Signature,
    pub evidence: &'static str,
}

/// Every error surface the tool knows how to read.
///
/// Order matters only for readability: all matching signatures are reported.
pub static SIGNATURES: &[Signature] = &[
    Signature {
        id: "win32-file-not-found",
        all_of: &["thesystemcannotfindthefilespecified"],
        any_of: &[],
        layer: Layer::Resolve,
        rules: &["R1.14", "R1.15"],
        case: "node-npx-enoent",
        diagnosis: "ERROR_FILE_NOT_FOUND (2), surfaced by whichever runtime you \
                    are in: the resolver walked its whole candidate list and none \
                    of them existed. libuv's list only ever holds `.com` and `.exe` \
                    candidates, so a name that exists on PATH as a `.cmd` shim, or \
                    as an extensionless shim, still ends here.",
        fixes: &[
            Fix {
                id: "explain.route-via-comspec",
                text: "Route the call through cmd.exe (Node `{shell:true}`, or spawn \
                       `cmd.exe /c <name>`): cmd walks PATH/PATHEXT on its own, and \
                       that walk is what finds a `.cmd` shim.",
            },
            Fix {
                id: "explain.spawn-with-extension",
                text: "Name the batch explicitly (`npx.cmd`) and expect the next \
                       error to change to EINVAL — bare-spawning a batch file is \
                       refused outright (CVE-2024-27980).",
            },
            Fix {
                id: "explain.compare-resolvers",
                text: "Compare the three resolvers before guessing: the same name \
                       can be found by cmd and missed by libuv, or found in the \
                       current directory first by the CreateProcess search.",
            },
        ],
        verify: "spawnfate <file> <args>        # prints the candidate list it probed",
    },
    Signature {
        id: "node-enoent",
        all_of: &["enoent"],
        any_of: &[],
        layer: Layer::Resolve,
        rules: &["R1.14", "R1.15"],
        case: "node-npx-enoent",
        diagnosis: "Node/libuv reports the failure as `ENOENT` (errno -4058) \
                    instead of the Win32 text. The name reached the resolver and \
                    nothing in its candidate table matched — and that table only \
                    ever holds `.com` and `.exe` candidates, so a `.cmd` shim \
                    sitting on PATH is invisible to this resolver. The same \
                    surface covers a `cwd` that does not exist: libuv chdirs \
                    before it execs and reports ENOENT for both (measured, node \
                    v24.15.0), so rule out the working directory too.",
        fixes: &[
            Fix {
                id: "explain.route-via-comspec",
                text: "Route the call through cmd.exe (Node `{shell:true}`, or spawn \
                       `cmd.exe /c <name>`): cmd walks PATH/PATHEXT on its own, and \
                       that walk is what finds a `.cmd` shim.",
            },
            Fix {
                id: "explain.check-cwd",
                text: "If the call passes a `cwd`, confirm it exists first — it \
                       fails with the same ENOENT as a missing program, so it is \
                       the cheaper half to rule out.",
            },
            Fix {
                id: "explain.print-path-probe",
                text: "If the name is a bare word, check it is not a victim of the \
                       runtime's own search order (CreateProcess looks in the \
                       application directory before CWD; libuv looks in CWD first).",
            },
        ],
        verify: "spawnfate <file> <args>        # prints the candidate list it probed",
    },
    Signature {
        id: "node-einval-batch",
        all_of: &["einval"],
        any_of: &[],
        layer: Layer::Serialize,
        rules: &["R1.11", "R1.12"],
        case: "node-npx-cmd-einval",
        diagnosis: "The target is a batch file and the caller asked for it without \
                    a shell. Node refuses this synchronously since CVE-2024-27980, \
                    because a batch file cannot be spawned safely without cmd.exe \
                    re-parsing the line.",
        fixes: &[
            Fix {
                id: "explain.route-via-comspec",
                text: "Route the call through cmd.exe (Node `{shell:true}`, or spawn \
                       `cmd.exe /c <name>`): cmd walks PATH/PATHEXT on its own, and \
                       that walk is what finds a `.cmd` shim.",
            },
            Fix {
                id: "explain.never-concatenate-name",
                text: "Do not get here by string surgery: a name ending in `.cmd.` \
                       slips past the extension guard and still resolves to a batch \
                       file (CVE-2024-43402).",
            },
        ],
        verify: "spawnfate <file>.cmd          # reproduces the gate, with the prescription",
    },
    Signature {
        id: "win32-bad-exe-format",
        all_of: &[],
        any_of: &["notavalidwin32application", "errorbadexeformat", "eftype"],
        layer: Layer::Exec,
        rules: &["R1.14", "R0.5"],
        case: "node-explicit-sh-193",
        diagnosis: "ERROR_BAD_EXE_FORMAT (193): the name resolved, the file exists, \
                    and it is not an image the loader can start — a shell script, a \
                    `.py` shim, or an extensionless Unix binary that rode along on \
                    PATH. Node maps 193 to `EFTYPE`.",
        fixes: &[
            Fix {
                id: "explain.invoke-interpreter",
                text: "Invoke the file through its interpreter (`sh <file>`, \
                       `python <file>`), or point the call at a real Windows \
                       executable instead.",
            },
            Fix {
                id: "explain.avoid-store-stub",
                text: "If the path is under `WindowsApps`, it is a Store reparse \
                       stub, not a binary: use the real install path, not the \
                       alias.",
            },
        ],
        verify: "spawnfate <file>              # shows the resolve step and the image check",
    },
    Signature {
        id: "cmd-not-recognized",
        all_of: &["notrecognizedasaninternalorexternalcommand"],
        any_of: &[],
        layer: Layer::CmdParse,
        rules: &["R1.16", "R2.3"],
        case: "cmd-resolver-sees-pathext",
        diagnosis: "This is cmd.exe's own resolver complaining, which means the \
                    line did reach cmd (usually via a shell). cmd walks PATH with \
                    PATHEXT, so a directory hit is not enough — the extension has \
                    to be in the list, and the extensionless name is tried first.",
        fixes: &[
            Fix {
                id: "explain.check-pathext",
                text: "Check both halves: the directory is on PATH **and** the \
                       extension is in PATHEXT. A `.cmd` in a PATH directory is \
                       still invisible when PATHEXT lost `.CMD`.",
            },
            Fix {
                id: "explain.shim-shadowing",
                text: "A bash shim with no extension shadows the `.cmd` sitting next \
                       to it, because cmd probes the extensionless name first.",
            },
        ],
        verify: "spawnfate raw \"<the line>\"  # re-parses it the way cmd would",
    },
];

/// Normalize an error surface for needle matching.
fn normalize(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != '_' && *c != '-')
        .flat_map(|c| c.to_lowercase())
        .collect()
}

/// The signature's firing needle, if the normalized text satisfies it.
fn fired(sig: &'static Signature, hay: &str) -> Option<&'static str> {
    if !sig.all_of.iter().all(|n| hay.contains(n)) {
        return None;
    }
    if sig.any_of.is_empty() {
        return sig.all_of.first().copied();
    }
    sig.any_of.iter().find(|n| hay.contains(*n)).copied()
}

/// Read `text` for known error surfaces. Returns every signature that fired,
/// in table order; an empty vector means the surface is not modelled yet.
pub fn explain(text: &str) -> Vec<Hit> {
    let hay = normalize(text);
    let mut hits = Vec::new();
    for sig in SIGNATURES {
        if let Some(evidence) = fired(sig, &hay) {
            hits.push(Hit {
                signature: sig,
                evidence,
            });
        }
    }
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The surfaces as they actually appear, one per signature.
    #[test]
    fn reads_real_surfaces() {
        let cases = [
            (
                "Error: spawn npx ENOENT\n    at ChildProcess._handle.onexit (node:internal/child_process:285:19)\n  errno: -4058,\n  code: 'ENOENT',\n  syscall: 'spawn npx',\n  path: 'npx'",
                "node-enoent",
                Layer::Resolve,
            ),
            (
                "FileNotFoundError: [WinError 2] The system cannot find the file specified",
                "win32-file-not-found",
                Layer::Resolve,
            ),
            (
                "Error: spawn EINVAL\n  errno: -4071,\n  code: 'EINVAL',\n  syscall: 'spawn npx.cmd'",
                "node-einval-batch",
                Layer::Serialize,
            ),
            (
                "Error: spawn npx.sh EFTYPE\n  errno: -4028,\n  code: 'EFTYPE'",
                "win32-bad-exe-format",
                Layer::Exec,
            ),
            (
                "OSError: [WinError 193] %1 is not a valid Win32 application",
                "win32-bad-exe-format",
                Layer::Exec,
            ),
            (
                "'npx' is not recognized as an internal or external command,\r\noperable program or batch file.",
                "cmd-not-recognized",
                Layer::CmdParse,
            ),
        ];
        for (text, id, layer) in cases {
            let hits = explain(text);
            assert!(
                hits.iter().any(|h| h.signature.id == id),
                "no `{id}` hit for: {text}\nmatched: {:?}",
                hits.iter().map(|h| h.signature.id).collect::<Vec<_>>()
            );
            let hit = hits.iter().find(|h| h.signature.id == id).unwrap();
            assert_eq!(hit.signature.layer, layer, "layer for {id}");
        }
    }

    #[test]
    fn unmatched_surface_is_empty() {
        assert!(explain("Segmentation fault (core dumped)").is_empty());
    }

    /// A rule without a case is a claim, not a fact: every signature must cite
    /// a rule that is in the spec and a case that is in the corpus.
    #[test]
    fn citations_resolve() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let spec = std::fs::read_to_string(root.join("docs/spec-v0.md")).expect("spec-v0.md");
        let corpus =
            std::fs::read_to_string(root.join("corpus/core.yaml")).expect("corpus/core.yaml");
        for sig in SIGNATURES {
            assert!(
                corpus.contains(&format!("- id: {}", sig.case)),
                "signature `{}` cites case `{}`, which is not in the corpus",
                sig.id,
                sig.case
            );
            for rule in sig.rules {
                assert!(
                    spec.contains(rule),
                    "signature `{}` cites rule `{}`, which is not in the spec",
                    sig.id,
                    rule
                );
            }
            assert!(!sig.fixes.is_empty(), "signature `{}` has no fixes", sig.id);
        }
    }
}
