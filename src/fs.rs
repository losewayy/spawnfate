//! Filesystem abstraction — the corpus must run identically on any machine,
//! so resolution talks to `Fs`, never to `std::fs` directly.

use std::collections::HashSet;

/// Minimal surface the resolvers need.
pub trait Fs {
    /// Does a *file* exist at this exact path?
    fn file_exists(&self, path: &str) -> bool;
    /// Is this file a native PE image (MZ/PE headers)? A bash shim named `npx`
    /// with no extension exists but must not be treated as spawnable (R0.5).
    fn is_pe(&self, path: &str) -> bool;
    /// Reparse point — junction, symlink, or an App Execution Alias stub
    /// (the `WindowsApps` Store trap). Default: VirtualFs never has these.
    fn is_reparse(&self, _path: &str) -> bool { false }
}

/// Normalize for Windows comparison — what the OS applies to every
/// component before a name lookup reaches the filesystem:
/// `/`→`\`, `.`/`..` collapse, and trailing dots/spaces stripped from
/// EACH component (`dir.oo.` == `diroo` — the CVE-2024-43402 surface
/// where `npx.` and `npx .` alias the same file).
/// Purely lexical + lowercase: no symlinks, junctions, or 8.3 names.
pub fn canon(path: &str) -> String {
    let p = path.replace('/', "\\");
    let (verbatim, p) = match p.strip_prefix("\\?\\") {
        Some(r) => (true, r.to_string()),
        None => (false, p.strip_prefix("\\.\\").map(str::to_string).unwrap_or(p)),
    };
    let is_unc = p.starts_with("\\");
    let (drive, rest) = if p.len() >= 2 && p.as_bytes()[1] == b':' {
        (Some(p[..2].to_string()), &p[2..])
    } else {
        (None, p.as_str())
    };
    let mut out: Vec<&str> = Vec::new();
    for (i, comp) in rest.split('\\').enumerate() {
        if comp.is_empty() {
            continue;
        }
        if verbatim || (is_unc && i < 2) {
            out.push(comp);
            continue;
        }
        match comp.trim_end_matches(['.', ' ']) {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            c => out.push(c),
        }
    }
    let joined = out.join("\\");
    match (drive, is_unc) {
        (Some(d), _) => format!("{d}\\{joined}"),
        (None, true) => format!("\\\\{joined}"),
        _ => joined,
    }
    .to_ascii_lowercase()
}
/// Same canonicalization as  but preserving case — for display: the
/// file the OS will actually open.  is the comparison key.
pub fn canon_path(path: &str) -> String {
    let c = canon(path);
    // canon lowercases for comparison; rebuild the display form by keeping
    // structure but original case: cheap approach — re-run the normalization
    // without the final lowercase.
    let p = path.replace('/', "\\");
    let (verbatim, p) = match p.strip_prefix("\\\\?\\") {
        Some(r) => (true, r.to_string()),
        None => (false, p.strip_prefix("\\\\.\\").map(str::to_string).unwrap_or(p)),
    };
    let is_unc = p.starts_with("\\");
    let (drive, rest) = if p.len() >= 2 && p.as_bytes()[1] == b':' {
        (Some(p[..2].to_string()), &p[2..])
    } else {
        (None, p.as_str())
    };
    let mut out: Vec<&str> = Vec::new();
    for (i, comp) in rest.split('\\').enumerate() {
        if comp.is_empty() { continue; }
        if verbatim || (is_unc && i < 2) { out.push(comp); continue; }
        match comp.trim_end_matches(['.', ' ']) {
            "" | "." => {}
            ".." => { out.pop(); }
            c => out.push(c),
        }
    }
    let joined = out.join("\\");
    let _ = c;
    match (drive, is_unc) {
        (Some(d), _) => format!("{d}\\{joined}"),
        (None, true) => format!("\\\\{joined}"),
        _ => joined,
    }
}



/// DOS reserved device names — they "exist" on every Windows machine via the
/// DOS device namespace regardless of PATH, but nothing matching one is a
/// spawnable PE. `spawn('con')` hits this class.
pub fn is_device_name(file: &str) -> bool {
    let base = file.rsplit(['\\', '/']).next().unwrap_or(file);
    let stem = base.split('.').next().unwrap_or(base);
    matches!(stem.to_ascii_uppercase().as_str(), "CON" | "PRN" | "AUX" | "NUL"
        | "COM1" | "COM2" | "COM3" | "COM4" | "COM5" | "COM6" | "COM7" | "COM8" | "COM9"
        | "LPT1" | "LPT2" | "LPT3" | "LPT4" | "LPT5" | "LPT6" | "LPT7" | "LPT8" | "LPT9")
}

/// Join `dir` + `name` with a backslash, tolerating a trailing separator.
pub fn join(dir: &str, name: &str) -> String {
    if dir.ends_with('\\') || dir.ends_with('/') {
        format!("{dir}{name}")
    } else {
        format!("{dir}\\{name}")
    }
}

/// Declared files for deterministic tests — the corpus runtime.
#[derive(Debug, Default)]
pub struct VirtualFs {
    files: HashSet<String>,
    pe: HashSet<String>,
    reparse: HashSet<String>,
}

impl VirtualFs {
    pub fn new() -> Self {
        Self::default()
    }
    /// Register a file; `pe` marks it as a native executable image.
    pub fn file(mut self, path: &str, pe: bool) -> Self {
        let c = canon(path);
        self.files.insert(c.clone());
        if pe {
            self.pe.insert(c);
        }
        self
    }
    /// Register a file as a reparse point (junction / App Execution Alias).
    pub fn reparse_file(mut self, path: &str) -> Self {
        let c = canon(path);
        self.files.insert(c.clone());
        self.reparse.insert(c);
        self
    }
}

impl Fs for VirtualFs {
    fn file_exists(&self, path: &str) -> bool {
        self.files.contains(&canon(path))
    }
    fn is_pe(&self, path: &str) -> bool {
        self.pe.contains(&canon(path))
    }
    fn is_reparse(&self, path: &str) -> bool {
        self.reparse.contains(&canon(path))
    }
}

/// The real machine — used when the user asks about their actual PATH.
pub struct RealFs;

impl Fs for RealFs {
    fn file_exists(&self, path: &str) -> bool {
        std::fs::metadata(path).map(|m| m.is_file()).unwrap_or(false)
    }
    fn is_reparse(&self, path: &str) -> bool {
        use std::os::windows::fs::MetadataExt;
        // FILE_ATTRIBUTE_REPARSE_POINT (0x400) — App Execution Aliases are
        // reparse-point stubs whose target is the Microsoft Store page.
        std::fs::metadata(path)
            .and_then(|m| Ok(m.file_attributes()))
            .map(|a: u32| a & 0x400 != 0)
            .unwrap_or(false)
    }

    fn is_pe(&self, path: &str) -> bool {
        use std::io::{Read, Seek, SeekFrom};
        let Ok(mut f) = std::fs::File::open(path) else {
            return false;
        };
        let mut mz = [0u8; 2];
        if f.read_exact(&mut mz).is_err() || &mz != b"MZ" {
            return false;
        }
        // e_lfanew at 0x3C → "PE\0\0" — cheap sanity beyond just MZ.
        let mut off = [0u8; 4];
        if f.seek(SeekFrom::Start(0x3C)).is_err() || f.read_exact(&mut off).is_err() {
            return true; // MZ alone is enough evidence on real images
        }
        let pos = u32::from_le_bytes(off) as u64;
        let mut sig = [0u8; 4];
        f.seek(SeekFrom::Start(pos)).is_ok()
            && f.read_exact(&mut sig).is_ok()
            && &sig == b"PE\0\0"
    }
}
