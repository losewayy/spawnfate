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
}

/// Normalize for Windows comparison: backslashes + case-insensitive.
pub fn canon(path: &str) -> String {
    path.replace('/', "\\").to_ascii_lowercase()
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
}

impl Fs for VirtualFs {
    fn file_exists(&self, path: &str) -> bool {
        self.files.contains(&canon(path))
    }
    fn is_pe(&self, path: &str) -> bool {
        self.pe.contains(&canon(path))
    }
}

/// The real machine — used when the user asks about their actual PATH.
pub struct RealFs;

impl Fs for RealFs {
    fn file_exists(&self, path: &str) -> bool {
        std::fs::metadata(path).map(|m| m.is_file()).unwrap_or(false)
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
