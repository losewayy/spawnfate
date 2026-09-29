# Changelog

## [1.0.0] — 2026-09-29

- **`Producer::WinSpawn` — a fourth fate.** Models caller-resolved Windows
  spawns: Rust `std::process::Command` / `tokio::process::Command` /
  `deno_task_shell` / Go `os/exec`. These do a `which`-style PATH+PATHEXT
  walk — **the working directory is never searched**, extensionless hits
  must pass `GetBinaryTypeW` (a text shim is skipped, not run) — then
  `CreateProcess` with MSVCRT argv quoting. `Command::new("npx")` finds
  `npx.cmd` where Node dies ENOENT and cmd gets fooled by the bare shim.
  New resolver `resolve_which` (R1.18); `spawnfate --producer winspawn`
  exposes it on the CLI.
- **selftest gained a Rust ground truth.** New `spawnprobe` helper binary
  reproduces the which-style resolve + `Command` spawn for real; seven new
  `winspawn` corpus cases verified against it (32 cases total, 0 diverged).
  File-not-found now also matches raw Win32 error 2 (localized messages
  carry the code, not English text).
- **The L4 table is measured now, and one rule in it was wrong.** Four
  ground-truth probes (MSVC CRT, shell32 `CommandLineToArgvW`, go1.27.1, a Rust
  binary) were fed the same crafted command lines through a verbatim
  `lpCommandLine`. `--target cltavw` turned out to model a pre-2008 CRT rather
  than `CommandLineToArgvW`: shell32 reads `"a""b c"` as two args, `a"b` and
  `c` — as Go does — not as `ab c`. The parser, the spec table and the unit
  test are corrected, and `l4-cltavw-divergence` pins it. Rust, measured the
  same way, is MSVCRT-standard on every vector including a malformed argv0, so
  there is no `--target rust` to add and the spec's argv[0] note is retracted.
- **R0.10 — a working directory that does not exist now dies before
  resolution**, instead of being silently assumed away. libuv chdirs before it
  execs, so the spawn fails `ENOENT` even when the name would have resolved;
  measured on node v24.15.0, and the new `cwd-missing-enoent` corpus case
  re-measures it through `selftest`. The assumption the model always made is
  now explicit (`env.cwd_missing`) and checkable.
- **`explain`**: read an error surface back to the layer that produced it —
  Win32 2 / 193, Node `ENOENT` / `EINVAL` / `EFTYPE`, and cmd's own complaint.
  Each reading cites the spec rule and the corpus case it rests on, prints the
  prescription, and prints the command that turns the reading into a verdict.
  `-` reads stdin; exit `0` matched, `4` not modelled. See
  [docs/explain.md](docs/explain.md).
- Measured (node v24.15.0): a `cwd` that does not exist surfaces as `ENOENT`
  (errno -4058), not Win32 status 3, so both failures read as one surface.

## [0.1.0] — 2026-09-26

Initial kernel.

- **L0 resolvers**: libuv `search_path`, cmd.exe PATH/PATHEXT walk, and the
  `CreateProcess` built-in search — modeled as three distinct resolvers.
- **L1 serialization**: MSVCRT-compatible argv quoting; Node's three shell
  modes (`none`, `cmd` → `/d /s /c "<verbatim>"`, other → `-c`); the
  CVE-2024-27980 EINVAL-on-batch gate.
- **L2 cmd re-parse**: `/c` `/s` quote-strip decision, metachar hazards
  (`& | < > ^`, `%VAR%`, `!delayed!`, newline injection), cmd builtins.
- **L4 argv parsers**: post-2008 MSVCRT, `CommandLineToArgvW`, Go, batch `%N`.
- **`selftest`**: materializes corpus cases and verifies predictions against
  real `node` spawns. 19/19 on first run; measured `EFTYPE` as Node's
  `ERROR_BAD_EXE_FORMAT` surface.
- `corpus/core.yaml`: 25 conformance cases with rule citations.
