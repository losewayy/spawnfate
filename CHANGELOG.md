# Changelog

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
