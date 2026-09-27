# Reading an error back

`spawnfate explain` takes the error you already have — a Node stack, a Python
traceback, a Rust `io` error, cmd's own complaint — and names the layer that
produced it, the spec rule behind it, and the corpus case that demonstrates it.

```console
$ spawnfate explain "Error: spawn npx ENOENT"
== reading ==
  node-enoent (on "enoent")
  layer: Resolve
  rules: R1.14, R1.15
  case:  node-npx-enoent (corpus/core.yaml)
  means: Node/libuv reports the failure as `ENOENT` (errno -4058) instead of
         the Win32 text. The name reached the resolver and nothing in its
         candidate table matched — and that table only ever holds `.com` and
         `.exe` candidates, so a `.cmd` shim sitting on PATH is invisible to
         this resolver.
== prescription ==
  → [explain.route-via-comspec] Route the call through cmd.exe ...
== definite answer ==
  spawnfate <file> <args>
```

This is a **differential, not a verdict**. The error text cannot say whether a
name was missing, shadowed, or invisible to the resolver — it names the layer
and the candidates, and prints the command that settles it. With the exact
call, `spawnfate <file> <args>` is authoritative.

`-` reads stdin, so a pasted traceback works without quoting:

```console
$ pbpaste | spawnfate explain -
```

Exit code `0` when a surface matched, `4` when nothing did. `--json` emits the
hits with their signatures.

## Surfaces

| Surface | Layer | Rules | Demonstrated by |
|---|---|---|---|
| `[WinError 2] The system cannot find the file specified` | Resolve | R1.14, R1.15 | `node-npx-enoent` |
| Node `ENOENT` (errno -4058) | Resolve | R1.14, R1.15 | `node-npx-enoent` |
| Node `EINVAL` (errno -4071) | Serialize | R1.11, R1.12 | `node-npx-cmd-einval` |
| `[WinError 193] %1 is not a valid Win32 application`, Node `EFTYPE` | Exec | R1.14, R0.5 | `node-explicit-sh-193` |
| `'x' is not recognized as an internal or external command` | CmdParse | R1.16, R2.3 | `cmd-resolver-sees-pathext` |

## `[WinError 2]` / `ENOENT` — nothing resolved

Three resolvers answer to this name and none of them found a file. Which one
was asking decides what "found" means:

- **libuv** (Node's `spawn`) probes only `.com` and `.exe`, and probes CWD
  first. A `.cmd` shim on PATH is not a candidate at all.
- **`CreateProcess`** searches the application directory *before* CWD, and
  appends `.exe` implicitly.
- **cmd.exe** walks PATH with PATHEXT, and tries the extensionless name first.

Route the call through cmd.exe (`{shell:true}`, or `cmd.exe /c <name>`) to get
the PATHEXT walk, or name the batch explicitly and expect the next error to
change to `EINVAL`. `spawnfate <file> <args>` lists the candidates each
resolver would have probed.

## `EINVAL` — a batch file was named without a shell

Node refuses to bare-spawn a `.bat`/`.cmd` since CVE-2024-27980: a batch file
cannot be started without cmd.exe re-parsing the line. The refusal is
synchronous, so it surfaces at the `spawn` call rather than as an `error` event.

Do not arrive here by string surgery either — a name ending in `.cmd.` slips
past the extension guard and still resolves to a batch file (CVE-2024-43402).

## `[WinError 193]` / `EFTYPE` — found, but not startable

The name resolved and the file exists; the loader cannot start it. In practice
this is a shell script, a `.py` shim, or an extensionless Unix binary that rode
along on PATH. Node maps the Win32 status to `EFTYPE` (errno -4028).

Invoke the file through its interpreter (`sh <file>`, `python <file>`), or call
a real Windows executable. If the path is under `WindowsApps`, it is a Store
reparse stub, not a binary — use the real install path.

## `is not recognized as an internal or external command` — cmd's own complaint

This text comes from cmd.exe, so the line did reach cmd (usually through a
shell). cmd walks PATH with PATHEXT, which means a directory hit is not enough:
the extension has to be in PATHEXT too. And cmd probes the extensionless name
first, so a bash shim can shadow the `.cmd` sitting next to it.

## Not modelled yet

Each of these needs a corpus case before it can be read, because a rule without
a case is a claim:

- `[WinError 3] The system cannot find the path specified` — not what Node
  emits: a `cwd` that does not exist surfaces as `ENOENT` (measured, node
  v24.15.0), so the reading above already covers it. Win32 status 3 reaches a
  caller through other runtimes.
- `[WinError 740]` — the operation requires elevation.
- `[WinError 267]` — the directory name is invalid.
- PowerShell's two hops (CLR → the PS binder), and Java's `CP_ACP` re-parse.

If you hit one of these, the argv path still applies: `spawnfate <file> <args>`
predicts from the call instead of from the symptom.

## Matching

Needles are matched against a normalized form of the text: lower-cased, with
ASCII whitespace, `_` and `-` removed. So `ERROR_BAD_EXE_FORMAT`,
`error_bad_exe_format` and `error bad exe format` all hit the same signature,
and a pasted multi-line traceback matches without any pre-processing.
