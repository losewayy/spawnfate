# spawnfate as an MCP server

`spawnfate mcp` speaks the Model Context Protocol over stdio, exposing one
tool — `analyze_spawn` — to any MCP-capable agent (Claude Code, Cursor,
Kimi, Cline, …). The intended workflow: **before an agent emits a
`spawn`/`subprocess`/`system` call that touches Windows, it asks spawnfate
what will happen.**

## Tool: `analyze_spawn`

| param | type | meaning |
|---|---|---|
| `file` | string (required) | program to spawn — bare name or path |
| `args` | string[] | argv vector, pre-serialization |
| `shell` | `"none" \| "cmd"` | `cmd` = Node `{shell:true}` (cmd re-parse) |
| `target` | `"msvcrt" \| "cltavw" \| "go" \| "batch"` | spawned program's argv dialect |
| `env` | object | optional synthetic environment — `cwd`, `path[]`, `pathext[]`, `cwd_missing`, `files[]`, `vars{}` |

The env surface is deliberately a subset of the model's switches: the ones an
agent asks about when it wonders "what would happen on a machine that isn't
this one". The rest (`node_bat_guard`, `delayed_expansion`,
`no_cd_in_exe_path`, `comspec`, …) live in the corpus, where a case can pin
them.

With no `env`, the prediction uses the machine's real PATH/PATHEXT/env.
With `env`, a synthetic filesystem is declared (`files`) and the analysis
runs purely against it — useful for "what would happen on a clean machine"
or reproducing a user's environment.

A `files` item is either a path string, or an object that carries the PE flag
explicitly:

```json
{ "path": "C:\\tools\\nodejs\\node.exe", "pe": true }
```

A string item means the file exists, and is treated as a PE image when its
extension is `.exe`/`.com`. Pass the object form when the extension is not a
reliable signal — an extensionless real image, or a `.exe` that is not one.
The flag decides the verdict: a resolved file that is not a PE image (and is
not `.bat`/`.cmd`) dies with `ERROR_BAD_EXE_FORMAT`.

Returns two content blocks: a human-readable finding list + verdict +
prescriptions, and the full structured report as JSON.

## Client configuration

Claude Desktop (`claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "spawnfate": {
      "command": "spawnfate",
      "args": ["mcp"]
    }
  }
}
```

Claude Code (`claude mcp add`):

```
claude mcp add spawnfate -- spawnfate mcp
```

Kimi Code / others: same shape — command `spawnfate`, args `["mcp"]`,
transport stdio.

## Claude Code hook alternative

If you'd rather *intercept* Bash calls than give the agent a tool it must
remember to call, a PreToolUse hook can run `spawnfate raw` on the command
string and warn on non-`Runs` verdicts. Example `.claude/settings.json`:

```json
{
  "hooks": {
    "PreToolUse": [{
      "matcher": "Bash",
      "hooks": [{
        "type": "command",
        "command": "spawnfate-hook.cmd"
      }]
    }]
  }
}
```

where `spawnfate-hook.cmd` reads the tool input JSON on stdin, extracts
`command`, runs `spawnfate raw <command> --json`, and exits non-zero with
stderr = the human summary when the verdict isn't `Runs`. (Hook JSON varies
by client version — the pattern is what matters.)
