# Migration guide

## 0.2.x → 0.3.0 (import rename)

0.3.0 renames the import module from `cacheback` to `gatecat`. The distribution
name is unchanged (`gate.cat` on PyPI, installed as `pip install gate-cat`); only
the top-level Python module changed. There is **no compatibility shim** for the
module — the old top-level name `cacheback` collided with an unrelated PyPI
package of the same name, which is a silent-shadowing risk in a security tool.

### What to change

| 0.2.x | 0.3.0 |
|---|---|
| `from cacheback.integrations import check_action` | `from gatecat.integrations import check_action` |
| `from cacheback import TruthPipeline` | `from gatecat import TruthPipeline` |
| `response.cacheback_hit` / `.cacheback_synthesized` | `response.gatecat_hit` / `.gatecat_synthesized` |
| `except CachebackError` / `CachebackBlocked` | `except GatecatError` / `GatecatBlocked` |
| console: `cacheback ...` / `cacheback-proxy` | `gatecat-cli ...` / `gatecat-proxy` |
| env: `CACHEBACK_*` (54 vars) | `GATECAT_*` |
| log dir `~/.cacheback/` | `~/.gatecat/` |

### Env vars: one-release safety net

Every `CACHEBACK_*` env var was renamed to `GATECAT_*`. To avoid silently
dropping an existing config, `import gatecat` copies any still-set `CACHEBACK_*`
var to its `GATECAT_*` name at import (new name wins if both are set) and emits a
single `DeprecationWarning` naming what to rename. **This shim is removed in
0.4** — rename your env vars now.

### Claude Code hook

The veto hook now ships inside the package. Register it by console script, not
by file path:

```json
{"hooks": {"PreToolUse": [{"matcher": "Bash|Write|Edit",
    "hooks": [{"type": "command", "command": "gatecat-hook"}]}]}}
```

If you had the old `.claude/settings.json` pointing at
`examples/.../veto_hook.py`, that path still works from a repo checkout (it now
fails closed if the package is missing), but the console script is the supported
path after `pip install gate-cat`.

### What does NOT change

The engine, the policies, the API surface (`VetoGate`, `before_action`,
`TruthPipeline`, `check_action`, `DOGFOOD_DEFAULTS`), and the honest line are
identical — this is a rename, not a rewrite. `koryto` and the project's naming
stay (canon).

## Older: `cacheback-ai` → `gate.cat`

The package was first published as `cacheback-ai`, then renamed to `gate.cat`.
The old `cacheback-ai` distribution on PyPI is deprecated and yanked at the
0.3.0 release; install `gate-cat`.
