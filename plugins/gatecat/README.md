# gatecat — Claude Code plugin

Registers the gate.cat **PreToolUse veto hook** for `Bash`/`Write`/`Edit`:
irreversible commands (`rm -rf`, `DROP TABLE`, `terraform destroy`, disk
wipes, secret exfiltration) are blocked with exit code 2 **before** they
execute, and the reason is fed back to the model. Deterministic — no model
call in the veto path.

## Install

```bash
pip install gate.cat        # the free engine (Apache-2.0, zero-dep core)
```

then in Claude Code:

```
/plugin marketplace add BGMLAI/gate.cat
/plugin install gatecat@gatecat
```

The hook calls the `gatecat-hook` console script installed by pip — if the
package is missing, the hook fails visibly rather than silently allowing.

Honest limits: the gate is certain only about what it **blocks**; an
unmatched action is *unchecked*, not *safe*. Details, measurements and the
published bypass map: [FACTS.md](https://github.com/BGMLAI/gate.cat/blob/master/FACTS.md).
