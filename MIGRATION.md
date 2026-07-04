# cacheback-ai → gate.cat: one product, one name

The veto engine ships under **`gate.cat`**. `cacheback-ai` was the earlier name
for the same project and is being retired. This file is the canonical migration
note so nobody hits two PyPI packages in the first minute of due diligence and
assumes the project is abandoned or forked.

Rule (VETO_PIPELINE_PLAN.md, rada#2): **one name, one package, `pip install` →
working veto in three lines.** Two live names without an explicit deprecation is
chaos — this note removes it.

---

## For the founder — what to do at the gate.cat 0.1.0 release

1. **Publish `gate.cat` 0.1.0** with the real veto engine (see `PUBLISH.md`).
2. **Cut one final `cacheback-ai` release** (e.g. `0.2.1`) whose *only* change is
   the deprecation banner below, pasted at the TOP of its `README.md` /
   PyPI long-description, and this line in its `pyproject.toml`:

   ```toml
   [project]
   # keep installs working; the package still imports, but points users onward
   description = "DEPRECATED - renamed to gate.cat. pip install gate.cat"
   ```

   (Optionally add a `DeprecationWarning` at import time in `cacheback/__init__.py`
   — see snippet at the bottom.)
3. Do **not** delete `cacheback-ai` from PyPI. Deleting breaks anyone who already
   `pip install`ed it and is irreversible. Deprecate, don't destroy.

---

## Deprecation banner — paste into `cacheback-ai`'s README / PyPI description

> ## ⚠️ `cacheback-ai` has been renamed to **`gate.cat`**
>
> This package is deprecated. The action-veto engine — block irreversible agent
> actions (`terraform destroy`, `rm -rf`, force-push, payments) before they run —
> now ships as **[`gate.cat`](https://pypi.org/project/gate-cat/)**.
>
> ```bash
> pip uninstall cacheback-ai
> pip install gate.cat
> ```
>
> Same engine, same honest line (the gate is certain only about what it
> **blocks**; unchecked ≠ safe). `cacheback-ai` stays installable so existing
> pins don't break, but receives no further updates. New work → `gate.cat`.

---

## Import-time nudge (optional, in `cacheback-ai`'s `cacheback/__init__.py`)

```python
import warnings

warnings.warn(
    "cacheback-ai is deprecated and renamed to gate.cat. "
    "Install it with: pip install gate.cat",
    DeprecationWarning,
    stacklevel=2,
)
```

Keep it a `DeprecationWarning` (silent by default, visible under `-W` / pytest)
so it informs without breaking anyone's console.

---

## What does NOT change

- The engine, the API (`VetoGate`, `before_action`, `ActionVetoed`), the
  policies, the honest line — all identical. This is a rename, not a rewrite.
- `koryto` and the τ-theory naming stay (canon; README carries a one-line gloss
  for English readers, not a translation).
