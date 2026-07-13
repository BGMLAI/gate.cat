"""`gate.cat dashboard` — the richer, cross-machine view (client-decrypted).

Two data sources, merged locally:

  * the LOCAL veto log (~/.gatecat/veto_log.jsonl) — plaintext, this machine,
    full command/policy/reason. This half is FREE and always available.
  * the CROSS-MACHINE ciphertext fetched from the cloud AND DECRYPTED LOCALLY
    (E2EE — the server never sees any of it). This half is the SUBSCRIPTION
    value: aggregation across the fleet, per-machine breakdown, the off-machine
    tamper-evident ledger. It appears only when a cloud key + API key are set.

The hosted/cross-machine aggregation is the paid part; the RENDERING is always
client-side (the server cannot read events). No cloud key => this degrades to a
richer render of the local log alone — the free local dashboard still works.

Output is a rich TERMINAL view by default; `gate.cat dashboard --html [file]`
writes a self-contained static HTML page the user opens in a browser (the key
lives where the render happens — on the user's machine).
"""
from __future__ import annotations

import html as _html
import json
import os
import sys
from collections import Counter
from typing import Optional


def _local_records() -> list:
    """Full local log (plaintext, this machine)."""
    try:
        from gatecat.integrations.dashboard import _read
        return _read()
    except Exception:
        return []


def _cloud_records() -> tuple:
    """Fetch + decrypt the cross-machine ciphertext. Returns (events, note).

    events: decrypted event dicts (empty if no cloud key / not entitled / error).
    note:   a human string describing why cloud data is or isn't present.
    """
    if not os.environ.get("GATECAT_CLOUD_API_KEY"):
        return [], "cloud off (no GATECAT_CLOUD_API_KEY) — showing local only"
    try:
        from gatecat import cloud_cli
        rows = cloud_cli._decrypt_all(cloud_cli._fetch())
        events = [e for e in rows if not e.get("_undecryptable")]
        undec = len(rows) - len(events)
        note = f"cross-machine: {len(events)} event(s) decrypted locally"
        if undec:
            note += f" ({undec} undecryptable — wrong key?)"
        return events, note
    except SystemExit:
        return [], "cloud key set but CLI reported it is off"
    except Exception as e:  # never let the dashboard crash on a network error
        return [], f"cloud fetch failed ({type(e).__name__}) — showing local only"


def _machine_of(ev: dict) -> str:
    """Best-effort per-machine label for the team breakdown."""
    return str(ev.get("machine") or ev.get("host") or ev.get("source") or "?")


def build_model(local: list, cloud: list) -> dict:
    """Aggregate a render-model from both sources (pure; easy to test)."""
    def summarize(records):
        dec = Counter(r.get("decision", "?") for r in records)
        pol = Counter(r.get("policy") for r in records
                      if r.get("decision") in ("block", "warn") and r.get("policy"))
        return {"total": len(records), "dec": dec, "pol": pol}

    ledger = [r for r in cloud if r.get("decision") in (
        "armed", "disarmed", "disarmed_off",
        "override_grant", "override_allow", "override_deny")]
    stagn = [r for r in (local + cloud) if r.get("decision") == "stagnation"]
    vetoes = [r for r in (local + cloud) if r.get("decision") == "block"]
    per_machine = Counter(_machine_of(r) for r in cloud) if cloud else Counter()

    return {
        "local": summarize(local),
        "cloud": summarize(cloud),
        "recent_vetoes": vetoes[-10:],
        "ledger": ledger[-20:],
        "stagnation": stagn[-10:],
        "per_machine": per_machine,
        "has_cloud": bool(cloud),
    }


def render_terminal(model: dict, note: str, color: bool = True) -> str:
    from gatecat.integrations.dashboard import _color
    c = _color(color)
    L, C = model["local"], model["cloud"]
    lines = [c("gate.cat dashboard", "bold"), "=" * 48,
             c(f"  {note}", "grey"), ""]
    lines.append(f"  local (this machine): {L['total']} watched  "
                 f"blocked={L['dec'].get('block', 0)}  warn={L['dec'].get('warn', 0)}")
    if model["has_cloud"]:
        lines.append(f"  cross-machine (fleet): {C['total']} events  "
                     f"blocked={C['dec'].get('block', 0)}")
        if model["per_machine"]:
            lines.append("")
            lines.append("  per-machine:")
            for m, n in model["per_machine"].most_common(10):
                lines.append(f"    {m[:32]:<32}  {n:>5} events")
    else:
        lines.append(c("  cross-machine: (subscribe + set a cloud key to aggregate "
                       "your fleet here)", "grey"))
    if model["recent_vetoes"]:
        lines += ["", "  recent vetoes:"]
        for r in reversed(model["recent_vetoes"]):
            cmd = (r.get("context") or r.get("ctx_sha256") or "").replace("\n", " ")[:44]
            lines.append(f"    {c(r.get('policy', '?') or '?', 'red'):<24}  {cmd}")
    if model["ledger"]:
        lines += ["", "  override / toggle ledger (off-machine):"]
        for r in model["ledger"][-8:]:
            lines.append(f"    {r.get('decision', '?'):<16}  "
                         f"{(r.get('context') or r.get('ctx_sha256') or '')[:36]}")
    if model["stagnation"]:
        lines += ["", f"  loop-guard / stagnation events: {len(model['stagnation'])}"]
        for r in model["stagnation"][-5:]:
            lines.append(f"    {c('no-progress', 'yellow')}  "
                         f"{(r.get('reason') or '')[:48]}")
    return "\n".join(lines)


def render_html(model: dict, note: str) -> str:
    """A self-contained static HTML page (no external assets)."""
    L, C = model["local"], model["cloud"]

    def esc(s):
        return _html.escape(str(s))

    rows = []
    for r in reversed(model["recent_vetoes"]):
        rows.append(f"<tr><td class=b>{esc(r.get('policy') or '?')}</td>"
                    f"<td>{esc((r.get('context') or r.get('ctx_sha256') or '')[:80])}</td></tr>")
    veto_rows = "".join(rows) or "<tr><td colspan=2>no vetoes</td></tr>"

    led = []
    for r in model["ledger"]:
        led.append(f"<tr><td>{esc(r.get('decision') or '?')}</td>"
                   f"<td>{esc((r.get('context') or r.get('ctx_sha256') or '')[:80])}</td></tr>")
    ledger_rows = "".join(led) or "<tr><td colspan=2>no ledger records</td></tr>"

    machines = "".join(
        f"<tr><td>{esc(m)}</td><td>{n}</td></tr>"
        for m, n in model["per_machine"].most_common(20)) or \
        "<tr><td colspan=2>(no cross-machine data — set a cloud key)</td></tr>"

    return f"""<!doctype html><meta charset=utf-8>
<title>gate.cat dashboard</title>
<style>body{{font-family:ui-monospace,Menlo,monospace;max-width:820px;margin:5vh auto;
padding:0 18px;background:#fbfaf2;color:#141410;line-height:1.5}}
h1{{font-family:Arial,sans-serif}} .card{{border:1px solid #dbe79a;border-radius:10px;
padding:14px 16px;margin:14px 0;background:#fff}} table{{width:100%;border-collapse:collapse}}
td{{padding:5px 8px;border-bottom:1px solid #eee;font-size:13px}} .b{{color:#a11}}
.note{{color:#777}} .k{{font-size:26px;font-weight:bold}}</style>
<h1>gate.cat dashboard</h1>
<p class=note>{esc(note)} — rendered locally; the server never reads your events.</p>
<div class=card><div class=k>{L['total']}</div>local commands watched
 ({L['dec'].get('block', 0)} blocked, {L['dec'].get('warn', 0)} warned)</div>
<div class=card><b>Cross-machine (fleet)</b>
<table>{machines}</table></div>
<div class=card><b>Recent vetoes</b><table>{veto_rows}</table></div>
<div class=card><b>Override / toggle ledger (off-machine)</b><table>{ledger_rows}</table></div>
"""


def main(argv: list) -> int:
    """`gate.cat dashboard [--html [file]]`."""
    as_html = "--html" in argv
    file_arg = None
    if as_html:
        rest = [a for a in argv if a != "--html"]
        file_arg = rest[0] if rest else None

    local = _local_records()
    cloud, note = _cloud_records()
    model = build_model(local, cloud)

    if as_html:
        page = render_html(model, note)
        if file_arg:
            with open(file_arg, "w", encoding="utf-8") as f:
                f.write(page)
            print(f"wrote dashboard -> {file_arg}  ({note})")
        else:
            sys.stdout.write(page)
        return 0

    from gatecat.integrations.dashboard import _use_color
    print(render_terminal(model, note, _use_color()))
    return 0
