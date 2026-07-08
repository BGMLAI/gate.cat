"""Large-corpus evaluation of the gate.cat action-veto on real agent commands.

Feeds thousands of REAL shell commands (extracted from published agent-trajectory
datasets) through the actual production entrypoint - guard.check_action with
DOGFOOD_DEFAULTS - and reports the block/warn/allow distribution plus every
blocked/warned command for false-block adjudication. This is the "does it work
on a large number of ready-made sets" check: the gate is only trustworthy if its
intervention rate on somebody else's agent traffic matches what we measured on
our own (no over/under-fitting), and if the blocks are genuinely dangerous.

Usage:
    python scripts/corpus_eval.py <corpus.jsonl|.parquet> [--source NAME] [--limit N]

Extractors are per-dataset (the JSON shape differs); add one and register it in
EXTRACTORS. Every extractor yields raw command strings; the harness dedups,
runs the gate, and writes results next to the corpus.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

# ensure the real (editable) gatecat is importable
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

os.environ.setdefault("GATECAT_VETO_EPHEMERAL", "0")  # measure ARMED behavior

from gatecat.integrations import check_action, ActionVetoed  # noqa: E402
from gatecat.integrations.policies import DOGFOOD_DEFAULTS  # noqa: E402


# --- gate: one command -> level -------------------------------------------
def classify(cmd: str, *, cwd: str, home: str) -> tuple[str, str | None]:
    """Return (level, policy). level in block|warn|allow. Never raises."""
    try:
        d = check_action("corpus", cmd, DOGFOOD_DEFAULTS, cwd=cwd, home=home)
        return d.level, d.policy
    except ActionVetoed:
        return "block", "raised"
    except Exception as exc:  # a crash IS a finding - surface, don't hide
        return "error", f"{type(exc).__name__}: {exc}"


# --- extractors: dataset JSON -> raw command strings ----------------------
def _iter_jsonl(path: Path):
    with path.open(encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                try:
                    yield json.loads(line)
                except ValueError:
                    continue


_BASH_NAMES = ("execute_bash", "run_bash", "bash")


def extract_nemotron(path: Path):
    """nvidia/Nemotron-RL-Agentic-SWE-Pivot-v1 uses the OpenAI *Responses API*
    shape: execute_bash calls are ``{"type":"function_call","name":"execute_bash",
    "arguments":"{...command...}"}`` items in responses_create_params.input[*],
    plus the expected_action and ref_message tool call. Walk all three."""
    for rec in _iter_jsonl(path):
        # 1) the expected next action
        ea = rec.get("expected_action") or {}
        if ea.get("name") in _BASH_NAMES:
            c = _cmd_from_args(ea.get("arguments"))
            if c:
                yield c
        # 2) every function_call already in the conversation history
        params = rec.get("responses_create_params") or {}
        for item in params.get("input", []) or []:
            if item.get("type") == "function_call" and item.get("name") in _BASH_NAMES:
                c = _cmd_from_args(item.get("arguments"))
                if c:
                    yield c
            # also handle chat-completions-style tool_calls if present
            for tc in (item.get("tool_calls") or []):
                fn = tc.get("function") or {}
                if fn.get("name") in _BASH_NAMES:
                    c = _cmd_from_args(fn.get("arguments"))
                    if c:
                        yield c
        # 3) the ref message (a function_call or a tool_calls carrier)
        rm = rec.get("ref_message") or {}
        if rm.get("type") == "function_call" and rm.get("name") in _BASH_NAMES:
            c = _cmd_from_args(rm.get("arguments"))
            if c:
                yield c
        for tc in (rm.get("tool_calls") or []):
            fn = tc.get("function") or {}
            if fn.get("name") in _BASH_NAMES:
                c = _cmd_from_args(fn.get("arguments"))
                if c:
                    yield c


def _cmd_from_args(arguments):
    """arguments may be a JSON string or a dict; pull out .command."""
    if arguments is None:
        return None
    if isinstance(arguments, str):
        try:
            arguments = json.loads(arguments)
        except ValueError:
            return None
    if isinstance(arguments, dict):
        c = arguments.get("command")
        return c if isinstance(c, str) and c.strip() else None
    return None


EXTRACTORS = {
    "nemotron": extract_nemotron,
}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("corpus")
    ap.add_argument("--source", default="nemotron", choices=list(EXTRACTORS))
    ap.add_argument("--limit", type=int, default=0, help="max unique commands (0=all)")
    ap.add_argument("--cwd", default="/workspace/repo", help="assumed agent cwd")
    ap.add_argument("--home", default="/root", help="assumed agent home")
    args = ap.parse_args()

    path = Path(args.corpus)
    extract = EXTRACTORS[args.source]

    # dedup while preserving first-seen order
    seen = {}
    for cmd in extract(path):
        if cmd not in seen:
            seen[cmd] = True
            if args.limit and len(seen) >= args.limit:
                break
    commands = list(seen)
    print(f"[{args.source}] unique commands extracted: {len(commands)}")

    levels = Counter()
    blocks, warns, errors = [], [], []
    for cmd in commands:
        level, policy = classify(cmd, cwd=args.cwd, home=args.home)
        levels[level] += 1
        if level == "block":
            blocks.append({"cmd": cmd, "policy": policy})
        elif level == "warn":
            warns.append({"cmd": cmd, "policy": policy})
        elif level == "error":
            errors.append({"cmd": cmd, "policy": policy})

    n = len(commands) or 1
    print(f"  block: {levels['block']:5} ({100*levels['block']/n:.2f}%)  = 1 in "
          f"{n // max(levels['block'],1)}")
    print(f"  warn:  {levels['warn']:5} ({100*levels['warn']/n:.2f}%)")
    print(f"  allow: {levels['allow']:5} ({100*levels['allow']/n:.2f}%)")
    print(f"  ERROR: {levels['error']:5} (crashes - must be 0)")

    out = path.with_name(f"{args.source}_gate_results.json")
    out.write_text(json.dumps({
        "source": args.source,
        "total_unique": len(commands),
        "levels": dict(levels),
        "intervention_rate": (levels["block"] + levels["warn"]) / n,
        "block_rate": levels["block"] / n,
        "blocks": blocks,
        "warns": warns[:200],
        "errors": errors,
    }, indent=2), encoding="utf-8")
    print(f"  -> {out}")
    if errors:
        print(f"  !! {len(errors)} CRASHES - first: {errors[0]['cmd'][:80]}")


if __name__ == "__main__":
    main()
