"""truthgate audit — "Gate Report": measure, on SOMEONE'S model and SOMEONE'S data,
on how many queries the model is guessing, and how well the gate predicts it.

This is the product deliverable: the client provides (1) their model (Ollama / vLLM /
OpenAI-compatible base_url) + (2) a Q&A set with gold (200-500 pairs) → receives
a report with numbers ON THEIR DATA:
  - gate hit-rate (% of queries flagged as uncertain),
  - gate AUC (whether the spread predicts errors — requires gold to score correctness),
  - confident-wrong: how many errors the model makes CONFIDENTLY (the gate does NOT catch them — honestly),
  - list of the worst cases.

HONESTY (built into the report, not to be skipped):
  - AUC computed ONLY when n_wrong >= 10 (otherwise winner's curse, unreliable).
  - The report explicitly separates "uncertain-wrong" (gate catches) from "confident-wrong"
    (gate lets through) — this is a structural limitation, not an implementation flaw.
  - Gate = uncertainty flag, NOT a hallucination guarantee. It reports it that way too.

Q&A format (JSONL, one pair per line):
    {"q": "Who wrote Hamlet?", "gold": "Shakespeare", "aliases": ["william shakespeare"]}

Usage (CLI):
    truthgate-audit --model qwen2.5:7b --backend ollama \\
        --data clients_qa.jsonl --n-samples 5 --out gate_report.json

Usage (programmatic):
    from gatecat.audit import run_audit
    report = run_audit(sample_fn=my_llm, answer_fn=my_llm_greedy, data=pairs)
"""
from __future__ import annotations

import json
import re
import statistics
from dataclasses import dataclass, field
from typing import Callable, Sequence

from gatecat.gate import Gate

STOP = {"the", "a", "an", "of", "and", "to", "in", "is", "was", "by"}


def _normalize(s: str) -> str:
    s = (s or "").lower().strip()
    s = re.sub(r"[^\w\s]", " ", s)
    return re.sub(r"\s+", " ", s).strip()


def is_correct(answer: str, gold: str, aliases: Sequence[str] = ()) -> bool:
    """Exact-match with a guard (BGML Study B C1): empty pred does not match,
    alias >= 3 chars, word-boundary (not substring)."""
    if not answer or not answer.strip():
        return False
    na = _normalize(answer)
    for cand in [gold, *(aliases or [])]:
        nc = _normalize(cand)
        if len(nc) < 3 or nc in STOP:
            continue
        if re.search(rf"(?<!\w){re.escape(nc)}(?!\w)", na):
            return True
    return False


def _auc(disagreements: list[float], wrong_flags: list[bool]) -> float | None:
    """AUC: whether disagreement predicts an error. Mann-Whitney U / (n_pos*n_neg).
    Returns None when there are too few cases of each class (unreliable)."""
    pos = [d for d, w in zip(disagreements, wrong_flags) if w]      # wrong
    neg = [d for d, w in zip(disagreements, wrong_flags) if not w]  # correct
    if len(pos) < 10 or len(neg) < 10:
        return None  # winner's curse guard
    wins = 0.0
    for p in pos:
        for n in neg:
            if p > n:
                wins += 1.0
            elif p == n:
                wins += 0.5
    return wins / (len(pos) * len(neg))


@dataclass
class AuditReport:
    n: int
    n_correct: int
    n_wrong: int
    base_accuracy: float
    gate_flag_rate: float                  # % flagged as uncertain
    auc: float | None                      # whether the gate predicts errors (None when n_wrong<10)
    uncertain_wrong: int                   # errors THAT the gate caught (uncertain=True)
    confident_wrong: int                   # errors THAT the gate let through (uncertain=False) — UNCATCHABLE
    recall_on_errors: float                # uncertain_wrong / n_wrong
    false_alarm_rate: float                # correct-but-flagged / n_correct
    worst_confident_wrong: list[dict] = field(default_factory=list)
    threshold: float = 0.30
    n_samples: int = 5
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "summary": {
                "n_questions": self.n,
                "base_accuracy": round(self.base_accuracy, 3),
                "gate_flag_rate": round(self.gate_flag_rate, 3),
                "auc_gate_predicts_error": (round(self.auc, 3) if self.auc is not None else None),
                "recall_on_errors": round(self.recall_on_errors, 3),
                "false_alarm_rate": round(self.false_alarm_rate, 3),
            },
            "error_breakdown": {
                "total_wrong": self.n_wrong,
                "caught_by_gate_uncertain": self.uncertain_wrong,
                "missed_confident_wrong": self.confident_wrong,
            },
            "config": {"threshold": self.threshold, "n_samples": self.n_samples},
            "worst_confident_wrong": self.worst_confident_wrong,
            "honest_notes": self.notes,
        }

    def render_text(self) -> str:
        L = []
        L.append("=" * 56)
        L.append("  TRUTHGATE — GATE REPORT")
        L.append("=" * 56)
        L.append(f"  Questions:            {self.n}")
        L.append(f"  Model accuracy:       {self.base_accuracy:.1%}  ({self.n_correct}/{self.n})")
        L.append(f"  Gate flagged:         {self.gate_flag_rate:.1%}  as uncertain")
        if self.auc is not None:
            L.append(f"  AUC (gate→error):     {self.auc:.3f}  (>0.5 = gate predicts errors)")
        else:
            L.append(f"  AUC:                  N/A  (too few errors <10, unreliable)")
        L.append("-" * 56)
        L.append(f"  Errors total:         {self.n_wrong}")
        L.append(f"  ├ caught (uncertain): {self.uncertain_wrong}  ({self.recall_on_errors:.0%} of errors)")
        L.append(f"  └ LET THROUGH:        {self.confident_wrong}  (model is CONFIDENTLY wrong)")
        L.append(f"  False alarms:         {self.false_alarm_rate:.1%}  of correct answers flagged")
        L.append("-" * 56)
        for note in self.notes:
            L.append(f"  ⚠ {note}")
        L.append("=" * 56)
        return "\n".join(L)


def run_audit(
    *,
    sample_fn: Callable[[str], str],
    answer_fn: Callable[[str], str] | None,
    data: Sequence[dict],
    n_samples: int = 5,
    threshold: float = 0.30,
    embedder=None,
    progress: Callable[[int, int], None] | None = None,
) -> AuditReport:
    """Run a Q&A set through the gate + correctness scoring.

    sample_fn(prompt)->str : a sample at temp>0 (the gate calls it N times).
    answer_fn(prompt)->str : a deterministic answer (temp=0) for correctness scoring.
                             If None, uses the first sample from sample_fn.
    data : list of {"q","gold","aliases"?}.
    """
    gate = Gate(sample_fn=sample_fn, n_samples=n_samples, threshold=threshold, embedder=embedder)
    diss: list[float] = []
    wrongs: list[bool] = []
    flagged: list[bool] = []
    confident_wrong_cases: list[dict] = []

    for i, row in enumerate(data):
        q = row.get("q") or row.get("question") or ""
        gold = row.get("gold") or row.get("answer") or ""
        aliases = row.get("aliases") or []
        verdict = gate.check(q)
        final = (answer_fn(q) if answer_fn else (verdict.samples[0] if verdict.samples else ""))
        correct = is_correct(final, gold, aliases)
        diss.append(verdict.disagreement)
        wrongs.append(not correct)
        flagged.append(verdict.uncertain)
        if (not correct) and (not verdict.uncertain):
            confident_wrong_cases.append({
                "q": q[:120], "gold": gold, "model_answer": final[:160],
                "disagreement": round(verdict.disagreement, 3),
            })
        if progress:
            progress(i + 1, len(data))

    n = len(data)
    n_wrong = sum(wrongs)
    n_correct = n - n_wrong
    uncertain_wrong = sum(1 for w, f in zip(wrongs, flagged) if w and f)
    confident_wrong = n_wrong - uncertain_wrong
    correct_flagged = sum(1 for w, f in zip(wrongs, flagged) if (not w) and f)

    notes = [
        "The gate detects UNCERTAINTY (sample spread), not falsehood. "
        "'Confident-wrong' (the model is confidently wrong) is UNCATCHABLE by spread.",
        "AUC>0.5 means the gate predicts errors better than random. "
        "The value is an uncertainty flag for human review, NOT a correctness guarantee.",
    ]
    auc = _auc(diss, wrongs)
    if auc is None:
        notes.append(f"AUC skipped: too few errors or correct answers (<10) for reliability.")
    if confident_wrong > uncertain_wrong:
        notes.append(
            f"MOST errors ({confident_wrong}/{n_wrong}) are confident-wrong — "
            f"the gate alone will not catch them; cache/web/human needed on those queries.")

    confident_wrong_cases.sort(key=lambda c: c["disagreement"])  # most confident errors first
    return AuditReport(
        n=n, n_correct=n_correct, n_wrong=n_wrong,
        base_accuracy=(n_correct / n if n else 0.0),
        gate_flag_rate=(sum(flagged) / n if n else 0.0),
        auc=auc,
        uncertain_wrong=uncertain_wrong,
        confident_wrong=confident_wrong,
        recall_on_errors=(uncertain_wrong / n_wrong if n_wrong else 0.0),
        false_alarm_rate=(correct_flagged / n_correct if n_correct else 0.0),
        worst_confident_wrong=confident_wrong_cases[:10],
        threshold=threshold, n_samples=n_samples, notes=notes,
    )


# ---- model backends (Ollama / OpenAI-compatible) ----
def make_backend(model: str, backend: str = "ollama", base_url: str | None = None,
                 api_key: str | None = None):
    """Returns (sample_fn, answer_fn) for the given backend.
    sample_fn: temp=0.7 (gate samples). answer_fn: temp=0 (answer for scoring)."""
    import os
    import httpx

    if backend == "ollama":
        url = (base_url or "http://localhost:11434").rstrip("/") + "/api/chat"

        def _call(prompt: str, temperature: float) -> str:
            r = httpx.post(url, json={
                "model": model, "messages": [{"role": "user", "content": prompt}],
                "stream": False, "options": {"temperature": temperature},
            }, timeout=120.0)
            return (r.json().get("message") or {}).get("content", "") or ""
        return (lambda p: _call(p, 0.7), lambda p: _call(p, 0.0))

    # openai-compatible (vLLM, llama.cpp server, OpenAI, OpenRouter...)
    url = (base_url or "https://api.openai.com/v1").rstrip("/") + "/chat/completions"
    key = api_key or os.environ.get("OPENAI_API_KEY", "")
    headers = {"Authorization": f"Bearer {key}"} if key else {}

    def _call(prompt: str, temperature: float) -> str:
        r = httpx.post(url, headers=headers, json={
            "model": model, "messages": [{"role": "user", "content": prompt}],
            "temperature": temperature, "max_tokens": 256,
        }, timeout=120.0)
        return (r.json().get("choices") or [{}])[0].get("message", {}).get("content", "") or ""
    return (lambda p: _call(p, 0.7), lambda p: _call(p, 0.0))


def main(argv: list[str] | None = None) -> int:
    import argparse
    ap = argparse.ArgumentParser(prog="truthgate-audit", description="Gate Report on your model + your data")
    ap.add_argument("--model", required=True, help="model name (e.g. qwen2.5:7b)")
    ap.add_argument("--backend", default="ollama", choices=["ollama", "openai"])
    ap.add_argument("--base-url", default=None)
    ap.add_argument("--data", required=True, help="JSONL with {q, gold, aliases?}")
    ap.add_argument("--n-samples", type=int, default=5)
    ap.add_argument("--threshold", type=float, default=0.30)
    ap.add_argument("--semantic", action="store_true", help="use MiniLM for semantic spread")
    ap.add_argument("--out", default=None, help="save JSON report")
    ap.add_argument("--limit", type=int, default=0, help="limit the number of questions (0=all)")
    args = ap.parse_args(argv)

    data = []
    with open(args.data, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                data.append(json.loads(line))
    if args.limit:
        data = data[: args.limit]

    embedder = None
    if args.semantic:
        try:
            from gatecat.embedders import get_embedder
            embedder = get_embedder("minilm")
        except Exception as e:
            print(f"[warn] semantic embedder unavailable ({e}); lexical fallback")

    sample_fn, answer_fn = make_backend(args.model, args.backend, args.base_url)

    def prog(i, total):
        if i % 10 == 0 or i == total:
            print(f"  [{i}/{total}]", flush=True)

    print(f"Auditing model '{args.model}' ({args.backend}) on {len(data)} questions...")
    report = run_audit(
        sample_fn=sample_fn, answer_fn=answer_fn, data=data,
        n_samples=args.n_samples, threshold=args.threshold,
        embedder=embedder, progress=prog,
    )
    print()
    print(report.render_text())
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(report.to_dict(), f, ensure_ascii=False, indent=2)
        print(f"\nJSON report -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
