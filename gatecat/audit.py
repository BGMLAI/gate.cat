"""truthgate audit — "Gate Report": zmierz na CZYIMŚ modelu i CZYICH danych,
na ilu zapytaniach model zgaduje, i jak dobrze gate to przewiduje.

To jest deliverable produktu: klient daje (1) swój model (Ollama / vLLM /
OpenAI-compatible base_url) + (2) zbiór Q&A z gold (200-500 par) → dostaje
raport z liczbami NA JEGO DANYCH:
  - hit-rate gate (% zapytań oflagowanych jako niepewne),
  - AUC gate (czy rozrzut przewiduje błąd — wymaga gold do scoringu poprawności),
  - confident-wrong: ile błędów model popełnia PEWNIE (gate ich NIE łapie — uczciwie),
  - lista najgorszych przypadków.

UCZCIWOŚĆ (wbudowana w raport, nie do pominięcia):
  - AUC liczone TYLKO gdy n_wrong >= 10 (inaczej winner's curse, niewiarygodne).
  - Raport jawnie rozdziela "uncertain-wrong" (gate łapie) od "confident-wrong"
    (gate przepuszcza) — to jest strukturalne ograniczenie, nie wada implementacji.
  - Gate = uncertainty flag, NIE hallucination guarantee. Tak też raportuje.

Format Q&A (JSONL, jedna para/linia):
    {"q": "Who wrote Hamlet?", "gold": "Shakespeare", "aliases": ["william shakespeare"]}

Użycie (CLI):
    truthgate-audit --model qwen2.5:7b --backend ollama \\
        --data clients_qa.jsonl --n-samples 5 --out gate_report.json

Użycie (programowo):
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
    """Exact-match z guardem (BGML Badanie B C1): pusta pred nie matchuje,
    alias >= 3 znaki, word-boundary (nie substring)."""
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
    """AUC: czy disagreement przewiduje błąd. Mann-Whitney U / (n_pos*n_neg).
    Zwraca None gdy za mało przypadków każdej klasy (niewiarygodne)."""
    pos = [d for d, w in zip(disagreements, wrong_flags) if w]      # błędne
    neg = [d for d, w in zip(disagreements, wrong_flags) if not w]  # poprawne
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
    gate_flag_rate: float                  # % oflagowanych jako niepewne
    auc: float | None                      # czy gate przewiduje błąd (None gdy n_wrong<10)
    uncertain_wrong: int                   # błędy KTÓRE gate złapał (uncertain=True)
    confident_wrong: int                   # błędy KTÓRE gate przepuścił (uncertain=False) — NIEŁAPALNE
    recall_on_errors: float                # uncertain_wrong / n_wrong
    false_alarm_rate: float                # poprawne-ale-oflagowane / n_correct
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
        L.append(f"  Pytań:                {self.n}")
        L.append(f"  Dokładność modelu:    {self.base_accuracy:.1%}  ({self.n_correct}/{self.n})")
        L.append(f"  Gate oflagował:       {self.gate_flag_rate:.1%}  jako niepewne")
        if self.auc is not None:
            L.append(f"  AUC (gate→błąd):      {self.auc:.3f}  (>0.5 = gate przewiduje błędy)")
        else:
            L.append(f"  AUC:                  N/A  (za mało błędów <10, niewiarygodne)")
        L.append("-" * 56)
        L.append(f"  Błędów łącznie:       {self.n_wrong}")
        L.append(f"  ├ złapane (niepewne): {self.uncertain_wrong}  ({self.recall_on_errors:.0%} błędów)")
        L.append(f"  └ PRZEPUSZCZONE:      {self.confident_wrong}  (model myli się PEWNIE)")
        L.append(f"  Fałszywe alarmy:      {self.false_alarm_rate:.1%}  poprawnych oflagowano")
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
    """Przepuść zbiór Q&A przez gate + scoring poprawności.

    sample_fn(prompt)->str : próbka przy temp>0 (gate woła N razy).
    answer_fn(prompt)->str : odpowiedź deterministyczna (temp=0) do scoringu poprawności.
                             Jeśli None, używa pierwszej próbki z sample_fn.
    data : lista {"q","gold","aliases"?}.
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
        "Gate wykrywa NIEPEWNOSC (rozrzut probek), nie klamstwo. "
        "'Confident-wrong' (model myli sie pewnie) jest NIELAPALNY rozrzutem.",
        "AUC>0.5 oznacza ze gate przewiduje bledy lepiej niz losowo. "
        "Wartosc to uncertainty-flag do human-review, NIE gwarancja poprawnosci.",
    ]
    auc = _auc(diss, wrongs)
    if auc is None:
        notes.append(f"AUC pominiete: za malo bledow lub poprawnych (<10) dla wiarygodnosci.")
    if confident_wrong > uncertain_wrong:
        notes.append(
            f"WIEKSZOSC bledow ({confident_wrong}/{n_wrong}) to confident-wrong — "
            f"gate sam ich nie zlapie; potrzebny cache/web/human na tych zapytaniach.")

    confident_wrong_cases.sort(key=lambda c: c["disagreement"])  # najpewniejsze błędy pierwsze
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


# ---- backendy modelu (Ollama / OpenAI-compatible) ----
def make_backend(model: str, backend: str = "ollama", base_url: str | None = None,
                 api_key: str | None = None):
    """Zwraca (sample_fn, answer_fn) dla danego backendu.
    sample_fn: temp=0.7 (próbki gate). answer_fn: temp=0 (odpowiedź do scoringu)."""
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
    ap.add_argument("--model", required=True, help="nazwa modelu (np. qwen2.5:7b)")
    ap.add_argument("--backend", default="ollama", choices=["ollama", "openai"])
    ap.add_argument("--base-url", default=None)
    ap.add_argument("--data", required=True, help="JSONL z {q, gold, aliases?}")
    ap.add_argument("--n-samples", type=int, default=5)
    ap.add_argument("--threshold", type=float, default=0.30)
    ap.add_argument("--semantic", action="store_true", help="użyj MiniLM do rozrzutu semantycznego")
    ap.add_argument("--out", default=None, help="zapisz raport JSON")
    ap.add_argument("--limit", type=int, default=0, help="ogranicz liczbę pytań (0=wszystkie)")
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
            print(f"[warn] semantic embedder niedostepny ({e}); lexical fallback")

    sample_fn, answer_fn = make_backend(args.model, args.backend, args.base_url)

    def prog(i, total):
        if i % 10 == 0 or i == total:
            print(f"  [{i}/{total}]", flush=True)

    print(f"Audyt modelu '{args.model}' ({args.backend}) na {len(data)} pytaniach...")
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
        print(f"\nRaport JSON -> {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
