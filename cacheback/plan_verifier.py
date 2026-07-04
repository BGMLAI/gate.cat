"""plan_verifier — koryto POSTEPU PROJEKTU. Agent deklaruje 'etap zrobiony' (RZEKA),
verifier wymaga DETERMINISTYCZNEGO, NIEZALEZNEGO DOWODU (KORYTO) zanim oznaczy done.

TEORIA (Aksjomat 1 / tau, BGML): 'zrobione' bez dowodu = confident-wrong postepu —
rzeka deklaracji wylewa z koryta faktu. To samo koryto co w koryto.py, inna domena.

=== MODEL ZAUFANIA (najwazniejsze — naprawione po adversarial review) ===
Verifier ma ODWROCONY model zaufania wzgledem koryto_sandbox. Tam wrogiem jest kod
Z RUCHU (agent=zaufany). TU evidence (selektor testu, sciezka, argv, url) dostarcza
SAM WERYFIKOWANY AGENT = strona NIEZAUFANA. Dlatego:

  1. EVIDENCE pochodzi z immutable spec (PlanStep) — verifier NIE czyta dowodu z
     narracji/desc agenta. Konsument planu dostarcza spec ZEWNETRZNIE.
  2. POSTEP (progress_pct, all_proven) liczy TYLKO `proven AND hard`. Kanal miekki
     (url) = jak `stale`: needs_recheck, NIE wlicza sie do twardego postepu. Inaczej
     agent stawia endpoint 200 i "udowadnia" etap.
  3. KANALY HARD sa zawezone do takich, ktorych agent NIE moze strywializowac:
     - test: pytest selektor MUSI zebrac >0 testow (collected>0) i przejsc. Pusty/no-op
       collect = unproven. (Pelna obrona przed no-op wymaga coverage-diff — patrz LIMITS.)
     - file: istnieje + niepusty + OBOWIAZKOWY must_contain (substring). Sciezka liczona
       od korzenia PAKIETU; ZERO repo-root fallback (dziura z review: trafial w stary
       plik pietro wyzej). Bez must_contain -> unproven.
     - command: allow-list binarek (pytest/python/...) — NIE deny-list wzorcow (deny =
       default-allow = nie do obronienia, jak JS-regex w koryto_sandbox). Komenda spoza
       allow-listy -> unproven+flagged. exit 0 + opcjonalny expect_in_stdout.
     - benchmark: NIE jest kanalem HARD. Metryka z agent-skryptu = RZEKA. -> stale/soft.
     - url: MIEKKI (hard=False, needs_recheck). 2xx + must_contain -> 'stale' (nie proven-hard).

GRANICA (uczciwa): proven-hard znaczy 'niezalezny dowod tej formy przeszedl', NIE 'etap
idealny'. test-proven = selektor zebral i zazielenil sie; file-proven = plik jest i zawiera
wymagany token. progress_pct liczy TYLKO te. Fail-closed: kazda niejasnosc (brak dowodu,
blad kanalu, dowod spoza allow-listy, siec) = unproven/stale, NIGDY proven-hard.

LIMITS (jawne, nie ukrywane): verifier NIE wykrywa, czy zielony test faktycznie pokrywa
zmieniony kod (to wymaga coverage-diff vs baseline git). Mierzy 'dowod istnieje i przechodzi',
nie 'dowod jest wystarczajacy'. To honest-floor, nie gwarancja.

Zero zaleznosci poza stdlib. Reuse _clean_env z koryto_sandbox (clean env, bez sekretow).
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional, Sequence

# Korzen pakietu cacheback (…/packages/cacheback). file-evidence liczony STAD.
# ZERO repo-root fallback — to byla dziura: stary bgml.ai/ARCHITECTURE.md "udowadnial"
# etap docs cacheback. Sciezka MUSI byc jednoznaczna w pakiecie.
_PKG_ROOT = Path(__file__).resolve().parent.parent

# Allow-list binarek dla kanalu `command`/`test`/`benchmark`. Default-DENY: cokolwiek
# spoza listy -> unproven+flagged. To odwrotnosc deny-listy (ktora jest nie do obronienia).
_ALLOWED_BINARIES = frozenset({
    "python", "python3", "py", sys.executable and Path(sys.executable).name or "python",
    "pytest", "coverage",
})


def _env() -> dict:
    """Srodowisko podprocesow: clean env z koryto_sandbox (PATH minimal, bez sekretow).
    Fail-soft: gdy import niemozliwy, minimalny PATH+SYSTEMROOT."""
    try:
        from cacheback.koryto_sandbox import _clean_env
        return _clean_env()
    except Exception:
        env = {"PATH": os.environ.get("PATH", "")}
        if sys.platform == "win32":
            env["SYSTEMROOT"] = os.environ.get("SYSTEMROOT", r"C:\Windows")
        return env


def _ascii(s: str) -> str:
    """ASCII-only do detail/print (Windows cp1252 crashuje na Unicode w print())."""
    return (s or "").encode("ascii", "replace").decode("ascii")


def _binary_allowed(argv: Sequence[str]) -> bool:
    """True gdy pierwszy element argv jest na allow-liscie binarek. Fail-closed:
    pusty argv / nie-lista -> False (nie wykonuj). Bierze samo basename bez sciezki."""
    if not argv or isinstance(argv, str):
        return False
    head = str(argv[0]).strip().strip('"')
    name = Path(head).name.lower()
    # zdejmij .exe (Windows)
    if name.endswith(".exe"):
        name = name[:-4]
    return name in {b.lower() for b in _ALLOWED_BINARIES if b}


# ======================================================================
# SPEC KROKU (immutable — dostarczany ZEWNETRZNIE, nie z narracji agenta)
# ======================================================================

@dataclass(frozen=True)
class PlanStep:
    """Jeden krok planu z DOWODEM. frozen=True: po utworzeniu niezmienny (immutable spec).

    evidence_kind: test | file | url | command | benchmark | none
    Pola dowodu zaleza od kind:
      test:      selector (sciezka::funkcja lub plik), wzgledem PKG_ROOT
      file:      path (wzgledem PKG_ROOT), must_contain (OBOWIAZKOWY substring), min_bytes
      url:       url, must_contain (substring w body) — kanal MIEKKI
      command:   argv (lista, binarka z allow-listy), expect_in_stdout (opcjonalny)
      benchmark: argv (jw.), metric_key, threshold — kanal MIEKKI (nie hard)
      none:      brak dowodu -> ZAWSZE unproven (sedno: deklaracja bez dowodu)
    """
    id: str
    desc: str
    evidence_kind: str = "none"
    # test
    selector: Optional[str] = None
    # file
    path: Optional[str] = None
    must_contain: Optional[str] = None
    min_bytes: int = 1
    # url
    url: Optional[str] = None
    # command / benchmark
    argv: Optional[tuple] = None
    expect_in_stdout: Optional[str] = None
    metric_key: Optional[str] = None
    threshold: Optional[float] = None


@dataclass
class StepVerdict:
    """Wynik weryfikacji jednego kroku. Analog KorytoVerdict.

    status:
      "proven"   — kanal HARD wykonal sie niezaleznie i potwierdzil.
      "stale"    — kanal MIEKKI (url/benchmark) potwierdzil, ale nieautorytatywnie ->
                   needs_recheck. NIE liczy sie do twardego progress_pct (fail-closed).
      "unproven" — brak dowodu / dowod padl / spoza allow-listy / deklaracja-bez-dowodu.
                   caught: confident-wrong postepu zlapany.
    """
    step_id: str
    status: str                        # proven | stale | unproven
    evidence_kind: str                 # test | file | url | command | benchmark | none
    detail: str = ""
    hard: bool = False
    needs_recheck: bool = False
    flagged: bool = False              # dowod spoza allow-listy / podejrzany -> NIE wykonano
    desc: str = ""

    @property
    def proven(self) -> bool:
        return self.status == "proven"

    @property
    def caught(self) -> bool:
        """Analog KorytoVerdict.caught: confident-wrong postepu zlapany."""
        return self.status == "unproven"

    def to_dict(self) -> dict:
        return {
            "step_id": self.step_id,
            "status": self.status,
            "evidence_kind": self.evidence_kind,
            "detail": self.detail,
            "hard": self.hard,
            "needs_recheck": self.needs_recheck,
            "flagged": self.flagged,
            "desc": self.desc,
        }


@dataclass
class PlanReport:
    """Raport calego planu. Fail-closed agregacja: TWARDY postep liczony z proven AND hard."""
    verdicts: list = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.verdicts)

    @property
    def proven_hard(self) -> int:
        """Liczba krokow z TWARDYM dowodem. Url/benchmark (miekkie) NIE wchodza."""
        return sum(1 for v in self.verdicts if v.status == "proven" and v.hard)

    @property
    def stale(self) -> int:
        return sum(1 for v in self.verdicts if v.status == "stale")

    @property
    def unproven(self) -> int:
        return sum(1 for v in self.verdicts if v.status == "unproven")

    @property
    def progress_pct(self) -> float:
        """% TWARDEGO postepu. 0 krokow -> 0.0 (NIE 100 — pusty plan != ukonczony)."""
        if self.total == 0:
            return 0.0
        return round(100.0 * self.proven_hard / self.total, 1)

    @property
    def all_proven(self) -> bool:
        """True TYLKO gdy sa kroki I wszystkie maja TWARDY dowod. Pusty plan -> False."""
        return self.total > 0 and self.proven_hard == self.total

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "proven_hard": self.proven_hard,
            "stale": self.stale,
            "unproven": self.unproven,
            "progress_pct": self.progress_pct,
            "all_proven": self.all_proven,
            "verdicts": [v.to_dict() for v in self.verdicts],
        }


class PlanVerifier:
    """Sklada kanaly dowodu. fetch_fn wstrzykiwalny TYLKO do testow (mock sieci);
    w produkcji url uzywa urllib. NIGDY nie czyta dowodu z desc/narracji."""

    def __init__(self, *, timeout_s: float = 120.0,
                 fetch_fn: Optional[Callable[[str], tuple]] = None):
        self.timeout_s = timeout_s
        self._fetch_fn = fetch_fn  # (url)->(status_code, body) — tylko test

    # ---- kanaly ----

    def _verify_test(self, step: PlanStep) -> StepVerdict:
        sel = step.selector
        if not sel:
            return StepVerdict(step.id, "unproven", "test", "brak selektora", desc=step.desc)
        # plik testowy musi istniec (selektor 'plik::func' -> plik)
        test_path = _PKG_ROOT / sel.split("::", 1)[0]
        if not test_path.exists():
            return StepVerdict(step.id, "unproven", "test",
                               _ascii(f"plik testu nie istnieje: {sel}"), desc=step.desc)
        argv = [sys.executable, "-m", "pytest", sel, "-q", "--no-header"]
        try:
            r = subprocess.run(argv, cwd=str(_PKG_ROOT), env=_env(),
                               capture_output=True, text=True, timeout=self.timeout_s)
        except Exception as e:
            return StepVerdict(step.id, "unproven", "test",
                               _ascii(f"pytest blad/timeout: {e}"), desc=step.desc)
        out = (r.stdout or "") + (r.stderr or "")
        # collected>0: pusty/no-op collect ('no tests ran') -> unproven
        if "no tests ran" in out.lower() or re.search(r"collected 0 items", out, re.I):
            return StepVerdict(step.id, "unproven", "test",
                               "pytest zebral 0 testow (no-op/pusty selektor)", desc=step.desc)
        if r.returncode == 0:
            m = re.search(r"(\d+)\s+passed", out)
            n = m.group(1) if m else "?"
            return StepVerdict(step.id, "proven", "test",
                               _ascii(f"pytest {sel}: {n} passed (exit 0)"),
                               hard=True, desc=step.desc)
        return StepVerdict(step.id, "unproven", "test",
                           _ascii(f"pytest exit {r.returncode}"), desc=step.desc)

    def _verify_file(self, step: PlanStep) -> StepVerdict:
        if not step.path:
            return StepVerdict(step.id, "unproven", "file", "brak sciezki", desc=step.desc)
        # must_contain OBOWIAZKOWY (bez niego 'plik istnieje' to nie dowod etapu)
        if not step.must_contain:
            return StepVerdict(step.id, "unproven", "file",
                               "brak must_contain (wymagany dla file-evidence)", desc=step.desc)
        p = _PKG_ROOT / step.path   # ZERO repo-root fallback
        if not p.exists() or not p.is_file():
            return StepVerdict(step.id, "unproven", "file",
                               _ascii(f"plik nie istnieje w pakiecie: {step.path}"), desc=step.desc)
        try:
            data = p.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            return StepVerdict(step.id, "unproven", "file",
                               _ascii(f"odczyt nieudany: {e}"), desc=step.desc)
        if len(data.encode("utf-8")) < max(1, step.min_bytes):
            return StepVerdict(step.id, "unproven", "file", "plik za maly", desc=step.desc)
        if step.must_contain not in data:
            return StepVerdict(step.id, "unproven", "file",
                               _ascii(f"brak wymaganego tokenu: {step.must_contain[:40]}"),
                               desc=step.desc)
        return StepVerdict(step.id, "proven", "file",
                           _ascii(f"plik ok + zawiera token: {step.path}"),
                           hard=True, desc=step.desc)

    def _verify_url(self, step: PlanStep) -> StepVerdict:
        """Kanal MIEKKI: 2xx + must_contain -> 'stale' (needs_recheck), NIE proven-hard."""
        if not step.url:
            return StepVerdict(step.id, "unproven", "url", "brak url", desc=step.desc)
        try:
            if self._fetch_fn is not None:
                code, body = self._fetch_fn(step.url)
            else:
                req = urllib.request.Request(step.url, headers={"User-Agent": "plan-verifier"})
                with urllib.request.urlopen(req, timeout=min(self.timeout_s, 20)) as resp:
                    code = resp.status
                    body = resp.read(200_000).decode("utf-8", "replace")
        except Exception as e:
            return StepVerdict(step.id, "unproven", "url",
                               _ascii(f"fetch nieudany: {e}"), desc=step.desc)
        if not (200 <= int(code) < 300):
            return StepVerdict(step.id, "unproven", "url",
                               _ascii(f"HTTP {code} (nie 2xx)"), desc=step.desc)
        if step.must_contain and step.must_contain not in body:
            return StepVerdict(step.id, "unproven", "url",
                               _ascii(f"2xx ale brak tokenu: {step.must_contain[:40]}"),
                               desc=step.desc)
        # 2xx (+token) ale siec moze klamac (cache/CDN) -> stale, nie twardy postep
        return StepVerdict(step.id, "stale", "url",
                           _ascii(f"HTTP {code} ok (miekki, needs_recheck): {step.url}"),
                           hard=False, needs_recheck=True, desc=step.desc)

    def _verify_command(self, step: PlanStep) -> StepVerdict:
        argv = list(step.argv) if step.argv else []
        if not _binary_allowed(argv):
            return StepVerdict(step.id, "unproven", "command",
                               _ascii(f"binarka spoza allow-listy: {argv[:1]}"),
                               flagged=True, desc=step.desc)
        try:
            r = subprocess.run(argv, cwd=str(_PKG_ROOT), env=_env(),
                               capture_output=True, text=True, timeout=self.timeout_s)
        except Exception as e:
            return StepVerdict(step.id, "unproven", "command",
                               _ascii(f"blad/timeout: {e}"), desc=step.desc)
        if r.returncode != 0:
            return StepVerdict(step.id, "unproven", "command",
                               _ascii(f"exit {r.returncode}"), desc=step.desc)
        if step.expect_in_stdout and step.expect_in_stdout not in (r.stdout or ""):
            return StepVerdict(step.id, "unproven", "command",
                               "exit 0 ale brak expect_in_stdout", desc=step.desc)
        return StepVerdict(step.id, "proven", "command",
                           _ascii(f"{argv[0]} exit 0"), hard=True, desc=step.desc)

    def _verify_benchmark(self, step: PlanStep) -> StepVerdict:
        """Kanal MIEKKI: metryka z agent-skryptu = RZEKA -> 'stale', NIE proven-hard."""
        argv = list(step.argv) if step.argv else []
        if not _binary_allowed(argv):
            return StepVerdict(step.id, "unproven", "benchmark",
                               _ascii(f"binarka spoza allow-listy: {argv[:1]}"),
                               flagged=True, desc=step.desc)
        if not step.metric_key or step.threshold is None:
            return StepVerdict(step.id, "unproven", "benchmark",
                               "brak metric_key/threshold", desc=step.desc)
        try:
            r = subprocess.run(argv, cwd=str(_PKG_ROOT), env=_env(),
                               capture_output=True, text=True, timeout=self.timeout_s)
        except Exception as e:
            return StepVerdict(step.id, "unproven", "benchmark",
                               _ascii(f"blad/timeout: {e}"), desc=step.desc)
        val = _parse_metric(r.stdout or "", step.metric_key)
        if val is None:
            return StepVerdict(step.id, "unproven", "benchmark",
                               _ascii(f"brak metryki {step.metric_key} w stdout"), desc=step.desc)
        if val >= step.threshold:
            return StepVerdict(step.id, "stale", "benchmark",
                               _ascii(f"{step.metric_key}={val}>={step.threshold} (miekki)"),
                               hard=False, needs_recheck=True, desc=step.desc)
        return StepVerdict(step.id, "unproven", "benchmark",
                           _ascii(f"{step.metric_key}={val}<{step.threshold}"), desc=step.desc)

    # ---- dispatch ----

    def verify_step(self, step: PlanStep) -> StepVerdict:
        kind = (step.evidence_kind or "none").lower()
        try:
            if kind == "test":
                return self._verify_test(step)
            if kind == "file":
                return self._verify_file(step)
            if kind == "url":
                return self._verify_url(step)
            if kind == "command":
                return self._verify_command(step)
            if kind == "benchmark":
                return self._verify_benchmark(step)
            # none / nieznany -> ZAWSZE unproven (deklaracja bez dowodu)
            return StepVerdict(step.id, "unproven", "none",
                               "brak zadeklarowanego dowodu", desc=step.desc)
        except Exception as e:  # catch-all: kazda niespodzianka = unproven (fail-closed)
            return StepVerdict(step.id, "unproven", kind,
                               _ascii(f"wyjatek kanalu: {e}"), desc=step.desc)

    def verify_plan(self, steps: Sequence[PlanStep]) -> PlanReport:
        return PlanReport(verdicts=[self.verify_step(s) for s in steps])


def _parse_metric(stdout: str, key: str) -> Optional[float]:
    """Wyciagnij metryke z JSON-linii lub 'key: value' w stdout. None gdy brak."""
    # ostatnia linia wygladajaca na JSON
    for line in reversed(stdout.strip().splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                d = json.loads(line)
                if key in d and isinstance(d[key], (int, float)):
                    return float(d[key])
            except Exception:
                pass
    m = re.search(rf"{re.escape(key)}\s*[:=]\s*([0-9.]+)", stdout)
    return float(m.group(1)) if m else None
