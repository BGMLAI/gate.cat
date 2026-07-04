"""koryto_sandbox — szczelne wykonanie kodu Z RUCHU dla koryto-exec.

KONTEKST (workflow exec-hardening, 5 pentesterów, 26 udanych ataków na naiwny sandbox,
REJESTR 2026-06-27): koryto-exec wykonuje kod by zweryfikować odpowiedź modelu. Gdy kod
pochodzi z `query` użytkownika = WROGIE WEJŚCIE. Naiwny subprocess+timeout jest dziurawy:
  - format-string omija deny-list AST ('{0.__class__.__bases__}'.format(()))
  - runner leakuje os.environ (sekrety) + pełne builtins (eval/exec/open)
  - Windows brak `import resource` → DoS-limity martwe (9**9**9 pali CPU)
  - subclasses()-chain → Popen bez importu

OBRONA (równoległe, niezależne mury + fail-closed):
  A. ast_gate ALLOW-LIST (default-deny) — dozwolone tylko bezpieczne węzły; Attribute
     zakazany BEZWARUNKOWO; Call tylko do SAFE_BUILTINS; statyczne capy anty-DoS.
  B. __builtins__ = SAFE_DICT — nawet gdyby gadget dotarł do runtime, brak eval/exec/open.
  C. isolated interp: python -I -S -E (bez env/site/usersite).
  D. clean env: tylko PATH minimal + SYSTEMROOT — NIGDY os.environ (sekrety nie istnieją w dziecku).
  E. OS limits: Linux setrlimit+setsid; Windows Job Object (fail-closed gdy setup zawiedzie).

UCZCIWY LIMIT (rekomendacja pentesterów): czysty pip-sandbox NIE jest w pełni szczelny
dla wrogiego JS / DoS-na-Windows. Auto-exec kodu z ruchu domyślnie OFF. Pełna izolacja
= deploy-level (kontener/microVM). Te warstwy = mocna obrona in-process, nie zastępują
izolacji kernela.
"""
from __future__ import annotations

import ast
import os
import subprocess
import sys
from dataclasses import dataclass
from typing import Optional

# --- limity statyczne (jedyna obrona anty-DoS cross-platform, bo resource brak na Win) ---
MAX_CODE_BYTES = 2048
MAX_AST_NODES = 500
MAX_AST_DEPTH = 50
MAX_INT_DIGITS = 7          # Constant int >7 cyfr (>~10^7) → DROP (anti 9**9**9 wynik)
MAX_POW_EXP = 20            # BinOp Pow z prawym Constant > 20 → DROP
MAX_SEQ_MULT = 1000        # 'a'*N / [0]*N z N>1000 → DROP
MAX_RANGE_ARG = 10 ** 6    # range/list arg Constant > 10^6 → DROP

# Nazwy site-builtins / introspekcyjne zakazane nawet jako bare Name (load).
# (-S usuwa license/help w runtime, ale blokujemy statycznie dla pewności i czytelności.)
DENY_NAMES = frozenset({
    "license", "help", "copyright", "credits", "exit", "quit", "breakpoint",
    "__import__", "eval", "exec", "compile", "open", "input", "globals", "locals",
    "vars", "getattr", "setattr", "delattr", "hasattr", "type", "object", "super",
    "memoryview", "bytearray", "bytes", "__builtins__", "__loader__", "__spec__",
})

# Białe listy: TYLKO te builtins wolno wołać (default-deny dla reszty).
SAFE_BUILTINS = frozenset({
    "len", "range", "sum", "min", "max", "abs", "round", "sorted", "int", "float",
    "str", "list", "dict", "set", "tuple", "bool", "enumerate", "zip", "map",
    "filter", "reversed", "chr", "ord", "divmod", "pow", "all", "any",
    "print",  # bezpieczny: pisze do stdout (który czytamy), nie daje escape
})

# Dozwolone typy węzłów AST (default-deny: cokolwiek spoza → DROP).
_ALLOWED_NODES = (
    ast.Module, ast.Interactive, ast.Expression, ast.Expr,
    ast.Assign, ast.AnnAssign, ast.AugAssign,
    ast.Name, ast.Load, ast.Store, ast.Constant,
    ast.BinOp, ast.UnaryOp, ast.BoolOp, ast.Compare,
    ast.Add, ast.Sub, ast.Mult, ast.Div, ast.FloorDiv, ast.Mod, ast.Pow,
    ast.LShift, ast.RShift, ast.BitOr, ast.BitXor, ast.BitAnd, ast.MatMult,
    ast.USub, ast.UAdd, ast.Not, ast.Invert,
    ast.And, ast.Or,
    ast.Eq, ast.NotEq, ast.Lt, ast.LtE, ast.Gt, ast.GtE, ast.Is, ast.IsNot, ast.In, ast.NotIn,
    ast.List, ast.Tuple, ast.Dict, ast.Set,
    ast.Subscript, ast.Slice, ast.Index if hasattr(ast, "Index") else ast.Slice,
    ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp, ast.comprehension,
    ast.IfExp, ast.keyword, ast.Starred,
    ast.Call,  # dozwolony WARUNKOWO (tylko Name w SAFE_BUILTINS) — sprawdzane osobno
)


@dataclass
class GateResult:
    ok: bool
    reason: str = ""


def _ast_depth(node, depth=0):
    children = list(ast.iter_child_nodes(node))
    if not children:
        return depth
    return max(_ast_depth(c, depth + 1) for c in children)


def ast_gate(code: str, lang: str = "python") -> GateResult:
    """Allow-list AST + statyczne capy. fail-closed: cokolwiek nierozpoznane → DROP."""
    if lang != "python":
        # JS: regex-deny niedo­obronienia → auto-exec OFF (chyba że vm-wrapper, osobna ścieżka)
        return GateResult(False, "js-exec-disabled (regex-deny nie do obronienia; wymaga vm-wrapper)")
    if not code or not code.strip():
        return GateResult(False, "pusty kod")
    if len(code.encode("utf-8")) > MAX_CODE_BYTES:
        return GateResult(False, f"kod > {MAX_CODE_BYTES}B")
    try:
        tree = ast.parse(code, mode="exec")
    except (SyntaxError, ValueError, RecursionError) as e:
        return GateResult(False, f"parse-fail: {type(e).__name__}")

    nodes = list(ast.walk(tree))
    if len(nodes) > MAX_AST_NODES:
        return GateResult(False, f"za dużo węzłów AST (>{MAX_AST_NODES})")
    if _ast_depth(tree) > MAX_AST_DEPTH:
        return GateResult(False, f"AST za głębokie (>{MAX_AST_DEPTH})")

    # zbierz nazwy zdefiniowane LOKALNIE (przypisania + targety comprehension + args lambda)
    # — wolno je wołać (np. [g() for g in fns] gdzie g to lambda). Bezpieczne, bo Attribute
    # zakazany + builtins-firewall + brak importów; lokalna nazwa nie da dostępu do gadgetów.
    local_names = set()
    for node in nodes:
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            local_names.add(node.id)
        elif isinstance(node, ast.arg):
            local_names.add(node.arg)
    # lambda jest dozwolona (potrzebna dla flagowego [lambda: i ...]) — dodaj jej węzły
    _allowed = _ALLOWED_NODES + (ast.Lambda, ast.arguments, ast.arg)

    for node in nodes:
        # ATTRIBUTE zakazany BEZWARUNKOWO (zabija .format/.__class__/.gi_frame/.mro)
        if isinstance(node, ast.Attribute):
            return GateResult(False, "ast.Attribute zakazany (gadget chains)")
        # nieznany typ węzła → DROP (default-deny)
        if not isinstance(node, _allowed):
            return GateResult(False, f"węzeł niedozwolony: {type(node).__name__}")
        # Name (load): zakaz nazw z DENY (site-gadgety/introspekcja), nawet bez Call
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            if node.id in DENY_NAMES:
                return GateResult(False, f"nazwa zakazana: {node.id}")
        # CALL tylko do Name w SAFE_BUILTINS lub nazwy zdefiniowanej lokalnie
        if isinstance(node, ast.Call):
            if not isinstance(node.func, ast.Name):
                return GateResult(False, f"Call do nie-Name: {type(node.func).__name__}")
            if node.func.id not in SAFE_BUILTINS and node.func.id not in local_names:
                return GateResult(False, f"Call do niedozwolonej funkcji: {node.func.id}")
        # statyczne capy anty-DoS
        if isinstance(node, ast.Constant):
            if isinstance(node.value, int) and not isinstance(node.value, bool):
                if len(str(abs(node.value))) > MAX_INT_DIGITS:
                    return GateResult(False, f"literal int > {MAX_INT_DIGITS} cyfr (DoS)")
            if isinstance(node.value, str) and len(node.value) > MAX_CODE_BYTES:
                return GateResult(False, "literal str za długi")
        if isinstance(node, ast.BinOp):
            # Pow: wykładnik MUSI być małym literałem całkowitym. Inaczej DROP — to zabija
            # wieżę potęg 9**9**9 (prawy operand = BinOp Pow, nie Constant → DROP) oraz 10**9.
            if isinstance(node.op, ast.Pow):
                r = node.right
                if not (isinstance(r, ast.Constant) and isinstance(r.value, int)
                        and not isinstance(r.value, bool) and 0 <= r.value <= MAX_POW_EXP):
                    return GateResult(False, f"potęga: wykładnik musi być literałem 0..{MAX_POW_EXP} (DoS)")
                # gdy baza też literał — policz statycznie i odrzuć gdy wynik za duży
                # (łapie 10**9, 10**10: wynik >7 cyfr → DROP). Nie-literałowa baza: dozwolona
                # (np. x**2 gdzie x mała lokalna), bo cap int na literałach i tak ogranicza wejścia.
                if isinstance(node.left, ast.Constant) and isinstance(node.left.value, int) \
                        and not isinstance(node.left.value, bool):
                    try:
                        val = node.left.value ** r.value
                        if len(str(abs(val))) > MAX_INT_DIGITS:
                            return GateResult(False, f"potęga: wynik > {MAX_INT_DIGITS} cyfr (DoS)")
                    except Exception:
                        return GateResult(False, "potęga: niepoliczalna statycznie (DoS)")
            # mnożenie sekwencji: List/Str/Tuple * N gdzie N duże LUB nie-literał
            if isinstance(node.op, ast.Mult):
                for side, other in ((node.left, node.right), (node.right, node.left)):
                    if isinstance(side, (ast.List, ast.Tuple)) or \
                       (isinstance(side, ast.Constant) and isinstance(side.value, str)):
                        # mnożnik musi być małym literałem
                        if not (isinstance(other, ast.Constant) and isinstance(other.value, int)
                                and not isinstance(other.value, bool) and abs(other.value) <= MAX_SEQ_MULT):
                            return GateResult(False, f"mnożenie sekwencji: mnożnik > {MAX_SEQ_MULT} lub nie-literał (DoS)")
        # range/list z dużym argumentem
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and \
           node.func.id in ("range", "list"):
            for a in node.args:
                if isinstance(a, ast.Constant) and isinstance(a.value, int) and a.value > MAX_RANGE_ARG:
                    return GateResult(False, f"{node.func.id}() arg > {MAX_RANGE_ARG} (DoS)")

    return GateResult(True, "")


# --- SAFE builtins dict (warstwa B: firewall runtime, niezależny od AST) ---
def _safe_builtins_dict() -> dict:
    import builtins as _b
    safe = {}
    for name in SAFE_BUILTINS:
        if hasattr(_b, name):
            safe[name] = getattr(_b, name)
    # True/False/None potrzebne jako stałe — i tak są słowami kluczowymi, ale dla pewności
    return safe


def _clean_env() -> dict:
    """Środowisko dziecka: tylko niezbędne. NIGDY os.environ (sekrety OPENAI/BRAVE
    nie wyciekną). PATH zawiera katalog interpretera (potrzebny by python.dll się
    załadował — to runtime-path, nie sekret) + systemowe minimum."""
    env = {}
    # katalog python.exe ORAZ base_prefix (venv-na-uv: python.exe to shim, prawdziwy
    # interpreter+DLL żyje w base_prefix — bez niego "Unable to create process").
    interp_dir = os.path.dirname(sys.executable)
    base_dir = getattr(sys, "base_prefix", sys.prefix)
    if sys.platform == "win32":
        sysroot = os.environ.get("SYSTEMROOT", r"C:\Windows")
        env["SYSTEMROOT"] = sysroot
        parts = [interp_dir, os.path.join(interp_dir, "Scripts"),
                 base_dir, os.path.join(base_dir, "Scripts"),
                 os.path.join(sysroot, "System32"), sysroot]
        env["PATH"] = os.pathsep.join(dict.fromkeys(parts))  # dedup, zachowaj kolejność
    else:
        parts = [interp_dir, os.path.join(base_dir, "bin"), "/usr/bin", "/bin"]
        env["PATH"] = os.pathsep.join(dict.fromkeys(parts))
    return env


def _linux_limits(timeout: float, mem_mb: int):
    """preexec_fn dla Linux: setrlimit (mem/cpu/nproc/fsize) + setsid (kill grupy)."""
    def _apply():
        import resource  # tylko Linux
        mem_bytes = mem_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
        cpu = max(1, int(timeout) + 1)
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
        resource.setrlimit(resource.RLIMIT_NPROC, (0, 0))      # fork-bomb
        resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))      # zakaz zapisu
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (16, 16))
        except Exception:
            pass
        os.setsid()
    return _apply


@dataclass
class SandboxResult:
    ok: bool                 # czy wykonano (False = odrzucono/błąd, NIE wynik kodu)
    stdout: Optional[str] = None
    reason: str = ""


def run_sandboxed(code: str, *, lang: str = "python", timeout: float = 5.0,
                  mem_mb: int = 256) -> SandboxResult:
    """Wykonaj kod w izolowanym procesie. fail-closed: gdy izolacja niemożliwa → NIE wykonuj.

    Warstwa A (ast_gate) MUSI być wywołana PRZED tym (caller), ale dla pewności robimy
    ją też tu (gate na granicy wykonania = każda ścieżka exec przez sandbox).
    """
    gate = ast_gate(code, lang)
    if not gate.ok:
        return SandboxResult(False, reason=f"gate-drop: {gate.reason}")
    if lang != "python":
        return SandboxResult(False, reason="js-exec-disabled")

    env = _clean_env()
    # warstwa B: opakuj kod w harness wymuszający SAFE __builtins__
    # (kod sam już przeszedł allow-list, ale to drugi mur)
    harness = (
        "_b=__builtins__\n"
        "_src=_b if isinstance(_b,dict) else vars(_b)\n"
        "_safe={}\n"
        "for _n in (" + ",".join(repr(n) for n in sorted(SAFE_BUILTINS)) + "):\n"
        "    if _n in _src: _safe[_n]=_src[_n]\n"
        "_ns={'__builtins__':_safe}\n"
        "exec(compile(" + repr(code) + ",'<koryto>','exec'), _ns)\n"
    )
    # bazowy interpreter, NIE venv-shim: shim (np. venv-na-uv) zależy od zmiennych
    # __PYVENV_LAUNCHER__ których clean-env nie ma → "Unable to create process".
    py = getattr(sys, "_base_executable", None) or sys.executable
    argv = [py, "-I", "-S", "-E", "-c", harness]

    kwargs = dict(capture_output=True, text=True, timeout=timeout, env=env)
    if sys.platform != "win32":
        kwargs["preexec_fn"] = _linux_limits(timeout, mem_mb)
        try:
            r = subprocess.run(argv, **kwargs)
            return SandboxResult(True, stdout=(r.stdout or "").strip())
        except subprocess.TimeoutExpired:
            return SandboxResult(False, reason="timeout")
        except Exception as e:
            return SandboxResult(False, reason=f"exec-error: {type(e).__name__}")
    else:
        # Windows: brak resource. Job Object jako WARUNEK (fail-closed gdy setup padnie).
        return _run_windows_jobobject(argv, env, timeout, mem_mb)


def run_context_guard(stmts, *, timeout: float = 5.0, mem_mb: int = 256) -> SandboxResult:
    """Wykonaj context-guard koryto (statementy[:-1] jako setup, [-1] jako eval) w sandboxie.

    BEZPIECZEŃSTWO: gate'uje KAŻDY statement użytkownika (allow-list AST) PRZED złożeniem
    harnessu. Harness sam (ns={}, exec, eval, print) jest NASZ/zaufany — nie przechodzi przez
    gate (inaczej własny exec/eval by się zablokował). Trust-boundary: gate na WEJŚCIU usera,
    harness deterministyczny. Wykonanie: izolowany interp + clean env + Job Object/rlimit.
    """
    stmts = [str(s) for s in (stmts or []) if str(s).strip()]
    if not stmts:
        return SandboxResult(False, reason="brak statementów")
    # gate na każdym statemencie usera (połączone, by złapać wieloliniowe konstrukcje)
    joined = "\n".join(stmts)
    gate = ast_gate(joined, "python")
    if not gate.ok:
        return SandboxResult(False, reason=f"gate-drop: {gate.reason}")

    # zaufany harness context-guard (NIE przez gate — to nasz kod, nie usera)
    setup = "\n".join(f"exec({s!r}, ns)" for s in stmts[:-1])
    harness = (
        "_b=__builtins__\n"
        "_src=_b if isinstance(_b,dict) else vars(_b)\n"
        "_safe={}\n"
        "for _n in (" + ",".join(repr(n) for n in sorted(SAFE_BUILTINS)) + "):\n"
        "    if _n in _src: _safe[_n]=_src[_n]\n"
        "ns={'__builtins__':_safe}\n"
        + setup + "\n"
        "print(eval(" + repr(stmts[-1]) + ", ns))\n"
    )
    py = getattr(sys, "_base_executable", None) or sys.executable
    argv = [py, "-I", "-S", "-E", "-c", harness]
    env = _clean_env()
    if sys.platform != "win32":
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout,
                               env=env, preexec_fn=_linux_limits(timeout, mem_mb))
            return SandboxResult(True, stdout=(r.stdout or "").strip())
        except subprocess.TimeoutExpired:
            return SandboxResult(False, reason="timeout")
        except Exception as e:
            return SandboxResult(False, reason=f"exec-error: {type(e).__name__}")
    return _run_windows_jobobject(argv, env, timeout, mem_mb)


def _run_windows_jobobject(argv, env, timeout: float, mem_mb: int) -> SandboxResult:
    """Windows: uruchom w Job Object z limitem pamięci + kill-on-close. fail-closed."""
    try:
        import ctypes
        from ctypes import wintypes
    except Exception:
        return SandboxResult(False, reason="ctypes-unavailable (fail-closed)")

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    # stałe
    JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
    CREATE_NO_WINDOW = 0x08000000
    CREATE_BREAKAWAY_FROM_JOB = 0x01000000

    try:
        hJob = kernel32.CreateJobObjectW(None, None)
        if not hJob:
            return SandboxResult(False, reason="CreateJobObject-fail (fail-closed)")

        # JOBOBJECT_EXTENDED_LIMIT_INFORMATION — uproszczona struktura
        class IO_COUNTERS(ctypes.Structure):
            _fields_ = [("ReadOperationCount", ctypes.c_ulonglong),
                        ("WriteOperationCount", ctypes.c_ulonglong),
                        ("OtherOperationCount", ctypes.c_ulonglong),
                        ("ReadTransferCount", ctypes.c_ulonglong),
                        ("WriteTransferCount", ctypes.c_ulonglong),
                        ("OtherTransferCount", ctypes.c_ulonglong)]

        class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", wintypes.LARGE_INTEGER),
                        ("PerJobUserTimeLimit", wintypes.LARGE_INTEGER),
                        ("LimitFlags", wintypes.DWORD),
                        ("MinimumWorkingSetSize", ctypes.c_size_t),
                        ("MaximumWorkingSetSize", ctypes.c_size_t),
                        ("ActiveProcessLimit", wintypes.DWORD),
                        ("Affinity", ctypes.POINTER(wintypes.ULONG)),
                        ("PriorityClass", wintypes.DWORD),
                        ("SchedulingClass", wintypes.DWORD)]

        class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
                        ("IoInfo", IO_COUNTERS),
                        ("ProcessMemoryLimit", ctypes.c_size_t),
                        ("JobMemoryLimit", ctypes.c_size_t),
                        ("PeakProcessMemoryUsed", ctypes.c_size_t),
                        ("PeakJobMemoryUsed", ctypes.c_size_t)]

        info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = (
            JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_ACTIVE_PROCESS |
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
        info.BasicLimitInformation.ActiveProcessLimit = 1
        # floor 512MB: Python interpreter + importy potrzebują bazowo ~kilkaset MB;
        # niższy limit zabija start procesu (ZMIERZONE: 256MB → proces nie wypisuje).
        info.ProcessMemoryLimit = max(mem_mb, 512) * 1024 * 1024

        JobObjectExtendedLimitInformation = 9
        ok = kernel32.SetInformationJobObject(
            hJob, JobObjectExtendedLimitInformation, ctypes.byref(info), ctypes.sizeof(info))
        if not ok:
            kernel32.CloseHandle(hJob)
            return SandboxResult(False, reason="SetInformationJobObject-fail (fail-closed)")

        # uruchom proces (bez suspend — Popen nie daje uchwytu wątku do ResumeThread),
        # natychmiast przypisz do Job. Mikro-okno przed assign akceptowalne: gate już
        # zablokował groźny kod, a Job egzekwuje limit pamięci/kill dla DoS.
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 env=env, creationflags=CREATE_NO_WINDOW)
        try:
            hProc = int(proc._handle)
            # FAIL-CLOSED (audyt 2026-06-27 #9): jeśli przypisanie do Job padnie, proces
            # leci BEZ limitu pamięci → DoS omija cap. Sprawdź wynik (SetInformationJobObject
            # wyżej JEST sprawdzany — to była niespójność). Assign-fail → zabij i odrzuć.
            assigned = kernel32.AssignProcessToJobObject(hJob, hProc)
            if not assigned:
                try:
                    proc.kill()
                except Exception:
                    pass
                kernel32.CloseHandle(hJob)
                return SandboxResult(False, reason="job-assign-fail (fail-closed)")
            out, _err = proc.communicate(timeout=timeout)
            kernel32.CloseHandle(hJob)
            return SandboxResult(True, stdout=(out.decode("utf-8", "replace") if out else "").strip())
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
                subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)],
                               capture_output=True, timeout=5)
            except Exception:
                pass
            kernel32.CloseHandle(hJob)  # KILL_ON_JOB_CLOSE ubije resztę drzewa
            return SandboxResult(False, reason="timeout")
    except Exception as e:
        return SandboxResult(False, reason=f"jobobject-setup-fail: {type(e).__name__} (fail-closed)")
