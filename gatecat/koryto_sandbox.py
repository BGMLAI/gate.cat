"""koryto_sandbox — airtight execution of IN-FLIGHT code for koryto-exec.

CONTEXT (exec-hardening workflow, 5 pentesters, 26 successful attacks on the naive sandbox,
REGISTRY 2026-06-27): koryto-exec runs code to verify the model's answer. When the code
comes from the user's `query` = HOSTILE INPUT. A naive subprocess+timeout is leaky:
  - format-string bypasses the AST deny-list ('{0.__class__.__bases__}'.format(()))
  - the runner leaks os.environ (secrets) + full builtins (eval/exec/open)
  - Windows lacks `import resource` → DoS limits are dead (9**9**9 burns CPU)
  - subclasses()-chain → Popen without an import

DEFENSE (parallel, independent walls + fail-closed):
  A. ast_gate ALLOW-LIST (default-deny) — only safe nodes allowed; Attribute
     forbidden UNCONDITIONALLY; Call only to SAFE_BUILTINS; static anti-DoS caps.
  B. __builtins__ = SAFE_DICT — even if a gadget reached runtime, no eval/exec/open.
  C. isolated interp: python -I -S -E (no env/site/usersite).
  D. clean env: only minimal PATH + SYSTEMROOT — NEVER os.environ (secrets do not exist in the child).
  E. OS limits: Linux setrlimit+setsid; Windows Job Object (fail-closed when setup fails).

HONEST LIMIT (pentesters' recommendation): a pure pip-sandbox is NOT fully airtight
against hostile JS / DoS-on-Windows. Auto-exec of in-flight code is OFF by default. Full isolation
= deploy-level (container/microVM). These layers = strong in-process defense, they do not replace
kernel isolation.
"""
from __future__ import annotations

import ast
import math
import os
import subprocess
import sys
from dataclasses import dataclass
from typing import Optional

# --- static limits (the only cross-platform anti-DoS defense, since resource is absent on Win) ---
MAX_CODE_BYTES = 2048
MAX_AST_NODES = 500
MAX_AST_DEPTH = 50
MAX_INT_DIGITS = 7          # Constant int >7 digits (>~10^7) → DROP (anti 9**9**9 result)
MAX_POW_EXP = 20            # BinOp Pow with right Constant > 20 → DROP
MAX_SEQ_MULT = 1000        # 'a'*N / [0]*N with N>1000 → DROP
MAX_RANGE_ARG = 10 ** 6    # range/list arg Constant > 10^6 → DROP

# site-builtins / introspection names forbidden even as a bare Name (load).
# (-S removes license/help at runtime, but we block statically for certainty and readability.)
DENY_NAMES = frozenset({
    "license", "help", "copyright", "credits", "exit", "quit", "breakpoint",
    "__import__", "eval", "exec", "compile", "open", "input", "globals", "locals",
    "vars", "getattr", "setattr", "delattr", "hasattr", "type", "object", "super",
    "memoryview", "bytearray", "bytes", "__builtins__", "__loader__", "__spec__",
})

# Allow-list: ONLY these builtins may be called (default-deny for the rest).
SAFE_BUILTINS = frozenset({
    "len", "range", "sum", "min", "max", "abs", "round", "sorted", "int", "float",
    "str", "list", "dict", "set", "tuple", "bool", "enumerate", "zip", "map",
    "filter", "reversed", "chr", "ord", "divmod", "pow", "all", "any",
    "print",  # safe: writes to stdout (which we read), does not grant an escape
})

# Allowed AST node types (default-deny: anything outside → DROP).
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
    ast.Call,  # allowed CONDITIONALLY (only Name in SAFE_BUILTINS) — checked separately
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
    """Allow-list AST + static caps. fail-closed: anything unrecognized → DROP."""
    if lang != "python":
        # JS: regex-deny is indefensible → auto-exec OFF (unless vm-wrapper, a separate path)
        return GateResult(False, "js-exec-disabled (regex-deny indefensible; requires vm-wrapper)")
    if not code or not code.strip():
        return GateResult(False, "empty code")
    if len(code.encode("utf-8")) > MAX_CODE_BYTES:
        return GateResult(False, f"code > {MAX_CODE_BYTES}B")
    try:
        tree = ast.parse(code, mode="exec")
    except (SyntaxError, ValueError, RecursionError) as e:
        return GateResult(False, f"parse-fail: {type(e).__name__}")

    nodes = list(ast.walk(tree))
    if len(nodes) > MAX_AST_NODES:
        return GateResult(False, f"too many AST nodes (>{MAX_AST_NODES})")
    if _ast_depth(tree) > MAX_AST_DEPTH:
        return GateResult(False, f"AST too deep (>{MAX_AST_DEPTH})")

    # collect names defined LOCALLY (assignments + comprehension targets + lambda args)
    # — they may be called (e.g. [g() for g in fns] where g is a lambda). Safe, because Attribute
    # is forbidden + builtins-firewall + no imports; a local name grants no access to gadgets.
    local_names = set()
    for node in nodes:
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            local_names.add(node.id)
        elif isinstance(node, ast.arg):
            local_names.add(node.arg)
    # lambda is allowed (needed for the flagged [lambda: i ...]) — add its nodes
    _allowed = _ALLOWED_NODES + (ast.Lambda, ast.arguments, ast.arg)

    for node in nodes:
        # ATTRIBUTE forbidden UNCONDITIONALLY (kills .format/.__class__/.gi_frame/.mro)
        if isinstance(node, ast.Attribute):
            return GateResult(False, "ast.Attribute forbidden (gadget chains)")
        # unknown node type → DROP (default-deny)
        if not isinstance(node, _allowed):
            return GateResult(False, f"node not allowed: {type(node).__name__}")
        # Name (load): forbid DENY names (site-gadgets/introspection), even without a Call
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            if node.id in DENY_NAMES:
                return GateResult(False, f"name forbidden: {node.id}")
        # CALL only to a Name in SAFE_BUILTINS or a locally defined name
        if isinstance(node, ast.Call):
            if not isinstance(node.func, ast.Name):
                return GateResult(False, f"Call to non-Name: {type(node.func).__name__}")
            if node.func.id not in SAFE_BUILTINS and node.func.id not in local_names:
                return GateResult(False, f"Call to disallowed function: {node.func.id}")
            # pow(base, exp) builtin is NOT capped by the ast.Pow branch below, so
            # pow(9999999, 9999999) passed the gate and burned CPU to the timeout
            # (Codex round-4 DoS). Cap the 2-arg form by estimating result digits
            # WITHOUT computing it. 3-arg pow(b,e,mod) is bounded by mod -> allowed.
            if node.func.id == "pow" and len(node.args) == 2:
                b, e = node.args[0], node.args[1]
                if (isinstance(b, ast.Constant) and isinstance(b.value, int)
                        and not isinstance(b.value, bool)
                        and isinstance(e, ast.Constant) and isinstance(e.value, int)
                        and not isinstance(e.value, bool)):
                    if abs(b.value) > 1 and e.value > 0:
                        digits = e.value * math.log10(abs(b.value)) + 1
                        if digits > MAX_INT_DIGITS:
                            return GateResult(False, f"pow(): result > {MAX_INT_DIGITS} digits (DoS)")
        # static anti-DoS caps
        if isinstance(node, ast.Constant):
            if isinstance(node.value, int) and not isinstance(node.value, bool):
                if len(str(abs(node.value))) > MAX_INT_DIGITS:
                    return GateResult(False, f"literal int > {MAX_INT_DIGITS} digits (DoS)")
            if isinstance(node.value, str) and len(node.value) > MAX_CODE_BYTES:
                return GateResult(False, "literal str too long")
        if isinstance(node, ast.BinOp):
            # Pow: the exponent MUST be a small integer literal. Otherwise DROP — this kills
            # the power tower 9**9**9 (right operand = BinOp Pow, not Constant → DROP) and 10**9.
            if isinstance(node.op, ast.Pow):
                r = node.right
                if not (isinstance(r, ast.Constant) and isinstance(r.value, int)
                        and not isinstance(r.value, bool) and 0 <= r.value <= MAX_POW_EXP):
                    return GateResult(False, f"power: exponent must be a literal 0..{MAX_POW_EXP} (DoS)")
                # when the base is a literal too — compute statically and reject when the result is too large
                # (catches 10**9, 10**10: result >7 digits → DROP). Non-literal base: allowed
                # (e.g. x**2 where x is a small local), because the int cap on literals limits inputs anyway.
                if isinstance(node.left, ast.Constant) and isinstance(node.left.value, int) \
                        and not isinstance(node.left.value, bool):
                    try:
                        val = node.left.value ** r.value
                        if len(str(abs(val))) > MAX_INT_DIGITS:
                            return GateResult(False, f"power: result > {MAX_INT_DIGITS} digits (DoS)")
                    except Exception:
                        return GateResult(False, "power: not statically computable (DoS)")
            # sequence multiplication: List/Str/Tuple * N where N is large OR non-literal
            if isinstance(node.op, ast.Mult):
                for side, other in ((node.left, node.right), (node.right, node.left)):
                    if isinstance(side, (ast.List, ast.Tuple)) or \
                       (isinstance(side, ast.Constant) and isinstance(side.value, str)):
                        # the multiplier must be a small literal
                        if not (isinstance(other, ast.Constant) and isinstance(other.value, int)
                                and not isinstance(other.value, bool) and abs(other.value) <= MAX_SEQ_MULT):
                            return GateResult(False, f"sequence multiplication: multiplier > {MAX_SEQ_MULT} or non-literal (DoS)")
        # range/list with a large argument
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and \
           node.func.id in ("range", "list"):
            for a in node.args:
                if isinstance(a, ast.Constant) and isinstance(a.value, int) and a.value > MAX_RANGE_ARG:
                    return GateResult(False, f"{node.func.id}() arg > {MAX_RANGE_ARG} (DoS)")

    return GateResult(True, "")


# --- SAFE builtins dict (layer B: runtime firewall, independent of the AST) ---
def _safe_builtins_dict() -> dict:
    import builtins as _b
    safe = {}
    for name in SAFE_BUILTINS:
        if hasattr(_b, name):
            safe[name] = getattr(_b, name)
    # True/False/None needed as constants — they are keywords anyway, but for certainty
    return safe


def _clean_env() -> dict:
    """Child environment: only the essentials. NEVER os.environ (OPENAI/BRAVE secrets
    will not leak). PATH contains the interpreter directory (needed so python.dll
    loads — this is a runtime-path, not a secret) + the system minimum."""
    env = {}
    # the python.exe directory AND base_prefix (venv-on-uv: python.exe is a shim, the real
    # interpreter+DLL lives in base_prefix — without it "Unable to create process").
    interp_dir = os.path.dirname(sys.executable)
    base_dir = getattr(sys, "base_prefix", sys.prefix)
    if sys.platform == "win32":
        sysroot = os.environ.get("SYSTEMROOT", r"C:\Windows")
        env["SYSTEMROOT"] = sysroot
        parts = [interp_dir, os.path.join(interp_dir, "Scripts"),
                 base_dir, os.path.join(base_dir, "Scripts"),
                 os.path.join(sysroot, "System32"), sysroot]
        env["PATH"] = os.pathsep.join(dict.fromkeys(parts))  # dedup, preserve order
    else:
        parts = [interp_dir, os.path.join(base_dir, "bin"), "/usr/bin", "/bin"]
        env["PATH"] = os.pathsep.join(dict.fromkeys(parts))
    return env


def _linux_limits(timeout: float, mem_mb: int):
    """preexec_fn for Linux: setrlimit (mem/cpu/nproc/fsize) + setsid (kill the group)."""
    def _apply():
        import resource  # Linux only
        mem_bytes = mem_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
        cpu = max(1, int(timeout) + 1)
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))
        resource.setrlimit(resource.RLIMIT_NPROC, (0, 0))      # fork-bomb
        resource.setrlimit(resource.RLIMIT_FSIZE, (0, 0))      # no writing allowed
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (16, 16))
        except Exception:
            pass
        os.setsid()
    return _apply


@dataclass
class SandboxResult:
    ok: bool                 # whether it ran (False = rejected/error, NOT the code's result)
    stdout: Optional[str] = None
    reason: str = ""


def run_sandboxed(code: str, *, lang: str = "python", timeout: float = 5.0,
                  mem_mb: int = 256) -> SandboxResult:
    """Run code in an isolated process. fail-closed: when isolation is impossible → DO NOT run.

    Layer A (ast_gate) MUST be called BEFORE this (the caller), but for certainty we run
    it here too (a gate at the execution boundary = every exec path goes through the sandbox).
    """
    gate = ast_gate(code, lang)
    if not gate.ok:
        return SandboxResult(False, reason=f"gate-drop: {gate.reason}")
    if lang != "python":
        return SandboxResult(False, reason="js-exec-disabled")

    env = _clean_env()
    # layer B: wrap the code in a harness that enforces SAFE __builtins__
    # (the code already passed the allow-list, but this is a second wall)
    harness = (
        "_b=__builtins__\n"
        "_src=_b if isinstance(_b,dict) else vars(_b)\n"
        "_safe={}\n"
        "for _n in (" + ",".join(repr(n) for n in sorted(SAFE_BUILTINS)) + "):\n"
        "    if _n in _src: _safe[_n]=_src[_n]\n"
        "_ns={'__builtins__':_safe}\n"
        "exec(compile(" + repr(code) + ",'<koryto>','exec'), _ns)\n"
    )
    # base interpreter, NOT the venv-shim: the shim (e.g. venv-on-uv) depends on the
    # __PYVENV_LAUNCHER__ variables that clean-env lacks → "Unable to create process".
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
        # Windows: no resource. Job Object as a REQUIREMENT (fail-closed when setup fails).
        return _run_windows_jobobject(argv, env, timeout, mem_mb)


def run_context_guard(stmts, *, timeout: float = 5.0, mem_mb: int = 256) -> SandboxResult:
    """Run the koryto context-guard (statements[:-1] as setup, [-1] as eval) in the sandbox.

    SECURITY: gates EVERY user statement (allow-list AST) BEFORE assembling the
    harness. The harness itself (ns={}, exec, eval, print) is OURS/trusted — it does not go through
    the gate (otherwise its own exec/eval would be blocked). Trust-boundary: gate on the user's INPUT,
    deterministic harness. Execution: isolated interp + clean env + Job Object/rlimit.
    """
    stmts = [str(s) for s in (stmts or []) if str(s).strip()]
    if not stmts:
        return SandboxResult(False, reason="no statements")
    # gate on every user statement (joined, to catch multi-line constructs)
    joined = "\n".join(stmts)
    gate = ast_gate(joined, "python")
    if not gate.ok:
        return SandboxResult(False, reason=f"gate-drop: {gate.reason}")

    # trusted context-guard harness (NOT through the gate — this is our code, not the user's)
    setup = "\n".join(f"exec({s!r}, ns)" for s in stmts[:-1])
    # Suppress setup-statement stdout: only the FINAL eval's value is the proof.
    # Otherwise a setup `print(999)` poisons the output and _clean_exec_output
    # (first line) mints Verified(value='999') for `['print(999)','2+2']` — a
    # forged HARD fact (Codex round-4). Setup writes to devnull; stdout is
    # restored only for the final print.
    harness = (
        "import os as _os, sys as _sys\n"
        "_b=__builtins__\n"
        "_src=_b if isinstance(_b,dict) else vars(_b)\n"
        "_safe={}\n"
        "for _n in (" + ",".join(repr(n) for n in sorted(SAFE_BUILTINS)) + "):\n"
        "    if _n in _src: _safe[_n]=_src[_n]\n"
        "ns={'__builtins__':_safe}\n"
        "_real_out=_sys.stdout\n"
        "_sys.stdout=open(_os.devnull,'w')\n"
        + setup + "\n"
        "_sys.stdout=_real_out\n"
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
    """Windows: run in a Job Object with a memory limit + kill-on-close. fail-closed."""
    try:
        import ctypes
        from ctypes import wintypes
    except Exception:
        return SandboxResult(False, reason="ctypes-unavailable (fail-closed)")

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    # constants
    JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
    JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
    CREATE_NO_WINDOW = 0x08000000
    CREATE_BREAKAWAY_FROM_JOB = 0x01000000

    try:
        hJob = kernel32.CreateJobObjectW(None, None)
        if not hJob:
            return SandboxResult(False, reason="CreateJobObject-fail (fail-closed)")

        # JOBOBJECT_EXTENDED_LIMIT_INFORMATION — simplified structure
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
        # floor 512MB: the Python interpreter + imports need ~a few hundred MB baseline;
        # a lower limit kills process startup (MEASURED: 256MB → the process prints nothing).
        info.ProcessMemoryLimit = max(mem_mb, 512) * 1024 * 1024

        JobObjectExtendedLimitInformation = 9
        ok = kernel32.SetInformationJobObject(
            hJob, JobObjectExtendedLimitInformation, ctypes.byref(info), ctypes.sizeof(info))
        if not ok:
            kernel32.CloseHandle(hJob)
            return SandboxResult(False, reason="SetInformationJobObject-fail (fail-closed)")

        # start the process (no suspend — Popen gives no thread handle for ResumeThread),
        # assign to the Job immediately. The micro-window before assign is acceptable: the gate already
        # blocked dangerous code, and the Job enforces the memory limit/kill for DoS.
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                 env=env, creationflags=CREATE_NO_WINDOW)
        try:
            hProc = int(proc._handle)
            # FAIL-CLOSED (audit 2026-06-27 #9): if the Job assignment fails, the process
            # runs WITHOUT a memory limit → DoS bypasses the cap. Check the result (SetInformationJobObject
            # above IS checked — that was an inconsistency). Assign-fail → kill and reject.
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
            kernel32.CloseHandle(hJob)  # KILL_ON_JOB_CLOSE will kill the rest of the tree
            return SandboxResult(False, reason="timeout")
    except Exception as e:
        return SandboxResult(False, reason=f"jobobject-setup-fail: {type(e).__name__} (fail-closed)")
