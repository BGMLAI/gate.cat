"""gatecat — Universal semantic cache for AI APIs.

Drop-in wrapper for OpenAI and Anthropic SDKs with multimodal support.
Cache semantically similar queries and return instant responses (<10ms).

Text cache:
    from gatecat import CachedOpenAI
    client = CachedOpenAI()
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "What is the capital of France?"}],
    )
    # First call: ~500ms (API + cache populate)
    # Second call: ~10ms (cache hit)
    print(response.gatecat_hit)  # True/False

Anthropic:
    from gatecat import CachedAnthropic
    client = CachedAnthropic()
    message = client.messages.create(...)

Async:
    from gatecat import AsyncCachedOpenAI, AsyncCachedAnthropic

Standalone cache (any modality):
    from gatecat import SemanticCache
    cache = SemanticCache(embedder="minilm")  # or "clip", "clap", "whisper"

Negative cache:
    client.cache.negative.add("bad query", reason="hallucination")
    client.cache.negative.check("similar query")

Apache 2.0 — https://gate.cat
"""

# --- env-var compat shim (F3 purge, D1=A: safe reader) ---------------------
# 0.3.0 renamed every CACHEBACK_* env var to GATECAT_*. To avoid SILENTLY
# dropping an existing operator's config (e.g. GATECAT_VETO_EPHEMERAL that arms
# the gate in CI), any still-set CACHEBACK_* var is copied to its GATECAT_*
# name at import — but only if the new name is not already set (new wins). A
# single DeprecationWarning names what to rename. Removed in 0.4. stdlib-only,
# runs before any module reads os.environ, so no read sees a stale name.
def _migrate_legacy_env() -> None:
    import os
    import warnings

    legacy = [k for k in list(os.environ) if k.startswith("CACHEBACK_")]
    migrated = []
    for old in legacy:
        new = "GATECAT_" + old[len("CACHEBACK_"):]
        if new not in os.environ:
            os.environ[new] = os.environ[old]
            migrated.append(old)
    if migrated:
        warnings.warn(
            "CACHEBACK_* env vars are deprecated (renamed to GATECAT_* in "
            "gate.cat 0.3.0) and will stop working in 0.4. Rename: "
            + ", ".join(sorted(migrated)),
            DeprecationWarning,
            stacklevel=2,
        )


_migrate_legacy_env()
del _migrate_legacy_env
# ---------------------------------------------------------------------------

# IMPORTANT: NOTHING is imported eagerly here.
#
# `gatecat` ships two things in one package: a lightweight action-veto
# guardrail (gate.cat: pure regex/string, stdlib-only) and a semantic cache
# (numpy + hnswlib + onnxruntime, hundreds of MB). Eager top-level imports used
# to pull the ENTIRE ML stack the moment anything under `gatecat` was touched
# - so `pip install gate.cat` + `import gatecat.integrations` dragged in 256
# numpy modules and could OOM / hang on a user's machine, for a guardrail that
# needs none of it.
#
# Everything is now lazy via __getattr__ (PEP 562): `from gatecat import X`
# still works for every public name, but the heavy module is imported ONLY when
# X is first accessed. The veto path (gatecat.veto -> koryto -> codeblocks) is
# stdlib-only, so it never triggers a numpy import; only cache/embedder names do.
# numpy/hnswlib/onnxruntime/huggingface-hub/tokenizers are now an optional extra
# (`pip install gate.cat[cache]`) - see pyproject. A clear ImportError tells the
# user to install the extra if they reach for a cache name without it.

__version__ = "0.4.12"

# name -> (submodule, is_cache_feature). is_cache_feature=True means the symbol
# lives behind the heavy ML stack, so a missing-dep ImportError is rewritten to
# point at the [cache] extra instead of a raw "No module named 'numpy'".
_LAZY: dict[str, tuple[str, bool]] = {
    # --- semantic cache (heavy: numpy/hnswlib/onnx) ---
    "SemanticCache": ("gatecat.cache", True),
    "AsyncSemanticCache": ("gatecat._async_cache", True),
    # --- lightweight guardrail / truth engine (stdlib-only) ---
    "GatecatBlocked": ("gatecat.exceptions", False),
    "GatecatError": ("gatecat.exceptions", False),
    "Gate": ("gatecat.gate", False),
    "GateVerdict": ("gatecat.gate", False),
    "WebBranch": ("gatecat.branches", False),
    "ToolBranch": ("gatecat.branches", False),
    "calculate": ("gatecat.branches", False),
    "brave_search": ("gatecat.branches", False),
    "GatedLoop": ("gatecat.agent", False),
    "StepResult": ("gatecat.agent", False),
    "LoopResult": ("gatecat.agent", False),
    "Koryto": ("gatecat.koryto", False),
    "KorytoVerdict": ("gatecat.koryto", False),
    "FactBase": ("gatecat.koryto", False),
    "StagnationMonitor": ("gatecat.stagnation", False),
    "StagnationState": ("gatecat.stagnation", False),
    "extract_code_blocks": ("gatecat.codeblocks", False),
    "to_exec_statements": ("gatecat.codeblocks", False),
    "CodeBlock": ("gatecat.codeblocks", False),
    "before_action": ("gatecat.veto", False),
    "VetoGate": ("gatecat.veto", False),
    "ActionPolicy": ("gatecat.veto", False),
    # the ONE veto exception (engine + integrations); lives in the stdlib-only
    # exceptions module so it resolves even when the engine itself does not.
    "ActionVetoed": ("gatecat.exceptions", False),
    "VetoDecision": ("gatecat.veto", False),
    # top-level check_action: `from gatecat import check_action` is the
    # published hero snippet; delegates to the integrations guard (stdlib-only).
    "check_action": ("gatecat.integrations.guard", False),
    "http_cache_source": ("gatecat.koryto_sources", False),
    "chroma_source": ("gatecat.koryto_sources", False),
    "multi_source": ("gatecat.koryto_sources", False),
    "is_mcq": ("gatecat.koryto_sources", False),
    "PlanVerifier": ("gatecat.plan_verifier", False),
    "PlanStep": ("gatecat.plan_verifier", False),
    "StepVerdict": ("gatecat.plan_verifier", False),
    "PlanReport": ("gatecat.plan_verifier", False),
    "provide_truth": ("gatecat.provider", False),
    "provide_hint": ("gatecat.provider", False),
    "verify_proof": ("gatecat.provider", False),
    "Verified": ("gatecat.provider", False),
    "Hint": ("gatecat.provider", False),
    "ProofRef": ("gatecat.provider", False),
    "BidirectionalGate": ("gatecat.bidirectional", False),
    "Provider": ("gatecat.bidirectional", False),
    "Guardian": ("gatecat.bidirectional", False),
    "TruthPipeline": ("gatecat.pipeline", False),
    "TruthReport": ("gatecat.pipeline", False),
    # --- optional SDK wrappers (openai/anthropic) ---
    "CachedOpenAI": ("gatecat.openai", False),
    "AsyncCachedOpenAI": ("gatecat.openai", False),
    "CachedAnthropic": ("gatecat.anthropic", False),
    "AsyncCachedAnthropic": ("gatecat.anthropic", False),
}

__all__ = [
    "SemanticCache",
    "AsyncSemanticCache",
    "GatecatBlocked",
    "GatecatError",
    "Gate",
    "GateVerdict",
    "WebBranch",
    "ToolBranch",
    "calculate",
    "brave_search",
    "GatedLoop",
    "StepResult",
    "LoopResult",
    "Koryto",
    "KorytoVerdict",
    "FactBase",
    "StagnationMonitor",
    "StagnationState",
    "http_cache_source",
    "chroma_source",
    "multi_source",
    "is_mcq",
    "extract_code_blocks",
    "to_exec_statements",
    "CodeBlock",
    "before_action",
    "VetoGate",
    "ActionPolicy",
    "ActionVetoed",
    "VetoDecision",
    "check_action",
    "PlanVerifier",
    "PlanStep",
    "StepVerdict",
    "PlanReport",
    "provide_truth",
    "provide_hint",
    "verify_proof",
    "Verified",
    "Hint",
    "ProofRef",
    "BidirectionalGate",
    "Provider",
    "Guardian",
    "TruthPipeline",
    "TruthReport",
    # Lazy imports for optional deps
    "CachedOpenAI",
    "AsyncCachedOpenAI",
    "CachedAnthropic",
    "AsyncCachedAnthropic",
]


def __getattr__(name):
    """PEP 562 lazy attribute access: import the owning submodule only when a
    public name is first used. Keeps `import gatecat` (and `import
    gatecat.integrations`, which touches this package) free of numpy/ONNX."""
    entry = _LAZY.get(name)
    if entry is None:
        raise AttributeError(f"module 'gatecat' has no attribute '{name}'")
    module_name, is_cache_feature = entry
    import importlib
    try:
        module = importlib.import_module(module_name)
    except ImportError as exc:
        # Rewrite a raw `No module named 'X'` into the exact extra to install.
        # is_cache_feature symbols always need [cache]; the SDK wrappers
        # (CachedOpenAI/Anthropic) need [cache] AND their SDK, so key off WHICH
        # dep is actually missing rather than the symbol — otherwise a user with
        # numpy but no openai would be told "[cache]" when they need "[openai]".
        missing = str(exc)
        cache_deps = ("numpy", "hnswlib", "onnxruntime", "tokenizers", "huggingface")
        if is_cache_feature or any(d in missing for d in cache_deps):
            raise ImportError(
                f"'{name}' needs the semantic-cache extra. Install it with "
                f"`pip install gate.cat[cache]` (adds numpy/hnswlib/onnxruntime). "
                f"The action-veto guardrail itself needs none of these."
            ) from exc
        if "openai" in missing:
            raise ImportError(
                f"'{name}' needs the OpenAI extra: `pip install gate.cat[openai]` "
                f"(and gate.cat[cache] for the caching it wraps)."
            ) from exc
        if "anthropic" in missing:
            raise ImportError(
                f"'{name}' needs the Anthropic extra: `pip install gate.cat[anthropic]` "
                f"(and gate.cat[cache] for the caching it wraps)."
            ) from exc
        raise
    return getattr(module, name)


def __dir__():
    return sorted(list(_LAZY) + ["__version__", "__all__"])
