"""cacheback — Universal semantic cache for AI APIs.

Drop-in wrapper for OpenAI and Anthropic SDKs with multimodal support.
Cache semantically similar queries and return instant responses (<10ms).

Text cache:
    from cacheback import CachedOpenAI
    client = CachedOpenAI()
    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": "What is the capital of France?"}],
    )
    # First call: ~500ms (API + cache populate)
    # Second call: ~10ms (cache hit)
    print(response.cacheback_hit)  # True/False

Anthropic:
    from cacheback import CachedAnthropic
    client = CachedAnthropic()
    message = client.messages.create(...)

Async:
    from cacheback import AsyncCachedOpenAI, AsyncCachedAnthropic

Standalone cache (any modality):
    from cacheback import SemanticCache
    cache = SemanticCache(embedder="minilm")  # or "clip", "clap", "whisper"

Negative cache:
    client.cache.negative.add("bad query", reason="hallucination")
    client.cache.negative.check("similar query")

Apache 2.0 — https://cacheback.ai
"""

from cacheback.cache import SemanticCache
from cacheback.exceptions import CachebackBlocked, CachebackError
from cacheback._async_cache import AsyncSemanticCache
from cacheback.gate import Gate, GateVerdict
from cacheback.branches import WebBranch, ToolBranch, calculate, brave_search
from cacheback.agent import GatedLoop, StepResult, LoopResult
from cacheback.koryto import Koryto, KorytoVerdict, FactBase
from cacheback.stagnation import StagnationMonitor, StagnationState
from cacheback.codeblocks import extract_code_blocks, to_exec_statements, CodeBlock
from cacheback.veto import (
    before_action, VetoGate, ActionPolicy, ActionVetoed, VetoDecision,
)
from cacheback.koryto_sources import (
    http_cache_source, chroma_source, multi_source, is_mcq,
)
from cacheback.plan_verifier import (
    PlanVerifier, PlanStep, StepVerdict, PlanReport,
)
from cacheback.provider import (
    provide_truth, provide_hint, verify_proof, Verified, Hint, ProofRef,
)
from cacheback.bidirectional import BidirectionalGate, Provider, Guardian
from cacheback.pipeline import TruthPipeline, TruthReport

__version__ = "0.2.0"

__all__ = [
    "SemanticCache",
    "AsyncSemanticCache",
    "CachebackBlocked",
    "CachebackError",
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
    """Lazy import wrappers to avoid requiring openai/anthropic at import time."""
    if name == "CachedOpenAI":
        from cacheback.openai import CachedOpenAI
        return CachedOpenAI
    if name == "AsyncCachedOpenAI":
        from cacheback.openai import AsyncCachedOpenAI
        return AsyncCachedOpenAI
    if name == "CachedAnthropic":
        from cacheback.anthropic import CachedAnthropic
        return CachedAnthropic
    if name == "AsyncCachedAnthropic":
        from cacheback.anthropic import AsyncCachedAnthropic
        return AsyncCachedAnthropic
    raise AttributeError(f"module 'cacheback' has no attribute '{name}'")
