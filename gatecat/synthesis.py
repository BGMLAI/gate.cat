"""Cache-Augmented Synthesis (CAS) — synthesize responses from cached Q&A pairs.

Instead of returning a stale verbatim cache hit or calling the expensive upstream API,
CAS retrieves the top-K similar cached Q&A pairs and uses a small/cheap model to
synthesize a fresh, contextual response.

Three-tier response:
  1. VERBATIM (sim >= 0.92): Return cached response directly (<10ms, $0.00)
  2. SYNTHESIS (sim >= 0.80): Synthesize from top-K cached pairs (~300ms, ~$0.002)
  3. UPSTREAM (sim < 0.80): Call upstream API (~500ms, ~$0.03)

Usage:
    engine = SynthesisEngine(model="google/gemini-2.0-flash-lite-001")
    result = engine.synthesize(query="What is photosynthesis?", candidates=[...])
"""

import logging
import time
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

# Default synthesis prompt — proven effective in benchmark (0.892 mean judge ratio)
SYNTHESIS_PROMPT = """\
You have {k} expert responses to questions similar to the user's question.
Synthesize a single, comprehensive answer using the knowledge from these responses.

{context}

User's question: {question}

Instructions:
- Combine the best information from the expert responses above.
- Write a fresh, coherent answer that directly addresses the user's question.
- Do not copy verbatim — synthesize and adapt to the specific question.
- If the expert responses disagree, prefer the most detailed/accurate one.
- Keep the answer concise but complete.

Answer:"""


@dataclass
class SynthesisCandidate:
    """A cached Q&A pair that is a synthesis candidate."""
    query: str
    response: str
    similarity: float
    cache_id: int


@dataclass
class SynthesisResult:
    """Result of a synthesis operation."""
    text: str
    source: str  # "verbatim", "synthesis", "miss"
    latency_ms: float = 0.0
    candidates_used: int = 0
    mean_similarity: float = 0.0
    model: str = ""
    tokens: int = 0


class SynthesisEngine:
    """Synthesize responses from cached Q&A pairs using an LLM.

    Supports any OpenAI-compatible API (OpenRouter, local llama-cpp, etc.).

    Args:
        model: Model ID for synthesis (e.g., "google/gemini-2.0-flash-lite-001",
               "local/phi-4-mini", or any OpenAI-compatible model name).
        base_url: API base URL. Defaults to OpenRouter if OPENROUTER_API_KEY is set,
                  otherwise "http://localhost:8080/v1" for local llama-cpp.
        api_key: API key. Auto-detected from OPENROUTER_API_KEY or OPENAI_API_KEY env vars.
        max_tokens: Max tokens for synthesis response.
        temperature: Sampling temperature (0.3 = slight creativity for synthesis).
        prompt_template: Custom synthesis prompt template. Must contain {k}, {context}, {question}.
    """

    def __init__(
        self,
        model: str = "google/gemini-2.0-flash-lite-001",
        base_url: Optional[str] = None,
        api_key: Optional[str] = None,
        max_tokens: int = 1024,
        temperature: float = 0.3,
        prompt_template: Optional[str] = None,
    ):
        self._model = model
        self._max_tokens = max_tokens
        self._temperature = temperature
        self._prompt_template = prompt_template or SYNTHESIS_PROMPT

        # Resolve API config
        import os
        if api_key is None:
            api_key = os.environ.get("OPENROUTER_API_KEY") or os.environ.get("OPENAI_API_KEY")
        if base_url is None:
            if os.environ.get("OPENROUTER_API_KEY"):
                base_url = "https://openrouter.ai/api/v1"
            else:
                base_url = "http://localhost:8080/v1"

        self._api_key = api_key
        self._base_url = base_url
        self._client = None

    def _get_client(self):
        """Lazy-init OpenAI client for synthesis calls."""
        if self._client is None:
            try:
                from openai import OpenAI
            except ImportError:
                raise ImportError(
                    "openai package required for CAS synthesis. "
                    "Install with: pip install gate.cat[openai]"
                )
            self._client = OpenAI(
                api_key=self._api_key or "unused",
                base_url=self._base_url,
            )
        return self._client

    def _build_context(self, candidates: list[SynthesisCandidate], max_chars: int = 3000) -> str:
        """Build context string from synthesis candidates.

        Truncates individual answers to fit within max_chars total.
        """
        if not candidates:
            return ""

        max_per_answer = max_chars // len(candidates)
        parts = []
        for i, c in enumerate(candidates, 1):
            answer = c.response[:max_per_answer]
            if len(c.response) > max_per_answer:
                answer += "..."
            parts.append(
                f"Expert Response #{i} (similarity: {c.similarity:.2f}):\n"
                f"Q: {c.query[:200]}\n"
                f"A: {answer}\n"
            )
        return "\n".join(parts)

    def synthesize(
        self,
        query: str,
        candidates: list[SynthesisCandidate],
    ) -> SynthesisResult:
        """Synthesize a response from cached Q&A pairs.

        Args:
            query: The user's question.
            candidates: Top-K cached Q&A pairs with similarity scores.

        Returns:
            SynthesisResult with synthesized text and metadata.
        """
        if not candidates:
            return SynthesisResult(text="", source="miss")

        context = self._build_context(candidates)
        prompt = self._prompt_template.format(
            k=len(candidates),
            context=context,
            question=query,
        )

        start = time.time()
        try:
            client = self._get_client()
            response = client.chat.completions.create(
                model=self._model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=self._max_tokens,
                temperature=self._temperature,
            )
            text = ""
            tokens = 0
            if response.choices:
                msg = response.choices[0].message
                if msg and getattr(msg, "content", None):
                    text = msg.content
            if response.usage:
                tokens = response.usage.completion_tokens or 0

            latency = (time.time() - start) * 1000
            mean_sim = sum(c.similarity for c in candidates) / len(candidates)

            logger.debug(
                "[gatecat] SYNTHESIS (%.0fms, %d candidates, mean_sim=%.3f) %s",
                latency, len(candidates), mean_sim, query[:80],
            )

            return SynthesisResult(
                text=text,
                source="synthesis",
                latency_ms=latency,
                candidates_used=len(candidates),
                mean_similarity=mean_sim,
                model=self._model,
                tokens=tokens,
            )

        except Exception as e:
            logger.warning("[gatecat] Synthesis failed: %s", e)
            return SynthesisResult(text="", source="miss")
