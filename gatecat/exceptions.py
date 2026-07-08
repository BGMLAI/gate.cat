"""Gatecat exceptions."""


class GatecatBlocked(Exception):
    """Raised when a query matches the negative cache and on_negative_hit="raise"."""

    def __init__(self, query: str, reason: str = "", similarity: float = 0.0):
        self.query = query
        self.reason = reason
        self.similarity = similarity
        super().__init__(
            f"Query blocked by negative cache (similarity={similarity:.4f}): "
            f"{reason or 'no reason provided'}"
        )


class GatecatError(Exception):
    """Base exception for gatecat internal errors."""
    pass


class ActionVetoed(RuntimeError):
    """An action was blocked BEFORE it executed - the irreversible never became fact.

    The ONE veto exception for the whole package. The engine (``gatecat.veto``)
    and the integrations layer (hook/adapters, ``gatecat.integrations``) used to
    raise two distinct classes of the same name, so ``except gatecat.ActionVetoed``
    silently missed a block raised by ``check_action``. Unified here (0.4.1):
    this module is stdlib-only and import-safe even when the veto engine is not
    importable, so both layers can share it.

    Two construction shapes, one class:
      - engine: ``ActionVetoed(decision)`` with a ``VetoDecision`` - carries
        ``.decision`` / ``.reason`` / ``.mur`` / ``.verdict`` for the audit
        trail; ``str(exc)`` is ``"[mur] reason"``.
      - integrations: ``ActionVetoed("reason")`` with a plain ASCII-safe string
        mapped to an exit code / framework interrupt; ``.decision`` / ``.mur`` /
        ``.verdict`` are None and ``str(exc)`` is the reason.
    """

    def __init__(self, decision):
        if isinstance(decision, str):
            self.decision = None
            self.reason = decision
            self.mur = None
            self.verdict = None
            super().__init__(decision)
        else:
            # Duck-typed VetoDecision (reason/mur/verdict). No isinstance check
            # against gatecat.veto.VetoDecision - this module must never import
            # the engine, or the fail-closed "engine unimportable" path dies.
            self.decision = decision
            self.reason = getattr(decision, "reason", "")
            self.mur = getattr(decision, "mur", None)
            self.verdict = getattr(decision, "verdict", None)
            super().__init__(f"[{self.mur}] {self.reason}")
