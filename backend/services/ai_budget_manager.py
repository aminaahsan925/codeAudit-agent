"""AI budget manager: hard caps on paid Nemotron calls per run.

Every Nemotron call in the multi-agent backend goes through
``allow_call(agent_name)`` BEFORE the provider is touched. The call is
checked AND reserved atomically: a granted call counts against the budget
even if the provider later fails, because the tokens were spent.

Two independent budgets exist per run:
    analysis     — specialist reasoning + evidence review
    remediation  — fix proposals (+ any verification explanations)

When the budget is exhausted the caller must NOT call the provider and
must surface the controlled status AI_BUDGET_EXHAUSTED instead. The
deterministic agents always run regardless of budget state.
"""

from __future__ import annotations

import threading

from models.schemas import AIBudgetReport

#: Controlled status returned when no AI budget remains. Deterministic
#: agents continue; only the AI reasoning layer degrades.
AI_BUDGET_EXHAUSTED = "AI_BUDGET_EXHAUSTED"


class AIBudgetManager:
    """Request-scoped hard budget for Nemotron calls. Thread-safe."""

    def __init__(
        self,
        mode: str,
        analysis_limit: int,
        remediation_limit: int,
    ) -> None:
        self._mode = mode
        self._limits = {
            "analysis": max(0, int(analysis_limit)),
            "remediation": max(0, int(remediation_limit)),
        }
        self._used = {"analysis": 0, "remediation": 0}
        # agent_name -> {"analysis": n, "remediation": n} for auditability.
        self._by_agent: dict[str, dict[str, int]] = {}
        self._lock = threading.Lock()

    @property
    def mode(self) -> str:
        return self._mode

    def allow_call(self, agent_name: str, purpose: str = "analysis") -> bool:
        """Check AND reserve one call. Returns False when exhausted.

        Call this immediately before invoking the provider. A True return
        means the call was counted; do not call allow_call twice for one
        provider invocation.
        """
        if purpose not in self._limits:
            raise ValueError(f"unknown budget purpose: {purpose!r}")
        with self._lock:
            if self._used[purpose] >= self._limits[purpose]:
                return False
            self._used[purpose] += 1
            entry = self._by_agent.setdefault(
                agent_name, {"analysis": 0, "remediation": 0}
            )
            entry[purpose] += 1
            return True

    def calls_used(self, purpose: str = "analysis") -> int:
        with self._lock:
            return self._used[purpose]

    def calls_remaining(self, purpose: str = "analysis") -> int:
        with self._lock:
            return max(0, self._limits[purpose] - self._used[purpose])

    def calls_by_agent(self) -> dict[str, dict[str, int]]:
        with self._lock:
            return {k: dict(v) for k, v in self._by_agent.items()}

    def total_calls_used(self) -> int:
        with self._lock:
            return sum(self._used.values())

    def report(self, purpose: str = "analysis") -> AIBudgetReport:
        with self._lock:
            limit = self._limits[purpose]
            used = self._used[purpose]
        return AIBudgetReport(
            mode=self._mode,
            purpose=purpose,
            limit=limit,
            used=used,
            remaining=max(0, limit - used),
        )


__all__ = ["AI_BUDGET_EXHAUSTED", "AIBudgetManager"]
