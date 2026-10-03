"""Bounded agent reasoning: explicit step budgets for AI-invoking agents.

Every agent that can call the model declares a hard cap on reasoning steps
(one provider call = one step). Steps are taken through ``take_step``; when
the cap trips the agent must NOT call the provider and must log the event.
This is defense-in-depth on top of the AIBudgetManager (which caps paid
calls): the reasoning budget caps *attempts*, including ones that would
fail before spending budget.

Current caps (single reasoning step each — the agents are single-shot by
design; the budget makes that structural property explicit and logged):
  * evidence_agent: 1 evidence-review call per run
  * <specialist>_review: 1 review call per specialist per run (full mode)
  * fix_agent: 1 proposal call per finding (enforced structurally in propose)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

#: Controlled status recorded when a reasoning-step cap trips.
REASONING_STEPS_EXHAUSTED = "REASONING_STEPS_EXHAUSTED"

#: Single-shot caps: one provider call per agent invocation.
EVIDENCE_AGENT_MAX_STEPS = 1
SPECIALIST_REVIEW_MAX_STEPS = 1
FIX_AGENT_MAX_STEPS = 1


@dataclass
class ReasoningBudget:
    """Hard cap on reasoning steps for one agent invocation."""

    agent_name: str
    max_steps: int
    steps_used: int = 0
    exhausted_logged: bool = field(default=False, repr=False)

    def take_step(self, purpose: str = "") -> bool:
        """Reserve one reasoning step. False (and a logged warning) when capped."""
        if self.steps_used >= self.max_steps:
            if not self.exhausted_logged:
                logger.warning(
                    "Reasoning budget exhausted for %s%s (max_steps=%d)",
                    self.agent_name,
                    f" ({purpose})" if purpose else "",
                    self.max_steps,
                )
                self.exhausted_logged = True
            return False
        self.steps_used += 1
        return True

    def remaining(self) -> int:
        return max(0, self.max_steps - self.steps_used)


__all__ = [
    "EVIDENCE_AGENT_MAX_STEPS",
    "FIX_AGENT_MAX_STEPS",
    "REASONING_STEPS_EXHAUSTED",
    "SPECIALIST_REVIEW_MAX_STEPS",
    "ReasoningBudget",
]
