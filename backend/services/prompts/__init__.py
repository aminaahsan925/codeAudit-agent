"""Prompt package: versioned, inspectable, testable prompts.

Rule: prompt strings live here and nowhere else. Each prompt carries an
explicit version identifier so AI reasoning stays traceable.
"""

from services.prompts.analysis_system import (
    CODEAUDIT_SECURITY_PROMPT_V1,
    SYSTEM_PROMPT,
)
from services.prompts.security_investigation import (
    EVIDENCE_CLOSE_TAG,
    EVIDENCE_OPEN_TAG,
    build_investigation_messages,
    wrap_untrusted,
)

__all__ = [
    "CODEAUDIT_SECURITY_PROMPT_V1",
    "SYSTEM_PROMPT",
    "EVIDENCE_OPEN_TAG",
    "EVIDENCE_CLOSE_TAG",
    "build_investigation_messages",
    "wrap_untrusted",
]
