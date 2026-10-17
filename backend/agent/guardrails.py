"""
backend/agent/guardrails.py
Security Guardrails & Access Controls for Project Fjord.

Enforces:
1. Prompt Injection Defense:
   - Sanitizes and wraps untrusted data strings (CVE descriptions, annotations, scanner logs)
     inside <untrusted_data> XML tags.
   - Truncates to max 2048 characters.
2. Tool Quotas:
   - Max 5 tool calls total per turn across all categories.
3. Verification Gates & UI-Role Isolation:
   - commit_verified_remediation strictly requires a preceding sandbox simulation
     with status VERIFIED_IN_MODEL for the exact (snapshot_sha, candidate_set_id).
   - record_operator_decision is UI-only and never exposed to the model schema.
4. Verbatim Quote Verification:
   - update_dependency_or_constraint requires the verbatim_quote to be an exact
     substring of the user prompt to prevent hallucinated constraint injections.
"""

from typing import Dict, Set, Optional, Tuple
from backend.schema import VerificationStatus


MAX_UNTRUSTED_DATA_LEN = 2048
MAX_TOOL_CALLS_PER_TURN = 5


def sanitize_untrusted_data(text: Optional[str], max_len: int = MAX_UNTRUSTED_DATA_LEN) -> str:
    """
    Wraps untrusted strings in <untrusted_data> tags and truncates to max_len.
    Escapes nested closing tags to prevent escape attacks.
    """
    if text is None:
        return "<untrusted_data></untrusted_data>"
    
    clean_text = str(text).replace("</untrusted_data>", "[escaped_tag]")
    if len(clean_text) > max_len:
        clean_text = clean_text[:max_len] + "... [TRUNCATED]"
        
    return f"<untrusted_data>{clean_text}</untrusted_data>"


class QuotaExceededError(Exception):
    """Raised when turn tool invocation quota exceeds max limit."""
    pass


class VerificationGateError(Exception):
    """Raised when an action violates the counterfactual verification gate."""
    pass


class QuoteVerificationError(Exception):
    """Raised when a proposed constraint quote does not match user instruction."""
    pass


class GuardrailManager:
    """
    Tracks turn execution state, enforces quotas, and validates verification gates.
    """

    def __init__(self):
        # Set of verified pairs: (snapshot_sha, candidate_set_id)
        self._verified_simulations: Set[Tuple[str, str]] = set()
        self._tool_calls_this_turn: int = 0

    def reset_turn(self):
        """Reset turn quota counter."""
        self._tool_calls_this_turn = 0

    def check_and_increment_quota(self, tool_name: str):
        """
        Increment call counter and verify tool call quota (max 5 per turn).
        """
        if self._tool_calls_this_turn >= MAX_TOOL_CALLS_PER_TURN:
            raise QuotaExceededError(
                f"Tool invocation quota exceeded. Max {MAX_TOOL_CALLS_PER_TURN} calls allowed per turn. "
                f"Attempted to call '{tool_name}'."
            )
        self._tool_calls_this_turn += 1

    @property
    def current_turn_tool_calls(self) -> int:
        return self._tool_calls_this_turn

    def register_verified_simulation(
        self,
        snapshot_sha: str,
        candidate_set_id: str,
        verification_status: VerificationStatus,
        surviving_paths: int,
        broken_flows: int
    ):
        """
        Record a sandbox simulation result. Only unlocks commit if
        verification_status == VERIFIED_IN_MODEL, surviving_paths == 0, broken_flows == 0.
        """
        if (
            verification_status == VerificationStatus.VERIFIED_IN_MODEL
            and surviving_paths == 0
            and broken_flows == 0
        ):
            self._verified_simulations.add((snapshot_sha, candidate_set_id))

    def is_verified(self, snapshot_sha: str, candidate_set_id: str) -> bool:
        """Check if candidate set has been verified in sandbox."""
        return (snapshot_sha, candidate_set_id) in self._verified_simulations

    def assert_verification_gate(self, snapshot_sha: str, candidate_set_id: str):
        """
        Asserts that candidate set has passed sandbox verification.
        Raises VerificationGateError if not verified.
        """
        if not self.is_verified(snapshot_sha, candidate_set_id):
            raise VerificationGateError(
                f"Verification gate violation: Candidate set '{candidate_set_id}' on snapshot "
                f"'{snapshot_sha}' has NOT passed counterfactual sandbox verification "
                f"(surviving_paths == 0, broken_flows == 0). Cannot commit unverified remediation."
            )

    @staticmethod
    def verify_quote(user_prompt: str, verbatim_quote: str) -> bool:
        """
        Verifies that verbatim_quote is a non-empty exact substring of user_prompt.
        """
        if not verbatim_quote or not verbatim_quote.strip():
            return False
        return verbatim_quote.strip() in user_prompt


# Global guardrail instance
guardrail_manager = GuardrailManager()
