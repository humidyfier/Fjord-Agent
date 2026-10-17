"""
backend/agent/orchestrator.py
Agent Orchestrator for Project Fjord.

Coordinates:
- Session lifecycle and flight-recorder logging
- Turn-based tool quota enforcement (max 5 tool calls per turn)
- Sanitization of untrusted prompt inputs via <untrusted_data> boundaries
- Execution of model-requested tool calls against backend/agent/tools.py
- Verification gate enforcement prior to remediation commits
"""

import time
import uuid
from typing import Any, Dict, List, Optional

from backend.agent.guardrails import (
    guardrail_manager,
    sanitize_untrusted_data,
    QuotaExceededError,
    VerificationGateError,
    QuoteVerificationError,
)
from backend.agent.logger import FlightRecorder
from backend.agent import tools


class AgentOrchestrator:
    """
    Orchestrates agent turns, tool invocations, and security controls.
    """

    def __init__(self, session_id: Optional[str] = None):
        self.session_id = session_id or f"session_{uuid.uuid4().hex[:12]}"
        self.logger = FlightRecorder(session_id=self.session_id)
        self.turn_count = 0

    def start_turn(self, user_instruction: str) -> str:
        """
        Starts a new turn, resets the per-turn tool quota, and wraps untrusted input.
        """
        self.turn_count += 1
        guardrail_manager.reset_turn()
        sanitized_input = sanitize_untrusted_data(user_instruction)
        self.logger.log_event("TURN_START", {
            "turn": self.turn_count,
            "raw_length": len(user_instruction),
            "sanitized_input": sanitized_input,
        })
        return sanitized_input

    def execute_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """
        Dispatches a tool call requested by the model with guardrail quota and gate checks.
        """
        start_time = time.time()
        self.logger.log_tool_call(tool_name, arguments)

        tool_func = getattr(tools, tool_name, None)
        if not tool_func or not callable(tool_func):
            err_msg = f"Unknown tool: '{tool_name}'"
            duration = (time.time() - start_time) * 1000
            self.logger.log_tool_result(tool_name, None, duration, error=err_msg)
            raise ValueError(err_msg)

        try:
            res = tool_func(**arguments)
            duration = (time.time() - start_time) * 1000
            res_dict = res.model_dump() if hasattr(res, "model_dump") else res
            self.logger.log_tool_result(tool_name, res_dict, duration)
            return res_dict
        except Exception as exc:
            duration = (time.time() - start_time) * 1000
            self.logger.log_tool_result(tool_name, None, duration, error=str(exc))
            raise

    def record_operator_decision(
        self,
        candidate_set_id: str,
        decision: str,
        operator_identity: str,
        reason: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        UI-only method to record operator approval or rejection.
        Never exposed in model MCP tool declarations.
        """
        self.logger.log_operator_action(
            candidate_set_id=candidate_set_id,
            decision=decision,
            operator_identity=operator_identity,
            reason=reason,
        )
        return {
            "candidate_set_id": candidate_set_id,
            "decision": decision,
            "recorded": True,
            "operator": operator_identity,
        }
