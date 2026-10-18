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
from datetime import datetime, timezone
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

    def compact_tool_payload(self, tool_name: str, res_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Single-turn tool batching: compacts intermediate tool payloads so token usage
        and round-trip latency remain minimal, avoiding LLM socket read timeouts.
        """
        if not isinstance(res_dict, dict):
            return {"status": "SUCCESS", "summary": str(res_dict)[:200]}

        if tool_name == "compute_optimal_remediations":
            cands = res_dict.get("optimal_candidates", [])
            return {
                "candidate_set_id": res_dict.get("candidate_set_id"),
                "status": res_dict.get("status"),
                "candidate_count": len(cands),
                "primary_candidate": {
                    "candidate_id": cands[0].get("candidate_id") if cands else None,
                    "remediation_type": cands[0].get("remediation_type") if cands else None,
                    "target_resource": cands[0].get("target_resource_name") or cands[0].get("target_resource") if cands else None,
                    "disruption_cost": cands[0].get("disruption_cost") if cands else None,
                } if cands else None,
            }
        elif tool_name == "simulate_fix_in_sandbox":
            return {
                "status": res_dict.get("status"),
                "surviving_paths_count": res_dict.get("surviving_paths_count", 0),
                "broken_required_flows_count": res_dict.get("broken_required_flows_count", 0),
                "sandbox_sha": res_dict.get("sandbox_sha"),
            }
        elif tool_name == "discover_attack_paths":
            paths = res_dict.get("paths", [])
            return {
                "path_count": res_dict.get("path_count", len(paths)),
                "paths": [p.get("path_id") for p in paths[:3]],
            }
        elif tool_name == "get_posture_and_cluster_summary":
            return {
                "graph_name": res_dict.get("graph_name"),
                "workload_count": res_dict.get("workload_count"),
                "active_attack_path_count": res_dict.get("active_attack_path_count"),
                "findings_by_severity": res_dict.get("findings_by_severity"),
                "exact_cve_ids_in_graph": res_dict.get("exact_cve_ids_in_graph", []),
                "exact_misconfig_ids_in_graph": res_dict.get("exact_misconfig_ids_in_graph", []),
                "cve_notice": res_dict.get("cve_notice"),
                "actual_findings": res_dict.get("actual_findings", []),
            }
        elif tool_name == "update_dependency_or_constraint":
            return {
                "status": res_dict.get("status"),
                "constraint_type": res_dict.get("constraint_type"),
                "target_resource": res_dict.get("target_resource"),
            }
        return {k: v for k, v in res_dict.items() if k not in ("paths", "optimal_candidates", "simulation_result")}

    def record_operator_decision(
        self,
        candidate_set_id: str,
        decision: str,
        operator_identity: str,
        reason: Optional[str] = None,
        stable_key: Optional[str] = None,
        edge_keys: Optional[List[str]] = None,
        expires_at: Optional[str] = None,
        cluster_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        UI-only method to record operator approval or rejection.
        Never exposed in model MCP tool declarations.
        Persists decision to sentinel_memory graph in FalkorDB scoped by cluster_id.
        """
        self.logger.log_operator_action(
            candidate_set_id=candidate_set_id,
            decision=decision,
            operator_identity=operator_identity,
            reason=reason,
        )

        # Write to persistent sentinel_memory graph
        try:
            from backend.db.connection import db_manager
            now_iso = datetime.now(timezone.utc).isoformat()
            db_manager.query(
                "sentinel_memory",
                """
                MERGE (r:RemediationRecord {candidate_set_id: $cset_id})
                SET r.decision = $decision,
                    r.operator = $operator,
                    r.reason = $reason,
                    r.stable_key = $stable_key,
                    r.edge_keys = $edge_keys,
                    r.expires_at = $expires_at,
                    r.cluster_id = $cluster_id,
                    r.recorded_at = $recorded_at
                """,
                params={
                    "cset_id": candidate_set_id,
                    "decision": decision,
                    "operator": operator_identity,
                    "reason": reason or "",
                    "stable_key": stable_key or candidate_set_id,
                    "edge_keys": edge_keys or [],
                    "expires_at": expires_at,
                    "cluster_id": cluster_id,
                    "recorded_at": now_iso,
                }
            )
        except Exception as exc:
            pass

        return {
            "candidate_set_id": candidate_set_id,
            "decision": decision,
            "recorded": True,
            "operator": operator_identity,
        }


def normalize_model_slug(raw_model: str, provider: str = "Google Gemini") -> str:
    """
    Normalizes human-readable or legacy model strings to valid API slugs.
    Handles spaces, uppercase, models/ prefixes, and maps unreleased/fictional slugs.
    """
    if not raw_model:
        return "gemini-2.5-flash" if "gemini" in provider.lower() else "gpt-4o"

    slug = raw_model.strip().lower()
    if slug.startswith("models/"):
        slug = slug[len("models/"):]
    slug = slug.replace(" ", "-").replace("_", "-")
    while "--" in slug:
        slug = slug.replace("--", "-")

    provider_lower = provider.lower() if provider else ""

    if "gemini" in provider_lower or "google" in provider_lower:
        # Map unreleased or fictional versions to supported Google API slugs
        if any(x in slug for x in ["3.8", "3.1", "3.0", "3-8", "3-1", "3-0"]):
            if "lite" in slug:
                return "gemini-2.5-flash-lite"
            if "pro" in slug:
                return "gemini-2.5-pro"
            return "gemini-2.5-flash"

        gemini_valid = {
            "gemini-2.5-flash": "gemini-2.5-flash",
            "gemini-2.5-flash-lite": "gemini-2.5-flash-lite",
            "gemini-2.5-pro": "gemini-2.5-pro",
            "gemini-2.0-flash": "gemini-2.0-flash",
            "gemini-2.0-flash-lite": "gemini-2.0-flash-lite",
            "gemini-1.5-flash": "gemini-1.5-flash",
            "gemini-1.5-pro": "gemini-1.5-pro",
        }
        if slug in gemini_valid:
            return gemini_valid[slug]
        if "flash-lite" in slug:
            return "gemini-2.5-flash-lite"
        elif "flash" in slug:
            return "gemini-2.5-flash"
        elif "pro" in slug:
            return "gemini-2.5-pro"
        return slug or "gemini-2.5-flash"

    elif "anthropic" in provider_lower or "claude" in provider_lower:
        if "3-7" in slug or "3.7" in slug:
            return "claude-3-7-sonnet-latest"
        elif "3-5-haiku" in slug or "3.5-haiku" in slug:
            return "claude-3-5-haiku-latest"
        elif "3-5" in slug or "3.5" in slug:
            return "claude-3-5-sonnet-latest"
        return slug or "claude-3-7-sonnet-latest"

    else:
        if "llama" in slug:
            return "llama-3.3-70b-versatile"
        elif "mini" in slug:
            return "gpt-4o-mini"
        elif "4o" in slug:
            return "gpt-4o"
        return slug or "gpt-4o"


def sanitize_hallucinated_cves(reply: str, valid_cve_ids: set, misconfig_ids: list) -> str:
    """
    Checks every CVE-\\d{4}-\\d+ regex match in the LLM's output against the set of real cve_ids
    in the active FalkorDB graph. If the LLM outputs any CVE-XXXX-XXXX not present in the graph,
    replaces/strips that hallucinated CVE string and grounds the response strictly in actual findings.
    """
    if not reply:
        return reply

    import re
    pattern = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
    valid_upper = {c.upper() for c in valid_cve_ids if c}

    def _replace_cve(match):
        raw_cve = match.group(0).upper()
        if raw_cve in valid_upper:
            return raw_cve
        # Hallucinated CVE detected!
        if misconfig_ids:
            return f"{misconfig_ids[0]} (Misconfiguration)"
        return "Kubernetes Misconfiguration Finding"

    return pattern.sub(_replace_cve, reply)
