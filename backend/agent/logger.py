"""
backend/agent/logger.py
Flight-Recorder Audit Logger for Project Fjord.

Logs every agent event, tool call, argument validation, sandbox run, and operator decision
to immutable JSONL files under runs/<session_id>.jsonl.
"""

import json
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional
from backend.schema import FlightRecorderEntry


DEFAULT_RUNS_DIR = Path("runs")


class FlightRecorder:
    """
    Appends structured audit log events into runs/<session_id>.jsonl.
    """

    def __init__(self, session_id: Optional[str] = None, runs_dir: Path = DEFAULT_RUNS_DIR):
        self.session_id = session_id or datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        self.runs_dir = runs_dir
        self.runs_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.runs_dir / f"{self.session_id}.jsonl"

    def log_event(self, event_type: str, payload: Dict[str, Any]):
        """
        Appends an entry conforming to FlightRecorderEntry schema.
        """
        now_iso = datetime.now(timezone.utc).isoformat()
        entry = FlightRecorderEntry(
            session_id=self.session_id,
            timestamp=now_iso,
            event_type=event_type,
            payload=payload,
        )

        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(entry.model_dump_json() + "\n")

    def log_tool_call(self, tool_name: str, arguments: Dict[str, Any]):
        """Log incoming tool invocation request."""
        self.log_event("TOOL_CALL", {"tool": tool_name, "arguments": arguments})

    def log_tool_result(
        self,
        tool_name: str,
        result: Any,
        duration_ms: float,
        error: Optional[str] = None
    ):
        """Log tool invocation result or error."""
        self.log_event("TOOL_RESULT", {
            "tool": tool_name,
            "duration_ms": duration_ms,
            "error": error,
            "result_summary": str(result)[:500] if result else None,
        })

    def log_sandbox_run(
        self,
        snapshot_sha: str,
        candidate_set_id: str,
        surviving_paths: int,
        broken_flows: int,
        status: str,
        details: str
    ):
        """Log sandbox verification result."""
        self.log_event("SANDBOX_RUN", {
            "snapshot_sha": snapshot_sha,
            "candidate_set_id": candidate_set_id,
            "surviving_paths": surviving_paths,
            "broken_flows": broken_flows,
            "verification_status": status,
            "details": details,
        })

    def log_commit(
        self,
        snapshot_sha: str,
        candidate_set_id: str,
        remediation_id: str,
        yaml_patches: list
    ):
        """Log committed remediation."""
        self.log_event("COMMIT", {
            "snapshot_sha": snapshot_sha,
            "candidate_set_id": candidate_set_id,
            "remediation_id": remediation_id,
            "patch_count": len(yaml_patches),
        })

    def log_operator_action(
        self,
        candidate_set_id: str,
        decision: str,
        operator_identity: str,
        reason: Optional[str] = None
    ):
        """Log UI operator decision."""
        self.log_event("OPERATOR_ACTION", {
            "candidate_set_id": candidate_set_id,
            "decision": decision,
            "operator_identity": operator_identity,
            "reason": reason,
        })
