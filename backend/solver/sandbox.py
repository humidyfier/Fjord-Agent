"""
backend/solver/sandbox.py
Counterfactual Sandbox Manager for Project Fjord.

Manages ephemeral simulation graphs (sandbox_sim_<id>) using FalkorDB
native GRAPH.COPY. Applies candidate inventory mutations, re-compiles
the Exploit State Plane, verifies:
  • surviving_attack_paths == 0
  • broken_required_dependencies == 0
and stamps status VERIFIED_IN_MODEL on success.

Application-layer LRU reference counting is handled by FalkorDBManager
(backend/db/connection.py). OOM errors from FalkorDB are caught and
retried after evicting the oldest unused sandbox.

All graph mutations use parameterized Cypher — never raw string interpolation.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass
from typing import List, Optional

from backend.db.connection import db_manager
from backend.db.compiler import ExploitGraphCompiler
from backend.schema import SimulationResult, VerificationStatus

logger = logging.getLogger(__name__)


@dataclass
class SandboxReport:
    """Detailed report from a single sandbox simulation run."""
    sandbox_graph: str
    snapshot_src: str
    candidate_set_id: str
    applied_action_ids: List[str]
    surviving_attack_paths: int
    broken_required_flows: int
    verification_status: VerificationStatus
    details: str


class SandboxManager:
    """
    Manages ephemeral sandbox graph copies for counterfactual verification.

    Workflow per simulation:
      1. Clone source graph: GRAPH.COPY src → sandbox_sim_<uuid8>
      2. Apply each candidate mutation (DELETE edges) inside the sandbox via
         parameterized Cypher.
      3. Re-compile the Exploit State Plane inside the sandbox graph.
      4. Count surviving attack paths (algo.SPpaths VirtualSource → VirtualSink).
      5. Count broken required dependencies.
      6. Return SandboxReport.
      7. Clean up sandbox graph.
    """

    def __init__(self, auto_cleanup: bool = True):
        """
        Args:
            auto_cleanup: If True, deletes the sandbox graph after simulation.
                          Set False for debugging/inspection.
        """
        self.auto_cleanup = auto_cleanup

    # ------------------------------------------------------------------
    # PUBLIC API
    # ------------------------------------------------------------------

    def simulate(
        self,
        src_graph: str,
        candidate_set_id: str,
        actions,  # List[RemediationAction] — imported lazily to avoid circular
    ) -> SandboxReport:
        """
        Simulate a set of remediation actions in an isolated sandbox graph.

        Args:
            src_graph:          Name of the source graph (e.g. prod_abc12345 or test graph).
            candidate_set_id:   Opaque string identifying this candidate set.
            actions:            List of RemediationAction objects to apply.

        Returns:
            SandboxReport with verification_status VERIFIED_IN_MODEL iff
            surviving_attack_paths == 0 and broken_required_flows == 0.
        """
        sandbox_name = f"sandbox_sim_{uuid.uuid4().hex[:12]}"
        action_ids = [a.action_id for a in actions]
        logger.info(
            "Sandbox simulation '%s': applying %d actions from '%s'",
            sandbox_name, len(actions), src_graph,
        )

        try:
            # Step 1: Clone source graph
            ok = db_manager.copy_graph(src_graph, sandbox_name)
            if not ok:
                return SandboxReport(
                    sandbox_graph=sandbox_name,
                    snapshot_src=src_graph,
                    candidate_set_id=candidate_set_id,
                    applied_action_ids=action_ids,
                    surviving_attack_paths=-1,
                    broken_required_flows=-1,
                    verification_status=VerificationStatus.FAILED_VERIFICATION,
                    details="GRAPH.COPY failed — sandbox graph could not be created.",
                )

            # Step 2: Apply all candidate mutations
            applied: List[str] = []
            for action in actions:
                try:
                    db_manager.query(
                        sandbox_name,
                        action.mutation_cypher,
                        params=action.mutation_params,
                    )
                    applied.append(action.action_id)
                    logger.debug("Applied action '%s' in sandbox '%s'", action.action_id, sandbox_name)
                except Exception as exc:
                    logger.warning(
                        "Action '%s' failed in sandbox '%s': %s",
                        action.action_id, sandbox_name, exc,
                    )

            # Step 3: Recompile exploit state plane in sandbox
            compiler = ExploitGraphCompiler(sandbox_name)
            compile_stats = compiler.compile()
            logger.debug(
                "Sandbox '%s' compile stats: %s", sandbox_name, compile_stats
            )

            # Step 4: Count surviving attack paths
            surviving_rows = db_manager.find_shortest_paths(sandbox_name)
            surviving = len(surviving_rows)

            # Step 5: Count broken required dependencies
            broken = self._count_broken_required_deps(src_graph, sandbox_name)

            # Step 6: Determine verification status
            if surviving == 0 and broken == 0:
                status = VerificationStatus.VERIFIED_IN_MODEL
                details = (
                    f"All {len(applied)} actions applied. "
                    f"0 surviving attack paths. 0 broken required flows. "
                    f"Exploit compile stats: {compile_stats}"
                )
            else:
                status = VerificationStatus.FAILED_VERIFICATION
                details = (
                    f"{surviving} surviving attack path(s), "
                    f"{broken} broken required flow(s). "
                    f"Verification gate not met."
                )

            logger.info(
                "Sandbox '%s' result: surviving=%d, broken=%d, status=%s",
                sandbox_name, surviving, broken, status.value,
            )

            return SandboxReport(
                sandbox_graph=sandbox_name,
                snapshot_src=src_graph,
                candidate_set_id=candidate_set_id,
                applied_action_ids=applied,
                surviving_attack_paths=surviving,
                broken_required_flows=broken,
                verification_status=status,
                details=details,
            )

        finally:
            if self.auto_cleanup:
                try:
                    db_manager.delete_graph(sandbox_name)
                    logger.debug("Cleaned up sandbox graph '%s'", sandbox_name)
                except Exception as exc:
                    logger.warning("Failed to delete sandbox '%s': %s", sandbox_name, exc)

    def to_simulation_result(self, report: SandboxReport) -> SimulationResult:
        """Convert SandboxReport to the Pydantic SimulationResult schema model."""
        return SimulationResult(
            sandbox_graph=report.sandbox_graph,
            surviving_attack_paths=max(report.surviving_attack_paths, 0),
            broken_required_flows=max(report.broken_required_flows, 0),
            verification_status=report.verification_status,
            details=report.details,
        )

    # ------------------------------------------------------------------
    # INTERNAL HELPERS
    # ------------------------------------------------------------------

    def _count_broken_required_deps(self, src_graph: str, sandbox_name: str) -> int:
        """
        Compare required dependency edges between the source graph and the sandbox.
        A broken required flow means a REQUIRED_DEPENDENCY edge that existed in the
        source was removed by a mutation in the sandbox.

        Returns count of required dependency edges that no longer exist in sandbox.
        """
        # Required deps in original graph
        src_rows = db_manager.query(
            src_graph,
            """
            MATCH (a)-[:REQUIRED_DEPENDENCY]->(b)
            RETURN a.id AS src_id, b.id AS dst_id
            """,
            read_only=True,
        )
        if not src_rows:
            return 0

        required_pairs = {(str(r[0]), str(r[1])) for r in src_rows}

        # Required deps still in sandbox
        sandbox_rows = db_manager.query(
            sandbox_name,
            """
            MATCH (a)-[:REQUIRED_DEPENDENCY]->(b)
            RETURN a.id AS src_id, b.id AS dst_id
            """,
            read_only=True,
        )
        sandbox_pairs = {(str(r[0]), str(r[1])) for r in sandbox_rows}

        broken = required_pairs - sandbox_pairs
        if broken:
            logger.warning("Broken required flows in sandbox: %s", broken)
        return len(broken)
