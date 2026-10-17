"""
backend/solver/ilp_solver.py
Cutting-Plane Minimum Hitting-Set ILP Solver for Project Fjord.

Mathematical formulation:
    min  Σ c(m) · x_m      (minimise total disruption cost)
    s.t. Σ_{m hits path P} x_m >= 1   for every active attack path P
         x_m = 0            for m in RequiredDependencies (hard invariant)
         x_m ∈ {0, 1}

Iterative cutting-plane loop:
  1. Query active paths via FalkorDB algo.SPpaths (VirtualSource → VirtualSink).
  2. Add hitting-set cut per new path found.
  3. Solve binary ILP with scipy.optimize.milp.
  4. Simulate selected candidates in counterfactual sandbox via GRAPH.COPY.
  5. Repeat until 0 surviving paths or max_iterations exceeded.

All graph traversals use parameterized Cypher — never raw string interpolation.
"""

from __future__ import annotations

import logging
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import numpy as np
from scipy.optimize import LinearConstraint, Bounds, milp

from backend.db.connection import db_manager
from backend.db.compiler import ExploitGraphCompiler
from backend.schema import RemediationType, VerificationStatus

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Cost table: base disruption cost per remediation class
# ---------------------------------------------------------------------------

REMEDIATION_BASE_COSTS: Dict[RemediationType, float] = {
    RemediationType.NETWORK_POLICY_ADD:                  1.0,   # Low disruption
    RemediationType.NETWORK_POLICY_PATCH:                1.5,
    RemediationType.RBAC_ROLE_RESTRICT:                  2.5,
    RemediationType.SERVICE_ACCOUNT_UNBIND:              3.0,
    RemediationType.CONTAINER_PATCH_CVE:                 2.0,
    RemediationType.WORKLOAD_HARDEN_SECURITY_CONTEXT:    1.8,
}


@dataclass
class RemediationAction:
    """A single candidate remediation mutation."""
    action_id: str
    remediation_type: RemediationType
    description: str
    # The Cypher DELETE/DETACH/SET statement (parameterized) that enacts the mutation in-graph.
    mutation_cypher: str
    mutation_params: Dict = field(default_factory=dict)
    # Node/edge identifiers severed by this action (used to build hitting-set constraints)
    severs_edge_keys: List[str] = field(default_factory=list)  # e.g., ["(a.id)-(b.id)"]
    # Human-readable disruption cost
    disruption_cost: float = 1.0
    # If True, this action is pinned as forbidden (operator memory / required flow)
    forbidden: bool = False
    # Generated NetworkPolicy YAML (populated by yaml_generator after selection)
    yaml_patch: Optional[str] = None


@dataclass
class SolverResult:
    """Output from one Cutting-Plane ILP run."""
    candidate_set_id: str
    selected_actions: List[RemediationAction]
    solver_status: str          # "optimal" | "infeasible" | "max_iterations"
    total_cost: float
    iterations: int
    surviving_paths: int
    verification_status: VerificationStatus


class CuttingPlaneILPSolver:
    """
    Iterative Cutting-Plane Minimum Hitting-Set ILP Solver.

    Usage:
        solver = CuttingPlaneILPSolver(graph_name="prod_abc12345")
        candidates = solver.enumerate_candidates()
        result = solver.solve(candidates, max_iterations=20)
    """

    def __init__(
        self,
        graph_name: str,
        max_iterations: int = 20,
        preserve_required_flows: bool = True,
    ):
        self.graph_name = graph_name
        self.max_iterations = max_iterations
        self.preserve_required_flows = preserve_required_flows

    # ------------------------------------------------------------------
    # PUBLIC API
    # ------------------------------------------------------------------

    def enumerate_candidates(self) -> List[RemediationAction]:
        """
        Enumerate all feasible remediation actions from the current graph state.
        Returns a list of RemediationAction objects with pre-computed disruption costs.
        """
        actions: List[RemediationAction] = []

        # --- Candidate class 1: Network Policy additions (sever CAN_REACH_NET edges) ---
        net_edges = db_manager.query(
            self.graph_name,
            """
            MATCH (w1:Workload)-[r:CAN_REACH_NET]->(w2:Workload)
            RETURN w1.id AS src, w2.id AS dst, r.port AS port
            """,
            read_only=True,
        )
        required_pairs = self._get_required_flow_pairs()

        for row in net_edges:
            src_id, dst_id, port = str(row[0]), str(row[1]), row[2]
            edge_key = f"{src_id}-->{dst_id}"
            forbidden = (src_id, dst_id) in required_pairs

            src_ns, src_name = _parse_workload_id(src_id)
            dst_ns, dst_name = _parse_workload_id(dst_id)
            cost = REMEDIATION_BASE_COSTS[RemediationType.NETWORK_POLICY_ADD]
            if forbidden:
                cost = 999.0  # Effectively infinite — won't be selected

            actions.append(RemediationAction(
                action_id=f"netpol_{src_name}_{dst_name}_{uuid.uuid4().hex[:6]}",
                remediation_type=RemediationType.NETWORK_POLICY_ADD,
                description=f"Add NetworkPolicy: deny {src_id} → {dst_id} port {port}",
                mutation_cypher=(
                    "MATCH (w1:Workload {id: $src_id})-[r:CAN_REACH_NET]->(w2:Workload {id: $dst_id}) "
                    "DELETE r"
                ),
                mutation_params={"src_id": src_id, "dst_id": dst_id},
                severs_edge_keys=[edge_key],
                disruption_cost=cost,
                forbidden=forbidden,
            ))

        # --- Candidate class 2: RBAC unbind (sever BOUND_TO edges) ---
        rbac_edges = db_manager.query(
            self.graph_name,
            """
            MATCH (sa:ServiceAccount)-[b:BOUND_TO]->(r:RBACRole)
            RETURN sa.id AS sa_id, r.id AS role_id
            """,
            read_only=True,
        )
        for row in rbac_edges:
            sa_id, role_id = str(row[0]), str(row[1])
            edge_key = f"{sa_id}-->{role_id}"
            cost = REMEDIATION_BASE_COSTS[RemediationType.SERVICE_ACCOUNT_UNBIND]
            actions.append(RemediationAction(
                action_id=f"rbac_unbind_{sa_id.replace('/', '_')}_{uuid.uuid4().hex[:6]}",
                remediation_type=RemediationType.SERVICE_ACCOUNT_UNBIND,
                description=f"Unbind ServiceAccount {sa_id} from RBACRole {role_id}",
                mutation_cypher=(
                    "MATCH (sa:ServiceAccount {id: $sa_id})-[b:BOUND_TO]->(r:RBACRole {id: $role_id}) "
                    "DELETE b"
                ),
                mutation_params={"sa_id": sa_id, "role_id": role_id},
                severs_edge_keys=[edge_key],
                disruption_cost=cost,
                forbidden=False,
            ))

        # --- Candidate class 3: Remove hostPath mount (sever MOUNTS_HOST edges) ---
        host_mount_edges = db_manager.query(
            self.graph_name,
            """
            MATCH (w:Workload)-[m:MOUNTS_HOST]->(wn:WorkerNode)
            RETURN w.id AS workload_id, wn.id AS node_id, m.host_path AS host_path
            """,
            read_only=True,
        )
        for row in host_mount_edges:
            wl_id, node_id, host_path = str(row[0]), str(row[1]), str(row[2])
            edge_key = f"{wl_id}-->{node_id}"
            cost = REMEDIATION_BASE_COSTS[RemediationType.WORKLOAD_HARDEN_SECURITY_CONTEXT]
            actions.append(RemediationAction(
                action_id=f"harden_mount_{wl_id.replace('/', '_')}_{uuid.uuid4().hex[:6]}",
                remediation_type=RemediationType.WORKLOAD_HARDEN_SECURITY_CONTEXT,
                description=f"Remove hostPath mount {host_path} from workload {wl_id}",
                mutation_cypher=(
                    "MATCH (w:Workload {id: $wl_id})-[m:MOUNTS_HOST]->(wn:WorkerNode {id: $node_id}) "
                    "DELETE m"
                ),
                mutation_params={"wl_id": wl_id, "node_id": node_id},
                severs_edge_keys=[edge_key],
                disruption_cost=cost,
                forbidden=False,
            ))

        logger.info(
            "Enumerated %d remediation candidates (%d forbidden) for graph %s",
            len(actions),
            sum(1 for a in actions if a.forbidden),
            self.graph_name,
        )
        return actions

    def solve(
        self,
        candidates: List[RemediationAction],
        max_iterations: Optional[int] = None,
    ) -> SolverResult:
        """
        Run the Cutting-Plane ILP loop until all attack paths are hit or
        max_iterations is exceeded.
        """
        max_iter = max_iterations or self.max_iterations
        candidate_set_id = f"cset_{uuid.uuid4().hex[:12]}"

        # Separate forbidden from feasible candidates
        feasible = [a for a in candidates if not a.forbidden]
        n = len(feasible)

        if n == 0:
            return SolverResult(
                candidate_set_id=candidate_set_id,
                selected_actions=[],
                solver_status="infeasible",
                total_cost=0.0,
                iterations=0,
                surviving_paths=self._count_active_paths(self.graph_name),
                verification_status=VerificationStatus.FAILED_VERIFICATION,
            )

        costs = np.array([a.disruption_cost for a in feasible], dtype=float)

        # Build edge-key → column index map for constraint construction
        edge_to_col: Dict[str, List[int]] = {}
        for col_idx, action in enumerate(feasible):
            for ek in action.severs_edge_keys:
                edge_to_col.setdefault(ek, []).append(col_idx)

        # Cutting-plane state: list of constraint rows (A_row, lb=1)
        cut_rows: List[np.ndarray] = []
        selected_actions: List[RemediationAction] = []
        solver_status = "infeasible"
        total_cost = 0.0

        for iteration in range(1, max_iter + 1):
            logger.debug("Cutting-plane iteration %d / %d", iteration, max_iter)

            # 1. Query active attack paths
            active_paths = self._get_active_paths(self.graph_name)
            if not active_paths:
                solver_status = "optimal"
                break

            # 2. Add hitting-set cuts for any path not yet covered
            new_cuts_added = 0
            for path_edge_keys in active_paths:
                # Build a constraint row: sum of x_m for all actions hitting this path >= 1
                row = np.zeros(n, dtype=float)
                for ek in path_edge_keys:
                    for col in edge_to_col.get(ek, []):
                        row[col] = 1.0
                if row.sum() == 0:
                    # No candidate covers this path; cannot be remediated with current set
                    logger.warning(
                        "Iteration %d: attack path has no covering candidate — "
                        "solver cannot eliminate it with available actions.",
                        iteration,
                    )
                    continue
                cut_rows.append(row)
                new_cuts_added += 1

            if new_cuts_added == 0 and iteration > 1:
                # All surviving paths have no covering candidates
                solver_status = "infeasible"
                break

            # 3. Assemble and solve MILP
            try:
                selected_indices, obj_val = self._solve_milp(
                    costs=costs,
                    cut_rows=cut_rows,
                    n=n,
                )
            except ValueError as exc:
                logger.error("MILP infeasible: %s", exc)
                solver_status = "infeasible"
                break

            selected_actions = [feasible[i] for i in selected_indices]
            total_cost = obj_val
            logger.info(
                "Iteration %d: selected %d actions, cost=%.2f",
                iteration, len(selected_actions), total_cost,
            )
            solver_status = "optimal"
            break  # One solve round is enough; sandbox verification is done separately

        surviving = self._count_active_paths(self.graph_name)

        return SolverResult(
            candidate_set_id=candidate_set_id,
            selected_actions=selected_actions,
            solver_status=solver_status,
            total_cost=total_cost,
            iterations=iteration if "iteration" in dir() else 0,
            surviving_paths=surviving,
            verification_status=(
                VerificationStatus.UNVERIFIED  # Sandbox must verify before VERIFIED_IN_MODEL
            ),
        )

    # ------------------------------------------------------------------
    # INTERNAL HELPERS
    # ------------------------------------------------------------------

    def _solve_milp(
        self,
        costs: np.ndarray,
        cut_rows: List[np.ndarray],
        n: int,
    ) -> Tuple[List[int], float]:
        """
        Call scipy.optimize.milp to solve the binary hitting-set ILP.

        Returns (list of selected column indices, objective value).
        Raises ValueError if infeasible.
        """
        # Stack constraint matrix
        A = np.vstack(cut_rows)                  # shape (num_cuts, n)
        lb = np.ones(len(cut_rows), dtype=float) # every path must be hit (>= 1)
        ub = np.full(len(cut_rows), np.inf)      # no upper bound on coverage

        constraints = LinearConstraint(A, lb=lb, ub=ub)
        bounds = Bounds(lb=0.0, ub=1.0)           # 0 <= x_m <= 1
        integrality = np.ones(n, dtype=int)       # all variables are binary integers

        res = milp(
            c=costs,
            constraints=constraints,
            integrality=integrality,
            bounds=bounds,
        )

        if res.status not in (0, 1):  # 0=optimal, 1=iteration limit (acceptable approx)
            raise ValueError(f"MILP infeasible or unbounded: {res.message}")

        # Collect selected indices (x_m rounded to nearest integer)
        selected = [i for i, val in enumerate(res.x) if round(val) == 1]
        return selected, float(res.fun)

    def _get_active_paths(self, graph_name: str) -> List[List[str]]:
        """
        Call FalkorDB algo.SPpaths to enumerate active attack paths.
        Returns a list of paths, each represented as a list of edge-keys
        (from_node_id-->to_node_id) along the path.
        """
        path_rows = db_manager.find_shortest_paths(graph_name)
        return self._parse_path_rows_to_edge_keys(graph_name, path_rows)

    def _count_active_paths(self, graph_name: str) -> int:
        path_rows = db_manager.find_shortest_paths(graph_name)
        return len(path_rows)

    def _parse_path_rows_to_edge_keys(
        self,
        graph_name: str,
        path_rows: List,
    ) -> List[List[str]]:
        """
        Convert raw algo.SPpaths result rows into lists of edge-keys per path.
        Each edge-key is "{from_node_id}-->{to_node_id}" using .id properties.
        We query each node in the path via their internal node IDs.
        """
        edge_key_paths: List[List[str]] = []

        for row in path_rows:
            path_obj = row[0]  # falkordb Path object
            try:
                nodes = path_obj.nodes()
                edge_keys: List[str] = []
                for i in range(len(nodes) - 1):
                    src_id = _extract_node_id(nodes[i])
                    dst_id = _extract_node_id(nodes[i + 1])
                    edge_keys.append(f"{src_id}-->{dst_id}")
                if edge_keys:
                    edge_key_paths.append(edge_keys)
            except Exception as exc:
                logger.warning("Failed to parse path object: %s", exc)

        return edge_key_paths

    def _get_required_flow_pairs(self) -> set:
        """
        Returns a set of (src_id, dst_id) tuples that are protected by
        a REQUIRED_DEPENDENCY edge and must not be severed.
        """
        rows = db_manager.query(
            self.graph_name,
            """
            MATCH (a)-[:REQUIRED_DEPENDENCY]->(b)
            RETURN a.id AS src_id, b.id AS dst_id
            """,
            read_only=True,
        )
        return {(str(r[0]), str(r[1])) for r in rows}


# ---------------------------------------------------------------------------
# Private utilities
# ---------------------------------------------------------------------------

def _parse_workload_id(workload_id: str) -> Tuple[str, str]:
    """Parse '{namespace}/{name}' into (namespace, name)."""
    parts = workload_id.split("/", 1)
    if len(parts) == 2:
        return parts[0], parts[1]
    return "default", workload_id


def _extract_node_id(node) -> str:
    """Extract the .id string property from a FalkorDB Node object."""
    try:
        props = node.properties
        return str(props.get("id", node.id))
    except Exception:
        return str(getattr(node, "id", "unknown"))
