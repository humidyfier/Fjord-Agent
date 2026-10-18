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
import time
import uuid
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

import warnings
warnings.filterwarnings("ignore", message=".*NumPy version.*")
warnings.filterwarnings("ignore", category=UserWarning)

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
    pure_milp_time_ms: float = 0.0
    total_loop_time_ms: float = 0.0


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

        # --- Candidate class 1b: Network Policy ingress isolation on exposed workloads (sever Service/Ingress exposure) ---
        exposed_workloads = db_manager.query(
            self.graph_name,
            """
            MATCH (ep:EntryPoint)-[:EXPOSES]->(s:Service)-[:SELECTS]->(w:Workload)
            RETURN ep.id AS ep_id, s.id AS svc_id, w.id AS wid
            """,
            read_only=True,
        )
        for row in exposed_workloads:
            ep_id, svc_id, wid = str(row[0]), str(row[1]), str(row[2])
            w_ns, w_name = _parse_workload_id(wid)
            edge_key = f"{ep_id}-->{wid}"
            actions.append(RemediationAction(
                action_id=f"netpol_isolate_{w_name}_{uuid.uuid4().hex[:6]}",
                remediation_type=RemediationType.NETWORK_POLICY_ADD,
                description=f"Add NetworkPolicy isolating exposed workload {wid}",
                mutation_cypher=(
                    "MATCH (s:Service)-[r:SELECTS]->(w:Workload {id: $wid}) "
                    "DELETE r"
                ),
                mutation_params={"wid": wid, "src_id": ep_id, "dst_id": wid},
                severs_edge_keys=[edge_key, f"{svc_id}-->{wid}"],
                disruption_cost=1.2,
                forbidden=False,
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

            # Query exploit-plane edges enabled by this SA -> Role binding
            affected_cypher = """
            MATCH (w:Workload)-[:USES_SA]->(sa:ServiceAccount {id: $sa_id})-[:BOUND_TO]->(r:RBACRole {id: $role_id})
            OPTIONAL MATCH (cj:CrownJewel)
            WHERE (cj.category = 'K8S_SECRET' OR cj.type = 'Opaque') AND (r.namespace = 'cluster' OR r.namespace = cj.namespace)
            RETURN w.id AS wid, cj.id AS cjid
            """
            aff_rows = db_manager.query(
                self.graph_name,
                affected_cypher,
                params={"sa_id": sa_id, "role_id": role_id},
                read_only=True
            )
            severs_keys = [edge_key]
            for arow in aff_rows:
                wid, cjid = arow[0], arow[1]
                if wid and cjid:
                    severs_keys.append(f"{wid}-->{cjid}")

            actions.append(RemediationAction(
                action_id=f"rbac_unbind_{sa_id.replace('/', '_')}_{uuid.uuid4().hex[:6]}",
                remediation_type=RemediationType.SERVICE_ACCOUNT_UNBIND,
                description=f"Unbind ServiceAccount {sa_id} from RBACRole {role_id}",
                mutation_cypher=(
                    "MATCH (sa:ServiceAccount {id: $sa_id})-[b:BOUND_TO]->(r:RBACRole {id: $role_id}) "
                    "DELETE b"
                ),
                mutation_params={"sa_id": sa_id, "role_id": role_id},
                severs_edge_keys=severs_keys,
                disruption_cost=cost,
                forbidden=False,
            ))

        # --- Candidate class 3: Workload hardening & hostPath removal (sever MOUNTS_HOST / CAN_ACCESS edges) ---
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

            # Also check if this workload directly reaches crown jewels
            severs_keys = [edge_key]
            cj_rows = db_manager.query(
                self.graph_name,
                "MATCH (w:Workload {id: $wid})-[:CAN_ACCESS|HOSTS_WORKLOAD|MOUNTS_SECRET]->(cj:CrownJewel) RETURN cj.id",
                params={"wid": wl_id},
                read_only=True
            )
            for cjr in cj_rows:
                severs_keys.append(f"{wl_id}-->{cjr[0]}")

            actions.append(RemediationAction(
                action_id=f"harden_mount_{wl_id.replace('/', '_')}_{uuid.uuid4().hex[:6]}",
                remediation_type=RemediationType.WORKLOAD_HARDEN_SECURITY_CONTEXT,
                description=f"Remove hostPath mount {host_path} and harden {wl_id}",
                mutation_cypher=(
                    "MATCH (w:Workload {id: $wl_id})-[m:MOUNTS_HOST]->(wn:WorkerNode {id: $node_id}) "
                    "DELETE m"
                ),
                mutation_params={"wl_id": wl_id, "node_id": node_id},
                severs_edge_keys=severs_keys,
                disruption_cost=cost,
                forbidden=False,
            ))

        # --- Candidate class 4: Cloud IAM Revocation (sever ASSUMES_IAM_ROLE edges) ---
        iam_edges = db_manager.query(
            self.graph_name,
            """
            MATCH (sa:ServiceAccount)-[r:ASSUMES_IAM_ROLE]->(ir:IAMRole)
            RETURN sa.id AS sa_id, ir.id AS role_id
            """,
            read_only=True,
        )
        for row in iam_edges:
            sa_id, role_id = str(row[0]), str(row[1])
            edge_key = f"{sa_id}-->{role_id}"
            cost = REMEDIATION_BASE_COSTS.get(RemediationType.RBAC_ROLE_RESTRICT, 2.5)

            # Query exploit-plane edges enabled by this IRSA bridge
            affected_cypher = """
            MATCH (w:Workload)-[:USES_SA]->(sa:ServiceAccount {id: $sa_id})-[:ASSUMES_IAM_ROLE]->(ir:IAMRole {id: $role_id}),
                  (cj:CrownJewel)
            WHERE cj.category STARTS WITH 'AWS_'
            RETURN w.id AS wid, cj.id AS cjid
            """
            aff_rows = db_manager.query(
                self.graph_name,
                affected_cypher,
                params={"sa_id": sa_id, "role_id": role_id},
                read_only=True,
            )
            severs_keys = [edge_key]
            for arow in aff_rows:
                wid, cjid = arow[0], arow[1]
                if wid and cjid:
                    severs_keys.append(f"{wid}-->{cjid}")

            actions.append(RemediationAction(
                action_id=f"iam_revoke_{sa_id.replace('/', '_')}_{uuid.uuid4().hex[:6]}",
                remediation_type=RemediationType.RBAC_ROLE_RESTRICT,
                description=f"Revoke IRSA IAM AssumeRole: detach {sa_id} from {role_id}",
                mutation_cypher=(
                    "MATCH (sa:ServiceAccount {id: $sa_id})-[r:ASSUMES_IAM_ROLE]->(ir:IAMRole {id: $role_id}) "
                    "DELETE r"
                ),
                mutation_params={"sa_id": sa_id, "role_id": role_id},
                severs_edge_keys=severs_keys,
                disruption_cost=cost,
                forbidden=False,
            ))

        # Check persistent sentinel_memory for operator vetoes (REJECTED_BY_OPERATOR)
        try:
            now_iso = datetime.now(timezone.utc).isoformat()
            veto_rows = db_manager.query(
                "sentinel_memory",
                """
                MATCH (r:RemediationRecord)
                WHERE r.decision = 'REJECTED_BY_OPERATOR'
                  AND (r.expires_at IS NULL OR r.expires_at > $now)
                  AND (r.cluster_id IS NULL OR r.cluster_id = $gname OR r.cluster_id = 'default')
                RETURN r.stable_key AS stable_key, r.edge_keys AS edge_keys
                """,
                params={"now": now_iso, "gname": self.graph_name},
                read_only=True,
            )
            vetoed_keys = set()
            for vrow in veto_rows:
                if vrow[0]:
                    vetoed_keys.add(str(vrow[0]))
                if vrow[1]:
                    if isinstance(vrow[1], list):
                        vetoed_keys.update(str(k) for k in vrow[1])
                    else:
                        vetoed_keys.add(str(vrow[1]))

            if vetoed_keys:
                for act in actions:
                    # If action's severs_edge_keys overlap with vetoed keys, mark forbidden
                    if any(k in vetoed_keys for k in act.severs_edge_keys) or act.action_id in vetoed_keys:
                        act.forbidden = True
                        act.disruption_cost = 999.0
                        logger.info("Candidate %s vetoed by sentinel_memory operator decision", act.action_id)
        except Exception as veto_exc:
            logger.debug("sentinel_memory check skipped or empty: %s", veto_exc)

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
        validate_in_sandbox: bool = True,
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
        total_pure_milp_ms = 0.0
        start_loop = time.perf_counter()

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
                selected_indices, obj_val, m_time = self._solve_milp(
                    costs=costs,
                    cut_rows=cut_rows,
                    n=n,
                )
                total_pure_milp_ms += m_time
            except (ValueError, OSError, Exception) as exc:
                logger.error("MILP infeasible: %s", exc)
                solver_status = "infeasible"
                break

            selected_actions = [feasible[i] for i in selected_indices]
            total_cost = obj_val
            logger.info(
                "Iteration %d: selected %d actions, cost=%.2f",
                iteration, len(selected_actions), total_cost,
            )

            # 4. Counterfactual validation: simulate selected candidates in an ephemeral sandbox
            # to check if any alternative attack paths survive (if validate_in_sandbox is enabled)
            if not validate_in_sandbox:
                solver_status = "optimal"
                break

            sim_sandbox = f"sandbox_ilp_{uuid.uuid4().hex[:10]}"
            try:
                ok = db_manager.copy_graph(self.graph_name, sim_sandbox)
                if not ok:
                    # If copy fails, fallback to breaking and trusting LP relaxation
                    solver_status = "optimal"
                    break

                for act in selected_actions:
                    try:
                        db_manager.query(sim_sandbox, act.mutation_cypher, params=act.mutation_params)
                    except Exception as act_exc:
                        logger.warning("Error applying action in ILP sandbox: %s", act_exc)

                comp = ExploitGraphCompiler(sim_sandbox)
                comp.compile()

                surviving_in_sim = self._get_active_paths(sim_sandbox)
                if not surviving_in_sim:
                    # All paths successfully eliminated!
                    solver_status = "optimal"
                    db_manager.delete_graph(sim_sandbox)
                    break

                # Alternative paths survived: add hitting cuts for surviving paths in next round
                logger.info(
                    "Iteration %d: %d surviving paths found in sandbox. Adding cuts for next iteration.",
                    iteration, len(surviving_in_sim),
                )
                cuts_from_sim = 0
                for path_edge_keys in surviving_in_sim:
                    row = np.zeros(n, dtype=float)
                    for ek in path_edge_keys:
                        for col in edge_to_col.get(ek, []):
                            row[col] = 1.0
                    if row.sum() > 0:
                        cut_rows.append(row)
                        cuts_from_sim += 1

                # No-good cut: If this exact combination of actions failed to eliminate paths,
                # forbid re-selecting the exact same subset without taking at least one more action:
                # sum_{i in selected} x_i <= len(selected) - 1 + sum_{j not in selected} x_j
                # Or simpler for binary hitting-set: if cuts_from_sim == 0 or all surviving paths have no covering candidate,
                # exclude this ineffective candidate configuration.
                if len(selected_indices) == 1 and cuts_from_sim == 0:
                    ineffective_col = selected_indices[0]
                    # Exclude this single ineffective candidate: x_ineffective = 0
                    ng_row = np.zeros(n, dtype=float)
                    ng_row[ineffective_col] = 1.0
                    # We can enforce by setting cost to infinity or bounds
                    costs[ineffective_col] = 999.0

                db_manager.delete_graph(sim_sandbox)

                if cuts_from_sim == 0:
                    # Cannot eliminate remaining paths with available candidates
                    solver_status = "infeasible"
                    break
            except Exception as sim_exc:
                logger.warning("Sandbox check in cutting-plane loop encountered error: %s", sim_exc)
                solver_status = "optimal"
                try:
                    db_manager.delete_graph(sim_sandbox)
                except Exception:
                    pass
                break

        surviving = self._count_active_paths(self.graph_name)
        total_loop_time_ms = (time.perf_counter() - start_loop) * 1000

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
            pure_milp_time_ms=round(total_pure_milp_ms, 2),
            total_loop_time_ms=round(total_loop_time_ms, 2),
        )

    # ------------------------------------------------------------------
    # INTERNAL HELPERS
    # ------------------------------------------------------------------

    def _solve_milp(
        self,
        costs: np.ndarray,
        cut_rows: List[np.ndarray],
        n: int,
    ) -> Tuple[List[int], float, float]:
        """
        Call scipy.optimize.milp to solve the binary hitting-set ILP.

        Returns (list of selected column indices, objective value, execution_time_ms).
        Raises ValueError if infeasible.
        """
        if not cut_rows or n == 0 or len(costs) == 0:
            raise ValueError("No valid constraints or variables to solve MILP.")

        # Stack constraint matrix safely
        A = np.vstack(cut_rows).astype(np.float64)  # shape (num_cuts, n)
        if A.shape[1] != n or A.shape[0] == 0:
            raise ValueError(f"Constraint matrix shape mismatch: {A.shape} vs n={n}")

        lb = np.ones(A.shape[0], dtype=np.float64)  # every path must be hit (>= 1)
        ub = np.full(A.shape[0], np.inf, dtype=np.float64)  # no upper bound on coverage

        constraints = LinearConstraint(A, lb=lb, ub=ub)
        bounds = Bounds(lb=np.zeros(n, dtype=np.float64), ub=np.ones(n, dtype=np.float64))  # 0 <= x_m <= 1
        integrality = np.ones(n, dtype=int)  # all variables are binary integers
        c_vector = np.ascontiguousarray(costs, dtype=np.float64)

        start_m = time.perf_counter()
        try:
            res = milp(
                c=c_vector,
                constraints=constraints,
                integrality=integrality,
                bounds=bounds,
            )
        except Exception as exc:
            raise ValueError(f"scipy.optimize.milp execution error: {exc}") from exc

        duration_ms = (time.perf_counter() - start_m) * 1000

        if res is None or res.status not in (0, 1) or res.x is None:  # 0=optimal, 1=iteration limit
            raise ValueError(f"MILP infeasible or unbounded: {getattr(res, 'message', 'No solution found')}")

        # Collect selected indices (x_m rounded to nearest integer)
        selected = [i for i, val in enumerate(res.x) if round(float(val)) == 1]
        return selected, float(res.fun), duration_ms

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
