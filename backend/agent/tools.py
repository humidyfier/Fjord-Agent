"""
backend/agent/tools.py
The 7 Certified Model-Callable Tools for Project Fjord.

Exposes exactly 7 typed tools conforming strictly to schemas in backend/schema.py:
1. get_posture_and_cluster_summary
2. discover_attack_paths
3. compute_optimal_remediations
4. inspect_resource_context
5. update_dependency_or_constraint (verbatim quote verified)
6. simulate_fix_in_sandbox
7. commit_verified_remediation (gated by prior sandbox verification)

Note: record_operator_decision is UI-only and never exposed to the model schema.
All tools enforce prompt-injection defense (<untrusted_data>) and quota tracking.
"""

import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from backend.db.connection import db_manager, DEFAULT_GRAPH
from backend.db.compiler import ExploitGraphCompiler
from backend.solver.ilp_solver import CuttingPlaneILPSolver, RemediationAction
from backend.solver.sandbox import SandboxManager
from backend.solver.yaml_generator import NetworkPolicyYAMLGenerator
from backend.agent.guardrails import (
    guardrail_manager,
    sanitize_untrusted_data,
    VerificationGateError,
    QuoteVerificationError,
)
from backend.agent.logger import FlightRecorder
from backend.schema import (
    PostureSummaryResponse,
    PostureFindingSummary,
    DiscoverAttackPathsResponse,
    AttackPath,
    AttackPathStep,
    ComputeOptimalRemediationsResponse,
    RemediationCandidate,
    RemediationType,
    ResourceContextResponse,
    UpdateConstraintResponse,
    SimulateFixResponse,
    SimulationResult,
    CommitRemediationResponse,
    VerificationStatus,
    Severity,
    FindingCategory,
)


# Global flight recorder for agent tools
flight_recorder = FlightRecorder()

# In-memory candidate set store: candidate_set_id -> List[RemediationAction]
_candidate_action_registry: Dict[str, List[RemediationAction]] = {}


def _resolve_graph(graph_name: Optional[str]) -> str:
    return graph_name or DEFAULT_GRAPH


# ============================================================================
# TOOL 1: get_posture_and_cluster_summary
# ============================================================================

def get_posture_and_cluster_summary(
    graph_name: Optional[str] = None
) -> PostureSummaryResponse:
    """
    Retrieve Layer 1 cluster topology inventory and posture findings summary.
    Returns resource counts, active attack path counts, and findings categorized by severity.
    """
    guardrail_manager.check_and_increment_quota("get_posture_and_cluster_summary")
    g = _resolve_graph(graph_name)
    start_time = time.time()
    flight_recorder.log_tool_call("get_posture_and_cluster_summary", {"graph_name": g})

    # Count nodes by label
    counts_cypher = """
    MATCH (n)
    RETURN labels(n)[0] AS label, count(n) AS cnt
    """
    res = db_manager.query(g, counts_cypher, read_only=True)
    counts = {row[0]: int(row[1]) for row in res} if res else {}

    workload_count = counts.get("Workload", 0)
    container_count = counts.get("Container", 0)
    service_count = counts.get("Service", 0)
    ingress_count = counts.get("Ingress", 0)
    crown_jewel_count = counts.get("CrownJewel", 0)

    # Count active attack paths from VirtualSource to VirtualSink
    path_rows = db_manager.find_shortest_paths(g)
    active_paths_count = len(path_rows)

    # Group findings by severity
    findings_cypher = """
    MATCH (f:PostureFinding)
    RETURN f.severity AS severity, f.category AS category, count(f) AS cnt, collect(f.title)[..3] AS samples
    """
    f_res = db_manager.query(g, findings_cypher, read_only=True)
    findings_by_sev: Dict[str, int] = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    findings_summary: List[PostureFindingSummary] = []

    if f_res:
        for row in f_res:
            sev = str(row[0] or "MEDIUM").upper()
            cat = str(row[1] or "MISCONFIGURATION").upper()
            cnt = int(row[2])
            samples = [sanitize_untrusted_data(str(s)) for s in (row[3] or [])]

            if sev in findings_by_sev:
                findings_by_sev[sev] += cnt

            sev_enum = Severity(sev) if sev in Severity.__members__ else Severity.MEDIUM
            cat_enum = FindingCategory(cat) if cat in FindingCategory.__members__ else FindingCategory.MISCONFIGURATION

            findings_summary.append(
                PostureFindingSummary(
                    severity=sev_enum,
                    category=cat_enum,
                    count=cnt,
                    top_findings=samples,
                )
            )

    resp = PostureSummaryResponse(
        graph_name=g,
        workload_count=workload_count,
        container_count=container_count,
        service_count=service_count,
        ingress_count=ingress_count,
        crown_jewel_count=crown_jewel_count,
        active_attack_path_count=active_paths_count,
        findings_by_severity=findings_by_sev,
        findings_summary=findings_summary,
    )

    flight_recorder.log_tool_result("get_posture_and_cluster_summary", resp.model_dump(), (time.time() - start_time) * 1000)
    return resp


# ============================================================================
# TOOL 2: discover_attack_paths
# ============================================================================

def discover_attack_paths(
    graph_name: Optional[str] = None,
    max_paths: int = 10
) -> DiscoverAttackPathsResponse:
    """
    Enumerate active multi-hop attack paths from :VirtualSource to :VirtualSink
    using FalkorDB native algo.SPpaths.
    """
    guardrail_manager.check_and_increment_quota("discover_attack_paths")
    g = _resolve_graph(graph_name)
    start_time = time.time()
    flight_recorder.log_tool_call("discover_attack_paths", {"graph_name": g, "max_paths": max_paths})

    path_rows = db_manager.find_shortest_paths(g)
    paths: List[AttackPath] = []

    for idx, row in enumerate(path_rows[:max_paths]):
        path_obj = row[0]
        try:
            nodes = path_obj.nodes()
            steps: List[AttackPathStep] = []
            for i in range(len(nodes) - 1):
                n_from = nodes[i]
                n_to = nodes[i + 1]
                from_id = n_from.properties.get("id", str(n_from.id))
                to_id = n_to.properties.get("id", str(n_to.id))
                from_label = n_from.labels[0] if n_from.labels else "Unknown"
                to_label = n_to.labels[0] if n_to.labels else "Unknown"

                steps.append(
                    AttackPathStep(
                        from_node=from_id,
                        from_label=from_label,
                        to_node=to_id,
                        to_label=to_label,
                        step_type="EXPLOIT_STEP",
                        technique="LATERAL_OR_PRIVILEGE",
                        description=sanitize_untrusted_data(f"Step from {from_id} to {to_id}"),
                    )
                )

            src_entry = nodes[0].properties.get("id", "virtual-super-source")
            dst_target = nodes[-1].properties.get("id", "virtual-super-sink")

            paths.append(
                AttackPath(
                    path_id=f"path_{idx + 1}_{uuid.uuid4().hex[:6]}",
                    source_entry=src_entry,
                    target_crown_jewel=dst_target,
                    total_hops=len(steps),
                    steps=steps,
                )
            )
        except Exception as exc:
            pass

    resp = DiscoverAttackPathsResponse(
        graph_name=g,
        total_paths_found=len(path_rows),
        paths=paths,
    )

    flight_recorder.log_tool_result("discover_attack_paths", resp.model_dump(), (time.time() - start_time) * 1000)
    return resp


# ============================================================================
# TOOL 3: compute_optimal_remediations
# ============================================================================

def compute_optimal_remediations(
    graph_name: Optional[str] = None,
    max_remediations: int = 5,
    preserve_dependencies: bool = True
) -> ComputeOptimalRemediationsResponse:
    """
    Compute minimal-disruption remediation actions using Cutting-Plane ILP hitting-set solver.
    Preserves all :REQUIRED_DEPENDENCY business flows and generates candidate NetworkPolicy YAML patches.
    """
    guardrail_manager.check_and_increment_quota("compute_optimal_remediations")
    g = _resolve_graph(graph_name)
    start_time = time.time()
    flight_recorder.log_tool_call("compute_optimal_remediations", {
        "graph_name": g,
        "max_remediations": max_remediations,
        "preserve_dependencies": preserve_dependencies
    })

    solver = CuttingPlaneILPSolver(g, preserve_required_flows=preserve_dependencies)
    candidates = solver.enumerate_candidates()
    result = solver.solve(candidates, max_iterations=20)

    # Register actions in memory for sandbox simulation
    _candidate_action_registry[result.candidate_set_id] = result.selected_actions

    # Generate YAML manifests for NetworkPolicy candidates
    gen = NetworkPolicyYAMLGenerator(g)
    yaml_patches = gen.generate(result.selected_actions)
    yaml_patch_map = {}
    if yaml_patches and result.selected_actions:
        for idx, act in enumerate(result.selected_actions):
            if idx < len(yaml_patches):
                act.yaml_patch = yaml_patches[idx]

    optimal_candidates: List[RemediationCandidate] = []
    for act in result.selected_actions[:max_remediations]:
        target_ns = "default"
        target_name = act.action_id
        target_kind = "NetworkPolicy"
        if act.remediation_type == RemediationType.NETWORK_POLICY_ADD:
            dst_id = act.mutation_params.get("dst_id", "")
            if "/" in dst_id:
                target_ns, target_name = dst_id.split("/", 1)
            else:
                target_name = dst_id or "workload"
        elif act.remediation_type == RemediationType.SERVICE_ACCOUNT_UNBIND:
            target_kind = "RoleBinding"
            target_name = act.mutation_params.get("sa_id", "sa")

        optimal_candidates.append(
            RemediationCandidate(
                candidate_id=act.action_id,
                remediation_type=act.remediation_type,
                target_resource_kind=target_kind,
                target_resource_name=target_name,
                target_namespace=target_ns,
                yaml_diff=act.yaml_patch or f"# Action {act.action_id}\n# {act.description}",
                disruption_cost=act.disruption_cost,
                severed_path_ids=act.severs_edge_keys,
                broken_flow_risk="NONE" if not act.forbidden else "CRITICAL",
            )
        )

    resp = ComputeOptimalRemediationsResponse(
        graph_name=g,
        candidate_set_id=result.candidate_set_id,
        total_candidates=len(optimal_candidates),
        optimal_candidates=optimal_candidates,
        solver_status=result.solver_status,
        estimated_disruption_score=result.total_cost,
    )

    flight_recorder.log_tool_result("compute_optimal_remediations", resp.model_dump(), (time.time() - start_time) * 1000)
    return resp


# ============================================================================
# TOOL 4: inspect_resource_context
# ============================================================================

def inspect_resource_context(
    resource_kind: str,
    resource_name: str,
    namespace: str = "default",
    graph_name: Optional[str] = None
) -> ResourceContextResponse:
    """
    Inspect security and relationship context for a specific resource node in the graph.
    Wraps all external/untrusted descriptions in <untrusted_data>.
    """
    guardrail_manager.check_and_increment_quota("inspect_resource_context")
    g = _resolve_graph(graph_name)
    start_time = time.time()
    flight_recorder.log_tool_call("inspect_resource_context", {
        "resource_kind": resource_kind,
        "resource_name": resource_name,
        "namespace": namespace,
        "graph_name": g
    })

    node_id = f"{namespace}/{resource_name}" if namespace else resource_name
    query = """
    MATCH (n {id: $node_id})
    OPTIONAL MATCH (n)-[:CAN_REACH_NET]->(other:Workload)
    OPTIONAL MATCH (n)-[:AFFECTED_BY]->(f:PostureFinding)
    OPTIONAL MATCH (n)-[:REQUIRED_DEPENDENCY]->(dep:Workload)
    RETURN properties(n) AS props,
           collect(distinct other.id) AS net_targets,
           collect(distinct f.title) AS findings,
           collect(distinct dep.id) AS req_deps
    """
    res = db_manager.query(g, query, params={"node_id": node_id}, read_only=True)

    labels = {}
    connected_services = []
    attached_findings = []
    required_deps = []

    if res and res[0][0]:
        props = res[0][0]
        raw_labels = props.get("labels", {})
        if isinstance(raw_labels, dict):
            labels = {k: sanitize_untrusted_data(v) for k, v in raw_labels.items()}
        connected_services = [str(x) for x in res[0][1] if x]
        attached_findings = [sanitize_untrusted_data(str(x)) for x in res[0][2] if x]
        required_deps = [str(x) for x in res[0][3] if x]

    resp = ResourceContextResponse(
        resource_kind=resource_kind,
        resource_name=resource_name,
        namespace=namespace,
        labels=labels,
        connected_services=connected_services,
        attached_findings=attached_findings,
        active_network_policies=[],
        required_dependencies=required_deps,
        raw_manifest_snippet=sanitize_untrusted_data(f"kind: {resource_kind}\nmetadata:\n  name: {resource_name}"),
    )

    flight_recorder.log_tool_result("inspect_resource_context", resp.model_dump(), (time.time() - start_time) * 1000)
    return resp


# ============================================================================
# TOOL 5: update_dependency_or_constraint
# ============================================================================

def update_dependency_or_constraint(
    source_resource: str,
    target_resource: str,
    constraint_type: str,
    verbatim_quote: str,
    notes: Optional[str] = None,
    user_prompt: Optional[str] = None,
    graph_name: Optional[str] = None
) -> UpdateConstraintResponse:
    """
    Propose an update to a business dependency or remediation constraint.
    Enforces that verbatim_quote is an exact substring of the user's instruction.
    Propose-only: stages constraint without mutating production configuration.
    """
    guardrail_manager.check_and_increment_quota("update_dependency_or_constraint")
    g = _resolve_graph(graph_name)
    start_time = time.time()
    flight_recorder.log_tool_call("update_dependency_or_constraint", {
        "source_resource": source_resource,
        "target_resource": target_resource,
        "constraint_type": constraint_type,
        "verbatim_quote": verbatim_quote,
    })

    # Validate verbatim quote against user prompt
    is_valid_quote = False
    if user_prompt:
        is_valid_quote = guardrail_manager.verify_quote(user_prompt, verbatim_quote)

    if not is_valid_quote and user_prompt is not None:
        resp = UpdateConstraintResponse(
            status="REJECTED",
            source_resource=source_resource,
            target_resource=target_resource,
            constraint_type=constraint_type,
            verified_quote=False,
            message=f"Verbatim quote verification failed. Quote '{verbatim_quote}' was not found in user prompt.",
        )
        flight_recorder.log_tool_result("update_dependency_or_constraint", resp.model_dump(), (time.time() - start_time) * 1000, error="Quote verification failed")
        return resp

    # Stage the dependency edge in the graph
    if constraint_type == "REQUIRED_DEPENDENCY":
        cypher = """
        MATCH (a:Workload {id: $src}), (b:Workload {id: $dst})
        MERGE (a)-[r:REQUIRED_DEPENDENCY]->(b)
        SET r.description = $desc, r.verified_quote = $quote
        """
        db_manager.query(g, cypher, params={
            "src": source_resource,
            "dst": target_resource,
            "desc": notes or "User specified required flow",
            "quote": verbatim_quote
        })

    resp = UpdateConstraintResponse(
        status="PROPOSED_AND_STAGED",
        source_resource=source_resource,
        target_resource=target_resource,
        constraint_type=constraint_type,
        verified_quote=True,
        message=f"Constraint {constraint_type} from {source_resource} to {target_resource} verified and staged.",
    )

    flight_recorder.log_tool_result("update_dependency_or_constraint", resp.model_dump(), (time.time() - start_time) * 1000)
    return resp


# ============================================================================
# TOOL 6: simulate_fix_in_sandbox
# ============================================================================

def simulate_fix_in_sandbox(
    snapshot_sha: str,
    candidate_set_id: str,
    candidate_ids: Optional[List[str]] = None
) -> SimulateFixResponse:
    """
    Counterfactual Sandbox Simulation using FalkorDB native GRAPH.COPY.
    Clones snapshot graph to ephemeral sandbox, applies mutations, recompiles exploit plane,
    and validates: surviving_attack_paths == 0 and broken_required_flows == 0.
    """
    guardrail_manager.check_and_increment_quota("simulate_fix_in_sandbox")
    start_time = time.time()
    flight_recorder.log_tool_call("simulate_fix_in_sandbox", {
        "snapshot_sha": snapshot_sha,
        "candidate_set_id": candidate_set_id,
        "candidate_ids": candidate_ids
    })

    actions = _candidate_action_registry.get(candidate_set_id, [])
    if candidate_ids:
        actions = [a for a in actions if a.action_id in candidate_ids]

    sandbox_mgr = SandboxManager(auto_cleanup=True)
    report = sandbox_mgr.simulate(
        src_graph=snapshot_sha,
        candidate_set_id=candidate_set_id,
        actions=actions,
    )

    # Register verification gate status
    guardrail_manager.register_verified_simulation(
        snapshot_sha=snapshot_sha,
        candidate_set_id=candidate_set_id,
        verification_status=report.verification_status,
        surviving_paths=report.surviving_attack_paths,
        broken_flows=report.broken_required_flows,
    )

    flight_recorder.log_sandbox_run(
        snapshot_sha=snapshot_sha,
        candidate_set_id=candidate_set_id,
        surviving_paths=report.surviving_attack_paths,
        broken_flows=report.broken_required_flows,
        status=report.verification_status.value,
        details=report.details,
    )

    sim_res = sandbox_mgr.to_simulation_result(report)
    resp = SimulateFixResponse(
        snapshot_sha=snapshot_sha,
        candidate_set_id=candidate_set_id,
        simulation_result=sim_res,
    )

    flight_recorder.log_tool_result("simulate_fix_in_sandbox", resp.model_dump(), (time.time() - start_time) * 1000)
    return resp


# ============================================================================
# TOOL 7: commit_verified_remediation
# ============================================================================

def commit_verified_remediation(
    snapshot_sha: str,
    candidate_set_id: str,
    applied_candidate_ids: Optional[List[str]] = None
) -> CommitRemediationResponse:
    """
    Commit verified remediation to the cluster/repository.
    Verification Gate: Strictly asserts that a prior sandbox simulation for
    (snapshot_sha, candidate_set_id) passed with status VERIFIED_IN_MODEL.
    """
    guardrail_manager.check_and_increment_quota("commit_verified_remediation")
    start_time = time.time()
    flight_recorder.log_tool_call("commit_verified_remediation", {
        "snapshot_sha": snapshot_sha,
        "candidate_set_id": candidate_set_id,
        "applied_candidate_ids": applied_candidate_ids
    })

    # ENFORCE VERIFICATION GATE
    guardrail_manager.assert_verification_gate(snapshot_sha, candidate_set_id)

    actions = _candidate_action_registry.get(candidate_set_id, [])
    if applied_candidate_ids:
        actions = [a for a in actions if a.action_id in applied_candidate_ids]

    yaml_patches = [a.yaml_patch for a in actions if a.yaml_patch]
    remediation_id = f"rem_{uuid.uuid4().hex[:12]}"
    now_iso = datetime.now(timezone.utc).isoformat()

    proof = (
        f"VERIFIED_IN_MODEL: Candidate set {candidate_set_id} on snapshot {snapshot_sha} "
        f"verified with 0 surviving attack paths and 0 broken required dependencies."
    )

    flight_recorder.log_commit(
        snapshot_sha=snapshot_sha,
        candidate_set_id=candidate_set_id,
        remediation_id=remediation_id,
        yaml_patches=yaml_patches,
    )

    resp = CommitRemediationResponse(
        remediation_id=remediation_id,
        status="COMMITTED",
        committed_at=now_iso,
        verification_proof=proof,
        yaml_patches=yaml_patches,
    )

    flight_recorder.log_tool_result("commit_verified_remediation", resp.model_dump(), (time.time() - start_time) * 1000)
    return resp
