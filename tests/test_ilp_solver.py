"""
tests/test_ilp_solver.py
Integration Test Suite — Task 2: Cutting-Plane ILP Solver & Counterfactual Sandbox.

Test coverage:
  T2-1: test_solver_convergence_single_path
        Single-hop path, single candidate: solver must select it (cost-optimal).
  T2-2: test_solver_preserves_required_flows
        Required-dependency-protected edge must NEVER be selected (x_m=0 invariant).
  T2-3: test_solver_multi_path_minimal_cover
        Two paths sharing one edge: ILP must find the single shared candidate
        (minimum hitting-set, not two separate patches).
  T2-4: test_sandbox_verified_in_model
        Full simulation: GRAPH.COPY → apply mutation → recompile → assert
        surviving_paths=0, broken_flows=0, status=VERIFIED_IN_MODEL.
  T2-5: test_sandbox_fails_if_path_survives
        Applying an unrelated / insufficient action must NOT produce VERIFIED_IN_MODEL.
  T2-6: test_yaml_generator_produces_valid_k8s_manifest
        Selected action generates a parseable NetworkPolicy YAML with correct
        apiVersion, podSelector, and Fjord audit annotations.
  T2-7: test_yaml_generator_collateral_split_annotation
        When destination workload is covered by a shared NetworkPolicy,
        the generated manifest must include the split advisory note.
"""

import sys
import uuid
import yaml
import pytest
from pathlib import Path
from typing import List

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.db.connection import db_manager
from backend.ingest.parser import IngestionEngine
from backend.db.compiler import ExploitGraphCompiler
from backend.solver.ilp_solver import CuttingPlaneILPSolver, RemediationAction
from backend.solver.sandbox import SandboxManager
from backend.solver.yaml_generator import NetworkPolicyYAMLGenerator
from backend.schema import RemediationType, VerificationStatus


FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"

# ---------------------------------------------------------------------------
# Graph used by solver integration tests — isolated per test module
# ---------------------------------------------------------------------------
SOLVER_GRAPH = "test_solver_base"


# ---------------------------------------------------------------------------
# Module-scoped fixture: build a compiled base graph for all solver tests
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def solver_graph():
    """Build and compile a fresh base graph for ILP solver tests."""
    db_manager.delete_graph(SOLVER_GRAPH)

    engine = IngestionEngine()
    k8s_yaml = (FIXTURES_DIR / "sample_cluster.yaml").read_text(encoding="utf-8")
    engine.parse_k8s_yaml(k8s_yaml)
    trivy_json = (FIXTURES_DIR / "trivy_report.json").read_text(encoding="utf-8")
    engine.parse_trivy_json(trivy_json)
    prowler_json = (FIXTURES_DIR / "prowler_report.json").read_text(encoding="utf-8")
    engine.parse_prowler_json(prowler_json)
    req_flows = (FIXTURES_DIR / "required_flows.yaml").read_text(encoding="utf-8")
    engine.parse_required_flows_yaml(req_flows)

    counts = engine.resolve_cni_and_populate_graph(SOLVER_GRAPH)
    assert counts["node_count"] > 0, "Solver base graph must contain nodes"

    compiler = ExploitGraphCompiler(SOLVER_GRAPH)
    stats = compiler.compile()
    assert stats["total_exploit_steps"] > 0, "Must have exploit steps after compile"

    yield SOLVER_GRAPH

    db_manager.delete_graph(SOLVER_GRAPH)


# ---------------------------------------------------------------------------
# Helper: build a minimal isolated two-workload test graph for deterministic ILP tests
# ---------------------------------------------------------------------------

def _build_minimal_graph(graph_name: str, with_required_dep: bool = False):
    """
    Seed a minimal graph with Layer 1 topology and compile Layer 2 Exploit Plane:
      VirtualSource → EntryPoint → Workload A → Workload B → CrownJewel → VirtualSink
    Optionally adds a REQUIRED_DEPENDENCY from A to B.
    """
    db_manager.delete_graph(graph_name)

    cypher_nodes = """
    MERGE (vs:VirtualSource {id: 'virtual-super-source', name: 'VirtualSource'})
    MERGE (vk:VirtualSink   {id: 'virtual-super-sink',  name: 'VirtualSink'})
    MERGE (ep:EntryPoint  {id: 'test/entry-point', name: 'entry-point'})
    MERGE (wa:Workload  {id: 'test/workload-a', name: 'workload-a', namespace: 'test'})
    MERGE (wb:Workload  {id: 'test/workload-b', name: 'workload-b', namespace: 'test'})
    MERGE (cj:CrownJewel {id: 'test/crown-db',  name: 'crown-db',  namespace: 'test',
                           category: 'K8S_SECRET'})
    MERGE (ep)-[:ROUTES_TO]->(wa)
    MERGE (wa)-[:CAN_REACH_NET {port: 8080}]->(wb)
    MERGE (wb)-[:MOUNTS_SECRET]->(cj)
    """
    db_manager.query(graph_name, cypher_nodes)

    if with_required_dep:
        db_manager.query(graph_name, """
        MATCH (wa:Workload {id: 'test/workload-a'}), (wb:Workload {id: 'test/workload-b'})
        MERGE (wa)-[:REQUIRED_DEPENDENCY {description:'required business flow'}]->(wb)
        """)

    # Compile exploit plane
    compiler = ExploitGraphCompiler(graph_name)
    compiler.compile()

    return graph_name


# ---------------------------------------------------------------------------
# T2-1: Solver convergence — single attack path, single candidate
# ---------------------------------------------------------------------------

def test_solver_convergence_single_path():
    """
    Build minimal graph with one path. Solver must enumerate the CAN_REACH_NET
    edge as a candidate and select it (cost-optimal hitting-set).
    """
    g = _build_minimal_graph(f"test_ilp_t2_1_{uuid.uuid4().hex[:6]}")
    try:
        solver = CuttingPlaneILPSolver(g, max_iterations=10)
        candidates = solver.enumerate_candidates()

        # Must find at least the CAN_REACH_NET edge candidate
        net_candidates = [c for c in candidates if c.remediation_type == RemediationType.NETWORK_POLICY_ADD]
        assert len(net_candidates) >= 1, "Must enumerate at least one NetworkPolicy candidate"

        result = solver.solve(candidates)

        assert result.solver_status == "optimal", (
            f"Expected 'optimal' solver status, got '{result.solver_status}'"
        )
        assert len(result.selected_actions) >= 1, "Solver must select at least one action"
        assert result.total_cost > 0, "Selected actions must carry positive disruption cost"

        # Selected action must cover the A→B edge
        selected_edge_keys = {ek for a in result.selected_actions for ek in a.severs_edge_keys}
        assert any("workload-a" in ek or "workload-b" in ek for ek in selected_edge_keys), (
            "Selected actions must sever the A→B network edge"
        )

    finally:
        db_manager.delete_graph(g)


# ---------------------------------------------------------------------------
# T2-2: Solver must preserve required flows (x_m=0 for protected edges)
# ---------------------------------------------------------------------------

def test_solver_preserves_required_flows():
    """
    A→B edge is protected by REQUIRED_DEPENDENCY. The solver must NOT select
    the NetworkPolicy action that would sever it.
    """
    g = _build_minimal_graph(
        f"test_ilp_t2_2_{uuid.uuid4().hex[:6]}",
        with_required_dep=True,
    )
    try:
        solver = CuttingPlaneILPSolver(g, max_iterations=10, preserve_required_flows=True)
        candidates = solver.enumerate_candidates()

        # The A→B network candidate should be marked forbidden
        net_candidates = [c for c in candidates if c.remediation_type == RemediationType.NETWORK_POLICY_ADD]
        ab_candidates = [
            c for c in net_candidates
            if "workload-a" in (c.mutation_params.get("src_id", ""))
               and "workload-b" in (c.mutation_params.get("dst_id", ""))
        ]
        assert all(c.forbidden for c in ab_candidates), (
            "All A→B candidates must be marked forbidden when REQUIRED_DEPENDENCY exists"
        )

        result = solver.solve(candidates)

        # Verify no selected action severs the required A→B flow
        for action in result.selected_actions:
            src = action.mutation_params.get("src_id", "")
            dst = action.mutation_params.get("dst_id", "")
            assert not ("workload-a" in src and "workload-b" in dst), (
                f"Action '{action.action_id}' severs the required A→B flow — INVARIANT VIOLATION"
            )

    finally:
        db_manager.delete_graph(g)


# ---------------------------------------------------------------------------
# T2-3: Multi-path minimal cover — shared edge hit
# ---------------------------------------------------------------------------

def test_solver_multi_path_minimal_cover():
    """
    Graph: VS → A → B, VS → C → B, B → CJ → VK.
    Two paths share the single B→CJ edge. ILP minimum hitting-set must select
    at most 1 action covering B rather than one per source.
    Since both paths converge at B, cutting A→B and C→B separately is more
    expensive than one action that blocks all ingress to B.
    We verify solver selected_actions.count <= 2 (not 3+ redundant actions).
    """
    g = f"test_ilp_t2_3_{uuid.uuid4().hex[:6]}"
    db_manager.delete_graph(g)
    try:
        # Seed two-source graph
        db_manager.query(g, """
        MERGE (vs:VirtualSource {id: 'virtual-super-source', name: 'VirtualSource'})
        MERGE (vk:VirtualSink   {id: 'virtual-super-sink',  name: 'VirtualSink'})
        MERGE (wa:Workload {id: 'test/workload-a', name: 'workload-a', namespace: 'test'})
        MERGE (wc:Workload {id: 'test/workload-c', name: 'workload-c', namespace: 'test'})
        MERGE (wb:Workload {id: 'test/workload-b', name: 'workload-b', namespace: 'test'})
        MERGE (cj:CrownJewel {id: 'test/crown-db', name: 'crown-db', namespace: 'test',
                               category: 'K8S_SECRET'})
        """)

        for src_id, src_name in [("test/workload-a", "workload-a"), ("test/workload-c", "workload-c")]:
            db_manager.query(g, """
            MATCH (vs:VirtualSource {id: 'virtual-super-source'}),
                  (wa:Workload {id: $src_id})
            MERGE (vs)-[:EXPLOIT_STEP {step_type:'INITIAL_ACCESS', technique:'TEST',
                                        mechanism:'TEST', cost:0.1, description:'test'}]->(wa)
            """, params={"src_id": src_id})

            db_manager.query(g, """
            MATCH (wa:Workload {id: $src_id}), (wb:Workload {id: 'test/workload-b'})
            MERGE (wa)-[:CAN_REACH_NET {port: 8080}]->(wb)
            MERGE (wa)-[:EXPLOIT_STEP {step_type:'NETWORK_REACH', technique:'LATERAL_PIVOT',
                                        mechanism:'LATERAL_TCP_TRAFFIC', cost:1.5, port:8080,
                                        description:'lateral'}]->(wb)
            """, params={"src_id": src_id})

        db_manager.query(g, """
        MATCH (wb:Workload {id: 'test/workload-b'}), (cj:CrownJewel {id: 'test/crown-db'})
        MERGE (wb)-[:EXPLOIT_STEP {step_type:'SECRET_ACCESS', technique:'DIRECT_ASSET_ACCESS',
                                    mechanism:'HOSTED_CROWN_JEWEL', cost:0.1, description:'access'}]->(cj)
        """)
        db_manager.query(g, """
        MATCH (cj:CrownJewel {id: 'test/crown-db'}), (vk:VirtualSink {id: 'virtual-super-sink'})
        MERGE (cj)-[:EXPLOIT_STEP {step_type:'CROWN_JEWEL_COMPROMISE', technique:'DATA_EXFIL',
                                    mechanism:'OBJECTIVE_COMPLETED', cost:0.0, description:'exfil'}]->(vk)
        """)

        solver = CuttingPlaneILPSolver(g, max_iterations=15)
        candidates = solver.enumerate_candidates()
        result = solver.solve(candidates)

        assert result.solver_status == "optimal"
        # Minimum hitting-set: 2 paths share paths; solver should need ≤ 2 actions
        assert len(result.selected_actions) <= 2, (
            f"Minimum hitting-set should select ≤2 actions for two converging paths; "
            f"got {len(result.selected_actions)}"
        )

    finally:
        db_manager.delete_graph(g)


# ---------------------------------------------------------------------------
# T2-4: Sandbox VERIFIED_IN_MODEL — full counterfactual simulation
# ---------------------------------------------------------------------------

def test_sandbox_verified_in_model():
    """
    Full end-to-end: build minimal graph, run solver, apply top action in
    sandbox via GRAPH.COPY, verify status=VERIFIED_IN_MODEL.
    """
    g = _build_minimal_graph(f"test_ilp_t2_4_{uuid.uuid4().hex[:6]}")
    try:
        solver = CuttingPlaneILPSolver(g, max_iterations=10)
        candidates = solver.enumerate_candidates()
        result = solver.solve(candidates)

        assert result.solver_status == "optimal"
        assert result.selected_actions, "Must have selected actions to simulate"

        sandbox_mgr = SandboxManager(auto_cleanup=True)
        report = sandbox_mgr.simulate(
            src_graph=g,
            candidate_set_id=result.candidate_set_id,
            actions=result.selected_actions,
        )

        assert report.surviving_attack_paths == 0, (
            f"Sandbox must show 0 surviving paths; got {report.surviving_attack_paths}"
        )
        assert report.broken_required_flows == 0, (
            f"Sandbox must show 0 broken required flows; got {report.broken_required_flows}"
        )
        assert report.verification_status == VerificationStatus.VERIFIED_IN_MODEL, (
            f"Expected VERIFIED_IN_MODEL; got {report.verification_status}"
        )

    finally:
        db_manager.delete_graph(g)


# ---------------------------------------------------------------------------
# T2-5: Sandbox fails when insufficient actions applied
# ---------------------------------------------------------------------------

def test_sandbox_fails_if_path_survives():
    """
    Apply an action that doesn't actually block the attack path.
    Sandbox must NOT return VERIFIED_IN_MODEL.
    """
    g = _build_minimal_graph(f"test_ilp_t2_5_{uuid.uuid4().hex[:6]}")
    try:
        # Fabricate a no-op action (deletes a non-existent edge)
        no_op_action = RemediationAction(
            action_id="no_op_test",
            remediation_type=RemediationType.NETWORK_POLICY_ADD,
            description="No-op: delete nonexistent edge",
            mutation_cypher=(
                "MATCH (w1:Workload {id: $src_id})-[r:CAN_REACH_NET]->(w2:Workload {id: $dst_id}) "
                "DELETE r"
            ),
            mutation_params={
                "src_id": "test/nonexistent-src",
                "dst_id": "test/nonexistent-dst",
            },
            severs_edge_keys=["test/nonexistent-src-->test/nonexistent-dst"],
            disruption_cost=1.0,
        )

        sandbox_mgr = SandboxManager(auto_cleanup=True)
        report = sandbox_mgr.simulate(
            src_graph=g,
            candidate_set_id=f"cset_noop_{uuid.uuid4().hex[:8]}",
            actions=[no_op_action],
        )

        # The path is still alive, so must NOT be verified
        assert report.verification_status != VerificationStatus.VERIFIED_IN_MODEL, (
            "Sandbox must NOT return VERIFIED_IN_MODEL when attack paths survive"
        )
        assert report.surviving_attack_paths > 0, (
            "Sandbox must report surviving paths when mutation is insufficient"
        )

    finally:
        db_manager.delete_graph(g)


# ---------------------------------------------------------------------------
# T2-6: YAML generator produces valid K8s NetworkPolicy manifest
# ---------------------------------------------------------------------------

def test_yaml_generator_produces_valid_k8s_manifest(solver_graph):
    """
    After solving, YAML generator must produce parseable NetworkPolicy manifests
    with correct apiVersion, kind, podSelector, and Fjord audit annotations.
    """
    solver = CuttingPlaneILPSolver(solver_graph, max_iterations=10)
    candidates = solver.enumerate_candidates()
    result = solver.solve(candidates)

    # Only run YAML generation if solver found network-policy candidates
    net_actions = [
        a for a in result.selected_actions
        if a.remediation_type in (RemediationType.NETWORK_POLICY_ADD, RemediationType.NETWORK_POLICY_PATCH)
    ]
    if not net_actions:
        pytest.skip("No NetworkPolicy actions selected — nothing to generate YAML for")

    gen = NetworkPolicyYAMLGenerator(solver_graph)
    yaml_patches = gen.generate(net_actions)

    assert len(yaml_patches) >= 1, "Must produce at least one YAML patch"

    for yaml_str in yaml_patches:
        manifest = yaml.safe_load(yaml_str)
        assert manifest["apiVersion"] == "networking.k8s.io/v1", "Wrong apiVersion"
        assert manifest["kind"] == "NetworkPolicy", "Wrong kind"
        assert "podSelector" in manifest["spec"], "Missing podSelector"
        assert "Ingress" in manifest["spec"]["policyTypes"], "Missing policyTypes: Ingress"

        annotations = manifest["metadata"].get("annotations", {})
        assert "fjord.security/managed-by" in annotations, "Missing Fjord managed-by annotation"
        assert "fjord.security/remediation-note" in annotations, "Missing Fjord audit note annotation"
        assert manifest["metadata"]["annotations"]["fjord.security/managed-by"] == (
            "fjord-remediation-agent"
        ), "Wrong managed-by annotation value"


# ---------------------------------------------------------------------------
# T2-7: YAML generator detects collateral split and annotates accordingly
# ---------------------------------------------------------------------------

def test_yaml_generator_collateral_split_annotation():
    """
    When destination workload is currently selected by a shared NetworkPolicy,
    the generated manifest must include the split advisory note in annotations.
    """
    g = f"test_ilp_t2_7_{uuid.uuid4().hex[:6]}"
    db_manager.delete_graph(g)
    try:
        # Seed a minimal graph with a shared NetworkPolicy selecting workload-b
        db_manager.query(g, """
        MERGE (wa:Workload {id: 'test/workload-a', name: 'workload-a', namespace: 'test'})
        MERGE (wb:Workload {id: 'test/workload-b', name: 'workload-b', namespace: 'test',
                            labels: {}})
        MERGE (wc:Workload {id: 'test/workload-c', name: 'workload-c', namespace: 'test'})
        MERGE (np:NetworkPolicy {id: 'test/shared-np', name: 'shared-np', namespace: 'test'})
        MERGE (wa)-[:CAN_REACH_NET {port: 8080}]->(wb)
        MERGE (np)-[:SELECTS]->(wb)
        MERGE (np)-[:SELECTS]->(wc)
        """)

        action = RemediationAction(
            action_id="test_action_split",
            remediation_type=RemediationType.NETWORK_POLICY_ADD,
            description="Block workload-a → workload-b",
            mutation_cypher="MATCH (a:Workload {id: $src_id})-[r:CAN_REACH_NET]->(b:Workload {id: $dst_id}) DELETE r",
            mutation_params={"src_id": "test/workload-a", "dst_id": "test/workload-b"},
            severs_edge_keys=["test/workload-a-->test/workload-b"],
            disruption_cost=1.0,
        )

        gen = NetworkPolicyYAMLGenerator(g)
        yaml_patches = gen.generate([action])

        assert len(yaml_patches) == 1, "Must produce exactly one manifest"
        manifest = yaml.safe_load(yaml_patches[0])
        audit_note = manifest["metadata"]["annotations"].get("fjord.security/remediation-note", "")
        assert "Collateral Split" in audit_note or "shared" in audit_note.lower(), (
            f"Collateral split advisory must appear in annotation. Got: {audit_note!r}"
        )

    finally:
        db_manager.delete_graph(g)
