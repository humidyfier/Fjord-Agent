"""
tests/test_compiler_monotonicity.py
Automated Monotonicity Property Tests for Project Fjord.

Invariant:
For any atomic remediation mutation m applied in a sandbox:
    EdgeSet_post-mutation(:EXPLOIT_STEP) <= EdgeSet_pre-mutation(:EXPLOIT_STEP)

Any mutation that introduces new unmonitored attack paths fails the test suite.
"""

import sys
from pathlib import Path
from typing import Set, Tuple
import pytest

# Ensure project root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.db.connection import db_manager
from backend.ingest.parser import IngestionEngine
from backend.db.compiler import ExploitGraphCompiler


FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
BASE_GRAPH = "test_mono_base"


@pytest.fixture(scope="module")
def base_graph():
    """Initializes and compiles the base topology graph in FalkorDB."""
    db_manager.delete_graph(BASE_GRAPH)

    engine = IngestionEngine()

    # 1. Ingest K8s YAML
    k8s_yaml = (FIXTURES_DIR / "sample_cluster.yaml").read_text(encoding="utf-8")
    engine.parse_k8s_yaml(k8s_yaml)

    # 2. Ingest Trivy
    trivy_json = (FIXTURES_DIR / "trivy_report.json").read_text(encoding="utf-8")
    engine.parse_trivy_json(trivy_json)

    # 3. Ingest Prowler
    prowler_json = (FIXTURES_DIR / "prowler_report.json").read_text(encoding="utf-8")
    engine.parse_prowler_json(prowler_json)

    # 4. Ingest Required Flows
    req_flows = (FIXTURES_DIR / "required_flows.yaml").read_text(encoding="utf-8")
    engine.parse_required_flows_yaml(req_flows)

    # 5. Materialize Layer 1 in FalkorDB
    counts = engine.resolve_cni_and_populate_graph(BASE_GRAPH)
    assert counts["node_count"] > 0, "Base graph must contain nodes"

    # 6. Compile Layer 2 Exploit Plane
    compiler = ExploitGraphCompiler(BASE_GRAPH)
    stats = compiler.compile()
    assert stats["total_exploit_steps"] > 0, "Exploit plane must contain :EXPLOIT_STEP edges"

    yield BASE_GRAPH

    # Teardown
    db_manager.delete_graph(BASE_GRAPH)


def _get_exploit_edge_set(graph_name: str) -> Set[Tuple[str, str, str, str]]:
    """
    Extracts all :EXPLOIT_STEP edges as a normalized set of tuples:
    (from_id, to_id, step_type, mechanism)
    """
    cypher = """
    MATCH (a)-[r:EXPLOIT_STEP]->(b)
    RETURN a.id AS from_id, b.id AS to_id, r.step_type AS step_type, r.mechanism AS mechanism
    """
    res = db_manager.query(graph_name, cypher)
    edge_set = set()
    for row in res:
        edge_set.add((str(row[0]), str(row[1]), str(row[2]), str(row[3])))
    return edge_set


def test_schema_conformance(base_graph):
    """Assert that base graph conforms to schema node labels and relationships."""
    # Verify node labels present
    labels_res = db_manager.query(base_graph, "MATCH (n) RETURN distinct labels(n)")
    present_labels = {lbl for row in labels_res for lbl in row[0]}
    assert "Workload" in present_labels
    assert "Container" in present_labels
    assert "Service" in present_labels
    assert "PostureFinding" in present_labels
    assert "CrownJewel" in present_labels
    assert "VirtualSource" in present_labels
    assert "VirtualSink" in present_labels

    # Verify relationships present
    rels_res = db_manager.query(base_graph, "MATCH ()-[r]->() RETURN distinct type(r)")
    present_rels = {row[0] for row in rels_res}
    assert "CAN_REACH_NET" in present_rels
    assert "EXPLOIT_STEP" in present_rels
    assert "REQUIRED_DEPENDENCY" in present_rels
    assert "HAS_CONTAINER" in present_rels


def test_mutation_monotonicity_network_sever(base_graph):
    """Mutation Class 1: Severing CAN_REACH_NET must strictly reduce or maintain exploit steps."""
    sandbox = "sandbox_mono_network"
    db_manager.copy_graph(base_graph, sandbox)
    try:
        pre_edges = _get_exploit_edge_set(sandbox)

        # Apply mutation: sever CAN_REACH_NET between frontend-app and backend-api
        db_manager.query(
            sandbox,
            "MATCH (w1:Workload {id: 'prod/frontend-app'})-[r:CAN_REACH_NET]->(w2:Workload {id: 'prod/backend-api'}) DELETE r"
        )

        # Recompile exploit plane
        compiler = ExploitGraphCompiler(sandbox)
        compiler.compile()

        post_edges = _get_exploit_edge_set(sandbox)

        # Monotonicity check: post <= pre
        new_edges = post_edges - pre_edges
        assert len(new_edges) == 0, f"Monotonicity violation! New exploit edges appeared: {new_edges}"
        assert len(post_edges) < len(pre_edges), "Expected edge reduction after severing network link."
    finally:
        db_manager.delete_graph(sandbox)


def test_mutation_monotonicity_rbac_unbind(base_graph):
    """Mutation Class 2: Revoking RBAC binding must not introduce new exploit paths."""
    sandbox = "sandbox_mono_rbac"
    db_manager.copy_graph(base_graph, sandbox)
    try:
        pre_edges = _get_exploit_edge_set(sandbox)

        # Apply mutation: unbind ServiceAccount from ClusterRole
        db_manager.query(
            sandbox,
            "MATCH (sa:ServiceAccount {id: 'prod/backend-sa'})-[r:BOUND_TO]->(role:RBACRole) DELETE r"
        )

        compiler = ExploitGraphCompiler(sandbox)
        compiler.compile()

        post_edges = _get_exploit_edge_set(sandbox)

        new_edges = post_edges - pre_edges
        assert len(new_edges) == 0, f"Monotonicity violation on RBAC unbind! New edges: {new_edges}"
        assert len(post_edges) <= len(pre_edges)
    finally:
        db_manager.delete_graph(sandbox)


def test_mutation_monotonicity_privilege_removal(base_graph):
    """Mutation Class 3: Removing privileged flag on container must strictly reduce escape steps."""
    sandbox = "sandbox_mono_priv"
    db_manager.copy_graph(base_graph, sandbox)
    try:
        pre_edges = _get_exploit_edge_set(sandbox)

        # Apply mutation: set privileged = false
        db_manager.query(
            sandbox,
            "MATCH (c:Container {privileged: true}) SET c.privileged = false"
        )

        compiler = ExploitGraphCompiler(sandbox)
        compiler.compile()

        post_edges = _get_exploit_edge_set(sandbox)

        new_edges = post_edges - pre_edges
        assert len(new_edges) == 0, f"Monotonicity violation on privilege removal! New edges: {new_edges}"
        assert len(post_edges) <= len(pre_edges)
    finally:
        db_manager.delete_graph(sandbox)


def test_mutation_monotonicity_hostpath_removal(base_graph):
    """Mutation Class 4: Removing hostPath socket mount must eliminate host escape edge."""
    sandbox = "sandbox_mono_hostpath"
    db_manager.copy_graph(base_graph, sandbox)
    try:
        pre_edges = _get_exploit_edge_set(sandbox)

        # Apply mutation: remove MOUNTS_HOST edge
        db_manager.query(
            sandbox,
            "MATCH ()-[r:MOUNTS_HOST]->() DELETE r"
        )

        compiler = ExploitGraphCompiler(sandbox)
        compiler.compile()

        post_edges = _get_exploit_edge_set(sandbox)

        new_edges = post_edges - pre_edges
        assert len(new_edges) == 0, f"Monotonicity violation on hostPath removal! New edges: {new_edges}"
        assert len(post_edges) < len(pre_edges)
    finally:
        db_manager.delete_graph(sandbox)


def test_mutation_monotonicity_cloud_iam_revocation(base_graph):
    """Mutation Class 5: Revoking AWS IRSA IAM AssumeRole must sever cloud pivot."""
    sandbox = "sandbox_mono_iam"
    db_manager.copy_graph(base_graph, sandbox)
    try:
        pre_edges = _get_exploit_edge_set(sandbox)

        # Apply mutation: remove ASSUMES_IAM_ROLE edge
        db_manager.query(
            sandbox,
            "MATCH ()-[r:ASSUMES_IAM_ROLE]->() DELETE r"
        )

        compiler = ExploitGraphCompiler(sandbox)
        compiler.compile()

        post_edges = _get_exploit_edge_set(sandbox)

        new_edges = post_edges - pre_edges
        assert len(new_edges) == 0, f"Monotonicity violation on IAM revocation! New edges: {new_edges}"
        assert len(post_edges) <= len(pre_edges)
    finally:
        db_manager.delete_graph(sandbox)
