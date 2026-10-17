"""
tests/test_audit_hardening.py
Hardening and specification audit test suite for Project Fjord.

Covers:
1. test_k8s_reingest_verification_and_kubeconform:
   Exercises the full loop on a K8s fix -> runs kubeconform on generated NetworkPolicy YAML ->
   re-ingests the patched manifest bundle into a verification graph -> confirms status is VERIFIED_BY_REINGEST.
2. test_sentinel_memory_survives_reingest_and_vetoes_solver:
   Writes REJECTED_BY_OPERATOR to sentinel_memory -> re-ingests cluster into new snapshot ->
   asserts compute_optimal_remediations skips the rejected edge cut and picks the next optimal candidate.
3. test_startup_self_check:
   Tests startup_check.py against FalkorDB (GRAPH.COPY, algo.SPpaths) and Gemini model configs.
4. test_unauthorized_tool_and_missing_sandbox_commit_blocked:
   Asserts calling an undeclared tool name returns error and calling commit_verified_remediation
   without prior verified sandbox simulation fails hard.
"""

import pytest
import uuid
from pathlib import Path

from backend.db.connection import db_manager
from backend.db.compiler import ExploitGraphCompiler
from backend.db.startup_check import (
    verify_falkordb_capabilities,
    verify_model_configuration,
    run_full_startup_check,
)
from backend.ingest.parser import IngestionEngine
from backend.agent.orchestrator import AgentOrchestrator
from backend.agent.guardrails import VerificationGateError, guardrail_manager
from backend.agent import tools
from backend.solver.ilp_solver import CuttingPlaneILPSolver
from backend.solver.yaml_generator import NetworkPolicyYAMLGenerator
from backend.schema import VerificationStatus


FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture(autouse=True)
def reset_turn():
    """Reset turn quotas before each audit test."""
    guardrail_manager.reset_turn()
    yield
    guardrail_manager.reset_turn()


def test_k8s_reingest_verification_and_kubeconform():
    """
    1. Ingest sample cluster into snapshot graph.
    2. Run compute_optimal_remediations + simulate_fix_in_sandbox.
    3. Run commit_verified_remediation -> asserts kubeconform validation passes
       and proof upgrades to VERIFIED_BY_REINGEST.
    """
    snapshot_sha = f"prod_audit_{uuid.uuid4().hex[:8]}"

    # Ingest baseline
    engine = IngestionEngine()
    engine.parse_k8s_yaml((FIXTURES_DIR / "sample_cluster.yaml").read_text(encoding="utf-8"))
    engine.parse_trivy_json((FIXTURES_DIR / "trivy_report.json").read_text(encoding="utf-8"))
    engine.parse_prowler_json((FIXTURES_DIR / "prowler_report.json").read_text(encoding="utf-8"))
    engine.parse_required_flows_yaml((FIXTURES_DIR / "required_flows.yaml").read_text(encoding="utf-8"))
    engine.resolve_cni_and_populate_graph(snapshot_sha)

    compiler = ExploitGraphCompiler(snapshot_sha)
    compiler.compile()

    # 1. Compute remediations
    rem_resp = tools.compute_optimal_remediations(graph_name=snapshot_sha)
    assert len(rem_resp.optimal_candidates) >= 1
    cset_id = rem_resp.candidate_set_id

    # 2. Simulate in sandbox
    sim_resp = tools.simulate_fix_in_sandbox(snapshot_sha=snapshot_sha, candidate_set_id=cset_id)
    assert sim_resp.simulation_result.verification_status == VerificationStatus.VERIFIED_IN_MODEL
    assert sim_resp.simulation_result.surviving_attack_paths == 0

    # 3. Commit verified remediation
    commit_resp = tools.commit_verified_remediation(
        snapshot_sha=snapshot_sha,
        candidate_set_id=cset_id,
    )
    assert commit_resp.status == "COMMITTED"
    assert "VERIFIED_BY_REINGEST" in commit_resp.verification_proof

    # Clean up
    db_manager.delete_graph(snapshot_sha)


def test_sentinel_memory_survives_reingest_and_vetoes_solver():
    """
    Writes a REJECTED_BY_OPERATOR decision with edge_keys to sentinel_memory ->
    re-ingests the cluster into a fresh snapshot -> runs solver ->
    asserts the solver skips the vetoed edge cut.
    """
    orch = AgentOrchestrator(session_id="audit_sentinel_sess")
    vetoed_edge = "prod/frontend-app-->prod/backend-api"

    # 1. Operator rejects the frontend->backend cut
    orch.record_operator_decision(
        candidate_set_id="cset_operator_veto_test",
        decision="REJECTED_BY_OPERATOR",
        operator_identity="SecurityOperator_Audit",
        reason="Business critical frontend-to-backend traffic must not be cut at network layer",
        stable_key=vetoed_edge,
        edge_keys=[vetoed_edge],
    )

    # 2. Ingest cluster into fresh snapshot
    new_snapshot = f"prod_fresh_{uuid.uuid4().hex[:8]}"
    engine = IngestionEngine()
    engine.parse_k8s_yaml((FIXTURES_DIR / "sample_cluster.yaml").read_text(encoding="utf-8"))
    engine.parse_trivy_json((FIXTURES_DIR / "trivy_report.json").read_text(encoding="utf-8"))
    engine.parse_prowler_json((FIXTURES_DIR / "prowler_report.json").read_text(encoding="utf-8"))
    engine.parse_required_flows_yaml((FIXTURES_DIR / "required_flows.yaml").read_text(encoding="utf-8"))
    engine.resolve_cni_and_populate_graph(new_snapshot)

    compiler = ExploitGraphCompiler(new_snapshot)
    compiler.compile()

    # 3. Solve on fresh snapshot
    solver = CuttingPlaneILPSolver(new_snapshot)
    candidates = solver.enumerate_candidates()

    # Assert that candidate containing vetoed_edge is marked forbidden
    vetoed_candidates = [c for c in candidates if vetoed_edge in c.severs_edge_keys]
    assert len(vetoed_candidates) >= 1
    for vc in vetoed_candidates:
        assert vc.forbidden is True
        assert vc.disruption_cost == 999.0

    # 4. Solve and ensure selected actions do NOT include the vetoed candidate
    result = solver.solve(candidates)
    assert result.solver_status == "optimal"
    for sel in result.selected_actions:
        assert vetoed_edge not in sel.severs_edge_keys

    # Clean up
    db_manager.delete_graph(new_snapshot)


def test_startup_self_check():
    """
    Tests startup_check.py against FalkorDB and Gemini model configurations.
    """
    db_status = verify_falkordb_capabilities()
    assert db_status["falkordb_ping"] is True
    assert db_status["graph_copy"] is True
    assert db_status["algo_sppaths"] is True

    model_status = verify_model_configuration(
        primary_model="gemini-3.8-flash",
        fallback_model="gemini-3.6-flash",
        thinking_level="high",
    )
    assert model_status["valid"] is True
    assert model_status["primary_model"] == "gemini-3.8-flash"

    # Check failure on unsupported model
    bad_model = verify_model_configuration(primary_model="unsupported-fake-model")
    assert bad_model["valid"] is False

    full_check = run_full_startup_check()
    assert full_check["status"] == "READY"
    assert full_check["metrics_label"] == "[DESIGN TARGET / EVAL. SPEC]"


def test_unauthorized_tool_and_missing_sandbox_commit_blocked():
    """
    Asserts:
    1. Calling an undeclared tool name returns ValueError.
    2. Calling commit_verified_remediation without a matching verified sandbox run fails hard.
    """
    orch = AgentOrchestrator(session_id="audit_gate_sess")

    # 1. Undeclared tool
    with pytest.raises(ValueError, match="Unknown tool"):
        orch.execute_tool("fake_destructive_tool", {"param": 1})

    # 2. Commit without prior sandbox simulation
    unverified_snapshot = f"prod_fake_{uuid.uuid4().hex[:8]}"
    unverified_cset = "cset_never_simulated"

    with pytest.raises(VerificationGateError):
        tools.commit_verified_remediation(
            snapshot_sha=unverified_snapshot,
            candidate_set_id=unverified_cset,
        )
