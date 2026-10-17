"""
tests/test_api.py
Integration tests for Task 4: FastAPI Bridge & Command Center API Endpoints.

Verifies:
1. Health and scenario listing endpoints.
2. Session initialization, snapshot graph creation, and UI token issuance.
3. Graph topology endpoint with attack path highlights.
4. Agent pipeline execution endpoint (posture -> discover -> ILP -> sandbox simulation).
5. Operator decision endpoint security:
   - Rejects requests with missing or invalid UI token (403 Forbidden).
   - Approves and executes verified commit with valid UI token.
6. Dashboard HTML endpoint serves 3-pane command center.
"""

import pytest
from fastapi.testclient import TestClient
from backend.api.app import app
from backend.schema import ActionDecision


client = TestClient(app)


def test_health_check():
    """Verify health endpoint connects to FalkorDB."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] in ("healthy", "degraded")
    assert data["metrics_label"] == "[DESIGN TARGET / EVAL. SPEC]"


def test_list_scenarios():
    """Verify built-in scenarios are listed."""
    response = client.get("/api/v1/scenarios")
    assert response.status_code == 200
    data = response.json()
    assert len(data) >= 4
    scenario_ids = [s["id"] for s in data]
    assert "sample_cluster" in scenario_ids
    assert "kubehound_reference" in scenario_ids


def test_session_lifecycle_and_operator_isolation():
    """
    Test complete session flow:
    1. Initialize session -> receives session_id, snapshot_sha, ui_token
    2. Query topology for snapshot_sha -> returns nodes, edges, attack paths
    3. Run remediation pipeline -> executes simulation and sets status
    4. Operator decision security gate:
       - Missing token -> 403 Forbidden
       - Invalid token -> 403 Forbidden
       - Valid token -> 200 OK + COMMITTED
    """
    # 1. Init session
    init_res = client.post("/api/v1/sessions/init", json={"scenario": "sample_cluster", "replay_mode": True})
    assert init_res.status_code == 200
    sess_data = init_res.json()
    session_id = sess_data["session_id"]
    snapshot_sha = sess_data["snapshot_sha"]
    ui_token = sess_data["ui_token"]
    assert session_id
    assert snapshot_sha.startswith("prod_")
    assert ui_token.startswith("uitok_")

    # 2. Get session
    get_res = client.get(f"/api/v1/sessions/{session_id}")
    assert get_res.status_code == 200
    assert get_res.json()["snapshot_sha"] == snapshot_sha

    # 3. Query Graph Topology
    topo_res = client.get(f"/api/v1/graph/{snapshot_sha}")
    assert topo_res.status_code == 200
    topo = topo_res.json()
    assert len(topo["nodes"]) > 0
    assert len(topo["edges"]) > 0
    assert topo["attack_path_count"] >= 1
    # Check attack path highlighted nodes
    attack_nodes = [n for n in topo["nodes"] if n["is_attack_path"]]
    assert len(attack_nodes) > 0

    # 4. Run Agent Pipeline
    run_res = client.post("/api/v1/agent/run", json={"session_id": session_id})
    assert run_res.status_code == 200
    run_data = run_res.json()
    assert run_data["status"] == "VERIFIED_IN_MODEL"
    candidate_set_id = run_data["candidate_set_id"]
    sandbox_sha = run_data["sandbox_sha"]
    assert candidate_set_id
    assert sandbox_sha.startswith("sandbox_sim_")

    # 5. Security Gate: Operator decision without token -> MUST FAIL (403)
    bad_res1 = client.post("/api/v1/operator/decision", json={
        "session_id": session_id,
        "candidate_set_id": candidate_set_id,
        "decision": ActionDecision.APPROVE.value,
    })
    assert bad_res1.status_code == 403

    # Security Gate: Operator decision with invalid token -> MUST FAIL (403)
    bad_res2 = client.post("/api/v1/operator/decision", json={
        "session_id": session_id,
        "candidate_set_id": candidate_set_id,
        "decision": ActionDecision.APPROVE.value,
        "ui_token": "fraudulent_token_attempt",
    })
    assert bad_res2.status_code == 403

    # Security Gate: Operator decision with VALID token -> MUST SUCCEED (200)
    good_res = client.post("/api/v1/operator/decision", json={
        "session_id": session_id,
        "candidate_set_id": candidate_set_id,
        "decision": ActionDecision.APPROVE.value,
        "ui_token": ui_token,
    })
    assert good_res.status_code == 200
    dec_data = good_res.json()
    assert dec_data["status"] == "RECORDED"
    assert dec_data["decision"] == "APPROVE"
    assert dec_data["commit_result"] is not None
    assert dec_data["commit_result"]["status"] == "COMMITTED"


def test_command_center_html_ui():
    """Verify Command Center HTML UI is served with 3-pane structure."""
    response = client.get("/")
    assert response.status_code == 200
    html = response.text
    assert "PROJECT FJORD" in html
    assert "FastMCP Flight Trace" in html
    assert "topology-canvas" in html
    assert "Explainable Path Proof" in html
    assert "Synthesized K8s Patch" in html
    assert "Operator Review Gate" in html
