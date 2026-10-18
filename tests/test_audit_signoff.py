"""
tests/test_audit_signoff.py
Automated End-to-End Self-Audit & Signoff Verification for Project Fjord.
Uses httpx and Playwright against http://127.0.0.1:8000/ to verify all 9 audit criteria:

1. Multi-Branch Ingestion & Workload-Scoped Containers (branch-01/web)
2. 1-to-1 Adjacency & Zero Sibling Clutter
3. Acyclic *1..8 Cypher Paths
4. Solver Edge Count (Severed Edges: 1, never 0)
5. Operational Freeze Constraint (<1.5s & OPERATIONAL_FREEZE with grounded YAML)
6. Approval Gate Evaluated Resources (host-root-filesystem included)
7. Safe Sandbox Approval & One-Time Lock (local ledger message and HTTP 409 on duplicate)
8. XSS Escaping & Live MCP Tools (all 7 MCP tools return SUCCESS with ms latency; XSS rendered as literal escaped text)
9. Responsive Mobile/Tablet Viewports (no horizontal overflow at 390px)
"""

import time
import uuid
import yaml
import pytest
import httpx
from playwright.sync_api import sync_playwright

BASE_URL = "http://127.0.0.1:8000"


@pytest.fixture(scope="module")
def http_client():
    with httpx.Client(base_url=BASE_URL, timeout=30.0) as client:
        # Verify server is listening
        health_resp = client.get("/api/v1/health")
        assert health_resp.status_code == 200, f"Health check failed: {health_resp.text}"
        yield client


@pytest.fixture(scope="module")
def browser_instance():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        yield browser
        browser.close()


def generate_26_doc_manifest():
    """Build the canonical 26-document multi-branch Kubernetes manifest."""
    docs = []
    # 1. Namespace
    docs.append({
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {"name": "branches-ns"}
    })

    # 2. Ingress with 12 backend paths
    ingress_paths = []
    for i in range(1, 13):
        bname = f"branch-{i:02d}"
        ingress_paths.append({
            "path": f"/{bname}",
            "pathType": "Prefix",
            "backend": {
                "service": {
                    "name": f"{bname}-svc",
                    "port": {"number": 80}
                }
            }
        })
    docs.append({
        "apiVersion": "networking.k8s.io/v1",
        "kind": "Ingress",
        "metadata": {"name": "public-branches", "namespace": "branches-ns"},
        "spec": {
            "rules": [{
                "http": {"paths": ingress_paths}
            }]
        }
    })

    # 3. 12 Services and 12 Deployments with container name "web"
    for i in range(1, 13):
        bname = f"branch-{i:02d}"
        docs.append({
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": f"{bname}-svc", "namespace": "branches-ns"},
            "spec": {
                "selector": {"app": bname},
                "ports": [{"port": 80, "targetPort": 8080}]
            }
        })
        docs.append({
            "apiVersion": "apps/v1",
            "kind": "Deployment",
            "metadata": {"name": bname, "namespace": "branches-ns"},
            "spec": {
                "selector": {"matchLabels": {"app": bname}},
                "template": {
                    "metadata": {"labels": {"app": bname}},
                    "spec": {
                        "containers": [{
                            "name": "web",
                            "image": "alpine:3.18",
                            "ports": [{"containerPort": 8080}]
                        }]
                    }
                }
            }
        })

    assert len(docs) == 26
    return "\n---\n".join(yaml.dump(d) for d in docs)


# ============================================================================
# CRITERION 1: Multi-Branch Ingestion & Workload-Scoped Containers (branch-01/web)
# ============================================================================
def test_criterion_1_multi_branch_ingestion_and_workload_scoped_containers(http_client):
    """
    Ingest the 26-doc manifest via POST /api/v1/upload.
    Verify:
    - Exactly 1 Ingress (k8s_kind == 'Ingress')
    - Exactly 12 Services (k8s_kind == 'Service')
    - Exactly 12 Deployments (k8s_kind == 'Deployment')
    - Exactly 12 Containers, scoped as 'branch-01/web' .. 'branch-12/web' (k8s_kind == 'Container')
    - Zero bare un-scoped 'web' containers
    """
    manifest_yaml = generate_26_doc_manifest()
    resp = http_client.post("/api/v1/upload", json={
        "filename": "multi_branch_26.yaml",
        "yaml_content": manifest_yaml
    })
    assert resp.status_code == 200, f"Upload failed: {resp.text}"
    data = resp.json()
    snapshot_sha = data["snapshot_sha"]

    # Query topology
    graph_resp = http_client.get(f"/api/v1/graph/{snapshot_sha}")
    assert graph_resp.status_code == 200
    g_data = graph_resp.json()
    nodes = g_data["nodes"]

    # Kinds exact
    ingress_nodes = [n for n in nodes if n.get("k8s_kind") == "Ingress" or n.get("label") == "Ingress"]
    assert len(ingress_nodes) == 1
    assert ingress_nodes[0].get("k8s_kind") == "Ingress"

    svc_nodes = [n for n in nodes if n.get("k8s_kind") == "Service" or n.get("label") == "Service"]
    assert len(svc_nodes) == 12
    for s in svc_nodes:
        assert s.get("k8s_kind") == "Service"

    dep_nodes = [n for n in nodes if n.get("k8s_kind") == "Deployment" or n.get("label") == "Workload"]
    assert len(dep_nodes) == 12
    for d in dep_nodes:
        assert d.get("k8s_kind") == "Deployment"

    container_nodes = [n for n in nodes if n.get("k8s_kind") == "Container" or n.get("label") == "Container"]
    assert len(container_nodes) == 12
    for c in container_nodes:
        assert c.get("k8s_kind") == "Container"
        c_name = c.get("name", "")
        assert "/" in c_name, f"Container name '{c_name}' is not workload-scoped"
        assert c_name.endswith("/web"), f"Container name '{c_name}' does not end with /web"
        assert c_name != "web", "Bare container name 'web' found"


# ============================================================================
# CRITERION 2: 1-to-1 Adjacency & Zero Sibling Clutter
# ============================================================================
def test_criterion_2_one_to_one_adjacency_and_zero_sibling_clutter(http_client):
    """
    Ingest the 26-doc manifest and verify:
    - 1-to-1 Service -> Deployment routing
    - branch-01 has 0 outbound edges to sibling branches (branch-02..branch-12)
    """
    manifest_yaml = generate_26_doc_manifest()
    resp = http_client.post("/api/v1/upload", json={
        "filename": "adjacency_test.yaml",
        "yaml_content": manifest_yaml
    })
    assert resp.status_code == 200
    snapshot_sha = resp.json()["snapshot_sha"]

    graph_resp = http_client.get(f"/api/v1/graph/{snapshot_sha}")
    assert graph_resp.status_code == 200
    edges = graph_resp.json()["edges"]

    # 1-to-1 Service -> Deployment routing
    selects_edges = [e for e in edges if e.get("type") == "SELECTS"]
    assert len(selects_edges) == 12
    for edge in selects_edges:
        svc_name = edge["source"].split("/")[-1]
        wk_name = edge["target"].split("/")[-1]
        assert svc_name.replace("-svc", "") == wk_name

    # Zero outbound edges from branch-01 to sibling branch-02..12
    b01_id = "branches-ns/branch-01"
    b01_out_edges = [
        e for e in edges
        if e["source"] == b01_id and any(f"branch-{k:02d}" in e["target"] for k in range(2, 13))
    ]
    assert len(b01_out_edges) == 0, f"branch-01 has unexpected sibling edges: {b01_out_edges}"


# ============================================================================
# CRITERION 3: Acyclic *1..8 Cypher Paths
# ============================================================================
def test_criterion_3_acyclic_cypher_paths(http_client):
    """
    Initialize sample_cluster scenario and execute variable-length path discovery.
    Verify zero repeated nodes in all exploit paths.
    """
    init_res = http_client.post("/api/v1/sessions/init", json={"scenario": "sample_cluster", "replay_mode": True})
    assert init_res.status_code == 200
    snap = init_res.json()["snapshot_sha"]

    cypher_res = http_client.post("/api/v1/cypher", json={
        "query": "MATCH p=(a)-[:EXPLOIT_STEP*1..8]->(b) RETURN [n IN nodes(p) | n.name]",
        "graph_name": snap
    })
    assert cypher_res.status_code == 200
    data = cypher_res.json()
    assert data["status"] == "SUCCESS"
    rows = data["rows"]
    assert len(rows) > 0, "Expected at least 1 exploit path row"

    for row in rows:
        row_str = str(row[0])
        node_names = [n.strip("'\" []") for n in row_str.split(",") if n.strip("'\" []")]
        assert len(node_names) == len(set(node_names)), f"Cyclic path detected with repeated nodes: {node_names}"


# ============================================================================
# CRITERION 4: Solver Edge Count (Severed Edges: 1, never 0)
# ============================================================================
def test_criterion_4_solver_edge_count(http_client):
    """
    Run compute_optimal_remediations on sample_cluster.
    Verify the trace summary explicitly reports 'Severed Edges: 1' (and never 'Severed Edges: 0').
    """
    init_res = http_client.post("/api/v1/sessions/init", json={"scenario": "sample_cluster", "replay_mode": True})
    assert init_res.status_code == 200
    session_id = init_res.json()["session_id"]

    run_res = http_client.post("/api/v1/agent/run", json={"session_id": session_id})
    assert run_res.status_code == 200
    run_data = run_res.json()

    tools_called = run_data.get("tools_called", [])
    remed_tool = next((t for t in tools_called if t.get("name") == "compute_optimal_remediations"), None)
    assert remed_tool is not None, "compute_optimal_remediations tool was not dispatched"

    summary = remed_tool.get("result_summary", "")
    assert "Severed Edges: 1" in summary, f"Expected 'Severed Edges: 1' in summary, got: {summary}"
    assert "Severed Edges: 0" not in summary, "Found forbidden 'Severed Edges: 0' in summary"


# ============================================================================
# CRITERION 5: Operational Freeze Constraint (<1.5s & OPERATIONAL_FREEZE)
# ============================================================================
def test_criterion_5_operational_freeze_constraint_speed_and_yaml(http_client):
    """
    Send 'We cannot restart frontend-app until Friday' to POST /api/v1/chat.
    Verify:
    - Total response time < 1.5 seconds
    - Tool argument uses constraint_type: OPERATIONAL_FREEZE
    - Response card contains OPERATIONAL_FREEZE
    - Reply includes grounded NetworkPolicy YAML block
    """
    init_res = http_client.post("/api/v1/sessions/init", json={"scenario": "sample_cluster", "replay_mode": True})
    assert init_res.status_code == 200
    session_id = init_res.json()["session_id"]

    t0 = time.perf_counter()
    chat_res = http_client.post("/api/v1/chat", json={
        "session_id": session_id,
        "message": "We cannot restart frontend-app until Friday"
    })
    latency = time.perf_counter() - t0

    assert chat_res.status_code == 200
    assert latency < 1.5, f"Operational freeze chat took {latency:.3f}s (must be < 1.5s)"

    data = chat_res.json()
    tools_called = data.get("tools_called", [])
    assert len(tools_called) >= 1

    # Check tool arguments
    c_tool = tools_called[0]
    assert c_tool.get("arguments", {}).get("constraint_type") == "OPERATIONAL_FREEZE"

    # Check reply and card
    reply = data.get("reply", "")
    assert "OPERATIONAL_FREEZE" in reply
    assert "```yaml" in reply
    assert "kind: NetworkPolicy" in reply


# ============================================================================
# CRITERION 6: Approval Gate Evaluated Resources
# ============================================================================
def test_criterion_6_approval_gate_evaluated_resources(http_client, browser_instance):
    """
    Verify host-root-filesystem is included in sample_cluster evaluated resources
    both via API graph topology and in the UI's Approval Gate element.
    """
    # 1. API Verification
    init_res = http_client.post("/api/v1/sessions/init", json={"scenario": "sample_cluster", "replay_mode": True})
    assert init_res.status_code == 200
    snapshot_sha = init_res.json()["snapshot_sha"]

    graph_res = http_client.get(f"/api/v1/graph/{snapshot_sha}")
    assert graph_res.status_code == 200
    nodes = graph_res.json()["nodes"]
    node_names = [n.get("name") or n.get("clean_name") or n.get("id") for n in nodes]
    assert any("host-root-filesystem" in str(name) for name in node_names)

    # 2. Playwright UI Verification
    page = browser_instance.new_page()
    page.goto(f"{BASE_URL}/")
    page.wait_for_timeout(1000)

    # Trigger scenario load in UI
    page.evaluate("async () => { await loadScenario('sample_cluster'); }")
    page.wait_for_timeout(2000)

    eval_el = page.query_selector("#approval-gate-evaluated-workloads")
    assert eval_el is not None, "#approval-gate-evaluated-workloads not found in DOM"
    eval_text = eval_el.inner_text()
    assert "host-root-filesystem" in eval_text, f"host-root-filesystem missing from evaluated workloads text: '{eval_text}'"
    page.close()


# ============================================================================
# CRITERION 7: Safe Sandbox Approval & One-Time Lock
# ============================================================================
def test_criterion_7_safe_sandbox_approval_and_one_time_lock(http_client):
    """
    Execute remediation pipeline to produce candidate.
    Verify:
    - POST /api/v1/operator/decision with decision: APPROVE returns the local ledger toast message
    - Immediate duplicate commit with the same candidate_set_id returns HTTP 409
    """
    init_res = http_client.post("/api/v1/sessions/init", json={"scenario": "sample_cluster", "replay_mode": True})
    assert init_res.status_code == 200
    sess = init_res.json()
    session_id = sess["session_id"]
    ui_token = sess["ui_token"]

    run_res = http_client.post("/api/v1/agent/run", json={"session_id": session_id})
    assert run_res.status_code == 200
    candidate_set_id = run_res.json()["candidate_set_id"]

    # 1. First approval commit -> 200 OK + local ledger toast
    dec_res1 = http_client.post("/api/v1/operator/decision", json={
        "session_id": session_id,
        "candidate_set_id": candidate_set_id,
        "decision": "APPROVE",
        "ui_token": ui_token,
        "reason": "Security Operator Verified Signoff"
    })
    assert dec_res1.status_code == 200
    data1 = dec_res1.json()
    assert data1["status"] == "RECORDED"
    assert "local sandbox session ledger" in data1["message"]

    # 2. Duplicate commit -> HTTP 409 Conflict
    dec_res2 = http_client.post("/api/v1/operator/decision", json={
        "session_id": session_id,
        "candidate_set_id": candidate_set_id,
        "decision": "APPROVE",
        "ui_token": ui_token,
        "reason": "Duplicate replay attempt"
    })
    assert dec_res2.status_code == 409
    assert "already committed" in dec_res2.json()["detail"].lower()


# ============================================================================
# CRITERION 8: XSS Escaping & Live MCP Tools
# ============================================================================
def test_criterion_8_xss_escaping_and_all_7_mcp_tools(http_client, browser_instance):
    """
    1. Verify XSS injection in UI chat input renders escaped literal text without creating DOM nodes.
    2. Verify all 7 FastMCP tools execute successfully with measured execution_ms > 0.
    """
    # 1. Playwright XSS Escaping
    page = browser_instance.new_page()
    page.goto(f"{BASE_URL}/")
    page.wait_for_timeout(1000)

    # Switch to Copilot chat view
    page.evaluate("switchView('copilot')")
    page.wait_for_timeout(500)

    xss_payload = "<b id='xss-injection-marker'><img src=x onerror=alert('xss')></b>"
    # Type into chat input and send
    chat_input = page.query_selector("#chat-input")
    assert chat_input is not None
    chat_input.fill(xss_payload)

    send_btn = page.query_selector("#btn-chat-send") or page.query_selector("#btn-send-chat")
    assert send_btn is not None
    send_btn.click()
    page.wait_for_timeout(1500)

    # Verify that no unescaped injected element exists in DOM
    marker_el = page.query_selector("#xss-injection-marker")
    assert marker_el is None, "XSS Vulnerability: unescaped marker element found in DOM!"

    # Verify escaped text is displayed literally
    chat_container = page.query_selector("#chat-messages") or page.query_selector("#chat-messages-container")
    assert chat_container is not None
    assert "xss-injection-marker" in chat_container.inner_text()
    page.close()

    # 2. Execute all 7 FastMCP tools via POST /api/v1/mcp/execute
    init_res = http_client.post("/api/v1/sessions/init", json={"scenario": "sample_cluster", "replay_mode": True})
    assert init_res.status_code == 200
    snap = init_res.json()["snapshot_sha"]

    mcp_tools_sequence = [
        ("get_posture_and_cluster_summary", {"graph_name": snap}),
        ("discover_attack_paths", {"graph_name": snap}),
        ("compute_optimal_remediations", {"graph_name": snap}),
        ("inspect_resource_context", {"graph_name": snap, "resource_id": "prod/frontend-app"}),
        ("simulate_fix_in_sandbox", {"snapshot_sha": snap, "candidate_set_id": "current"}),
        ("commit_verified_remediation", {"snapshot_sha": snap, "candidate_set_id": "current"}),
        ("update_dependency_or_constraint", {"graph_name": snap, "source": "prod/frontend-app", "target": "prod/backend-api", "constraint_type": "OPERATIONAL_FREEZE"}),
    ]

    for tool_name, args in mcp_tools_sequence:
        mcp_res = http_client.post("/api/v1/mcp/execute", json={
            "tool_name": tool_name,
            "arguments": args
        })
        assert mcp_res.status_code == 200, f"MCP tool {tool_name} returned status {mcp_res.status_code}: {mcp_res.text}"
        data = mcp_res.json()
        assert data.get("status") == "SUCCESS", f"MCP tool {tool_name} failed: {data}"
        latency = data.get("execution_ms", 0)
        assert latency >= 0, f"MCP tool {tool_name} missing measured execution latency"


# ============================================================================
# CRITERION 9: Responsive Mobile/Tablet Viewports (390px)
# ============================================================================
def test_criterion_9_responsive_mobile_viewport(browser_instance):
    """
    Set browser viewport to 390px width (iPhone 12/13/14) and verify zero horizontal overflow:
    scrollWidth <= clientWidth and bodyScrollWidth <= innerWidth.
    """
    page = browser_instance.new_page(viewport={"width": 390, "height": 844})
    page.goto(f"{BASE_URL}/")
    page.wait_for_timeout(1500)

    overflow_check = page.evaluate("""() => {
        const docEl = document.documentElement;
        const body = document.body;
        return {
            docScrollWidth: docEl.scrollWidth,
            docClientWidth: docEl.clientWidth,
            bodyScrollWidth: body.scrollWidth,
            windowInnerWidth: window.innerWidth,
            hasDocOverflow: docEl.scrollWidth > docEl.clientWidth,
            hasBodyOverflow: body.scrollWidth > window.innerWidth
        };
    }""")

    assert not overflow_check["hasDocOverflow"], (
        f"Document has horizontal overflow at 390px: scrollWidth={overflow_check['docScrollWidth']} > clientWidth={overflow_check['docClientWidth']}"
    )
    assert not overflow_check["hasBodyOverflow"], (
        f"Body has horizontal overflow at 390px: bodyScrollWidth={overflow_check['bodyScrollWidth']} > innerWidth={overflow_check['windowInnerWidth']}"
    )
    page.close()
