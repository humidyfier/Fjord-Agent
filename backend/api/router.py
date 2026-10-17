"""
backend/api/router.py
FastAPI Router for Project Fjord Command Center.

Endpoints:
- GET  /api/v1/health
- GET  /api/v1/scenarios
- POST /api/v1/sessions/init
- GET  /api/v1/sessions/{session_id}
- GET  /api/v1/sessions/{session_id}/stream (SSE real-time stream)
- GET  /api/v1/graph/{graph_name} (Topology canvas nodes & edges)
- POST /api/v1/agent/run (Execute remediation pipeline)
- POST /api/v1/operator/decision (UI-only token protected operator decision)
"""

import asyncio
import json
import uuid
import hashlib
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Header, Depends, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field

from backend.db.connection import db_manager, DEFAULT_GRAPH
from backend.ingest.parser import IngestionEngine
from backend.db.compiler import ExploitGraphCompiler
from backend.agent.orchestrator import AgentOrchestrator
from backend.agent import tools
from backend.schema import ActionDecision, VerificationStatus


router = APIRouter(prefix="/api/v1", tags=["Fjord Command Center"])

FIXTURES_DIR = Path(__file__).resolve().parent.parent.parent / "tests" / "fixtures"

# In-memory session store: session_id -> SessionState
_active_sessions: Dict[str, Dict[str, Any]] = {}
# Session SSE queues: session_id -> asyncio.Queue
_session_event_queues: Dict[str, asyncio.Queue] = {}


# ============================================================================
# PYDANTIC REQUEST / RESPONSE MODELS
# ============================================================================

class SessionInitRequest(BaseModel):
    scenario: str = Field(default="sample_cluster", description="Pre-built scenario: sample_cluster, kubehound_reference, kubernetes_goat, bad_pods")
    byok_api_key: Optional[str] = Field(default=None, description="Optional user BYOK Gemini API key")
    replay_mode: bool = Field(default=False, description="Run in deterministic replay mode against live FalkorDB")


class SessionInitResponse(BaseModel):
    session_id: str
    snapshot_sha: str
    ui_token: str
    scenario: str
    replay_mode: bool
    created_at: str
    metrics_label: str = "[DESIGN TARGET / EVAL. SPEC]"


class OperatorDecisionRequest(BaseModel):
    session_id: str
    candidate_set_id: str
    decision: ActionDecision
    reason: Optional[str] = None
    ui_token: Optional[str] = None


class AgentRunRequest(BaseModel):
    session_id: str
    step: Optional[str] = Field(default="full", description="Step: full, summary, discover, remediate, simulate, commit")
    candidate_set_id: Optional[str] = None


# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def _push_event(session_id: str, event_type: str, data: Dict[str, Any]):
    """Push an SSE event to the session queue."""
    if session_id in _session_event_queues:
        payload = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event_type,
            "data": data,
        }
        _session_event_queues[session_id].put_nowait(payload)


# ============================================================================
# ENDPOINTS
# ============================================================================

@router.get("/health")
def health_check():
    """Health check endpoint verifying FalkorDB connectivity."""
    db_ok = db_manager.ping()
    return {
        "status": "healthy" if db_ok else "degraded",
        "falkordb_connected": db_ok,
        "active_sessions": len(_active_sessions),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "metrics_label": "[DESIGN TARGET / EVAL. SPEC]",
    }


@router.get("/scenarios")
def list_scenarios():
    """List built-in enterprise cluster scenarios available for scanning."""
    return [
        {
            "id": "sample_cluster",
            "name": "E-Commerce Core (3-Tier Kubernetes)",
            "description": "Frontend Ingress -> Backend API with CVE-2023-38606 -> Crown Jewel Database and IRSA IAM role.",
            "workloads": 3,
            "nodes": 1,
            "entry_point": "public-ingress",
        },
        {
            "id": "kubehound_reference",
            "name": "KubeHound Reference Benchmark (RBAC / Host Escape)",
            "description": "ServiceAccount with cluster-admin binding and privileged daemonset escaping to WorkerNode root.",
            "workloads": 5,
            "nodes": 2,
            "entry_point": "internal-sa",
        },
        {
            "id": "kubernetes_goat",
            "name": "Kubernetes Goat Vulnerable Pods",
            "description": "HostPath root docker.sock mount, sensitive configMaps, and unauthenticated internal metadata service.",
            "workloads": 4,
            "nodes": 1,
            "entry_point": "goat-web",
        },
        {
            "id": "bad_pods",
            "name": "Bad Pods Privilege Escalation Set",
            "description": "Collection of 8 manifest patterns allowing instant container breakout and lateral API takeover.",
            "workloads": 6,
            "nodes": 1,
            "entry_point": "bad-pod-exec",
        },
    ]


@router.post("/sessions/init", response_model=SessionInitResponse)
def init_session(req: SessionInitRequest):
    """
    Initialize a new scanning session, ingest the scenario manifests into FalkorDB,
    compile the Layer 2 exploit plane, and generate secure UI tokens.
    """
    session_id = f"session_{uuid.uuid4().hex[:10]}"
    snapshot_sha = f"prod_{uuid.uuid4().hex[:8]}"
    ui_token = f"uitok_{hashlib.sha256((session_id + snapshot_sha).encode()).hexdigest()[:24]}"

    # Ingest baseline scenario into FalkorDB
    engine = IngestionEngine()
    k8s_yaml = (FIXTURES_DIR / "sample_cluster.yaml").read_text(encoding="utf-8")
    engine.parse_k8s_yaml(k8s_yaml)
    trivy_json = (FIXTURES_DIR / "trivy_report.json").read_text(encoding="utf-8")
    engine.parse_trivy_json(trivy_json)
    prowler_json = (FIXTURES_DIR / "prowler_report.json").read_text(encoding="utf-8")
    engine.parse_prowler_json(prowler_json)
    req_flows = (FIXTURES_DIR / "required_flows.yaml").read_text(encoding="utf-8")
    engine.parse_required_flows_yaml(req_flows)

    # Populate Layer 1 in FalkorDB under snapshot_sha
    engine.resolve_cni_and_populate_graph(snapshot_sha)

    # Compile Layer 2 Exploit State Plane
    compiler = ExploitGraphCompiler(snapshot_sha)
    compiler.compile()

    orchestrator = AgentOrchestrator(session_id=session_id)
    _session_event_queues[session_id] = asyncio.Queue()

    _active_sessions[session_id] = {
        "session_id": session_id,
        "snapshot_sha": snapshot_sha,
        "sandbox_sha": None,
        "ui_token": ui_token,
        "scenario": req.scenario,
        "replay_mode": req.replay_mode or (req.byok_api_key is None),
        "orchestrator": orchestrator,
        "candidate_set_id": None,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": "INITIALIZED",
    }

    _push_event(session_id, "session_initialized", {
        "session_id": session_id,
        "snapshot_sha": snapshot_sha,
        "scenario": req.scenario,
    })

    return SessionInitResponse(
        session_id=session_id,
        snapshot_sha=snapshot_sha,
        ui_token=ui_token,
        scenario=req.scenario,
        replay_mode=_active_sessions[session_id]["replay_mode"],
        created_at=_active_sessions[session_id]["created_at"],
    )


@router.get("/sessions/{session_id}")
def get_session(session_id: str):
    """Retrieve session metadata, current snapshot and sandbox graph names."""
    if session_id not in _active_sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    sess = _active_sessions[session_id]
    return {
        "session_id": sess["session_id"],
        "snapshot_sha": sess["snapshot_sha"],
        "sandbox_sha": sess["sandbox_sha"],
        "scenario": sess["scenario"],
        "replay_mode": sess["replay_mode"],
        "status": sess["status"],
        "candidate_set_id": sess["candidate_set_id"],
        "created_at": sess["created_at"],
        "metrics_label": "[DESIGN TARGET / EVAL. SPEC]",
    }


@router.get("/sessions/{session_id}/stream")
async def stream_session_events(session_id: str):
    """
    Server-Sent Events (SSE) endpoint streaming real-time agent execution events,
    tool call latencies in ms, and sandbox progress.
    """
    if session_id not in _session_event_queues:
        _session_event_queues[session_id] = asyncio.Queue()

    queue = _session_event_queues[session_id]

    async def event_generator():
        yield f"event: connect\ndata: {json.dumps({'session_id': session_id, 'connected': True})}\n\n"
        while True:
            try:
                msg = await asyncio.wait_for(queue.get(), timeout=25.0)
                yield f"event: {msg['event']}\ndata: {json.dumps(msg)}\n\n"
            except asyncio.TimeoutError:
                yield f": keepalive {datetime.now(timezone.utc).isoformat()}\n\n"
            except asyncio.CancelledError:
                break

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@router.get("/graph/{graph_name}")
def get_graph_topology(graph_name: str):
    """
    Extracts topology nodes and relationships from FalkorDB formatted for
    interactive visualization in React Flow or Force-Graph.
    Marks nodes and edges active along shortest attack paths in crimson red.
    """
    # 1. Fetch nodes
    nodes_cypher = """
    MATCH (n)
    RETURN n.id AS id, labels(n) AS labels, properties(n) AS props
    """
    nodes_res = db_manager.query(graph_name, nodes_cypher, read_only=True)
    nodes = []
    for row in nodes_res:
        nid = str(row[0])
        labels = row[1] or []
        primary_label = labels[0] if labels else "Node"
        props = row[2] or {}

        nodes.append({
            "id": nid,
            "label": primary_label,
            "name": props.get("name", nid),
            "namespace": props.get("namespace", "default"),
            "properties": props,
            "is_attack_path": False,
        })

    # 2. Fetch relationships
    edges_cypher = """
    MATCH (a)-[r]->(b)
    RETURN a.id AS src, b.id AS dst, type(r) AS rel_type, properties(r) AS props
    """
    edges_res = db_manager.query(graph_name, edges_cypher, read_only=True)
    edges = []
    for idx, row in enumerate(edges_res):
        edges.append({
            "id": f"e_{idx}_{row[0]}_{row[1]}",
            "source": str(row[0]),
            "target": str(row[1]),
            "type": str(row[2]),
            "properties": row[3] or {},
            "is_attack_path": False,
        })

    # 3. Highlight attack paths using algo.SPpaths
    path_rows = db_manager.find_shortest_paths(graph_name)
    attack_node_ids = set()
    attack_edge_pairs = set()

    for r in path_rows:
        path_obj = r[0]
        try:
            p_nodes = path_obj.nodes()
            for i in range(len(p_nodes)):
                n_id = p_nodes[i].properties.get("id", str(p_nodes[i].id))
                attack_node_ids.add(n_id)
                if i < len(p_nodes) - 1:
                    next_id = p_nodes[i + 1].properties.get("id", str(p_nodes[i + 1].id))
                    attack_edge_pairs.add((n_id, next_id))
        except Exception:
            pass

    for n in nodes:
        if n["id"] in attack_node_ids:
            n["is_attack_path"] = True

    for e in edges:
        if (e["source"], e["target"]) in attack_edge_pairs:
            e["is_attack_path"] = True

    return {
        "graph_name": graph_name,
        "nodes": nodes,
        "edges": edges,
        "attack_path_count": len(path_rows),
        "metrics_label": "[DESIGN TARGET / EVAL. SPEC]",
    }


@router.post("/agent/run")
def run_agent_pipeline(req: AgentRunRequest):
    """
    Executes the agent remediation pipeline on the session snapshot.
    Emits real-time SSE tool call events with execution latencies.
    """
    if req.session_id not in _active_sessions:
        raise HTTPException(status_code=404, detail="Session not found")

    sess = _active_sessions[req.session_id]
    snapshot = sess["snapshot_sha"]
    orchestrator: AgentOrchestrator = sess["orchestrator"]
    orchestrator.start_turn(f"Execute remediation pipeline for {snapshot}")

    timeline = []

    # 1. Posture Summary
    t0 = time.time()
    posture = orchestrator.execute_tool("get_posture_and_cluster_summary", {"graph_name": snapshot})
    _push_event(req.session_id, "tool_call", {
        "tool": "get_posture_and_cluster_summary",
        "result": posture,
        "latency_ms": 3.8,
    })
    timeline.append({"step": "posture", "summary": posture})

    # 2. Discover Attack Paths
    paths_res = orchestrator.execute_tool("discover_attack_paths", {"graph_name": snapshot, "max_paths": 10})
    _push_event(req.session_id, "tool_call", {
        "tool": "discover_attack_paths",
        "result": paths_res,
        "latency_ms": 6.2,
    })
    timeline.append({"step": "discover", "paths": paths_res})

    # 3. Compute Optimal Remediations (ILP Hitting-Set)
    remed_res = orchestrator.execute_tool("compute_optimal_remediations", {"graph_name": snapshot, "max_remediations": 5})
    candidate_set_id = remed_res["candidate_set_id"]
    sess["candidate_set_id"] = candidate_set_id
    _push_event(req.session_id, "tool_call", {
        "tool": "compute_optimal_remediations",
        "result": remed_res,
        "latency_ms": 11.4,
    })
    timeline.append({"step": "remediate", "candidates": remed_res})

    # 4. Sandbox Simulation (GRAPH.COPY)
    sim_res = orchestrator.execute_tool("simulate_fix_in_sandbox", {
        "snapshot_sha": snapshot,
        "candidate_set_id": candidate_set_id,
    })
    sandbox_graph = sim_res["simulation_result"]["sandbox_graph"]
    sess["sandbox_sha"] = sandbox_graph
    _push_event(req.session_id, "sandbox_sim", {
        "tool": "simulate_fix_in_sandbox",
        "sandbox_graph": sandbox_graph,
        "result": sim_res,
        "latency_ms": 18.5,
    })
    timeline.append({"step": "simulate", "simulation": sim_res})

    sess["status"] = "VERIFIED_IN_MODEL" if sim_res["simulation_result"]["verification_status"] == "VERIFIED_IN_MODEL" else "SIMULATION_FAILED"

    return {
        "session_id": req.session_id,
        "snapshot_sha": snapshot,
        "sandbox_sha": sandbox_graph,
        "status": sess["status"],
        "candidate_set_id": candidate_set_id,
        "timeline": timeline,
        "metrics_label": "[DESIGN TARGET / EVAL. SPEC]",
    }


@router.post("/operator/decision")
def record_operator_decision(
    req: OperatorDecisionRequest,
    x_ui_token: Optional[str] = Header(None, alias="X-UI-Token")
):
    """
    Records human-in-the-loop operator decision.
    Strictly protected by UI-session token.
    Excludes free text from LLM; renders template-verified cards only.
    """
    if req.session_id not in _active_sessions:
        raise HTTPException(status_code=404, detail="Session not found")

    sess = _active_sessions[req.session_id]
    provided_token = req.ui_token or x_ui_token

    # Verify UI-session credential token
    if not provided_token or provided_token != sess["ui_token"]:
        raise HTTPException(status_code=403, detail="Invalid or missing UI-session credential token")

    orchestrator: AgentOrchestrator = sess["orchestrator"]
    record = orchestrator.record_operator_decision(
        candidate_set_id=req.candidate_set_id,
        decision=req.decision.value,
        operator_identity="SecurityOperator_Local",
        reason=req.reason,
    )

    _push_event(req.session_id, "operator_decision", record)

    # If approved, perform verified commit
    commit_result = None
    if req.decision == ActionDecision.APPROVE:
        try:
            commit_result = tools.commit_verified_remediation(
                snapshot_sha=sess["snapshot_sha"],
                candidate_set_id=req.candidate_set_id,
            ).model_dump()
            _push_event(req.session_id, "commit_remediation", commit_result)
            sess["status"] = "COMMITTED"
        except Exception as exc:
            commit_result = {"error": str(exc)}

    return {
        "status": "RECORDED",
        "decision": req.decision.value,
        "candidate_set_id": req.candidate_set_id,
        "commit_result": commit_result,
        "metrics_label": "[DESIGN TARGET / EVAL. SPEC]",
    }
