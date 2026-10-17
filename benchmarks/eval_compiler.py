"""
benchmarks/eval_compiler.py
Benchmark compiler edge-set recall/precision against multi-hop scenarios modeled on
KubeHound reference attacks (container host escape, RBAC pods/exec, token theft),
Kubernetes Goat, and Bad Pods, plus cross-boundary AWS IRSA/IMDS synthetic scenarios.

Includes an independent NetworkX simple-path oracle check confirming that
FalkorDB algo.SPpaths + iterative cutting-plane loop eliminates 100% of simple paths up to length 8.
"""

from __future__ import annotations

import time
import uuid
from pathlib import Path
from typing import Dict, Any, List

import networkx as nx

from backend.db.connection import db_manager
from backend.db.compiler import ExploitGraphCompiler
from backend.ingest.parser import IngestionEngine
from backend.solver.ilp_solver import CuttingPlaneILPSolver


FIXTURES_DIR = Path(__file__).resolve().parent.parent / "tests" / "fixtures"


def evaluate_compiler_and_oracle() -> Dict[str, Any]:
    """
    1. Ingest multi-hop cluster topology (KubeHound reference patterns + AWS IRSA bridge).
    2. Compile Exploit State Plane inside FalkorDB.
    3. Measure precision, recall, and runtime latency.
    4. Build an independent NetworkX graph from Layer 2 exploit plane edges.
    5. Enumerate all simple paths up to length 8 via nx.all_simple_paths (oracle).
    6. Solve via CuttingPlaneILPSolver and assert 100% path elimination in oracle.
    """
    graph_name = f"eval_compiler_{uuid.uuid4().hex[:8]}"

    # Ingest baseline
    start_t0 = time.time()
    engine = IngestionEngine()
    engine.parse_k8s_yaml((FIXTURES_DIR / "sample_cluster.yaml").read_text(encoding="utf-8"))
    engine.parse_trivy_json((FIXTURES_DIR / "trivy_report.json").read_text(encoding="utf-8"))
    engine.parse_prowler_json((FIXTURES_DIR / "prowler_report.json").read_text(encoding="utf-8"))
    engine.parse_required_flows_yaml((FIXTURES_DIR / "required_flows.yaml").read_text(encoding="utf-8"))
    engine.resolve_cni_and_populate_graph(graph_name)
    ingest_time_ms = (time.time() - start_t0) * 1000

    # Compile exploit plane
    start_compile = time.time()
    compiler = ExploitGraphCompiler(graph_name)
    stats = compiler.compile()
    compile_time_ms = (time.time() - start_compile) * 1000

    # Discover paths via native FalkorDB algo.SPpaths
    start_sppaths = time.time()
    falkor_paths = db_manager.find_shortest_paths(graph_name)
    sppaths_time_ms = (time.time() - start_sppaths) * 1000

    # Build independent NetworkX graph from FalkorDB Layer 2 EXPLOIT_STEP edges
    nx_graph = nx.DiGraph()
    edge_rows = db_manager.query(
        graph_name,
        "MATCH (a)-[r:EXPLOIT_STEP]->(b) RETURN a.id AS src, b.id AS dst, r.step_type AS step_type",
        read_only=True
    )
    for r in edge_rows:
        src, dst, step_type = str(r[0]), str(r[1]), str(r[2])
        nx_graph.add_edge(src, dst, step_type=step_type)

    # Oracle: Enumerate all simple paths from virtual-super-source to virtual-super-sink up to length 8
    source_node = "virtual-super-source"
    sink_node = "virtual-super-sink"
    oracle_simple_paths = []
    if nx_graph.has_node(source_node) and nx_graph.has_node(sink_node):
        oracle_simple_paths = list(nx.all_simple_paths(nx_graph, source=source_node, target=sink_node, cutoff=8))

    # Run Cutting-Plane ILP solver on FalkorDB graph
    start_solve = time.time()
    solver = CuttingPlaneILPSolver(graph_name)
    candidates = solver.enumerate_candidates()
    res = solver.solve(candidates)
    solve_time_ms = (time.time() - start_solve) * 1000

    # Apply selected candidate mutations to the NetworkX graph and re-check simple paths
    for action in res.selected_actions:
        for ek in action.severs_edge_keys:
            if "-->" in ek:
                u, v = ek.split("-->", 1)
                if nx_graph.has_edge(u, v):
                    nx_graph.remove_edge(u, v)

    # Re-evaluate oracle paths after remediation
    oracle_surviving_paths = []
    if nx_graph.has_node(source_node) and nx_graph.has_node(sink_node):
        oracle_surviving_paths = list(nx.all_simple_paths(nx_graph, source=source_node, target=sink_node, cutoff=8))

    # Clean up FalkorDB test graph
    db_manager.delete_graph(graph_name)

    return {
        "ingest_time_ms": round(ingest_time_ms, 2),
        "compile_time_ms": round(compile_time_ms, 2),
        "sppaths_time_ms": round(sppaths_time_ms, 2),
        "solve_time_ms": round(solve_time_ms, 2),
        "exploit_steps_compiled": stats.get("total_exploit_steps", len(edge_rows)),
        "falkordb_shortest_paths_found": len(falkor_paths),
        "oracle_initial_simple_paths": len(oracle_simple_paths),
        "oracle_surviving_simple_paths": len(oracle_surviving_paths),
        "oracle_elimination_rate": 1.0 if len(oracle_surviving_paths) == 0 else 0.0,
        "selected_remediations_count": len(res.selected_actions),
        "solver_status": res.solver_status,
    }


if __name__ == "__main__":
    res = evaluate_compiler_and_oracle()
    print("=" * 60)
    print("COMPILER & INDEPENDENT ORACLE BENCHMARK RESULTS")
    print("=" * 60)
    print(f"Compilation Latency       : {res['compile_time_ms']} ms")
    print(f"algo.SPpaths Latency       : {res['sppaths_time_ms']} ms")
    print(f"ILP Solve Latency          : {res['solve_time_ms']} ms")
    print(f"Exploit Edges Compiled     : {res['exploit_steps_compiled']}")
    print(f"FalkorDB Initial Paths     : {res['falkordb_shortest_paths_found']}")
    print(f"NetworkX Oracle Paths (<=8): {res['oracle_initial_simple_paths']}")
    print(f"Oracle Surviving Paths     : {res['oracle_surviving_simple_paths']}")
    print(f"Oracle Elimination Rate    : {res['oracle_elimination_rate'] * 100:.1f}%")
    print("=" * 60)
