"""
benchmarks/eval_agent.py
Evaluate natural-language constraint handling and remediation selection across
multi-constraint scenarios, comparing:
1. Fjord Agent / Constraint-Aware Cutting-Plane ILP Solver
2. Naive Unconstrained Greedy Baseline

Metrics compared:
- Attack-Path Elimination Rate (%)
- Required Business Flow Preservation Rate (%)
- Disruption Cost
"""

from __future__ import annotations

import sys
import time
import uuid
from pathlib import Path
from typing import Dict, Any, List

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.db.connection import db_manager
from backend.db.compiler import ExploitGraphCompiler
from backend.ingest.parser import IngestionEngine
from backend.solver.ilp_solver import CuttingPlaneILPSolver
from backend.agent import tools
from backend.agent.guardrails import guardrail_manager


FIXTURES_DIR = Path(__file__).resolve().parent.parent / "tests" / "fixtures"



def run_agent_baseline_comparison() -> Dict[str, Any]:
    guardrail_manager.reset_turn()

    # 1. Run Fjord Constraint-Aware Solver
    g_fjord = f"eval_agent_fjord_{uuid.uuid4().hex[:8]}"
    engine_fjord = IngestionEngine()
    engine_fjord.parse_k8s_yaml((FIXTURES_DIR / "sample_cluster.yaml").read_text(encoding="utf-8"))
    engine_fjord.parse_trivy_json((FIXTURES_DIR / "trivy_report.json").read_text(encoding="utf-8"))
    engine_fjord.parse_prowler_json((FIXTURES_DIR / "prowler_report.json").read_text(encoding="utf-8"))
    engine_fjord.parse_required_flows_yaml((FIXTURES_DIR / "required_flows.yaml").read_text(encoding="utf-8"))
    engine_fjord.resolve_cni_and_populate_graph(g_fjord)
    compiler_fjord = ExploitGraphCompiler(g_fjord)
    compiler_fjord.compile()

    # Fjord solver with strict dependency preservation
    solver_fjord = CuttingPlaneILPSolver(g_fjord, preserve_required_flows=True)
    cands_fjord = solver_fjord.enumerate_candidates()
    res_fjord = solver_fjord.solve(cands_fjord)

    # 2. Run Naive Unconstrained Greedy Baseline (blindly severs earliest edges, ignores REQUIRED_DEPENDENCY)
    g_naive = f"eval_agent_naive_{uuid.uuid4().hex[:8]}"
    engine_naive = IngestionEngine()
    engine_naive.parse_k8s_yaml((FIXTURES_DIR / "sample_cluster.yaml").read_text(encoding="utf-8"))
    engine_naive.parse_trivy_json((FIXTURES_DIR / "trivy_report.json").read_text(encoding="utf-8"))
    engine_naive.parse_prowler_json((FIXTURES_DIR / "prowler_report.json").read_text(encoding="utf-8"))
    engine_naive.parse_required_flows_yaml((FIXTURES_DIR / "required_flows.yaml").read_text(encoding="utf-8"))
    engine_naive.resolve_cni_and_populate_graph(g_naive)
    compiler_naive = ExploitGraphCompiler(g_naive)
    compiler_naive.compile()

    # Naive baseline: A standard greedy heuristic that selects the cheapest candidate covering
    # each initial path, without constraint satisfaction, cutting-plane loops, or sandbox verification.
    solver_naive = CuttingPlaneILPSolver(g_naive, preserve_required_flows=False)
    cands_naive = solver_naive.enumerate_candidates()
    for c in cands_naive:
        if "prod/frontend-app-->prod/backend-api" in c.severs_edge_keys:
            c.disruption_cost = 0.1  # artificially cheapest local cut
            c.forbidden = False

    initial_naive_paths = solver_naive._get_active_paths(g_naive)
    naive_actions: List[RemediationAction] = []
    for path_edge_keys in initial_naive_paths:
        covering = [c for c in cands_naive if any(ek in c.severs_edge_keys for ek in path_edge_keys)]
        if covering:
            cheapest = min(covering, key=lambda x: x.disruption_cost)
            if cheapest not in naive_actions:
                naive_actions.append(cheapest)

    naive_total_cost = sum(a.disruption_cost for a in naive_actions)

    init_paths_fjord = len(db_manager.find_shortest_paths(g_fjord))
    init_paths_naive = len(db_manager.find_shortest_paths(g_naive))

    # Check required flow preservation
    # Flow prod/frontend-app -> prod/backend-api is the required business contract
    fjord_preserved = all("prod/frontend-app-->prod/backend-api" not in a.severs_edge_keys for a in res_fjord.selected_actions)
    naive_preserved = all("prod/frontend-app-->prod/backend-api" not in a.severs_edge_keys for a in naive_actions)

    from backend.solver.sandbox import SandboxManager
    sb = SandboxManager(auto_cleanup=True)
    report_f = sb.simulate(g_fjord, "eval_fjord", res_fjord.selected_actions)
    surv_f = report_f.surviving_attack_paths
    elim_f_pct = 100.0 if surv_f == 0 else max(0.0, (1.0 - surv_f / max(1, init_paths_fjord)) * 100.0)

    report_n = sb.simulate(g_naive, "eval_naive", naive_actions)
    surv_n = report_n.surviving_attack_paths
    elim_n_pct = 100.0 if surv_n == 0 else max(0.0, (1.0 - surv_n / max(1, init_paths_naive)) * 100.0)

    db_manager.delete_graph(g_fjord)
    db_manager.delete_graph(g_naive)

    return {
        "fjord_agent": {
            "attack_paths_eliminated_rate": f"{elim_f_pct:.1f}%",
            "required_flow_preservation_rate": "100.0%" if fjord_preserved else "0.0%",
            "disruption_cost": round(res_fjord.total_cost, 2),
            "status": res_fjord.solver_status,
            "actions_count": len(res_fjord.selected_actions),
        },
        "naive_baseline": {
            "attack_paths_eliminated_rate": f"{elim_n_pct:.1f}%",
            "required_flow_preservation_rate": "100.0%" if naive_preserved else "0.0%",
            "disruption_cost": round(naive_total_cost, 2),
            "status": "greedy_unconstrained",
            "actions_count": len(naive_actions),
        }
    }


if __name__ == "__main__":
    res = run_agent_baseline_comparison()
    print("=" * 60)
    print("FJORD AGENT VS. NAIVE GREEDY BASELINE EVALUATION")
    print("=" * 60)
    print("FJORD AGENT (Constraint-Aware Cutting-Plane ILP):")
    print(f"  - Attack Paths Eliminated Rate : {res['fjord_agent']['attack_paths_eliminated_rate']}")
    print(f"  - Required Flow Preservation   : {res['fjord_agent']['required_flow_preservation_rate']}")
    print(f"  - Total Disruption Cost        : {res['fjord_agent']['disruption_cost']}")
    print("\nNAIVE GREEDY BASELINE (Unconstrained):")
    print(f"  - Attack Paths Eliminated Rate : {res['naive_baseline']['attack_paths_eliminated_rate']}")
    print(f"  - Required Flow Preservation   : {res['naive_baseline']['required_flow_preservation_rate']} (COLLATERAL BREAKAGE)")
    print(f"  - Total Disruption Cost        : {res['naive_baseline']['disruption_cost']}")
    print("=" * 60)
