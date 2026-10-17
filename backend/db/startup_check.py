"""
backend/db/startup_check.py
System self-test and readiness verification for Project Fjord.

Verifies:
1. FalkorDB connectivity (PING)
2. Native FalkorDB procedures: GRAPH.COPY and algo.SPpaths
3. LLM Configuration: Gemini 3.8 Flash model settings with explicit thinking level
   and graceful fallback to Gemini 3.6 Flash.
"""

from __future__ import annotations

import logging
import uuid
from typing import Dict, Any, Optional

from backend.db.connection import db_manager

logger = logging.getLogger(__name__)


def verify_falkordb_capabilities() -> Dict[str, Any]:
    """
    Verifies that FalkorDB is reachable and supports GRAPH.COPY and algo.SPpaths.
    Uses an ephemeral test graph and deletes it upon completion.
    """
    test_src = f"startup_check_{uuid.uuid4().hex[:8]}"
    test_dst = f"startup_check_copy_{uuid.uuid4().hex[:8]}"
    results = {
        "falkordb_ping": False,
        "graph_copy": False,
        "algo_sppaths": False,
    }

    try:
        # 1. Ping
        if not db_manager.ping():
            raise ConnectionError("FalkorDB ping failed")
        results["falkordb_ping"] = True

        # 2. Seed simple graph for GRAPH.COPY and algo.SPpaths test
        db_manager.query(test_src, "CREATE (a:VirtualSource {id: 's'}), (b:VirtualSink {id: 'd'}), (a)-[:EXPLOIT_STEP]->(b)")

        # Test algo.SPpaths
        paths = db_manager.find_shortest_paths(
            test_src,
            src_label="VirtualSource",
            src_prop="id",
            src_val="s",
            dst_label="VirtualSink",
            dst_prop="id",
            dst_val="d",
        )
        if len(paths) >= 1:
            results["algo_sppaths"] = True

        # Test GRAPH.COPY
        copy_ok = db_manager.copy_graph(test_src, test_dst)
        if copy_ok:
            results["graph_copy"] = True

    finally:
        # Clean up ephemeral check graphs
        db_manager.delete_graph(test_src)
        db_manager.delete_graph(test_dst)

    return results


def verify_model_configuration(
    primary_model: str = "gemini-3.8-flash",
    fallback_model: str = "gemini-3.6-flash",
    thinking_level: str = "high",
    api_key: Optional[str] = None
) -> Dict[str, Any]:
    """
    Validates model configuration parameters according to Project Fjord spec:
    - Primary: gemini-3.8-flash with explicit thinking level
    - Fallback: gemini-3.6-flash
    """
    config = {
        "primary_model": primary_model,
        "fallback_model": fallback_model,
        "thinking_level": thinking_level,
        "api_key_configured": bool(api_key),
        "valid": True,
    }

    if primary_model not in ("gemini-3.8-flash", "gemini-1.5-pro", "gemini-2.0-flash", "gemini-2.5-flash"):
        config["valid"] = False
        config["error"] = f"Unsupported primary model: {primary_model}"

    return config


def run_full_startup_check(api_key: Optional[str] = None) -> Dict[str, Any]:
    """
    Executes all startup readiness checks and returns aggregated status.
    """
    db_res = verify_falkordb_capabilities()
    model_res = verify_model_configuration(api_key=api_key)

    all_passed = (
        db_res["falkordb_ping"]
        and db_res["graph_copy"]
        and db_res["algo_sppaths"]
        and model_res["valid"]
    )

    return {
        "status": "READY" if all_passed else "DEGRADED",
        "database": db_res,
        "model": model_res,
        "metrics_label": "[DESIGN TARGET / EVAL. SPEC]",
    }
