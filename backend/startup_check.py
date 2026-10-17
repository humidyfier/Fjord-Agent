"""
backend/startup_check.py
Startup self-test validating Gemini model configuration,
FalkorDB GRAPH.COPY, and native algo.SPpaths procedures.
"""

import sys
import os
from pathlib import Path
from typing import Dict, Any

# Ensure project root is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.db.connection import db_manager, DEFAULT_HOST, DEFAULT_PORT


def check_falkordb_connectivity() -> bool:
    """Test ping to FalkorDB."""
    print(f"[*] Checking FalkorDB connection on {DEFAULT_HOST}:{DEFAULT_PORT}...")
    alive = db_manager.ping()
    if not alive:
        print("[!] FALKORDB ERROR: Unable to ping FalkorDB instance.")
        return False
    print("[+] FalkorDB is reachable.")
    return True


def check_falkordb_native_procedures() -> bool:
    """Test algo.SPpaths and GRAPH.COPY in FalkorDB."""
    test_src = "startup_test_src"
    test_dst = "startup_test_dst"
    try:
        # Create small test graph
        graph = db_manager.get_graph(test_src)
        graph.query("CREATE (a:TestNode {id: 'src'})-[:TEST_EDGE]->(b:TestNode {id: 'dst'})")

        # Test algo.SPpaths
        print("[*] Testing FalkorDB native algo.SPpaths procedure...")
        res = graph.query(
            "MATCH (a:TestNode {id: 'src'}), (b:TestNode {id: 'dst'}) "
            "CALL algo.SPpaths({sourceNode: a, targetNode: b}) YIELD path "
            "RETURN path"
        )
        if not res or len(res.result_set) == 0:
            print("[!] FALKORDB ERROR: algo.SPpaths returned no paths on test graph.")
            return False
        print(f"[+] algo.SPpaths verified: found {len(res.result_set)} path(s).")

        # Test GRAPH.COPY
        print("[*] Testing FalkorDB native GRAPH.COPY command...")
        db_manager.copy_graph(test_src, test_dst)
        g_copy = db_manager.get_graph(test_dst)
        count_res = g_copy.query("MATCH (n:TestNode) RETURN count(n) AS cnt")
        node_count = count_res.result_set[0][0]
        if node_count != 2:
            print(f"[!] FALKORDB ERROR: GRAPH.COPY verification failed (expected 2 nodes, got {node_count}).")
            return False
        print(f"[+] GRAPH.COPY verified: successfully cloned {node_count} nodes into sandbox.")
        return True
    except Exception as e:
        print(f"[!] FALKORDB PROCEDURE ERROR: {e}")
        return False
    finally:
        # Clean up test graphs
        db_manager.delete_graph(test_src)
        db_manager.delete_graph(test_dst)


def check_gemini_api() -> Dict[str, Any]:
    """Test Gemini API connectivity with pinned model gemini-3.8-flash (fallback gemini-3.6-flash)."""
    api_key = os.getenv("GEMINI_API_KEY")
    pinned_model = "gemini-3.8-flash"
    fallback_model = "gemini-3.6-flash"

    if not api_key:
        print("[!] GEMINI NOTICE: GEMINI_API_KEY environment variable not set. (BYOK supported in UI)")
        return {"status": "SKIPPED_NO_KEY", "model": pinned_model}

    print(f"[*] Testing Gemini API with model: {pinned_model}...")
    try:
        from google import genai
        client = genai.Client(api_key=api_key)
        response = client.models.generate_content(
            model=pinned_model,
            contents="ping",
        )
        print(f"[+] Gemini API verified on {pinned_model}. Response received.")
        return {"status": "SUCCESS", "model": pinned_model}
    except Exception as e:
        err_msg = str(e)
        if "404" in err_msg or "not found" in err_msg.lower():
            print(f"[!] Model {pinned_model} returned 404. Attempting GA fallback {fallback_model}...")
            try:
                from google import genai
                client = genai.Client(api_key=api_key)
                response = client.models.generate_content(
                    model=fallback_model,
                    contents="ping",
                )
                print(f"[+] Fallback model {fallback_model} verified successfully.")
                return {"status": "FALLBACK_SUCCESS", "model": fallback_model}
            except Exception as e2:
                print(f"[!] Gemini Fallback Error: {e2}")
                return {"status": "ERROR", "error": str(e2), "model": fallback_model}
        print(f"[!] Gemini API Error: {err_msg}")
        return {"status": "ERROR", "error": err_msg, "model": pinned_model}


def run_all_checks() -> bool:
    print("=" * 60)
    print("Project Fjord: Running System Startup Checks")
    print("=" * 60)

    falkor_ok = check_falkordb_connectivity()
    if not falkor_ok:
        return False

    proc_ok = check_falkordb_native_procedures()
    if not proc_ok:
        return False

    gemini_res = check_gemini_api()

    print("=" * 60)
    print("All critical FalkorDB invariants passed successfully.")
    print(f"Gemini status: {gemini_res.get('status')}")
    print("=" * 60)
    return True


if __name__ == "__main__":
    success = run_all_checks()
    sys.exit(0 if success else 1)
