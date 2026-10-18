"""
backend/db/connection.py
FalkorDB connection management, native GRAPH.COPY sandboxing,
and algo.SPpaths graph traversal execution.
"""

import os
import time
from typing import Any, Dict, List, Optional
from collections import OrderedDict
from falkordb import FalkorDB, Graph
import redis


DEFAULT_HOST = os.getenv("FALKORDB_HOST", "localhost")
DEFAULT_PORT = int(os.getenv("FALKORDB_PORT", "6380"))
DEFAULT_GRAPH = os.getenv("FALKORDB_GRAPH", "fjord_main")
MAX_SNAPSHOT_GRAPHS = int(os.getenv("MAX_SNAPSHOT_GRAPHS", "10"))


class FalkorDBManager:
    """
    Manages connections to FalkorDB and provides abstractions for:
    - Executing parameterized Cypher queries
    - Running native algo.SPpaths shortest attack path discovery
    - Cloning graphs via native GRAPH.COPY for sandboxed counterfactual evaluation
    - Tracking snapshot LRU to prevent out-of-memory under noeviction policy
    """

    def __init__(self, host: str = DEFAULT_HOST, port: int = DEFAULT_PORT):
        self.host = host
        self.port = port
        self.client = FalkorDB(host=self.host, port=self.port)
        self._snapshot_lru: OrderedDict[str, int] = OrderedDict()  # graph_name -> ref_count

    def ping(self) -> bool:
        """Check if FalkorDB is reachable."""
        try:
            res = self.client.connection.ping()
            return bool(res)
        except Exception:
            return False

    def get_graph(self, graph_name: str = DEFAULT_GRAPH) -> Graph:
        """Retrieve a graph instance by name."""
        return self.client.select_graph(graph_name)

    def query(
        self,
        graph_name: str,
        cypher: str,
        params: Optional[Dict[str, Any]] = None,
        read_only: bool = False
    ) -> List[Any]:
        """
        Execute a parameterized Cypher query on the specified graph.
        Never interpolates untrusted raw strings into Cypher.
        """
        graph = self.get_graph(graph_name)
        if read_only and hasattr(graph, "ro_query"):
            result = graph.ro_query(cypher, params=params)
        else:
            result = graph.query(cypher, params=params)
        return result.result_set if result else []

    def query_with_header(
        self,
        graph_name: str,
        cypher: str,
        params: Optional[Dict[str, Any]] = None,
        read_only: bool = False
    ) -> tuple:
        """
        Execute Cypher query and return (header_column_names, rows).
        """
        graph = self.get_graph(graph_name)
        if read_only and hasattr(graph, "ro_query"):
            result = graph.ro_query(cypher, params=params)
        else:
            result = graph.query(cypher, params=params)

        headers: List[str] = []
        if result and hasattr(result, "header") and result.header:
            for h in result.header:
                if isinstance(h, (list, tuple)) and len(h) > 1:
                    headers.append(str(h[1]))
                else:
                    headers.append(str(h))
        rows = result.result_set if result else []
        return headers, rows

    def copy_graph(self, src_graph: str, dst_graph: str) -> bool:
        """
        Perform native FalkorDB GRAPH.COPY from src_graph to dst_graph.
        Used for zero-overhead counterfactual sandboxing.
        """
        self._track_snapshot(dst_graph)
        max_retries = 3
        for attempt in range(max_retries):
            try:
                self.client.connection.execute_command("GRAPH.COPY", src_graph, dst_graph)
                return True
            except redis.exceptions.ResponseError as e:
                err_str = str(e).upper()
                if ("OOM" in err_str or "MAXMEMORY" in err_str or "COULD NOT FORK" in err_str) and attempt < max_retries - 1:
                    self._evict_oldest_unused_snapshot()
                    time.sleep(0.3 * (attempt + 1))
                    continue
                raise

    def delete_graph(self, graph_name: str) -> bool:
        """Delete a graph from FalkorDB."""
        try:
            graph = self.get_graph(graph_name)
            graph.delete()
            self._snapshot_lru.pop(graph_name, None)
            return True
        except Exception:
            return False

    def find_shortest_paths(
        self,
        graph_name: str,
        src_label: str = "VirtualSource",
        src_prop: str = "id",
        src_val: str = "virtual-super-source",
        dst_label: str = "VirtualSink",
        dst_prop: str = "id",
        dst_val: str = "virtual-super-sink",
        rel_types: Optional[List[str]] = None,
    ) -> List[Any]:
        """
        Find shortest paths between source and destination using native FalkorDB algo.SPpaths.
        Defaults to relTypes: ['EXPLOIT_STEP'] to strictly traverse the compiled Exploit State Plane.
        FalkorDB procedure signature:
        MATCH (s:Label {prop: val}), (d:Label {prop: val})
        CALL algo.SPpaths({sourceNode: s, targetNode: d, relTypes: $rel_types}) YIELD path RETURN path
        """
        if rel_types is None:
            rel_types = ["EXPLOIT_STEP"]

        cypher = f"""
        MATCH (s:{src_label} {{{src_prop}: $src_val}}), (d:{dst_label} {{{dst_prop}: $dst_val}})
        CALL algo.SPpaths({{sourceNode: s, targetNode: d, relTypes: $rel_types}}) YIELD path
        RETURN path
        """
        return self.query(graph_name, cypher, params={"src_val": src_val, "dst_val": dst_val, "rel_types": rel_types})

    def _track_snapshot(self, graph_name: str):
        """Track snapshot in LRU cache."""
        if graph_name.startswith("sandbox_sim_") or graph_name.startswith("prod_"):
            if len(self._snapshot_lru) >= MAX_SNAPSHOT_GRAPHS:
                self._evict_oldest_unused_snapshot()
            self._snapshot_lru[graph_name] = 0

    def _evict_oldest_unused_snapshot(self):
        """Evict oldest unreferenced snapshot graph if capacity exceeded."""
        evicted = 0
        for name, refs in list(self._snapshot_lru.items()):
            if refs <= 0:
                self.delete_graph(name)
                evicted += 1
                if evicted >= 3:
                    break
        try:
            # Query actual graphs directly from FalkorDB via GRAPH.LIST to prevent fork / OOM errors
            graphs = self.client.connection.execute_command("GRAPH.LIST")
            protected = {"sentinel_memory", "fjord_main", "topology"}
            candidates = []
            for g in (graphs or []):
                g_str = g.decode('utf-8', errors='ignore') if isinstance(g, bytes) else str(g)
                if g_str not in protected and (g_str.startswith("sandbox_sim_") or g_str.startswith("prod_")):
                    if self._snapshot_lru.get(g_str, 0) <= 0:
                        candidates.append(g_str)
            if len(graphs) > MAX_SNAPSHOT_GRAPHS or candidates:
                for c in candidates[:max(5, len(graphs) - MAX_SNAPSHOT_GRAPHS)]:
                    self.delete_graph(c)
        except Exception:
            pass


# Global singleton instance
db_manager = FalkorDBManager()
