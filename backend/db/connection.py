"""
backend/db/connection.py
FalkorDB connection management, native GRAPH.COPY sandboxing,
and algo.SPpaths graph traversal execution.
"""

import os
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

    def copy_graph(self, src_graph: str, dst_graph: str) -> bool:
        """
        Perform native FalkorDB GRAPH.COPY from src_graph to dst_graph.
        Used for zero-overhead counterfactual sandboxing.
        """
        try:
            # Register in LRU before copy
            self._track_snapshot(dst_graph)
            self.client.connection.execute_command("GRAPH.COPY", src_graph, dst_graph)
            return True
        except redis.exceptions.ResponseError as e:
            # Handle out of memory error
            if "OOM" in str(e).upper() or "MAXMEMORY" in str(e).upper():
                self._evict_oldest_unused_snapshot()
                self.client.connection.execute_command("GRAPH.COPY", src_graph, dst_graph)
                return True
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
        for name, refs in list(self._snapshot_lru.items()):
            if refs <= 0:
                self.delete_graph(name)
                break


# Global singleton instance
db_manager = FalkorDBManager()
