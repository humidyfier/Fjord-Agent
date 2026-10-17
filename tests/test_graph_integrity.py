"""
tests/test_graph_integrity.py
Regression tests for EntryPoint materialization, schema adherence, and graph integrity.

Verifies:
1. EntryPoint materialization: Ingesting public LoadBalancer Service and Ingress
   creates an EntryPoint node ("entry:internet") and all EXPOSES edges connect real nodes.
2. Graph integrity: No relationship has missing source or target nodes.
3. Schema conformity: All node labels and relationship types are strictly defined in backend/schema.py.
4. Ingestion idempotence: Re-ingesting the exact same bundle yields identical node and edge counts.
"""

import sys
from pathlib import Path
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.schema import NODE_LABELS, REL_TYPES
from backend.db.connection import db_manager
from backend.ingest.parser import IngestionEngine


FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
TEST_GRAPH_INTEGRITY = "test_integrity_graph"


# ============================================================================
# 1a. REGRESSION TEST: EntryPoint Materialization & EXPOSES Edge Reality
# ============================================================================

def test_entrypoint_materialization_and_exposes_edges():
    """
    Regression test for missing-EntryPoint bug:
    Ingest manifest with a public LoadBalancer Service and an Ingress.
    Assert that the EntryPoint node exists and that each EXPOSES edge connects real nodes.
    """
    graph_name = f"{TEST_GRAPH_INTEGRITY}_ep"
    db_manager.delete_graph(graph_name)

    sample_manifest = """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: web-app
  namespace: test-ep
spec:
  replicas: 1
  selector:
    matchLabels:
      app: web
  template:
    metadata:
      labels:
        app: web
    spec:
      containers:
      - name: web
        image: nginx:1.21
        ports:
        - containerPort: 80
---
apiVersion: v1
kind: Service
metadata:
  name: public-lb
  namespace: test-ep
spec:
  type: LoadBalancer
  selector:
    app: web
  ports:
  - port: 80
    targetPort: 80
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: public-ing
  namespace: test-ep
spec:
  rules:
  - http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: public-lb
            port:
              number: 80
"""
    engine = IngestionEngine()
    engine.parse_k8s_yaml(sample_manifest)
    counts = engine.resolve_cni_and_populate_graph(graph_name)

    try:
        assert counts["node_count"] > 0
        assert counts["edge_count"] > 0

        # 1. Assert EntryPoint node with id 'entry:internet' exists
        ep_label = NODE_LABELS["ENTRY_POINT"]
        ep_res = db_manager.query(
            graph_name,
            f"MATCH (ep:{ep_label} {{id: $ep_id}}) RETURN ep.id, ep.name, ep.entry_type",
            params={"ep_id": "entry:internet"},
            read_only=True
        )
        assert len(ep_res) == 1, f"Expected exactly 1 EntryPoint node with id 'entry:internet', got {len(ep_res)}"
        assert ep_res[0][0] == "entry:internet"

        # 2. Assert EXPOSES edges exist
        exposes_res = db_manager.query(
            graph_name,
            "MATCH (a)-[r:EXPOSES]->(b) RETURN a.id, labels(a), type(r), b.id, labels(b)",
            read_only=True
        )
        assert len(exposes_res) >= 2, f"Expected at least 2 EXPOSES edges (Service & Ingress), got {len(exposes_res)}"

        # 3. Assert each EXPOSES edge connects real nodes
        for row in exposes_res:
            src_id, src_labels, rel_type, dst_id, dst_labels = row[0], row[1], row[2], row[3], row[4]
            assert src_id == "entry:internet"
            assert ep_label in src_labels
            assert rel_type == "EXPOSES"
            assert dst_id is not None
            assert len(dst_labels) > 0

    finally:
        db_manager.delete_graph(graph_name)


# ============================================================================
# 1b. GRAPH INTEGRITY & IDEMPOTENCE TEST
# ============================================================================

def test_graph_integrity_and_idempotence():
    """
    General graph-integrity test:
    - no relationship has a missing source or target node,
    - every node label and relationship type is in schema.py,
    - re-ingesting the same bundle produces the same node and edge counts.
    """
    graph_name = f"{TEST_GRAPH_INTEGRITY}_full"
    db_manager.delete_graph(graph_name)

    def _ingest_bundle():
        engine = IngestionEngine()
        k8s_yaml = (FIXTURES_DIR / "sample_cluster.yaml").read_text(encoding="utf-8")
        engine.parse_k8s_yaml(k8s_yaml)
        trivy_json = (FIXTURES_DIR / "trivy_report.json").read_text(encoding="utf-8")
        engine.parse_trivy_json(trivy_json)
        prowler_json = (FIXTURES_DIR / "prowler_report.json").read_text(encoding="utf-8")
        engine.parse_prowler_json(prowler_json)
        req_flows = (FIXTURES_DIR / "required_flows.yaml").read_text(encoding="utf-8")
        engine.parse_required_flows_yaml(req_flows)
        return engine.resolve_cni_and_populate_graph(graph_name)

    try:
        # First ingestion
        counts1 = _ingest_bundle()
        assert counts1["node_count"] > 0
        assert counts1["edge_count"] > 0

        # Check 1: No relationship has a missing source or target node
        dangling_res = db_manager.query(
            graph_name,
            """
            MATCH ()-[r]->()
            WHERE startNode(r) IS NULL OR endNode(r) IS NULL
            RETURN count(r)
            """,
            read_only=True
        )
        assert dangling_res[0][0] == 0, f"Found {dangling_res[0][0]} relationships with missing source or target nodes"

        # Check 2: Every node label is in schema.py
        allowed_node_labels = set(NODE_LABELS.values())
        node_labels_res = db_manager.query(
            graph_name,
            "MATCH (n) RETURN distinct labels(n)",
            read_only=True
        )
        for row in node_labels_res:
            for lbl in row[0]:
                assert lbl in allowed_node_labels, f"Node label '{lbl}' is not defined in schema.py: {allowed_node_labels}"

        # Check 3: Every relationship type is in schema.py
        allowed_rel_types = set(REL_TYPES)
        rel_types_res = db_manager.query(
            graph_name,
            "MATCH ()-[r]->() RETURN distinct type(r)",
            read_only=True
        )
        for row in rel_types_res:
            rtype = row[0]
            assert rtype in allowed_rel_types, f"Relationship type '{rtype}' is not defined in schema.py: {allowed_rel_types}"

        # Check 4: Ingestion idempotence — re-ingesting the exact same bundle yields identical counts
        counts2 = _ingest_bundle()
        assert counts2["node_count"] == counts1["node_count"], (
            f"Idempotence violation: first ingest had {counts1['node_count']} nodes, "
            f"second ingest has {counts2['node_count']} nodes"
        )
        assert counts2["edge_count"] == counts1["edge_count"], (
            f"Idempotence violation: first ingest had {counts1['edge_count']} edges, "
            f"second ingest has {counts2['edge_count']} edges"
        )

    finally:
        db_manager.delete_graph(graph_name)
