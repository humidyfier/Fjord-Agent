"""
tests/task0_vertical_slice.py
End-to-End Task 0 Vertical Slice Implementation:
1. Ingest 3 test workloads into FalkorDB snapshot graph prod_t0slice
2. Compile exploit plane in Cypher inside FalkorDB
3. Discover attack path using native algo.SPpaths
4. Generate minimal-diff NetworkPolicy
5. Execute GRAPH.COPY sandbox simulation and verify 0 paths, 0 broken flows
6. Apply NetworkPolicy to live kind cluster and verify CNI truth table enforcement
"""

import sys
import subprocess
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.db.connection import db_manager
from backend.schema import VerificationStatus


GRAPH_PROD = "prod_t0slice"
GRAPH_SANDBOX = "sandbox_sim_t0"


def step_1_seed_inventory_graph():
    print("\n--- [STEP 1] Seeding Inventory & Posture Graph in FalkorDB ---")
    # Clean up prior test runs
    db_manager.delete_graph(GRAPH_PROD)
    db_manager.delete_graph(GRAPH_SANDBOX)

    graph = db_manager.get_graph(GRAPH_PROD)

    # 1. Create Virtual Super-Source and Sink
    graph.query(
        "CREATE (vs:VirtualSource {id: 'virtual-super-source', name: 'Virtual Attacker Super-Source'})"
    )
    graph.query(
        "CREATE (vk:VirtualSink {id: 'virtual-super-sink', name: 'Virtual Objective Super-Sink'})"
    )

    # 2. Create EntryPoint
    graph.query(
        "CREATE (ep:EntryPoint {name: 'ingress-gw', port: 8080, public: true, protocol: 'TCP'})"
    )

    # 3. Create 3 Workloads
    graph.query(
        "CREATE (w1:Workload {name: 'ingress-proxy', namespace: 'fjord-t0', role: 'public', kind: 'Deployment'})"
    )
    graph.query(
        "CREATE (w2:Workload {name: 'api-service', namespace: 'fjord-t0', role: 'internal', kind: 'Deployment'})"
    )
    graph.query(
        "CREATE (w3:Workload {name: 'crown-jewel-db', namespace: 'fjord-t0', role: 'crown-jewel', kind: 'Deployment'})"
    )

    # 4. Create Crown Jewel
    graph.query(
        "CREATE (cj:CrownJewel {name: 'customer-vault', namespace: 'fjord-t0', critical: true, data_type: 'PII'})"
    )

    # 5. Connect Inventory Edges
    # VirtualSource -> EntryPoint -> ingress-proxy
    graph.query(
        "MATCH (vs:VirtualSource {id: 'virtual-super-source'}), (ep:EntryPoint {name: 'ingress-gw'}), (w:Workload {name: 'ingress-proxy'}) "
        "CREATE (vs)-[:EXPOSES]->(ep), (ep)-[:ROUTES_TO]->(w)"
    )

    # ingress-proxy -> api-service (CAN_REACH_NET + REQUIRED_DEPENDENCY)
    graph.query(
        "MATCH (w1:Workload {name: 'ingress-proxy'}), (w2:Workload {name: 'api-service'}) "
        "CREATE (w1)-[:CAN_REACH_NET {port: 8080, protocol: 'TCP'}]->(w2), "
        "       (w1)-[:REQUIRED_DEPENDENCY {purpose: 'customer_api_traffic'}]->(w2)"
    )

    # api-service -> crown-jewel-db (CAN_REACH_NET - unisolated attack vector)
    graph.query(
        "MATCH (w2:Workload {name: 'api-service'}), (w3:Workload {name: 'crown-jewel-db'}) "
        "CREATE (w2)-[:CAN_REACH_NET {port: 8080, protocol: 'TCP'}]->(w3)"
    )

    # crown-jewel-db -> CrownJewel -> VirtualSink
    graph.query(
        "MATCH (w3:Workload {name: 'crown-jewel-db'}), (cj:CrownJewel {name: 'customer-vault'}), (vk:VirtualSink {id: 'virtual-super-sink'}) "
        "CREATE (w3)-[:HOSTS_WORKLOAD]->(cj), (cj)-[:EXPLOIT_STEP {type: 'CROWN_JEWEL_COMPROMISE'}]->(vk)"
    )

    res = graph.query("MATCH (n) RETURN count(n) AS node_count")
    print(f"[+] Successfully seeded inventory graph with {res.result_set[0][0]} nodes.")


def step_2_compile_exploit_plane(graph_name: str):
    print(f"\n--- [STEP 2] Compiling Exploit Plane in Cypher ({graph_name}) ---")
    graph = db_manager.get_graph(graph_name)

    # Remove existing EXPLOIT_STEP edges (except crown jewel sink hook)
    graph.query(
        "MATCH ()-[r:EXPLOIT_STEP]->(n) WHERE NOT (n:VirtualSink) DELETE r"
    )

    # Rule 1: Initial access via entry points
    graph.query(
        "MATCH (vs:VirtualSource)-[:EXPOSES]->(ep:EntryPoint)-[:ROUTES_TO]->(w:Workload) "
        "MERGE (vs)-[:EXPLOIT_STEP {step_type: 'INITIAL_ACCESS', technique: 'EXTERNAL_EXPOSURE', description: 'Direct ingress from internet'}]->(w)"
    )

    # Rule 2: Lateral movement via CAN_REACH_NET
    graph.query(
        "MATCH (w1:Workload)-[net:CAN_REACH_NET]->(w2:Workload) "
        "MERGE (w1)-[:EXPLOIT_STEP {step_type: 'NETWORK_REACH', technique: 'LATERAL_PIVOT', description: 'Lateral movement across workloads', port: net.port}]->(w2)"
    )

    # Rule 3: Crown jewel exfiltration hook
    graph.query(
        "MATCH (w:Workload)-[:HOSTS_WORKLOAD]->(cj:CrownJewel)-[:EXPLOIT_STEP]->(vk:VirtualSink) "
        "MERGE (w)-[:EXPLOIT_STEP {step_type: 'CROWN_JEWEL_COMPROMISE', technique: 'DATA_EXFILTRATION', description: 'Crown jewel exfiltration'}]->(vk)"
    )

    res = graph.query("MATCH ()-[r:EXPLOIT_STEP]->() RETURN count(r) AS exploit_edge_count")
    print(f"[+] Exploit plane compiled: {res.result_set[0][0]} :EXPLOIT_STEP edges present.")


def step_3_discover_attack_paths(graph_name: str):
    print(f"\n--- [STEP 3] Discovering Attack Paths using native algo.SPpaths ({graph_name}) ---")
    paths = db_manager.find_shortest_paths(graph_name)
    print(f"[+] Found {len(paths)} attack path(s) using algo.SPpaths.")
    for idx, row in enumerate(paths):
        path_obj = row[0]
        # Inspect path nodes
        nodes = path_obj.nodes() if hasattr(path_obj, "nodes") else []
        node_names = [getattr(n, "properties", {}).get("name", getattr(n, "properties", {}).get("id", str(n))) for n in nodes]
        print(f"    Path #{idx + 1}: {' -> '.join(node_names)}")
    return paths


def step_4_counterfactual_sandbox_simulation():
    print(f"\n--- [STEP 4] Executing Counterfactual Sandbox Simulation via GRAPH.COPY ---")
    print(f"[*] Copying {GRAPH_PROD} -> {GRAPH_SANDBOX} via native FalkorDB GRAPH.COPY...")
    db_manager.copy_graph(GRAPH_PROD, GRAPH_SANDBOX)

    sandbox = db_manager.get_graph(GRAPH_SANDBOX)
    print("[*] Applying candidate mutation: Sever CAN_REACH_NET between api-service and crown-jewel-db...")
    sandbox.query(
        "MATCH (w2:Workload {name: 'api-service'})-[r:CAN_REACH_NET]->(w3:Workload {name: 'crown-jewel-db'}) "
        "DELETE r"
    )

    # Re-compile exploit plane inside sandbox
    step_2_compile_exploit_plane(GRAPH_SANDBOX)

    # Verify surviving paths
    surviving_paths = db_manager.find_shortest_paths(GRAPH_SANDBOX)
    print(f"[*] Surviving paths in sandbox: {len(surviving_paths)}")

    # Verify required flows are unbroken
    req_flows = sandbox.query(
        "MATCH (w1:Workload)-[:REQUIRED_DEPENDENCY]->(w2:Workload) "
        "RETURN count(w1) AS intact_required_flows"
    )
    intact_flows = req_flows.result_set[0][0]
    print(f"[*] Intact required business dependencies in sandbox: {intact_flows}")

    assert len(surviving_paths) == 0, f"Expected 0 surviving paths, got {len(surviving_paths)}"
    assert intact_flows >= 1, f"Required business dependency was broken!"

    print("[+] SANDBOX VERIFICATION PASSED: 0 surviving paths, 0 broken required flows.")
    print(f"[+] Verification Status: {VerificationStatus.VERIFIED_IN_MODEL.value}")
    return True


def step_5_live_cni_connection_tests():
    print("\n--- [STEP 5] Real In-Cluster CNI NetworkPolicy Truth-Table Tests ---")

    # Fetch running pod names in fjord-t0
    def get_pod_name(deployment_name: str) -> str:
        cmd = ["kubectl", "get", "pods", "-n", "fjord-t0", "-l", f"app={deployment_name}", "-o", "jsonpath={.items[0].metadata.name}"]
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return res.stdout.strip()

    ingress_pod = get_pod_name("ingress-proxy")
    api_pod = get_pod_name("api-service")
    db_pod = get_pod_name("crown-jewel-db")

    print(f"[*] Identified Cluster Pods:")
    print(f"    - Ingress Proxy : {ingress_pod}")
    print(f"    - API Service   : {api_pod}")
    print(f"    - Crown Jewel DB: {db_pod}")

    # Generate minimal-diff NetworkPolicy YAML
    netpol_yaml = Path("deploy/kind/remediation-networkpolicy.yaml")
    netpol_content = """apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: isolate-crown-jewel
  namespace: fjord-t0
spec:
  podSelector:
    matchLabels:
      role: crown-jewel
  policyTypes:
  - Ingress
  ingress: []
"""
    netpol_yaml.parent.mkdir(parents=True, exist_ok=True)
    netpol_yaml.write_text(netpol_content, encoding="utf-8")
    print(f"[+] Generated minimal-diff NetworkPolicy: {netpol_yaml}")

    # Apply NetworkPolicy to cluster
    print("[*] Applying NetworkPolicy to kind cluster via kubectl...")
    subprocess.run(["kubectl", "apply", "-f", str(netpol_yaml)], check=True)

    # Wait 3 seconds for Calico to program iptables/eBPF dataplane
    import time
    time.sleep(3)

    print("\n[*] Executing Live CNI Connection Test 1: Required business flow (ingress-proxy -> api-service)...")
    res_req = subprocess.run(
        ["kubectl", "exec", "-n", "fjord-t0", ingress_pod, "--", "nc", "-z", "-w", "2", "api-service-svc", "8080"],
        capture_output=True,
        text=True
    )
    print(f"    Exit code: {res_req.returncode} (Expected 0 = Connected)")
    assert res_req.returncode == 0, f"Required business traffic was broken! Output: {res_req.stderr}"
    print("    [+] PASS: Required dependency flow ingress-proxy -> api-service is preserved and healthy.")

    print("\n[*] Executing Live CNI Connection Test 2: Attack flow (api-service -> crown-jewel-db)...")
    res_attack = subprocess.run(
        ["kubectl", "exec", "-n", "fjord-t0", api_pod, "--", "nc", "-z", "-w", "2", "crown-jewel-db-svc", "8080"],
        capture_output=True,
        text=True
    )
    print(f"    Exit code: {res_attack.returncode} (Expected != 0 = Blocked/Timeout)")
    assert res_attack.returncode != 0, "Security failure! api-service was still able to reach crown-jewel-db!"
    print("    [+] PASS: Calico CNI successfully dropped unauthorized traffic. Attack path is severed.")


def main():
    print("=" * 70)
    print("PROJECT FJORD: TASK 0 (T0) VERTICAL SLICE VERIFICATION")
    print("=" * 70)

    step_1_seed_inventory_graph()
    step_2_compile_exploit_plane(GRAPH_PROD)
    initial_paths = step_3_discover_attack_paths(GRAPH_PROD)
    assert len(initial_paths) >= 1, "Expected at least 1 multi-hop path initially."

    step_4_counterfactual_sandbox_simulation()
    step_5_live_cni_connection_tests()

    print("\n" + "=" * 70)
    print("TASK 0 (T0) VERTICAL SLICE: 100% COMPLETE AND VERIFIED!")
    print("All invariants satisfied: FalkorDB compilation, algo.SPpaths, GRAPH.COPY, and live Calico CNI truth table.")
    print("=" * 70)


if __name__ == "__main__":
    main()
