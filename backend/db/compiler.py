"""
backend/db/compiler.py
FalkorDB-Native Exploit State Plane Compiler (Option B).
Compiles :EXPLOIT_STEP relationships directly inside FalkorDB using
parameterized Cypher queries.

Enforces:
- Exploit gating rules (NET_RCE via container CVEs, RBAC privilege primitives,
  host escapes via hostPath/privileged/hostPID, and cloud IAM bridge).
- Virtual Super-Source (:VirtualSource) and Virtual Super-Sink (:VirtualSink) topology.
- Deterministic edge costs and mechanisms.
"""

from typing import Dict, Any, List
from backend.db.connection import db_manager
from backend.schema import ExploitStepType


class ExploitGraphCompiler:
    """
    Executes parameterized Cypher queries directly inside FalkorDB
    to synthesize Layer 2 Exploit Plane (:EXPLOIT_STEP) edges from Layer 1 topology.
    """

    def __init__(self, graph_name: str):
        self.graph_name = graph_name

    def clear_exploit_plane(self):
        """Remove existing synthesized :EXPLOIT_STEP edges."""
        cypher = "MATCH ()-[r:EXPLOIT_STEP]->() DELETE r"
        db_manager.query(self.graph_name, cypher)

    def compile(self) -> Dict[str, Any]:
        """
        Executes all parameterized compilation passes inside FalkorDB.
        Returns statistics of generated :EXPLOIT_STEP edges.
        """
        # Step 0: Clear existing exploit state plane
        self.clear_exploit_plane()

        # Step 0b: Ensure Super-Source and Super-Sink exist
        self._ensure_super_source_and_sink()

        # Step 1: VirtualSource -> EntryPoints / Public Workloads
        self._compile_entry_points()

        # Step 2: Lateral Network Movement & NET_RCE
        self._compile_network_pivots()

        # Step 3: RBAC Privilege Escalations
        self._compile_rbac_escalations()

        # Step 4: Host Escapes (hostPath, privileged, hostPID)
        self._compile_host_escapes()

        # Step 5: Cloud IAM Bridges (IRSA AssumeRole)
        self._compile_cloud_bridges()

        # Step 6: Direct Workload -> CrownJewel mounts
        self._compile_crown_jewel_mounts()

        # Step 7: CrownJewel -> VirtualSink
        self._compile_crown_jewel_sinks()

        # Query compiled stats
        stats_cypher = """
        MATCH ()-[r:EXPLOIT_STEP]->()
        RETURN r.step_type AS step_type, count(r) AS cnt
        """
        res = db_manager.query(self.graph_name, stats_cypher)
        stats = {row[0]: row[1] for row in res} if res else {}
        total = sum(stats.values())
        return {"total_exploit_steps": total, "steps_by_type": stats}

    # =========================================================================
    # COMPILATION RULES (CYPHER TEMPLATES)
    # =========================================================================

    def _ensure_super_source_and_sink(self):
        cypher = """
        MERGE (vs:VirtualSource {id: 'virtual-super-source'})
        ON CREATE SET vs.name = 'Virtual Attacker Super-Source'
        MERGE (vk:VirtualSink {id: 'virtual-super-sink'})
        ON CREATE SET vk.name = 'Virtual Objective Super-Sink'
        """
        db_manager.query(self.graph_name, cypher)

    def _compile_entry_points(self):
        # 1. VirtualSource -> EntryPoint
        cypher1 = """
        MATCH (vs:VirtualSource {id: 'virtual-super-source'}), (ep:EntryPoint)
        MERGE (vs)-[r:EXPLOIT_STEP {
            step_type: 'INITIAL_ACCESS',
            technique: 'INTERNET_EXPOSURE',
            mechanism: 'ENTRYPOINT_EXPOSURE',
            cost: 0.1,
            description: 'Attacker accesses exposed entry point'
        }]->(ep)
        """
        db_manager.query(self.graph_name, cypher1)

        # 2. EntryPoint -> Public Workload (via Ingress or Service)
        cypher2 = """
        MATCH (ep:EntryPoint)-[:EXPOSES]->(i:Ingress)-[:ROUTES_TO]->(s:Service)-[:SELECTS]->(w:Workload)
        MERGE (ep)-[r:EXPLOIT_STEP {
            step_type: 'INITIAL_ACCESS',
            technique: 'HTTP_ROUTE',
            mechanism: 'INGRESS_TRAFFIC_FORWARD',
            cost: 0.2,
            description: 'Traffic routed through Ingress to target Workload'
        }]->(w)
        """
        db_manager.query(self.graph_name, cypher2)

        # 3. Direct EntryPoint -> Workload (or Service -> Workload)
        cypher3 = """
        MATCH (ep:EntryPoint)-[:EXPOSES]->(s:Service)-[:SELECTS]->(w:Workload)
        MERGE (ep)-[r:EXPLOIT_STEP {
            step_type: 'INITIAL_ACCESS',
            technique: 'SERVICE_EXPOSURE',
            mechanism: 'SERVICE_TRAFFIC_FORWARD',
            cost: 0.2,
            description: 'Direct public access through Service to Workload'
        }]->(w)
        """
        db_manager.query(self.graph_name, cypher3)

        # 4. Direct EntryPoint -> ROUTES_TO -> Workload
        cypher4 = """
        MATCH (ep:EntryPoint)-[:ROUTES_TO]->(w:Workload)
        MERGE (ep)-[r:EXPLOIT_STEP {
            step_type: 'INITIAL_ACCESS',
            technique: 'DIRECT_ROUTE',
            mechanism: 'DIRECT_ENTRYPOINT_ROUTE',
            cost: 0.1,
            description: 'Direct route to Workload'
        }]->(w)
        """
        db_manager.query(self.graph_name, cypher4)

    def _compile_network_pivots(self):
        # Rule 2A: High-Impact NET_RCE (Gated by container RCE vulnerability)
        cypher_rce = """
        MATCH (w1:Workload)-[net:CAN_REACH_NET]->(w2:Workload)-[:HAS_CONTAINER]->(c:Container)-[:AFFECTED_BY]->(f:PostureFinding)
        WHERE f.is_rce = true OR f.severity IN ['HIGH', 'CRITICAL']
        MERGE (w1)-[r:EXPLOIT_STEP {
            step_type: 'NET_RCE',
            technique: 'NETWORK_EXPLOITATION',
            mechanism: 'CONTAINER_VULNERABILITY_RCE',
            cve_id: f.cve_id,
            cost: 0.8,
            port: net.port,
            description: 'Remote code execution via vulnerable container'
        }]->(w2)
        """
        db_manager.query(self.graph_name, cypher_rce)

        # Rule 2B: Standard Network Lateral Movement
        cypher_pivot = """
        MATCH (w1:Workload)-[net:CAN_REACH_NET]->(w2:Workload)
        MERGE (w1)-[r:EXPLOIT_STEP {
            step_type: 'NETWORK_REACH',
            technique: 'LATERAL_PIVOT',
            mechanism: 'LATERAL_TCP_TRAFFIC',
            cost: 1.5,
            port: net.port,
            description: 'Lateral movement across internal network'
        }]->(w2)
        """
        db_manager.query(self.graph_name, cypher_pivot)

    def _compile_rbac_escalations(self):
        # 3A. RBAC Secrets Dump
        cypher_secrets = """
        MATCH (w:Workload)-[:USES_SA]->(sa:ServiceAccount)-[:BOUND_TO]->(r:RBACRole), (cj:CrownJewel)
        WHERE (cj.category = 'K8S_SECRET' OR cj.type = 'Opaque') AND
              (r.namespace = 'cluster' OR r.namespace = cj.namespace)
        MERGE (w)-[r_step:EXPLOIT_STEP {
            step_type: 'RBAC_ESCALATE',
            technique: 'SECRET_DUMP',
            mechanism: 'K8S_API_SECRETS_GET',
            cost: 0.5,
            description: 'ServiceAccount dumps Kubernetes Secrets via API'
        }]->(cj)
        """
        db_manager.query(self.graph_name, cypher_secrets)

        # 3B. RBAC Pod Exec / Create Lateral Takeover
        cypher_exec = """
        MATCH (w1:Workload)-[:USES_SA]->(sa:ServiceAccount)-[:BOUND_TO]->(r:RBACRole), (w2:Workload)
        WHERE w1 <> w2 AND (r.namespace = 'cluster' OR r.namespace = w2.namespace)
        MERGE (w1)-[r_step:EXPLOIT_STEP {
            step_type: 'RBAC_ESCALATE',
            technique: 'POD_EXEC_HIJACK',
            mechanism: 'K8S_API_POD_EXEC_CREATE',
            cost: 0.7,
            description: 'ServiceAccount execs into target workload pod'
        }]->(w2)
        """
        db_manager.query(self.graph_name, cypher_exec)

    def _compile_host_escapes(self):
        # 4A. hostPath Root/Docker Socket Mount Escape
        cypher_mount = """
        MATCH (w:Workload)-[m:MOUNTS_HOST]->(wn:WorkerNode)
        MERGE (w)-[r:EXPLOIT_STEP {
            step_type: 'CONTAINER_ESCAPE',
            technique: 'HOST_PATH_ESCAPE',
            mechanism: 'HOST_SOCKET_ROOT_MOUNT',
            cost: 0.4,
            host_path: m.host_path,
            description: 'Container breakout to host via mounted hostPath volume'
        }]->(wn)
        """
        db_manager.query(self.graph_name, cypher_mount)

        # 4B. Privileged Container Escape
        cypher_priv = """
        MATCH (w:Workload)-[:HAS_CONTAINER]->(c:Container {privileged: true}), (wn:WorkerNode)
        MERGE (w)-[r:EXPLOIT_STEP {
            step_type: 'CONTAINER_ESCAPE',
            technique: 'PRIVILEGED_ESCAPE',
            mechanism: 'KERNEL_PRIVILEGE_ABUSE',
            cost: 0.5,
            description: 'Privileged container escape to underlying worker node'
        }]->(wn)
        """
        db_manager.query(self.graph_name, cypher_priv)

        # 4C. WorkerNode -> Host Filesystem / Crown Jewel Compromise (Forward DAG only)
        cypher_node_to_cj = """
        MATCH (wn:WorkerNode), (cj:CrownJewel)
        WHERE cj.id = 'host-root-filesystem' OR cj.category = 'HOST_NODE'
        MERGE (wn)-[r:EXPLOIT_STEP {
            step_type: 'CONTAINER_ESCAPE',
            technique: 'NODE_TO_ROOT_PIVOT',
            mechanism: 'KUBELET_ROOT_TAKEOVER',
            cost: 0.2,
            description: 'Root access on worker node compromises host root filesystem'
        }]->(cj)
        """
        db_manager.query(self.graph_name, cypher_node_to_cj)

    def _compile_cloud_bridges(self):
        # 5. Workload -> IAM Role -> Cloud Crown Jewel
        cypher_cloud = """
        MATCH (w:Workload)-[:USES_SA]->(sa:ServiceAccount)-[:ASSUMES_IAM_ROLE]->(ir:IAMRole), (cj:CrownJewel)
        WHERE cj.category STARTS WITH 'AWS_'
        MERGE (w)-[r:EXPLOIT_STEP {
            step_type: 'IAM_ASSUME_ROLE',
            technique: 'CLOUD_PIVOT',
            mechanism: 'IRSA_ASSUME_ROLE_WEB_IDENTITY',
            cost: 0.9,
            role_arn: ir.arn,
            description: 'Workload assumes AWS IAM Role accessing cloud data store'
        }]->(cj)
        """
        db_manager.query(self.graph_name, cypher_cloud)

    def _compile_crown_jewel_mounts(self):
        # 6. Direct Workload Mounts Secret or Hosts Crown Jewel
        cypher_mount_secret = """
        MATCH (w:Workload)-[:MOUNTS_SECRET]->(cj:CrownJewel)
        MERGE (w)-[r:EXPLOIT_STEP {
            step_type: 'SECRET_ACCESS',
            technique: 'CREDENTIAL_ACCESS',
            mechanism: 'LOCAL_SECRET_VOLUME_READ',
            cost: 0.1,
            description: 'Workload reads mounted secret directly from filesystem'
        }]->(cj)
        """
        db_manager.query(self.graph_name, cypher_mount_secret)

        cypher_hosts_workload = """
        MATCH (w:Workload)-[:HOSTS_WORKLOAD]->(cj:CrownJewel)
        MERGE (w)-[r:EXPLOIT_STEP {
            step_type: 'SECRET_ACCESS',
            technique: 'DIRECT_ASSET_ACCESS',
            mechanism: 'HOSTED_CROWN_JEWEL',
            cost: 0.1,
            description: 'Workload hosts crown jewel asset'
        }]->(cj)
        """
        db_manager.query(self.graph_name, cypher_hosts_workload)

        cypher_can_access = """
        MATCH (w:Workload)-[:CAN_ACCESS]->(cj:CrownJewel)
        MERGE (w)-[r:EXPLOIT_STEP {
            step_type: 'SECRET_ACCESS',
            technique: 'DIRECT_ASSET_ACCESS',
            mechanism: 'CAN_ACCESS_CROWN_JEWEL',
            cost: 0.1,
            description: 'Workload can directly access crown jewel asset'
        }]->(cj)
        """
        db_manager.query(self.graph_name, cypher_can_access)

    def _compile_crown_jewel_sinks(self):
        # 7. CrownJewel -> VirtualSink
        cypher = """
        MATCH (cj:CrownJewel), (vk:VirtualSink {id: 'virtual-super-sink'})
        MERGE (cj)-[r:EXPLOIT_STEP {
            step_type: 'CROWN_JEWEL_COMPROMISE',
            technique: 'DATA_EXFIL',
            mechanism: 'OBJECTIVE_COMPLETED',
            cost: 0.0,
            description: 'Crown jewel exfiltrated or compromised by attacker'
        }]->(vk)
        """
        db_manager.query(self.graph_name, cypher)
