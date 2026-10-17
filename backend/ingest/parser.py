"""
backend/ingest/parser.py
Multi-Format Ingestion Engine for Project Fjord:
- Kubernetes Multi-Document YAML (Deployments, Services, RBAC, Ingress, NetworkPolicies, Secrets)
- Trivy Vulnerability JSON (Container CVE findings)
- Prowler AWS Posture JSON (IAM Roles, Cloud Crown Jewels, Cross-boundary AssumeRole bridges)
- Required Flows / Dependency Contracts (required-flows.yaml and environment variable inference)
Populates Layer 1 Inventory & Posture Graph in FalkorDB adhering strictly to schema.py.
"""

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
import yaml

from backend.schema import (
    NODE_LABELS,
    REL_TYPES,
    Severity,
    FindingCategory,
    AllowsApiEdgeProps
)
from backend.ingest.cni_resolver import (
    ParsedWorkload,
    ParsedNetworkPolicy,
    NetworkPolicyRule,
    NetworkPolicyRulePort,
    NetworkPolicyPeer,
    CNIReachabilityResolver,
    matches_selector
)
from backend.db.connection import db_manager


class IngestionEngine:
    """
    Ingests and normalizes multi-source infrastructure and security data
    into typed graph models ready for FalkorDB ingestion.
    """

    def __init__(self):
        self.workloads: Dict[str, Dict[str, Any]] = {}  # key: ns/name
        self.containers: Dict[str, Dict[str, Any]] = {}  # key: workload_key/c_name
        self.services: Dict[str, Dict[str, Any]] = {}
        self.ingresses: Dict[str, Dict[str, Any]] = {}
        self.network_policies: List[ParsedNetworkPolicy] = []
        self.service_accounts: Dict[str, Dict[str, Any]] = {}
        self.rbac_roles: Dict[str, Dict[str, Any]] = {}
        self.role_bindings: List[Dict[str, Any]] = []
        self.worker_nodes: Dict[str, Dict[str, Any]] = {}
        self.crown_jewels: Dict[str, Dict[str, Any]] = {}
        self.entry_points: Dict[str, Dict[str, Any]] = {}
        self.iam_roles: Dict[str, Dict[str, Any]] = {}
        self.iam_policies: Dict[str, Dict[str, Any]] = {}
        self.posture_findings: Dict[str, Dict[str, Any]] = {}
        self.required_dependencies: List[Dict[str, Any]] = []

        # Inter-node edges to create
        self.edges: List[Dict[str, Any]] = []

    # =========================================================================
    # 1. KUBERNETES MANIFEST PARSING
    # =========================================================================

    def parse_k8s_yaml(self, yaml_content: str):
        """Parse multi-document Kubernetes YAML string."""
        docs = list(yaml.safe_load_all(yaml_content))
        for doc in docs:
            if not doc or not isinstance(doc, dict):
                continue
            kind = doc.get("kind", "")
            metadata = doc.get("metadata", {})
            name = metadata.get("name", "")
            namespace = metadata.get("namespace", "default")
            labels = metadata.get("labels", {}) or {}
            annotations = metadata.get("annotations", {}) or {}

            if kind in ["Deployment", "StatefulSet", "DaemonSet", "Job", "Pod"]:
                self._parse_workload(doc, kind, name, namespace, labels, annotations)
            elif kind == "Service":
                self._parse_service(doc, name, namespace, labels)
            elif kind == "Ingress":
                self._parse_ingress(doc, name, namespace, labels)
            elif kind == "NetworkPolicy":
                self._parse_network_policy(doc, name, namespace)
            elif kind == "ServiceAccount":
                self._parse_service_account(name, namespace, annotations)
            elif kind in ["Role", "ClusterRole"]:
                self._parse_rbac_role(doc, kind, name, namespace)
            elif kind in ["RoleBinding", "ClusterRoleBinding"]:
                self._parse_role_binding(doc, kind, name, namespace)
            elif kind == "Secret":
                self._parse_secret(doc, name, namespace, doc.get("type", "Opaque"))
            elif kind == "Node":
                self.worker_nodes[name] = {"name": name, "labels": labels}

    def _parse_workload(self, doc: dict, kind: str, name: str, namespace: str, labels: dict, annotations: dict):
        key = f"{namespace}/{name}"
        spec = doc.get("spec", {})
        pod_spec = spec.get("template", {}).get("spec", spec)  # For Pod vs Deployment
        pod_labels = spec.get("template", {}).get("metadata", {}).get("labels", labels) or labels

        host_network = bool(pod_spec.get("hostNetwork", False))
        host_pid = bool(pod_spec.get("hostPID", False))
        sa_name = pod_spec.get("serviceAccountName", pod_spec.get("serviceAccount", "default"))

        # Extract container ports & images
        container_list = pod_spec.get("containers", [])
        init_container_list = pod_spec.get("initContainers", [])
        all_containers = container_list + init_container_list

        ports: List[int] = []
        for c in all_containers:
            c_name = c.get("name", "main")
            c_image = c.get("image", "unknown")
            c_key = f"{key}/{c_name}"
            c_ports = [p.get("containerPort", 8080) for p in c.get("ports", [])]
            ports.extend(c_ports)

            # Security Context / Privileged
            sec_ctx = c.get("securityContext", {})
            privileged = bool(sec_ctx.get("privileged", False))
            allow_priv_esc = bool(sec_ctx.get("allowPrivilegeEscalation", False))

            self.containers[c_key] = {
                "id": c_key,
                "name": c_name,
                "image": c_image,
                "privileged": privileged,
                "allow_privilege_escalation": allow_priv_esc,
                "ports": c_ports or [8080]
            }

            self.edges.append({
                "type": "HAS_CONTAINER",
                "from_label": NODE_LABELS["WORKLOAD"],
                "from_id": key,
                "to_label": NODE_LABELS["CONTAINER"],
                "to_id": c_key,
                "props": {}
            })

            # Check for host socket / root volume mounts
            volume_mounts = c.get("volumeMounts", [])
            volumes = pod_spec.get("volumes", [])
            vol_map = {v.get("name"): v for v in volumes}
            for vm in volume_mounts:
                vol_name = vm.get("name")
                v_obj = vol_map.get(vol_name, {})
                if "hostPath" in v_obj:
                    hp = v_obj["hostPath"].get("path", "")
                    self.edges.append({
                        "type": "MOUNTS_HOST",
                        "from_label": NODE_LABELS["WORKLOAD"],
                        "from_id": key,
                        "to_label": NODE_LABELS["WORKER_NODE"],
                        "to_id": "default-worker-node",
                        "props": {"host_path": hp, "read_only": vm.get("readOnly", False)}
                    })
                elif "secret" in v_obj:
                    s_name = v_obj["secret"].get("secretName", "")
                    s_key = f"{namespace}/{s_name}"
                    self.edges.append({
                        "type": "MOUNTS_SECRET",
                        "from_label": NODE_LABELS["WORKLOAD"],
                        "from_id": key,
                        "to_label": NODE_LABELS["CROWN_JEWEL"],
                        "to_id": s_key,
                        "props": {"mount_path": vm.get("mountPath", "")}
                    })

            # Check env vars for cold-start dependency inference
            for env in c.get("env", []):
                val = str(env.get("value", ""))
                # Infer HTTP/Service dependencies: http://<service-name>:<port> or <svc-name>.<ns>
                match = re.search(r"https?://([a-zA-Z0-9\-]+)(?:\.([a-zA-Z0-9\-]+))?(?::(\d+))?", val)
                if match:
                    dep_svc = match.group(1)
                    dep_ns = match.group(2) or namespace
                    self.required_dependencies.append({
                        "source": key,
                        "target_svc": f"{dep_ns}/{dep_svc}",
                        "purpose": f"inferred_from_env_{env.get('name')}"
                    })

        self.workloads[key] = {
            "id": key,
            "name": name,
            "namespace": namespace,
            "kind": kind,
            "labels": pod_labels,
            "ports": list(set(ports)) if ports else [8080],
            "host_network": host_network,
            "host_pid": host_pid,
            "service_account": sa_name
        }

        # Workload -> ServiceAccount
        sa_key = f"{namespace}/{sa_name}"
        self.edges.append({
            "type": "USES_SA",
            "from_label": NODE_LABELS["WORKLOAD"],
            "from_id": key,
            "to_label": NODE_LABELS["SERVICE_ACCOUNT"],
            "to_id": sa_key,
            "props": {}
        })

    def _parse_service(self, doc: dict, name: str, namespace: str, labels: dict):
        key = f"{namespace}/{name}"
        spec = doc.get("spec", {})
        selector = spec.get("selector", {}) or {}
        svc_type = spec.get("type", "ClusterIP")
        ports = [p.get("port", 80) for p in spec.get("ports", [])]

        self.services[key] = {
            "id": key,
            "name": name,
            "namespace": namespace,
            "type": svc_type,
            "selector": selector,
            "ports": ports
        }

        # If NodePort or LoadBalancer, create EntryPoint
        if svc_type in ["LoadBalancer", "NodePort"]:
            ep_key = "entry:internet"
            self.entry_points[ep_key] = {
                "id": ep_key,
                "name": "Internet Gateway",
                "entry_type": "EXTERNAL"
            }
            self.edges.append({
                "type": "EXPOSES",
                "from_label": NODE_LABELS["ENTRY_POINT"],
                "from_id": ep_key,
                "to_label": NODE_LABELS["SERVICE"],
                "to_id": key,
                "props": {"public": True}
            })

    def _parse_ingress(self, doc: dict, name: str, namespace: str, labels: dict):
        key = f"{namespace}/{name}"
        ep_key = "entry:internet"
        self.entry_points[ep_key] = {
            "id": ep_key,
            "name": "Internet Gateway",
            "entry_type": "EXTERNAL"
        }
        self.ingresses[key] = {"id": key, "name": name, "namespace": namespace}

        # EntryPoint -> Ingress
        self.edges.append({
            "type": "EXPOSES",
            "from_label": NODE_LABELS["ENTRY_POINT"],
            "from_id": ep_key,
            "to_label": NODE_LABELS["INGRESS"],
            "to_id": key,
            "props": {"public": True}
        })

        # Routes to backend services
        rules = doc.get("spec", {}).get("rules", [])
        for r in rules:
            http_paths = r.get("http", {}).get("paths", [])
            for p in http_paths:
                backend = p.get("backend", {})
                svc_name = backend.get("service", {}).get("name") or backend.get("serviceName")
                if svc_name:
                    svc_key = f"{namespace}/{svc_name}"
                    self.edges.append({
                        "type": "ROUTES_TO",
                        "from_label": NODE_LABELS["INGRESS"],
                        "from_id": key,
                        "to_label": NODE_LABELS["SERVICE"],
                        "to_id": svc_key,
                        "props": {"path": p.get("path", "/")}
                    })

    def add_assume_breach_workload(self, workload_id: str):
        """Creates an assume-breach entry point node targeting a specific workload."""
        ep_key = f"entry:breach:{workload_id}"
        self.entry_points[ep_key] = {
            "id": ep_key,
            "name": f"Assumed Breach: {workload_id}",
            "entry_type": "ASSUME_BREACH"
        }
        self.edges.append({
            "type": "EXPOSES",
            "from_label": NODE_LABELS["ENTRY_POINT"],
            "from_id": ep_key,
            "to_label": NODE_LABELS["WORKLOAD"],
            "to_id": workload_id,
            "props": {"assume_breach": True}
        })

    def _parse_network_policy(self, doc: dict, name: str, namespace: str):
        spec = doc.get("spec", {})
        pod_sel = spec.get("podSelector", {}) or {}
        policy_types = spec.get("policyTypes", [])
        if not policy_types:
            policy_types = ["Ingress"]

        ingress_rules: List[NetworkPolicyRule] = []
        for ing in spec.get("ingress", []):
            ports = [NetworkPolicyRulePort(protocol=p.get("protocol", "TCP"), port=p.get("port")) for p in ing.get("ports", [])]
            peers: List[NetworkPolicyPeer] = []
            for f in ing.get("from", []):
                peers.append(NetworkPolicyPeer(
                    pod_selector=f.get("podSelector"),
                    namespace_selector=f.get("namespaceSelector"),
                    ip_block=f.get("ipBlock")
                ))
            ingress_rules.append(NetworkPolicyRule(ports=ports, peers=peers))

        egress_rules: List[NetworkPolicyRule] = []
        for eg in spec.get("egress", []):
            ports = [NetworkPolicyRulePort(protocol=p.get("protocol", "TCP"), port=p.get("port")) for p in eg.get("ports", [])]
            peers = []
            for t in eg.get("to", []):
                peers.append(NetworkPolicyPeer(
                    pod_selector=t.get("podSelector"),
                    namespace_selector=t.get("namespaceSelector"),
                    ip_block=t.get("ipBlock")
                ))
            egress_rules.append(NetworkPolicyRule(ports=ports, peers=peers))

        netpol = ParsedNetworkPolicy(
            name=name,
            namespace=namespace,
            pod_selector=pod_sel,
            policy_types=policy_types,
            ingress_rules=ingress_rules,
            egress_rules=egress_rules
        )
        self.network_policies.append(netpol)

    def _parse_service_account(self, name: str, namespace: str, annotations: dict):
        key = f"{namespace}/{name}"
        self.service_accounts[key] = {
            "id": key,
            "name": name,
            "namespace": namespace,
            "annotations": annotations
        }
        # Check for AWS IAM Role assumption via annotation (IRSA)
        role_arn = annotations.get("eks.amazonaws.com/role-arn")
        if role_arn:
            iam_role_name = role_arn.split("/")[-1]
            self.iam_roles[iam_role_name] = {"name": iam_role_name, "arn": role_arn}
            self.edges.append({
                "type": "ASSUMES_IAM_ROLE",
                "from_label": NODE_LABELS["SERVICE_ACCOUNT"],
                "from_id": key,
                "to_label": NODE_LABELS["IAM_ROLE"],
                "to_id": iam_role_name,
                "props": {"role_arn": role_arn}
            })

    def _parse_rbac_role(self, doc: dict, kind: str, name: str, namespace: str):
        is_cluster_scoped = (kind == "ClusterRole")
        key = name if is_cluster_scoped else f"{namespace}/{name}"
        rules = doc.get("rules", [])

        # Pre-flatten RBAC rules into booleans
        allows_secrets_get = False
        allows_pods_exec = False
        allows_pods_create_patch = False
        allows_impersonate = False
        allows_bind_escalate = False
        is_wildcard = False
        resource_names: Set[str] = set()

        for r in rules:
            verbs = set(r.get("verbs", []))
            resources = set(r.get("resources", []))
            r_names = r.get("resourceNames", [])
            resource_names.update(r_names)

            if "*" in verbs or "*" in resources:
                is_wildcard = True

            # Secrets access
            if ("secrets" in resources or "*" in resources) and ({"get", "list", "*"}.intersection(verbs)):
                allows_secrets_get = True

            # Pods exec
            if ("pods/exec" in resources or "*" in resources) and ({"create", "get", "*"}.intersection(verbs)):
                allows_pods_exec = True

            # Pods create/patch
            if ("pods" in resources or "*" in resources) and ({"create", "patch", "update", "*"}.intersection(verbs)):
                allows_pods_create_patch = True

            # Impersonate
            if ("users" in resources or "serviceaccounts" in resources or "*" in resources) and ({"impersonate", "*"}.intersection(verbs)):
                allows_impersonate = True

            # Bind / Escalate
            if ({"roles", "clusterroles", "*"}.intersection(resources)) and ({"bind", "escalate", "*"}.intersection(verbs)):
                allows_bind_escalate = True

        self.rbac_roles[key] = {
            "id": key,
            "name": name,
            "namespace": namespace if not is_cluster_scoped else "cluster",
            "is_cluster_scoped": is_cluster_scoped,
            "props": AllowsApiEdgeProps(
                allows_secrets_get=allows_secrets_get,
                allows_pods_exec=allows_pods_exec,
                allows_pods_create_patch=allows_pods_create_patch,
                allows_impersonate=allows_impersonate,
                allows_bind_escalate=allows_bind_escalate,
                is_wildcard=is_wildcard,
                is_cluster_scoped=is_cluster_scoped,
                resource_names=list(resource_names)
            ).model_dump()
        }

    def _parse_role_binding(self, doc: dict, kind: str, name: str, namespace: str):
        is_cluster_scoped = (kind == "ClusterRoleBinding")
        role_ref = doc.get("roleRef", {})
        role_name = role_ref.get("name", "")
        role_kind = role_ref.get("kind", "Role")
        role_key = role_name if role_kind == "ClusterRole" else f"{namespace}/{role_name}"

        subjects = doc.get("subjects", [])
        for subj in subjects:
            if subj.get("kind") == "ServiceAccount":
                sa_ns = subj.get("namespace", namespace)
                sa_name = subj.get("name", "")
                sa_key = f"{sa_ns}/{sa_name}"

                # Ensure SA exists in inventory
                if sa_key not in self.service_accounts:
                    self.service_accounts[sa_key] = {"id": sa_key, "name": sa_name, "namespace": sa_ns, "annotations": {}}

                self.edges.append({
                    "type": "BOUND_TO",
                    "from_label": NODE_LABELS["SERVICE_ACCOUNT"],
                    "from_id": sa_key,
                    "to_label": NODE_LABELS["RBAC_ROLE"],
                    "to_id": role_key,
                    "props": {}
                })

    def _parse_secret(self, doc: dict, name: str, namespace: str, sec_type: str):
        key = f"{namespace}/{name}"
        # Security invariant: Never store raw secret data or stringData in FalkorDB
        data_keys = list(doc.get("data", {}).keys()) if isinstance(doc.get("data"), dict) else []
        string_data_keys = list(doc.get("stringData", {}).keys()) if isinstance(doc.get("stringData"), dict) else []
        all_keys = list(set(data_keys + string_data_keys))

        self.crown_jewels[key] = {
            "id": key,
            "name": name,
            "namespace": namespace,
            "type": sec_type,
            "category": "K8S_SECRET",
            "secret_keys": all_keys,
            # Note: No raw data or stringData stored in graph
        }

    # =========================================================================
    # 2. TRIVY VULNERABILITY REPORT INGESTION
    # =========================================================================

    def parse_trivy_json(self, json_content: str):
        """Parse Trivy container vulnerability report."""
        try:
            data = json.loads(json_content)
        except Exception as e:
            print(f"[!] Warning: Failed to parse Trivy JSON: {e}")
            return

        artifact_name = data.get("ArtifactName", "unknown-image")
        # Normalize image tag / digest
        normalized_image = artifact_name.split("@")[0]

        results = data.get("Results", [])
        for res in results:
            target = res.get("Target", "")
            vulns = res.get("Vulnerabilities", [])
            for v in vulns:
                cve_id = v.get("VulnerabilityID", "")
                severity_str = v.get("Severity", "LOW").upper()
                sev = getattr(Severity, severity_str, Severity.LOW)
                title = v.get("Title", "")
                desc = v.get("Description", "")
                cvss = 0.0
                if "CVSS" in v:
                    for cvss_provider in v["CVSS"].values():
                        cvss = max(cvss, float(cvss_provider.get("V3Score", 0.0)))

                # Determine if CVE enables Remote Code Execution (RCE)
                cwe_ids = v.get("CweIDs", [])
                is_rce = any(cwe in ["CWE-94", "CWE-78", "CWE-502", "CWE-89", "CWE-77"] for cwe in cwe_ids) or \
                         "remote code execution" in desc.lower() or "command injection" in desc.lower()

                finding_key = f"cve-{cve_id}"
                self.posture_findings[finding_key] = {
                    "id": finding_key,
                    "cve_id": cve_id,
                    "severity": sev.value,
                    "category": FindingCategory.VULNERABILITY.value,
                    "title": title,
                    "description": desc[:500],
                    "cvss_score": cvss,
                    "is_rce": is_rce,
                    "image": normalized_image
                }

                # Link to all containers using this image
                for c_key, c_val in self.containers.items():
                    if normalized_image in c_val["image"] or c_val["image"] in normalized_image:
                        self.edges.append({
                            "type": "AFFECTED_BY",
                            "from_label": NODE_LABELS["CONTAINER"],
                            "from_id": c_key,
                            "to_label": NODE_LABELS["POSTURE_FINDING"],
                            "to_id": finding_key,
                            "props": {"is_rce": is_rce, "cvss": cvss}
                        })

    # =========================================================================
    # 3. PROWLER / AWS POSTURE REPORT INGESTION
    # =========================================================================

    def parse_prowler_json(self, json_content: str):
        """Parse Prowler / Checkov AWS security assessment report."""
        try:
            items = json.loads(json_content)
            if isinstance(items, dict) and "findings" in items:
                items = items["findings"]
            elif isinstance(items, dict):
                items = [items]
        except Exception as e:
            print(f"[!] Warning: Failed to parse Prowler JSON: {e}")
            return

        for item in items:
            check_id = item.get("CheckID") or item.get("id") or "prowler_check"
            status = item.get("Status", "FAIL").upper()
            if status != "FAIL":
                continue

            resource_arn = item.get("ResourceArn") or item.get("resource_id") or ""
            service_name = item.get("ServiceName") or item.get("service") or "aws"
            severity_str = item.get("Severity", "HIGH").upper()
            sev = getattr(Severity, severity_str, Severity.HIGH)

            finding_id = f"prowler-{check_id}-{resource_arn.split('/')[-1]}"
            self.posture_findings[finding_id] = {
                "id": finding_id,
                "check_id": check_id,
                "severity": sev.value,
                "category": FindingCategory.MISCONFIGURATION.value,
                "service": service_name,
                "resource_arn": resource_arn,
                "description": item.get("Description", "")[:500]
            }

            # Map AWS Crown Jewels (S3 bucket, RDS, DynamoDB)
            if service_name.lower() in ["s3", "rds", "dynamodb"]:
                cj_id = resource_arn.split(":")[-1] or resource_arn.split("/")[-1]
                self.crown_jewels[cj_id] = {
                    "id": cj_id,
                    "name": cj_id,
                    "category": f"AWS_{service_name.upper()}",
                    "arn": resource_arn
                }
                self.edges.append({
                    "type": "AFFECTED_BY",
                    "from_label": NODE_LABELS["CROWN_JEWEL"],
                    "from_id": cj_id,
                    "to_label": NODE_LABELS["POSTURE_FINDING"],
                    "to_id": finding_id,
                    "props": {}
                })

            # Map IAM Roles & Policies
            elif service_name.lower() == "iam":
                role_name = resource_arn.split("/")[-1]
                self.iam_roles[role_name] = {"id": role_name, "name": role_name, "arn": resource_arn}
                self.edges.append({
                    "type": "AFFECTED_BY",
                    "from_label": NODE_LABELS["IAM_ROLE"],
                    "from_id": role_name,
                    "to_label": NODE_LABELS["POSTURE_FINDING"],
                    "to_id": finding_id,
                    "props": {}
                })

    # =========================================================================
    # 4. REQUIRED FLOWS INGESTION
    # =========================================================================

    def parse_required_flows_yaml(self, yaml_content: str):
        """Parse required-flows.yaml business dependency contracts."""
        try:
            data = yaml.safe_load(yaml_content)
            flows = data.get("required_flows", []) if isinstance(data, dict) else []
            for f in flows:
                self.required_dependencies.append({
                    "source": f.get("from_workload"),
                    "target_workload": f.get("to_workload"),
                    "purpose": f.get("purpose", "business_critical_flow")
                })
        except Exception as e:
            print(f"[!] Warning: Failed to parse required-flows.yaml: {e}")

    # =========================================================================
    # 5. RESOLVE CNI REACHABILITY & MATERIALIZE FALKORDB GRAPH
    # =========================================================================

    def resolve_cni_and_populate_graph(self, graph_name: str) -> Dict[str, int]:
        """
        Executes CNI truth-table resolver across all workloads,
        connects Service selectors, Ingress routes, and populates FalkorDB.
        """
        # 1. Connect Services to Workloads via selector matching
        for svc_key, svc in self.services.items():
            sel = svc["selector"]
            if not sel:
                continue
            for w_key, w in self.workloads.items():
                if w["namespace"] == svc["namespace"] and matches_selector(w["labels"], {"matchLabels": sel}):
                    self.edges.append({
                        "type": "SELECTS",
                        "from_label": NODE_LABELS["SERVICE"],
                        "from_id": svc_key,
                        "to_label": NODE_LABELS["WORKLOAD"],
                        "to_id": w_key,
                        "props": {}
                    })

        # 2. Run CNI Reachability Resolver
        parsed_workloads = [
            ParsedWorkload(
                id=w["id"],
                name=w["name"],
                namespace=w["namespace"],
                kind=w["kind"],
                labels=w["labels"],
                ports=w["ports"],
                host_network=w["host_network"],
                service_account=w["service_account"]
            )
            for w in self.workloads.values()
        ]

        resolver = CNIReachabilityResolver(parsed_workloads, self.network_policies)
        reachable_links = resolver.compute_reachability()

        for src, dest, port, protocol in reachable_links:
            self.edges.append({
                "type": "CAN_REACH_NET",
                "from_label": NODE_LABELS["WORKLOAD"],
                "from_id": src.id,
                "to_label": NODE_LABELS["WORKLOAD"],
                "to_id": dest.id,
                "props": {"port": port, "protocol": protocol}
            })

        # 3. Resolve required dependencies to Workloads
        for req in self.required_dependencies:
            src_key = req.get("source")
            target_key = req.get("target_workload")
            target_svc = req.get("target_svc")

            # Resolve service target to workload if needed
            if not target_key and target_svc:
                svc = self.services.get(target_svc)
                if svc:
                    sel = svc["selector"]
                    for w_key, w in self.workloads.items():
                        if w["namespace"] == svc["namespace"] and matches_selector(w["labels"], {"matchLabels": sel}):
                            target_key = w_key
                            break

            if src_key and target_key and src_key in self.workloads and target_key in self.workloads:
                self.edges.append({
                    "type": "REQUIRED_DEPENDENCY",
                    "from_label": NODE_LABELS["WORKLOAD"],
                    "from_id": src_key,
                    "to_label": NODE_LABELS["WORKLOAD"],
                    "to_id": target_key,
                    "props": {"purpose": req.get("purpose", "business_dependency")}
                })

        # 4. Populate FalkorDB with Layer 1 nodes and edges
        return self._write_to_falkordb(graph_name)

    def _write_to_falkordb(self, graph_name: str) -> Dict[str, int]:
        """Materialize nodes and edges using parameterized Cypher."""
        graph = db_manager.get_graph(graph_name)

        # Create Default WorkerNode if not created
        if not self.worker_nodes:
            self.worker_nodes["default-worker-node"] = {"name": "default-worker-node", "labels": {}}

        # A. Create Workload nodes
        for w in self.workloads.values():
            graph.query(
                "MERGE (w:Workload {id: $id}) "
                "SET w.name = $name, w.namespace = $namespace, w.kind = $kind, "
                "    w.host_network = $host_net, w.host_pid = $host_pid, w.service_account = $sa",
                params={
                    "id": w["id"], "name": w["name"], "namespace": w["namespace"],
                    "kind": w["kind"], "host_net": w["host_network"], "host_pid": w["host_pid"],
                    "sa": w["service_account"]
                }
            )

        # B. Create Container nodes
        for c in self.containers.values():
            graph.query(
                "MERGE (c:Container {id: $id}) "
                "SET c.name = $name, c.image = $image, c.privileged = $privileged, "
                "    c.allow_privilege_escalation = $allow_esc",
                params={
                    "id": c["id"], "name": c["name"], "image": c["image"],
                    "privileged": c["privileged"], "allow_esc": c["allow_privilege_escalation"]
                }
            )

        # C. Create Service nodes
        for s in self.services.values():
            graph.query(
                "MERGE (s:Service {id: $id}) "
                "SET s.name = $name, s.namespace = $namespace, s.type = $type",
                params={"id": s["id"], "name": s["name"], "namespace": s["namespace"], "type": s["type"]}
            )

        # D. Create Ingress nodes
        for ing in self.ingresses.values():
            graph.query(
                "MERGE (i:Ingress {id: $id}) SET i.name = $name, i.namespace = $namespace",
                params={"id": ing["id"], "name": ing["name"], "namespace": ing["namespace"]}
            )

        # E. Create ServiceAccount nodes
        for sa in self.service_accounts.values():
            graph.query(
                "MERGE (sa:ServiceAccount {id: $id}) SET sa.name = $name, sa.namespace = $namespace",
                params={"id": sa["id"], "name": sa["name"], "namespace": sa["namespace"]}
            )

        # F. Create RBACRole nodes
        for r in self.rbac_roles.values():
            graph.query(
                "MERGE (r:RBACRole {id: $id}) "
                "SET r.name = $name, r.namespace = $namespace, r.is_cluster_scoped = $is_cs",
                params={"id": r["id"], "name": r["name"], "namespace": r["namespace"], "is_cs": r["is_cluster_scoped"]}
            )

        # G. Create CrownJewel nodes
        for cj in self.crown_jewels.values():
            graph.query(
                "MERGE (cj:CrownJewel {id: $id}) "
                "SET cj.name = $name, cj.category = $cat, cj.secret_keys = $secret_keys",
                params={
                    "id": cj["id"],
                    "name": cj["name"],
                    "cat": cj.get("category", "SENSITIVE_DATA"),
                    "secret_keys": cj.get("secret_keys", [])
                }
            )

        # H. Create WorkerNode nodes
        for wn in self.worker_nodes.values():
            graph.query(
                "MERGE (wn:WorkerNode {id: $id}) SET wn.name = $name",
                params={"id": wn["name"], "name": wn["name"]}
            )

        # I. Create IAMRole nodes
        for ir in self.iam_roles.values():
            graph.query(
                "MERGE (ir:IAMRole {id: $id}) SET ir.name = $name, ir.arn = $arn",
                params={"id": ir.get("id", ir["name"]), "name": ir["name"], "arn": ir.get("arn", "")}
            )

        # J. Create PostureFinding nodes
        for pf in self.posture_findings.values():
            graph.query(
                "MERGE (pf:PostureFinding {id: $id}) "
                "SET pf.cve_id = $cve_id, pf.severity = $sev, pf.category = $cat, "
                "    pf.cvss_score = $cvss, pf.is_rce = $is_rce, pf.title = $title",
                params={
                    "id": pf["id"], "cve_id": pf.get("cve_id", pf["id"]),
                    "sev": pf.get("severity", "MEDIUM"), "cat": pf.get("category", "VULNERABILITY"),
                    "cvss": pf.get("cvss_score", 0.0), "is_rce": pf.get("is_rce", False),
                    "title": pf.get("title", "")
                }
            )

        # J2. Create EntryPoint nodes (idempotent MERGE)
        for ep in self.entry_points.values():
            graph.query(
                f"MERGE (ep:{NODE_LABELS['ENTRY_POINT']} {{id: $id}}) "
                "SET ep.name = $name, ep.entry_type = $entry_type",
                params={
                    "id": ep["id"],
                    "name": ep.get("name", ep["id"]),
                    "entry_type": ep.get("entry_type", "EXTERNAL")
                }
            )

        # K. Materialize all edges
        for edge in self.edges:
            rel_type = edge["type"]
            from_lbl = edge["from_label"]
            to_lbl = edge["to_label"]
            from_id = edge["from_id"]
            to_id = edge["to_id"]
            props = edge.get("props", {})

            # Parameterized Cypher edge creation
            cypher = f"""
            MATCH (a:{from_lbl} {{id: $from_id}}), (b:{to_lbl} {{id: $to_id}})
            MERGE (a)-[r:{rel_type}]->(b)
            SET r += $props
            """
            graph.query(cypher, params={"from_id": from_id, "to_id": to_id, "props": props})

        # Return summary counts
        node_res = graph.query("MATCH (n) RETURN count(n) AS cnt")
        edge_res = graph.query("MATCH ()-[r]->() RETURN count(r) AS cnt")
        return {
            "node_count": node_res.result_set[0][0] if node_res else 0,
            "edge_count": edge_res.result_set[0][0] if edge_res else 0
        }
