"""
backend/ingest/cni_resolver.py
Kubernetes CNI NetworkPolicy Reachability Resolver.
Evaluates ingress and egress isolation, pod/namespace selector matching,
and emits exact :CAN_REACH_NET relationships between workloads.
"""

from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field


@dataclass
class ParsedWorkload:
    id: str
    name: str
    namespace: str
    kind: str
    labels: Dict[str, str] = field(default_factory=dict)
    ports: List[int] = field(default_factory=lambda: [8080])
    host_network: bool = False
    service_account: str = "default"


@dataclass
class NetworkPolicyRulePort:
    protocol: str = "TCP"
    port: Optional[int] = None


@dataclass
class NetworkPolicyPeer:
    pod_selector: Optional[Dict[str, Any]] = None
    namespace_selector: Optional[Dict[str, Any]] = None
    ip_block: Optional[Dict[str, Any]] = None


@dataclass
class NetworkPolicyRule:
    ports: List[NetworkPolicyRulePort] = field(default_factory=list)
    peers: List[NetworkPolicyPeer] = field(default_factory=list)  # from or to


@dataclass
class ParsedNetworkPolicy:
    name: str
    namespace: str
    pod_selector: Dict[str, Any]
    policy_types: List[str]  # "Ingress", "Egress"
    ingress_rules: List[NetworkPolicyRule] = field(default_factory=list)
    egress_rules: List[NetworkPolicyRule] = field(default_factory=list)


def matches_selector(
    target_labels: Dict[str, str],
    selector: Optional[Dict[str, Any]]
) -> bool:
    """
    Evaluates whether target_labels satisfy a Kubernetes LabelSelector.
    - None means no selector specified.
    - {} means empty selector, matching all targets.
    - matchLabels requires exact key-value equality.
    - matchExpressions supports In, NotIn, Exists, DoesNotExist.
    """
    if selector is None:
        return False
    if len(selector) == 0:
        return True

    # 1. matchLabels
    match_labels = selector.get("matchLabels")
    if match_labels is not None:
        for k, v in match_labels.items():
            if target_labels.get(k) != str(v):
                return False

    # 2. matchExpressions
    match_exprs = selector.get("matchExpressions", [])
    for expr in match_exprs:
        key = expr.get("key")
        operator = expr.get("operator")
        values = [str(x) for x in expr.get("values", [])]

        if operator == "In":
            if key not in target_labels or target_labels[key] not in values:
                return False
        elif operator == "NotIn":
            if key in target_labels and target_labels[key] in values:
                return False
        elif operator == "Exists":
            if key not in target_labels:
                return False
        elif operator == "DoesNotExist":
            if key in target_labels:
                return False

    return True


class CNIReachabilityResolver:
    """
    Computes reachability between workloads by resolving Kubernetes NetworkPolicies.
    Implements standard Kubernetes CNI truth table:
    - Default allow unless isolated by an active policy.
    - Additive allow-rules across all selecting policies.
    - Bidirectional permission required (Egress on source AND Ingress on destination).
    """

    def __init__(
        self,
        workloads: List[ParsedWorkload],
        policies: List[ParsedNetworkPolicy],
        namespace_labels: Optional[Dict[str, Dict[str, str]]] = None
    ):
        self.workloads = workloads
        self.policies = policies
        self.namespace_labels = namespace_labels or {}

    def get_namespace_labels(self, ns_name: str) -> Dict[str, str]:
        # Return namespace labels with standard kubernetes.io/metadata.name label
        labels = dict(self.namespace_labels.get(ns_name, {}))
        labels.setdefault("kubernetes.io/metadata.name", ns_name)
        return labels

    def is_workload_selected_by_policy(self, workload: ParsedWorkload, policy: ParsedNetworkPolicy) -> bool:
        if policy.namespace != workload.namespace:
            return False
        return matches_selector(workload.labels, policy.pod_selector)

    def is_isolated_for_ingress(self, workload: ParsedWorkload) -> Tuple[bool, List[ParsedNetworkPolicy]]:
        if workload.host_network:
            return False, []
        selecting = [p for p in self.policies if "Ingress" in p.policy_types and self.is_workload_selected_by_policy(workload, p)]
        return len(selecting) > 0, selecting

    def is_isolated_for_egress(self, workload: ParsedWorkload) -> Tuple[bool, List[ParsedNetworkPolicy]]:
        if workload.host_network:
            return False, []
        selecting = [p for p in self.policies if "Egress" in p.policy_types and self.is_workload_selected_by_policy(workload, p)]
        return len(selecting) > 0, selecting

    def allows_ingress(
        self,
        dest: ParsedWorkload,
        src: ParsedWorkload,
        port: int,
        protocol: str = "TCP"
    ) -> bool:
        isolated, selecting_policies = self.is_isolated_for_ingress(dest)
        if not isolated:
            return True  # Default allow

        # Must match at least one ingress rule in any selecting policy (union)
        for policy in selecting_policies:
            for rule in policy.ingress_rules:
                # Check port match
                if rule.ports:
                    port_matched = any(
                        (p.port is None or p.port == port) and p.protocol.upper() == protocol.upper()
                        for p in rule.ports
                    )
                    if not port_matched:
                        continue

                # If rule has no peers (empty from list), it allows all traffic
                if not rule.peers:
                    return True

                # Check peers (OR logic between peer items)
                for peer in rule.peers:
                    # Pod selector within same namespace
                    if peer.pod_selector is not None and peer.namespace_selector is None:
                        if src.namespace == policy.namespace and matches_selector(src.labels, peer.pod_selector):
                            return True
                    # Namespace selector matching any pod in matching namespaces
                    elif peer.namespace_selector is not None and peer.pod_selector is None:
                        src_ns_labels = self.get_namespace_labels(src.namespace)
                        if matches_selector(src_ns_labels, peer.namespace_selector):
                            return True
                    # Combined namespaceSelector AND podSelector
                    elif peer.namespace_selector is not None and peer.pod_selector is not None:
                        src_ns_labels = self.get_namespace_labels(src.namespace)
                        if matches_selector(src_ns_labels, peer.namespace_selector) and matches_selector(src.labels, peer.pod_selector):
                            return True

        return False

    def allows_egress(
        self,
        src: ParsedWorkload,
        dest: ParsedWorkload,
        port: int,
        protocol: str = "TCP"
    ) -> bool:
        isolated, selecting_policies = self.is_isolated_for_egress(src)
        if not isolated:
            return True  # Default allow

        # Must match at least one egress rule in any selecting policy
        for policy in selecting_policies:
            for rule in policy.egress_rules:
                if rule.ports:
                    port_matched = any(
                        (p.port is None or p.port == port) and p.protocol.upper() == protocol.upper()
                        for p in rule.ports
                    )
                    if not port_matched:
                        continue

                if not rule.peers:
                    return True

                for peer in rule.peers:
                    if peer.pod_selector is not None and peer.namespace_selector is None:
                        if dest.namespace == policy.namespace and matches_selector(dest.labels, peer.pod_selector):
                            return True
                    elif peer.namespace_selector is not None and peer.pod_selector is None:
                        dest_ns_labels = self.get_namespace_labels(dest.namespace)
                        if matches_selector(dest_ns_labels, peer.namespace_selector):
                            return True
                    elif peer.namespace_selector is not None and peer.pod_selector is not None:
                        dest_ns_labels = self.get_namespace_labels(dest.namespace)
                        if matches_selector(dest_ns_labels, peer.namespace_selector) and matches_selector(dest.labels, peer.pod_selector):
                            return True

        return False

    def compute_reachability(self) -> List[Tuple[ParsedWorkload, ParsedWorkload, int, str]]:
        """
        Calculates all active (source -> dest) reachability links across all workloads.
        Returns list of (src, dest, port, protocol).
        """
        reachable_links: List[Tuple[ParsedWorkload, ParsedWorkload, int, str]] = []

        for src in self.workloads:
            for dest in self.workloads:
                if src.id == dest.id:
                    continue  # Intra-pod/workload loopback not modeled as lateral pivot

                # Test destination's exposed ports
                dest_ports = dest.ports if dest.ports else [8080]
                for port in dest_ports:
                    egress_ok = self.allows_egress(src, dest, port, "TCP")
                    ingress_ok = self.allows_ingress(dest, src, port, "TCP")

                    if egress_ok and ingress_ok:
                        reachable_links.append((src, dest, port, "TCP"))

        return reachable_links
