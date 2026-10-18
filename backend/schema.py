"""
backend/schema.py
Single Source of Truth for Project Fjord.
Defines Node Labels, Relationship Types, Enums, and Tool Pydantic Models.
"""

from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


# ============================================================================
# EXACT 16 NODE LABELS (+ RemediationRecord in sentinel_memory)
# ============================================================================

NODE_LABELS = {
    "ENTRY_POINT": "EntryPoint",
    "INGRESS": "Ingress",
    "SERVICE": "Service",
    "WORKLOAD": "Workload",
    "CONTAINER": "Container",
    "POSTURE_FINDING": "PostureFinding",
    "SERVICE_ACCOUNT": "ServiceAccount",
    "RBAC_ROLE": "RBACRole",
    "WORKER_NODE": "WorkerNode",
    "IAM_ROLE": "IAMRole",
    "CROWN_JEWEL": "CrownJewel",
    "NETWORK_POLICY": "NetworkPolicy",
    "ATTACKER_STATE": "AttackerState",
    "VIRTUAL_SOURCE": "VirtualSource",
    "VIRTUAL_SINK": "VirtualSink",
    "IAM_POLICY": "IAMPolicy",
    "REMEDIATION_RECORD": "RemediationRecord",  # In sentinel_memory graph
}


# ============================================================================
# EXACT RELATIONSHIP TYPES (Inventory + Exploit Plane)
# ============================================================================

REL_TYPES = [
    "EXPOSES",
    "ROUTES_TO",
    "SELECTS",
    "HAS_CONTAINER",
    "AFFECTED_BY",
    "HAS_FINDING",
    "CAN_REACH_NET",
    "CAN_ACCESS",
    "USES_SA",
    "BOUND_TO",
    "ALLOWS_API",
    "MOUNTS_SECRET",
    "MOUNTS_HOST",
    "HOSTS_WORKLOAD",
    "ASSUMES_IAM_ROLE",
    "ALLOWS_CLOUD_ACCESS",
    "REQUIRED_DEPENDENCY",
    "EXPLOIT_STEP",
]



# ============================================================================
# ENUMS
# ============================================================================

class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FindingCategory(str, Enum):
    VULNERABILITY = "VULNERABILITY"  # e.g., Trivy CVE
    MISCONFIGURATION = "MISCONFIGURATION"  # e.g., Prowler or PodSecurity
    RBAC_RISK = "RBAC_RISK"
    NETWORK_EXPOSURE = "NETWORK_EXPOSURE"
    SECRET_LEAK = "SECRET_LEAK"


class ExploitStepType(str, Enum):
    NETWORK_REACH = "NETWORK_REACH"
    CVE_RCE = "CVE_RCE"
    RBAC_ESCALATE = "RBAC_ESCALATE"
    SECRET_ACCESS = "SECRET_ACCESS"
    CONTAINER_ESCAPE = "CONTAINER_ESCAPE"
    IAM_ASSUME_ROLE = "IAM_ASSUME_ROLE"
    CLOUD_EXFIL = "CLOUD_EXFIL"
    CROWN_JEWEL_COMPROMISE = "CROWN_JEWEL_COMPROMISE"


class VerificationStatus(str, Enum):
    UNVERIFIED = "UNVERIFIED"
    VERIFIED_IN_MODEL = "VERIFIED_IN_MODEL"
    VERIFIED_BY_REINGEST = "VERIFIED_BY_REINGEST"
    FAILED_VERIFICATION = "FAILED_VERIFICATION"


class RemediationType(str, Enum):
    NETWORK_POLICY_ADD = "NETWORK_POLICY_ADD"
    NETWORK_POLICY_PATCH = "NETWORK_POLICY_PATCH"
    RBAC_ROLE_RESTRICT = "RBAC_ROLE_RESTRICT"
    SERVICE_ACCOUNT_UNBIND = "SERVICE_ACCOUNT_UNBIND"
    CONTAINER_PATCH_CVE = "CONTAINER_PATCH_CVE"
    WORKLOAD_HARDEN_SECURITY_CONTEXT = "WORKLOAD_HARDEN_SECURITY_CONTEXT"


class ActionDecision(str, Enum):
    APPROVE = "APPROVE"
    REJECT = "REJECT"
    REQUEST_CHANGES = "REQUEST_CHANGES"


# ============================================================================
# GRAPH PROPERTY MODELS
# ============================================================================

class AllowsApiEdgeProps(BaseModel):
    """Pre-flattened RBAC permission flags for Cypher query performance."""
    allows_secrets_get: bool = False
    allows_pods_exec: bool = False
    allows_pods_create_patch: bool = False
    allows_impersonate: bool = False
    allows_bind_escalate: bool = False
    is_wildcard: bool = False
    is_cluster_scoped: bool = False
    resource_names: List[str] = Field(default_factory=list)


class ExploitStepEdgeProps(BaseModel):
    step_type: ExploitStepType
    technique: str
    description: str
    weight: float = 1.0
    cve_id: Optional[str] = None


class WorkloadNodeProps(BaseModel):
    name: str
    namespace: str
    kind: str  # Deployment, DaemonSet, StatefulSet, Pod
    labels: Dict[str, str] = Field(default_factory=dict)
    service_account: str = "default"
    host_network: bool = False
    host_pid: bool = False


# ============================================================================
# TOOL 1: get_posture_and_cluster_summary
# ============================================================================

class PostureSummaryRequest(BaseModel):
    graph_name: Optional[str] = Field(default=None, description="Graph snapshot name (e.g. prod_<sha8>)")


class PostureFindingSummary(BaseModel):
    severity: Severity
    category: FindingCategory
    count: int
    top_findings: List[str] = Field(default_factory=list)


class PostureSummaryResponse(BaseModel):
    graph_name: str
    workload_count: int
    container_count: int
    service_count: int
    ingress_count: int
    crown_jewel_count: int
    active_attack_path_count: int
    findings_by_severity: Dict[str, int]
    findings_summary: List[PostureFindingSummary] = Field(default_factory=list)
    actual_findings: List[Dict[str, Any]] = Field(default_factory=list)
    exact_cve_ids_in_graph: List[str] = Field(default_factory=list)
    exact_misconfig_ids_in_graph: List[str] = Field(default_factory=list)
    cve_notice: Optional[str] = None


# ============================================================================
# TOOL 2: discover_attack_paths
# ============================================================================

class DiscoverAttackPathsRequest(BaseModel):
    graph_name: Optional[str] = Field(default=None, description="Graph snapshot to evaluate")
    max_paths: int = Field(default=10, ge=1, le=50, description="Max attack paths to return")


class AttackPathStep(BaseModel):
    from_node: str
    from_label: str
    to_node: str
    to_label: str
    step_type: str
    technique: str
    description: str


class AttackPath(BaseModel):
    path_id: str
    source_entry: str
    target_crown_jewel: str
    total_hops: int
    steps: List[AttackPathStep]


class DiscoverAttackPathsResponse(BaseModel):
    graph_name: str
    total_paths_found: int
    paths: List[AttackPath]


# ============================================================================
# TOOL 3: compute_optimal_remediations
# ============================================================================

class ComputeOptimalRemediationsRequest(BaseModel):
    graph_name: Optional[str] = Field(default=None, description="Graph snapshot to remediate")
    max_remediations: int = Field(default=5, ge=1, le=20)
    preserve_dependencies: bool = Field(default=True, description="Strictly forbid severing REQUIRED_DEPENDENCY edges")


class RemediationCandidate(BaseModel):
    candidate_id: str
    remediation_type: RemediationType
    target_resource_kind: str
    target_resource_name: str
    target_namespace: str
    yaml_diff: str
    disruption_cost: float
    severed_path_ids: List[str]
    broken_flow_risk: Optional[str] = None


class ComputeOptimalRemediationsResponse(BaseModel):
    graph_name: str
    candidate_set_id: str
    total_candidates: int
    optimal_candidates: List[RemediationCandidate]
    solver_status: str
    estimated_disruption_score: float


# ============================================================================
# TOOL 4: inspect_resource_context
# ============================================================================

class InspectResourceContextRequest(BaseModel):
    resource_kind: Optional[str] = "Workload"
    resource_name: Optional[str] = None
    resource_id: Optional[str] = None
    namespace: str = "default"
    graph_name: Optional[str] = None


class ResourceContextResponse(BaseModel):
    resource_kind: str
    resource_name: str
    namespace: str
    labels: Dict[str, str] = Field(default_factory=dict)
    connected_services: List[str] = Field(default_factory=list)
    attached_findings: List[str] = Field(default_factory=list)
    active_network_policies: List[str] = Field(default_factory=list)
    required_dependencies: List[str] = Field(default_factory=list)
    raw_manifest_snippet: Optional[str] = None


# ============================================================================
# TOOL 5: update_dependency_or_constraint
# ============================================================================

class UpdateConstraintRequest(BaseModel):
    source_resource: str
    target_resource: str
    constraint_type: str = Field(description="'REQUIRED_DEPENDENCY' or 'FORBIDDEN_EDGE'")
    verbatim_quote: str = Field(description="Exact quote from user message instructing this constraint change")
    notes: Optional[str] = None


class UpdateConstraintResponse(BaseModel):
    status: str
    source_resource: str
    target_resource: str
    constraint_type: str
    verified_quote: bool
    message: str


# ============================================================================
# TOOL 6: simulate_fix_in_sandbox
# ============================================================================

class SimulateFixRequest(BaseModel):
    snapshot_sha: str
    candidate_set_id: str
    candidate_ids: List[str]


class SimulationResult(BaseModel):
    sandbox_graph: str
    surviving_attack_paths: int
    broken_required_flows: int
    verification_status: VerificationStatus
    details: str


class SimulateFixResponse(BaseModel):
    snapshot_sha: str
    candidate_set_id: str
    simulation_result: SimulationResult


# ============================================================================
# TOOL 7: commit_verified_remediation
# ============================================================================

class CommitRemediationRequest(BaseModel):
    snapshot_sha: str
    candidate_set_id: str
    applied_candidate_ids: List[str]


class CommitRemediationResponse(BaseModel):
    remediation_id: str
    status: str
    committed_at: str
    verification_proof: str
    yaml_patches: List[str]


# ============================================================================
# UI-SIDE OPERATOR DECISION (PROTECTED - NOT IN MODEL SCHEMA)
# ============================================================================

class OperatorApprovalRequest(BaseModel):
    candidate_set_id: str
    decision: ActionDecision
    operator_token: str
    reason: Optional[str] = None


class OperatorApprovalRecord(BaseModel):
    candidate_set_id: str
    decision: ActionDecision
    approved_at: str
    operator_identity: str
    reason: Optional[str] = None


# ============================================================================
# FLIGHT RECORDER LOG SCHEMA
# ============================================================================

class FlightRecorderEntry(BaseModel):
    session_id: str
    timestamp: str
    event_type: str  # TOOL_CALL, TOOL_RESULT, SANDBOX_RUN, COMMIT, OPERATOR_ACTION
    payload: Dict[str, Any]
