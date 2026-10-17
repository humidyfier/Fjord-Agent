"""
backend/agent/server.py
FastMCP Server for Project Fjord.

Exposes exactly 7 certified tools to AI models.
Excludes UI-only operator actions (e.g. record_operator_decision) from model tool schemas.
"""

from typing import List, Optional

try:
    from mcp.server.mcpserver import MCPServer
    server = MCPServer("fjord-security-agent")
except ImportError:
    try:
        from mcp.server.fastmcp import FastMCP
        server = FastMCP("fjord-security-agent")
    except ImportError:
        from fastmcp import FastMCP
        server = FastMCP("fjord-security-agent")

from backend.agent.tools import (
    get_posture_and_cluster_summary as _get_posture_and_cluster_summary,
    discover_attack_paths as _discover_attack_paths,
    compute_optimal_remediations as _compute_optimal_remediations,
    inspect_resource_context as _inspect_resource_context,
    update_dependency_or_constraint as _update_dependency_or_constraint,
    simulate_fix_in_sandbox as _simulate_fix_in_sandbox,
    commit_verified_remediation as _commit_verified_remediation,
)
from backend.schema import (
    PostureSummaryResponse,
    DiscoverAttackPathsResponse,
    ComputeOptimalRemediationsResponse,
    ResourceContextResponse,
    UpdateConstraintResponse,
    SimulateFixResponse,
    CommitRemediationResponse,
)


# ============================================================================
# TOOL REGISTRATIONS (EXACTLY 7 CERTIFIED TOOLS)
# ============================================================================

@server.tool()
def get_posture_and_cluster_summary(
    graph_name: Optional[str] = None
) -> PostureSummaryResponse:
    """Retrieve Layer 1 cluster topology inventory and posture findings summary."""
    return _get_posture_and_cluster_summary(graph_name=graph_name)


@server.tool()
def discover_attack_paths(
    graph_name: Optional[str] = None,
    max_paths: int = 10
) -> DiscoverAttackPathsResponse:
    """Enumerate active multi-hop attack paths from :VirtualSource to :VirtualSink."""
    return _discover_attack_paths(graph_name=graph_name, max_paths=max_paths)


@server.tool()
def compute_optimal_remediations(
    graph_name: Optional[str] = None,
    max_remediations: int = 5,
    preserve_dependencies: bool = True
) -> ComputeOptimalRemediationsResponse:
    """Compute minimal-disruption remediation actions using Cutting-Plane ILP hitting-set solver."""
    return _compute_optimal_remediations(
        graph_name=graph_name,
        max_remediations=max_remediations,
        preserve_dependencies=preserve_dependencies
    )


@server.tool()
def inspect_resource_context(
    resource_kind: str,
    resource_name: str,
    namespace: str = "default",
    graph_name: Optional[str] = None
) -> ResourceContextResponse:
    """Inspect security and relationship context for a specific resource node."""
    return _inspect_resource_context(
        resource_kind=resource_kind,
        resource_name=resource_name,
        namespace=namespace,
        graph_name=graph_name
    )


@server.tool()
def update_dependency_or_constraint(
    source_resource: str,
    target_resource: str,
    constraint_type: str,
    verbatim_quote: str,
    notes: Optional[str] = None,
    user_prompt: Optional[str] = None,
    graph_name: Optional[str] = None
) -> UpdateConstraintResponse:
    """Propose an update to a business dependency or remediation constraint with verbatim quote validation."""
    return _update_dependency_or_constraint(
        source_resource=source_resource,
        target_resource=target_resource,
        constraint_type=constraint_type,
        verbatim_quote=verbatim_quote,
        notes=notes,
        user_prompt=user_prompt,
        graph_name=graph_name
    )


@server.tool()
def simulate_fix_in_sandbox(
    snapshot_sha: str,
    candidate_set_id: str,
    candidate_ids: Optional[List[str]] = None
) -> SimulateFixResponse:
    """Simulate candidate mutations in an ephemeral FalkorDB sandbox graph (GRAPH.COPY)."""
    return _simulate_fix_in_sandbox(
        snapshot_sha=snapshot_sha,
        candidate_set_id=candidate_set_id,
        candidate_ids=candidate_ids
    )


@server.tool()
def commit_verified_remediation(
    snapshot_sha: str,
    candidate_set_id: str,
    applied_candidate_ids: Optional[List[str]] = None
) -> CommitRemediationResponse:
    """Commit verified remediation. Strictly requires prior sandbox verification."""
    return _commit_verified_remediation(
        snapshot_sha=snapshot_sha,
        candidate_set_id=candidate_set_id,
        applied_candidate_ids=applied_candidate_ids
    )


def get_registered_tool_names() -> List[str]:
    """Return names of all tools registered on the server."""
    if hasattr(server, "_tools"):
        return list(server._tools.keys())
    elif hasattr(server, "tools"):
        return list(server.tools.keys())
    return [
        "get_posture_and_cluster_summary",
        "discover_attack_paths",
        "compute_optimal_remediations",
        "inspect_resource_context",
        "update_dependency_or_constraint",
        "simulate_fix_in_sandbox",
        "commit_verified_remediation",
    ]


if __name__ == "__main__":
    server.run()
