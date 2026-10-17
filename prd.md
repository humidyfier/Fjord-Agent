# Product Requirements Document: Project Fjord

## Mission
Track 1 WeMakeDevs FalkorDB Hackathon ("Agents That Act on Connected Data").

## Core Value Proposition
Posture prioritization (ingesting Trivy/Prowler raw feeds into Layer 1 posture nodes) combined with Layer 2 Exploit-State graph compilation, counterfactual in-graph sandbox simulation (`GRAPH.COPY`), constraint-aware ILP remediation selection, and re-ingestion verification (`VERIFIED_BY_REINGEST` / `VERIFIED_IN_MODEL`).

## Key Metrics
*All marked [DESIGN TARGET / EVAL. SPEC] until benchmark logs are committed:*
- **0/50 prompt injection success rate** (7.1% upper bound) `[DESIGN TARGET / EVAL. SPEC]`
- **< 30ms FalkorDB traversal** on 500 workloads `[DESIGN TARGET / EVAL. SPEC]`
- **100% contract compliance** across all tool inputs/outputs `[DESIGN TARGET / EVAL. SPEC]`
- **Zero broken required flows** on computed minimal-diff remediations `[DESIGN TARGET / EVAL. SPEC]`
- **Monotonic exploit-plane reduction** ($post \subseteq pre$) `[DESIGN TARGET / EVAL. SPEC]`

## Target Architecture & Pipeline
1. **Dual-Layer Graph in FalkorDB:**
   - **Layer 1 (Inventory & Posture):** Ingests Kubernetes manifests, Trivy vulnerability scans, and Prowler AWS cloud posture findings. Pre-flattens RBAC permissions and resolves CNI reachability matrices.
   - **Layer 2 (Exploit-State Plane):** Compiles multi-hop attack steps directly in FalkorDB Cypher, connecting virtual super-sources to virtual super-sinks (Crown Jewels).
2. **Cutting-Plane ILP Remediation:**
   - Formulates hitting-set problem over active attack paths using `scipy.optimize.milp`.
   - Generates minimal-diff NetworkPolicies and RBAC restrictions with collateral workload policy splitting.
3. **Counterfactual Sandboxing:**
   - Uses native FalkorDB `GRAPH.COPY` to create ephemeral simulation graphs (`sandbox_sim_<id>`).
   - Re-compiles exploit plane in sandbox to mathematically verify path elimination prior to approval.
4. **Agent Orchestrator & FastMCP:**
   - Exposes 7 strictly typed model tools with flight-recorder audit logging and XML data boundaries.
   - Enforces UI-side tokens for operator approvals (`record_operator_decision`).
5. **Interactive Frontend Command Center:**
   - 3-pane dashboard featuring scenario selection, BYOK API key input, live MCP trace, interactive topology visualization, sandbox toggle, and copyable K8s YAML patches.
