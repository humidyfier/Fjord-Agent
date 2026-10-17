# Fjord Agentic Development Guidelines

## Core Invariants
- **Zero Hallucination on Rules:** The LLM never writes raw OpenCypher; all graph traversals and exploit-plane compilations use parameterized Cypher templates or FalkorDB native algorithms (`algo.SPpaths`).
- **Single Source of Truth:** All node labels, relationship types, enums, and tool contracts must be imported directly from `backend/schema.py`. Any divergence between code and schema fails contract tests.
- **Verification Gates:** No remediation can be committed (`commit_verified_remediation`) unless a prior sandbox run for the exact `(snapshot_sha, candidate_set_id)` succeeded with 0 surviving paths and 0 broken required flows.
- **Safety by Design:** Operator approvals are strictly UI-side tokens. Inferred required flows are untrusted warnings. All model inputs are wrapped and truncated.

## Tool Execution & Safety Architecture
- **Tool Quotas:** Max 5 tool calls total per turn across all categories.
- **Strict Role Separation:** LLM tools are strictly separated from operator actions. `record_operator_decision` is UI-only and never exposed in the LLM tool schema.
- **Prompt Injection Defense:** Wrap and truncate all untrusted cluster strings in `<untrusted_data>` XML tags before presenting to the LLM.
- **Flight Recorder:** Every session writes immutable jsonl logs to `runs/<session_id>.jsonl` tracking model requests, tool calls, sandbox simulations, and verification results.
- **Counterfactual Sandboxing:** All mutations are simulated in an isolated FalkorDB graph copy (`sandbox_sim_<id>`) created via native `GRAPH.COPY`. No direct writes to the production snapshot graph (`prod_<sha8>`).
- **Platform Integrity:** Run natively on Windows. Do not switch to WSL or Ubuntu. Use `pathlib.Path` and Windows-compatible commands.
