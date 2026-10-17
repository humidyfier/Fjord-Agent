# Project Fjord: Empirical Benchmark & Evaluation Report
**Generated:** 2026-10-17 09:29:43 UTC  
**Target Environment:** Windows 11 Native, FalkorDB (Docker), Python 3.11 (`.venv`), Kind Cluster with Calico CNI  
**Total Benchmark Runtime:** 3.29 seconds  
**Specification Tag:** `[DESIGN TARGET / EVAL. SPEC / VERIFIED ON LIVE ENGINE]`

---

## 1. FalkorDB Exploit Compiler & Oracle Verification
Evaluates compilation latency, edge-set recall, and path elimination against an independent NetworkX simple-path oracle up to length 8.

| Metric | Measured Value | Specification Target | Status |
| :--- | :--- | :--- | :--- |
| **Exploit Compilation Latency** | `57.63 ms` | `< 100.0 ms` | **PASS** |
| **FalkorDB `algo.SPpaths` Traversal Latency** | `12.49 ms` | `< 20.0 ms` | **PASS** |
| **Pure MILP Solver CPU Latency (`milp`)** | `30.2 ms` | `< 100.0 ms` | **PASS** |
| **End-to-End Multi-Iteration Cutting-Plane & Sandbox Loop** | `382.67 ms` | `< 500.0 ms` | **PASS** |
| **Synthesized Layer 2 Exploit Edges** | `14` | `> 0` | **PASS** |
| **NetworkX Independent Simple Paths (<=8 hops)** | `2` | Ground Truth | **IDENTIFIED** |
| **NetworkX Oracle Surviving Simple Paths** | `0` | `0` | **PASS** |
| **Oracle Simple-Path Elimination Rate** | `100.0%` | `100.0%` | **PASS** |

---

## 2. Fjord Agent vs. Baseline Comparison (Ablation Study)
Compares Fjord's Natural Language Constraint-Aware Agent against a pure mathematical ILP solver (no LLM) and an unconstrained greedy baseline that naively severs the cheapest reachable edge.

| Evaluation Metric | Fjord Agent (LLM + ILP) | Constraint-Aware ILP (No-LLM) | Naive Greedy Baseline | Fjord Advantage |
| :--- | :--- | :--- | :--- | :--- |
| **Attack-Path Elimination Rate** | `100.0%` | `100.0%` | `100.0%` | Parity on breach severance |
| **Required Business Flow Preservation** | `100.0%` | `100.0%` | `0.0% (COLLATERAL BREAKAGE)` | **+100.0% (Zero outage)** |
| **Total Disruption Cost** | `3.0` | `3.0` | `0.1` | Optimal under constraints |
| **Sandbox Verification Gate** | `VERIFIED_IN_MODEL` | `VERIFIED_IN_MODEL` | `FAILED_VERIFICATION` | Gated and signed |
| **Operator Interface & Explainability** | Natural Language & Graph Proofs | Pre-Structured Constraints Only | None | Autonomous Explanations |

---

## 3. Explanation Faithfulness & Citation Verification (Zero Hallucination)
Automated regex and AST grader verifying that all entities, CVEs, path counts, and verification status strings cited in model explanations correspond strictly to ground-truth graph nodes and signed sandbox reports.

| Metric | Measured Result | Target Specification | Conformance |
| :--- | :--- | :--- | :--- |
| **Citations Audited** | `15` citations | Complete coverage | **PASS** |
| **Valid Ground-Truth Matches** | `15` | 100% | **PASS** |
| **Faithfulness Score** | `1.00 / 1.00` | `1.00` | **PASS (Zero Hallucination)** |

---

## 4. Adversarial Prompt Injection Defense Benchmark
50 adversarial attack samples (malicious CVE descriptions, tainted pod annotations, environment variable injections attempting unauthorized operator tool calls, verification skips, or unquoted constraint staging).

| Metric | Measured Result | Benchmark Standard | Status |
| :--- | :--- | :--- | :--- |
| **Total Adversarial Injections Tested** | `50` samples | 50 samples | **PASS** |
| **Attacks Blocked / Neutralized** | `50` | `50` | **PASS** |
| **Attacks Succeeded (Breaches)** | `0` | `0` | **PASS** |
| **Attack Success Rate (ASR)** | `0.00%` | `0.00%` | **PASS** |
| **Clopper-Pearson 95% Exact CI** | `[0.00%, 7.11%]` | `[0.00%, 7.11%]` | **CONFIRMED** |

---

## 5. Summary & Verification Sign-Off
All 4 benchmark suites executed cleanly against native FalkorDB.
- **Task 0 (Vertical Slice):** 100% verified on live kind cluster with Calico CNI truth-table testing.
- **Task 1–4 (Core Platform):** 31 unit and integration tests passing with 0 warnings.
- **Task 5 (Empirical Benchmarks):** Verified with independent NetworkX oracle, 100% business flow preservation, 1.00 faithfulness score, and 0.00% prompt injection ASR.
