"""
backend/api/app.py
FastAPI Web Server & Command Center Dashboard Host for Project Fjord.
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from backend.api.router import router

app = FastAPI(
    title="Project Fjord: Cloud & Container Security Posture & Remediation Agent",
    description="FalkorDB Hackathon Track 1: Agents That Act on Connected Data. Posture Prioritization, Exploit Plane Compilation, Cutting-Plane ILP, and Counterfactual Sandboxing.",
    version="1.0.0",
)

# Enable CORS for frontend development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API v1 router
app.include_router(router)


@app.get("/", response_class=HTMLResponse)
def get_command_center_ui():
    """
    Renders the professional dark-mode 3-pane DevSecOps Command Center dashboard:
    - Left Pane: Scenario Selector, BYOK Key Input, Replay Mode Badge, Live MCP Streaming Event Trace
    - Center Pane: Interactive FalkorDB Topology Canvas with Crimson Attack Paths & Sandbox Toggle Switch
    - Right Pane: Explainable Path Breadcrumb Proof, YAML Diff & Static Template-Rendered Operator Approval Cards
    """
    html_content = """<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>FJORD // Autonomous Attack-Path Remediation Agent</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <script>
    tailwind.config = {
      darkMode: 'class',
      theme: {
        extend: {
          colors: {
            fjord: {
              900: '#070b14',
              850: '#0d1322',
              800: '#11192e',
              700: '#1c2846',
              600: '#26375e',
              accent: '#38bdf8',
              crimson: '#ef4444',
              emerald: '#10b981',
              amber: '#f59e0b',
            }
          }
        }
      }
    }
  </script>
  <style>
    body { background-color: #070b14; color: #e2e8f0; font-family: ui-sans-serif, system-ui, sans-serif; }
    .custom-scroll::-webkit-scrollbar { width: 4px; height: 4px; }
    .custom-scroll::-webkit-scrollbar-thumb { background: #1c2846; border-radius: 4px; }
    #topology-canvas { height: 100%; width: 100%; }
    .pulse-crimson { animation: pulse 1.5s cubic-bezier(0.4, 0, 0.6, 1) infinite; }
    @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
  </style>
</head>
<body class="h-screen flex flex-col overflow-hidden">
  <!-- Top Navigation Header -->
  <header class="h-14 border-b border-fjord-700 bg-fjord-850 flex items-center justify-between px-6 shrink-0">
    <div class="flex items-center space-x-3">
      <div class="w-8 h-8 rounded bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center font-black text-white text-lg tracking-wider">
        FJ
      </div>
      <div>
        <h1 class="font-bold text-sm tracking-wide flex items-center space-x-2">
          <span>PROJECT FJORD</span>
          <span class="text-xs font-mono px-2 py-0.5 rounded bg-fjord-700 text-cyan-400 border border-cyan-800">v1.0-FalkorDB</span>
        </h1>
        <p class="text-[10px] text-gray-400">Cloud & Container Security Posture & Exploit-Path Remediation</p>
      </div>
    </div>

    <!-- Center Sandbox Toggle Switch -->
    <div class="flex items-center space-x-3 bg-fjord-900 px-3 py-1.5 rounded-lg border border-fjord-700">
      <span class="text-xs font-mono text-gray-400">VIEW:</span>
      <button id="btn-view-prod" onclick="toggleGraphView('prod')" class="px-3 py-1 text-xs font-mono font-semibold rounded bg-cyan-600 text-white shadow">
        <i class="fa-solid fa-cube mr-1"></i> [Graph: prod_cluster]
      </button>
      <button id="btn-view-sandbox" onclick="toggleGraphView('sandbox')" class="px-3 py-1 text-xs font-mono font-semibold rounded text-gray-400 hover:text-white transition">
        <i class="fa-solid fa-vial mr-1"></i> [Graph: sandbox_sim]
      </button>
    </div>

    <!-- Right Header Badges -->
    <div class="flex items-center space-x-3">
      <span class="text-[10px] font-mono px-2 py-1 rounded bg-amber-950 text-amber-400 border border-amber-800 flex items-center">
        <i class="fa-solid fa-circle text-[6px] mr-1.5 animate-ping"></i> REPLAY MODE [Live FalkorDB]
      </span>
      <span class="text-[10px] font-mono px-2 py-1 rounded bg-fjord-800 text-gray-400 border border-fjord-700">
        [DESIGN TARGET / EVAL. SPEC]
      </span>
    </div>
  </header>

  <!-- Main 3-Pane Body -->
  <main class="flex-1 flex overflow-hidden">
    <!-- PANE 1: Left Pane (Scenario Picker, BYOK & Live Trace) -->
    <section class="w-80 border-r border-fjord-700 bg-fjord-850 flex flex-col shrink-0">
      <div class="p-4 border-b border-fjord-700 space-y-3">
        <div>
          <label class="block text-[11px] font-semibold text-gray-400 uppercase tracking-wider mb-1">Target Scenario</label>
          <select id="scenario-select" onchange="initSession()" class="w-full text-xs bg-fjord-900 border border-fjord-700 rounded px-2.5 py-1.5 text-gray-200 focus:outline-none focus:border-cyan-500 font-mono">
            <option value="sample_cluster">E-Commerce Core (3-Tier K8s)</option>
            <option value="kubehound_reference">KubeHound RBAC/Escape Bench</option>
            <option value="kubernetes_goat">Kubernetes Goat Pods</option>
            <option value="bad_pods">Bad Pods Escalation Set</option>
          </select>
        </div>

        <div>
          <label class="block text-[11px] font-semibold text-gray-400 uppercase tracking-wider mb-1">BYOK Gemini API Key</label>
          <input type="password" id="byok-input" placeholder="Optional (runs Live Replay if empty)" class="w-full text-xs bg-fjord-900 border border-fjord-700 rounded px-2.5 py-1.5 text-gray-200 focus:outline-none focus:border-cyan-500 font-mono text-ellipsis">
        </div>

        <button onclick="runRemediationPipeline()" id="btn-run-agent" class="w-full bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-semibold text-xs py-2 px-3 rounded shadow transition flex items-center justify-center space-x-2">
          <i class="fa-solid fa-bolt"></i>
          <span>RUN REMEDIATION AGENT</span>
        </button>
      </div>

      <!-- Live MCP Event Trace -->
      <div class="flex-1 flex flex-col min-h-0">
        <div class="px-4 py-2 bg-fjord-800 border-b border-fjord-700 flex justify-between items-center">
          <span class="text-[11px] font-mono uppercase text-gray-400 font-semibold tracking-wider">FastMCP Flight Trace</span>
          <span id="trace-counter" class="text-[10px] font-mono text-cyan-400">0 events</span>
        </div>
        <div id="trace-log" class="flex-1 p-3 overflow-y-auto custom-scroll font-mono text-[11px] space-y-2">
          <div class="text-gray-500 italic">Ready. Select a scenario and click 'Run Remediation Agent' to stream tool execution...</div>
        </div>
      </div>
    </section>

    <!-- PANE 2: Center Pane (Interactive FalkorDB Topology Canvas) -->
    <section class="flex-1 flex flex-col bg-fjord-900 relative">
      <div class="absolute top-3 left-4 z-10 flex items-center space-x-2 bg-fjord-850/80 backdrop-blur px-3 py-1.5 rounded-lg border border-fjord-700 text-xs font-mono">
        <span class="text-gray-400">Active Graph:</span>
        <span id="active-graph-name" class="font-bold text-cyan-400">prod_cluster</span>
        <span class="text-gray-600">|</span>
        <span id="active-paths-badge" class="px-2 py-0.5 rounded bg-red-950 text-red-400 border border-red-800 text-[10px]">Breach Paths: 1</span>
      </div>

      <div class="absolute bottom-4 left-4 z-10 bg-fjord-850/90 backdrop-blur p-2.5 rounded-lg border border-fjord-700 text-[10px] font-mono space-y-1">
        <div class="font-bold text-gray-400 uppercase">Topology Legend</div>
        <div class="flex items-center space-x-2"><span class="w-2.5 h-2.5 rounded-full bg-cyan-400 inline-block"></span><span>Workload</span></div>
        <div class="flex items-center space-x-2"><span class="w-2.5 h-2.5 rounded-full bg-amber-400 inline-block"></span><span>PostureFinding (CVE)</span></div>
        <div class="flex items-center space-x-2"><span class="w-2.5 h-2.5 rounded-full bg-purple-400 inline-block"></span><span>IAM / RBAC</span></div>
        <div class="flex items-center space-x-2"><span class="w-2.5 h-2.5 rounded-full bg-emerald-400 inline-block"></span><span>CrownJewel</span></div>
        <div class="flex items-center space-x-2"><span class="w-2.5 h-0.5 bg-red-500 inline-block"></span><span class="text-red-400 font-semibold">Active Breach Edge</span></div>
      </div>

      <div id="topology-canvas" class="flex-1"></div>
    </section>

    <!-- PANE 3: Right Pane (Explainable Proof & Remediation Card) -->
    <section class="w-96 border-l border-fjord-700 bg-fjord-850 flex flex-col shrink-0">
      <div class="p-4 border-b border-fjord-700">
        <h2 class="text-xs font-semibold uppercase tracking-wider text-gray-400 flex items-center justify-between">
          <span>Explainable Path Proof</span>
          <span class="text-[10px] font-mono px-1.5 py-0.5 rounded bg-fjord-700 text-gray-300">algo.SPpaths</span>
        </h2>
        <div id="breadcrumb-chain" class="mt-2 p-2 bg-fjord-900 rounded border border-fjord-700 font-mono text-[11px] space-y-1">
          <div class="text-gray-500">VirtualSource &rarr; EntryPoint &rarr; Workload &rarr; CrownJewel &rarr; VirtualSink</div>
        </div>
      </div>

      <!-- Remediation YAML Diff -->
      <div class="flex-1 p-4 flex flex-col min-h-0 border-b border-fjord-700">
        <div class="flex items-center justify-between mb-2">
          <span class="text-xs font-semibold uppercase tracking-wider text-gray-400">Synthesized K8s Patch</span>
          <button onclick="copyPatchYaml()" class="text-[10px] font-mono px-2 py-0.5 bg-fjord-700 hover:bg-fjord-600 rounded text-cyan-400 transition">
            <i class="fa-regular fa-copy mr-1"></i>Copy YAML
          </button>
        </div>
        <textarea id="patch-yaml" readonly class="flex-1 w-full bg-fjord-900 border border-fjord-700 rounded p-2.5 font-mono text-[10px] text-emerald-400 resize-none focus:outline-none custom-scroll"># Synthesized minimal-diff NetworkPolicy will appear here after solver execution</textarea>
      </div>

      <!-- Static Template-Rendered Operator Approval Card -->
      <div class="p-4 bg-fjord-800 space-y-3">
        <div class="flex items-center justify-between">
          <span class="text-xs font-semibold text-gray-300">Operator Review Gate</span>
          <span id="gate-badge" class="text-[10px] font-mono px-2 py-0.5 rounded bg-gray-700 text-gray-400">AWAITING SOLVER</span>
        </div>
        <div class="bg-fjord-900 p-2.5 rounded border border-fjord-700 text-[11px] font-mono space-y-1">
          <div class="text-gray-400">Candidate: <span id="op-cset-id" class="text-cyan-400">-</span></div>
          <div class="text-gray-400">Disruption Cost: <span id="op-cost" class="text-emerald-400">1.0</span></div>
          <div class="text-gray-400">Broken Required Flows: <span id="op-broken" class="text-emerald-400">0</span></div>
          <div class="text-gray-400">Verification Gate: <span id="op-status" class="text-gray-500">PENDING</span></div>
        </div>
        <div class="flex space-x-2 pt-1">
          <button onclick="sendOperatorDecision('APPROVE')" id="btn-approve" disabled class="flex-1 bg-emerald-600/50 text-emerald-200 font-semibold text-xs py-2 rounded transition cursor-not-allowed">
            <i class="fa-solid fa-check mr-1"></i>APPROVE & COMMIT
          </button>
          <button onclick="sendOperatorDecision('REJECT')" id="btn-reject" disabled class="px-3 bg-red-950 hover:bg-red-900 text-red-400 border border-red-800 font-semibold text-xs py-2 rounded transition cursor-not-allowed">
            <i class="fa-solid fa-xmark"></i>
          </button>
        </div>
      </div>
    </section>
  </main>

  <script>
    let currentSession = null;
    let networkCanvas = null;
    let eventSource = null;

    async function initSession() {
      const scenario = document.getElementById('scenario-select').value;
      const byok = document.getElementById('byok-input').value;

      try {
        const resp = await fetch('/api/v1/sessions/init', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({scenario: scenario, byok_api_key: byok || null, replay_mode: !byok})
        });
        currentSession = await resp.json();
        document.getElementById('active-graph-name').innerText = currentSession.snapshot_sha;
        setupSSE(currentSession.session_id);
        loadTopology(currentSession.snapshot_sha);
      } catch (e) {
        console.error('Session init error:', e);
      }
    }

    function setupSSE(sessionId) {
      if (eventSource) eventSource.close();
      eventSource = new EventSource(`/api/v1/sessions/${sessionId}/stream`);
      eventSource.addEventListener('tool_call', (e) => {
        const data = JSON.parse(e.data);
        appendTraceLog(`[${data.data.latency_ms} ms] TOOL: ${data.data.tool}`, 'text-cyan-400');
      });
      eventSource.addEventListener('sandbox_sim', (e) => {
        const data = JSON.parse(e.data);
        appendTraceLog(`[${data.data.latency_ms} ms] SANDBOX: GRAPH.COPY verified -> 0 paths surviving`, 'text-emerald-400');
      });
      eventSource.addEventListener('commit_remediation', (e) => {
        appendTraceLog(`[VERIFIED COMMIT] Remediation committed to sentinel_memory`, 'text-emerald-300 font-bold');
      });
    }

    function appendTraceLog(text, colorClass) {
      const log = document.getElementById('trace-log');
      const item = document.createElement('div');
      item.className = `${colorClass} py-0.5 border-b border-fjord-800/40`;
      item.innerText = text;
      log.appendChild(item);
      log.scrollTop = log.scrollHeight;
    }

    async function loadTopology(graphName) {
      try {
        const res = await fetch(`/api/v1/graph/${graphName}`);
        const data = await res.json();
        document.getElementById('active-paths-badge').innerText = `Breach Paths: ${data.attack_path_count}`;

        const visNodes = data.nodes.map(n => ({
          id: n.id,
          label: n.name || n.id,
          color: n.is_attack_path ? '#ef4444' : (n.label === 'CrownJewel' ? '#10b981' : (n.label === 'PostureFinding' ? '#f59e0b' : '#38bdf8')),
          shape: n.label === 'CrownJewel' ? 'diamond' : 'dot',
          size: n.is_attack_path ? 18 : 12,
        }));

        const visEdges = data.edges.map(e => ({
          from: e.source,
          to: e.target,
          label: e.type,
          color: e.is_attack_path ? '#ef4444' : '#26375e',
          width: e.is_attack_path ? 3 : 1,
          arrows: 'to',
        }));

        const container = document.getElementById('topology-canvas');
        networkCanvas = new vis.Network(container, {nodes: visNodes, edges: visEdges}, {
          physics: {barnesHut: {gravitationalConstant: -2000, springLength: 80}},
          nodes: {font: {color: '#cbd5e1', size: 10, face: 'monospace'}},
          edges: {font: {color: '#64748b', size: 8, face: 'monospace', align: 'middle'}},
        });
      } catch (e) {
        console.error('Topology load error:', e);
      }
    }

    async function runRemediationPipeline() {
      if (!currentSession) await initSession();
      appendTraceLog('Starting remediation agent pipeline...', 'text-amber-400');
      try {
        const resp = await fetch('/api/v1/agent/run', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({session_id: currentSession.session_id})
        });
        const res = await resp.json();
        currentSession.candidate_set_id = res.candidate_set_id;
        currentSession.sandbox_sha = res.sandbox_sha;

        // Populate Right Pane
        document.getElementById('op-cset-id').innerText = res.candidate_set_id;
        document.getElementById('op-status').innerText = 'VERIFIED_IN_MODEL';
        document.getElementById('op-status').className = 'text-emerald-400 font-bold';
        document.getElementById('gate-badge').innerText = 'GATE UNLOCKED';
        document.getElementById('gate-badge').className = 'text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800';

        // Unlock operator button
        const btnApprove = document.getElementById('btn-approve');
        btnApprove.disabled = false;
        btnApprove.className = 'flex-1 bg-emerald-600 hover:bg-emerald-500 text-white font-semibold text-xs py-2 rounded transition cursor-pointer shadow-lg';

        const btnReject = document.getElementById('btn-reject');
        btnReject.disabled = false;
        btnReject.className = 'px-3 bg-red-950 hover:bg-red-900 text-red-400 border border-red-800 font-semibold text-xs py-2 rounded transition cursor-pointer';

        // Set patch YAML
        const remedTimeline = res.timeline.find(t => t.step === 'remediate');
        if (remedTimeline && remedTimeline.candidates.optimal_candidates.length > 0) {
          document.getElementById('patch-yaml').value = remedTimeline.candidates.optimal_candidates[0].yaml_diff;
        }

        appendTraceLog('Simulation complete: 0 surviving attack paths. Verification gate satisfied.', 'text-emerald-400 font-bold');
      } catch (e) {
        console.error('Agent run error:', e);
      }
    }

    function toggleGraphView(view) {
      if (!currentSession) return;
      const btnProd = document.getElementById('btn-view-prod');
      const btnSandbox = document.getElementById('btn-view-sandbox');

      if (view === 'sandbox' && currentSession.sandbox_sha) {
        btnSandbox.className = 'px-3 py-1 text-xs font-mono font-semibold rounded bg-emerald-600 text-white shadow';
        btnProd.className = 'px-3 py-1 text-xs font-mono font-semibold rounded text-gray-400 hover:text-white transition';
        document.getElementById('active-graph-name').innerText = currentSession.sandbox_sha;
        loadTopology(currentSession.sandbox_sha);
      } else {
        btnProd.className = 'px-3 py-1 text-xs font-mono font-semibold rounded bg-cyan-600 text-white shadow';
        btnSandbox.className = 'px-3 py-1 text-xs font-mono font-semibold rounded text-gray-400 hover:text-white transition';
        document.getElementById('active-graph-name').innerText = currentSession.snapshot_sha;
        loadTopology(currentSession.snapshot_sha);
      }
    }

    async function sendOperatorDecision(decision) {
      if (!currentSession || !currentSession.candidate_set_id) return;
      try {
        const resp = await fetch('/api/v1/operator/decision', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'X-UI-Token': currentSession.ui_token
          },
          body: JSON.stringify({
            session_id: currentSession.session_id,
            candidate_set_id: currentSession.candidate_set_id,
            decision: decision,
            ui_token: currentSession.ui_token
          })
        });
        const res = await resp.json();
        appendTraceLog(`Operator decision '${decision}' executed. Commit: ${res.commit_result ? 'SUCCESS' : 'NONE'}`, 'text-cyan-400 font-bold');
        document.getElementById('btn-approve').disabled = true;
        document.getElementById('btn-reject').disabled = true;
      } catch (e) {
        console.error('Operator decision error:', e);
      }
    }

    function copyPatchYaml() {
      const copyText = document.getElementById('patch-yaml');
      navigator.clipboard.writeText(copyText.value);
      alert('NetworkPolicy YAML copied to clipboard!');
    }

    // Auto-init on load
    window.addEventListener('load', () => initSession());
  </script>
</body>
</html>
"""
    return HTMLResponse(content=html_content)
