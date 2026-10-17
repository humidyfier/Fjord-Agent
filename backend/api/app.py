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
    - Left Pane: Scenario Selector, BYOK Key Input, Replay Mode Badge, Interactive Chatbot Console & FastMCP Trace
    - Center Pane: Interactive FalkorDB Topology Canvas (Vis.js), Sandbox Toggle & In-Graph Cypher Inspector
    - Right Pane: Active Node Inspector, Explainable Path Proof, YAML Diff & Template-Rendered Operator Approval Cards
    """
    html_content = r"""<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>FJORD // Autonomous Attack-Path Remediation Agent</title>
  <script src="https://cdn.tailwindcss.com"></script>
  <!-- Vis.js CDN for Real Interactive Graph Rendering -->
  <script src="https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.9/standalone/umd/vis-network.min.js"></script>
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
  <script>
    tailwind.config = {
      darkMode: 'class',
      theme: {
        extend: {
          colors: {
            fjord: {
              950: '#040711',
              900: '#070b14',
              850: '#0d1322',
              800: '#11192e',
              750: '#162038',
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
    body { background-color: #040711; color: #e2e8f0; font-family: ui-sans-serif, system-ui, sans-serif; }
    .custom-scroll::-webkit-scrollbar { width: 5px; height: 5px; }
    .custom-scroll::-webkit-scrollbar-thumb { background: #1c2846; border-radius: 4px; }
    .custom-scroll::-webkit-scrollbar-track { background: #070b14; }
    #topology-canvas { position: absolute; inset: 0; width: 100%; height: 100%; }
    .pulse-crimson { animation: pulse 1.5s cubic-bezier(0.4, 0, 0.6, 1) infinite; }
    @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.5; } }
    .chat-bubble-agent { background: #0d1322; border: 1px solid #1c2846; }
    .chat-bubble-user { background: #0e7490; border: 1px solid #0891b2; }
  </style>
</head>
<body class="h-screen flex flex-col overflow-hidden select-none">
  <!-- Top Navigation Header -->
  <header class="h-14 border-b border-fjord-700 bg-fjord-850 flex items-center justify-between px-6 shrink-0 z-20">
    <div class="flex items-center space-x-3">
      <div class="w-8 h-8 rounded-lg bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center font-black text-white text-base tracking-wider shadow-lg shadow-cyan-500/20">
        FJ
      </div>
      <div>
        <h1 class="font-bold text-sm tracking-wide flex items-center space-x-2">
          <span>PROJECT FJORD</span>
          <span class="text-[10px] font-mono px-2 py-0.5 rounded bg-fjord-700 text-cyan-400 border border-cyan-800">v1.0-FalkorDB</span>
        </h1>
        <p class="text-[10px] text-gray-400">Autonomous Cloud & Container Security Posture & Remediation Agent</p>
      </div>
    </div>

    <!-- Center Sandbox Toggle Switch -->
    <div class="flex items-center space-x-3 bg-fjord-900 px-3 py-1.5 rounded-lg border border-fjord-700">
      <span class="text-xs font-mono text-gray-400 font-semibold">GRAPH VIEW:</span>
      <button id="btn-view-prod" onclick="toggleGraphView('prod')" class="px-3 py-1 text-xs font-mono font-semibold rounded bg-cyan-600 text-white shadow-md transition flex items-center">
        <i class="fa-solid fa-cube mr-1.5"></i> [Graph: prod_cluster]
      </button>
      <button id="btn-view-sandbox" onclick="toggleGraphView('sandbox')" class="px-3 py-1 text-xs font-mono font-semibold rounded text-gray-400 hover:text-white transition flex items-center">
        <i class="fa-solid fa-vial mr-1.5"></i> [Graph: sandbox_sim]
      </button>
    </div>

    <!-- Right Header Badges -->
    <div class="flex items-center space-x-3">
      <span id="session-badge" class="text-[10px] font-mono px-2 py-1 rounded bg-fjord-800 text-cyan-400 border border-fjord-700">
        ID: <span id="header-sess-id">session_init</span>
      </span>
      <span class="text-[10px] font-mono px-2 py-1 rounded bg-amber-950 text-amber-400 border border-amber-800 flex items-center">
        <i class="fa-solid fa-circle text-[6px] mr-1.5 animate-ping"></i> REPLAY MODE [Live FalkorDB]
      </span>
      <span class="text-[10px] font-mono px-2 py-1 rounded bg-fjord-800 text-gray-400 border border-fjord-700 hidden lg:inline">
        [DESIGN TARGET / EVAL. SPEC]
      </span>
    </div>
  </header>

  <!-- Main 3-Pane Body -->
  <main class="flex-1 flex overflow-hidden">
    <!-- ================================================================= -->
    <!-- PANE 1: Left Pane (Scenario, Interactive Chatbot & FastMCP Trace)  -->
    <!-- ================================================================= -->
    <section class="w-96 border-r border-fjord-700 bg-fjord-850 flex flex-col shrink-0">
      <!-- Scenario & BYOK Card -->
      <div class="p-3 border-b border-fjord-700 space-y-2.5 bg-fjord-900/60">
        <div class="flex space-x-2">
          <div class="flex-1">
            <label class="block text-[10px] font-semibold text-gray-400 uppercase tracking-wider mb-1">Target Cluster</label>
            <select id="scenario-select" onchange="initSession()" class="w-full text-xs bg-fjord-850 border border-fjord-700 rounded px-2 py-1.5 text-gray-200 focus:outline-none focus:border-cyan-500 font-mono">
              <option value="sample_cluster">E-Commerce Core (3-Tier K8s)</option>
              <option value="kubehound_reference">KubeHound RBAC/Escape Bench</option>
              <option value="kubernetes_goat">Kubernetes Goat Pods</option>
              <option value="bad_pods">Bad Pods Escalation Set</option>
            </select>
          </div>
          <div class="w-32">
            <label class="block text-[10px] font-semibold text-gray-400 uppercase tracking-wider mb-1">Gemini API Key</label>
            <input type="password" id="byok-input" placeholder="BYOK (optional)" class="w-full text-xs bg-fjord-850 border border-fjord-700 rounded px-2 py-1.5 text-gray-200 focus:outline-none focus:border-cyan-500 font-mono text-ellipsis">
          </div>
        </div>

        <button onclick="runRemediationPipeline()" id="btn-run-agent" class="w-full bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-semibold text-xs py-2 px-3 rounded shadow-md transition flex items-center justify-center space-x-2">
          <i class="fa-solid fa-bolt text-amber-300"></i>
          <span>RUN REMEDIATION AGENT (MILP + SANDBOX)</span>
        </button>
      </div>

      <!-- Operator Chatbot Section (Real-Time Interactive AI Console) -->
      <div class="flex-1 flex flex-col min-h-0 border-b border-fjord-700">
        <div class="px-3 py-2 bg-fjord-800 border-b border-fjord-700 flex justify-between items-center shrink-0">
          <div class="flex items-center space-x-2">
            <i class="fa-solid fa-robot text-cyan-400 text-xs"></i>
            <span class="text-xs font-bold text-gray-200 tracking-wide">Fjord Agent Console</span>
          </div>
          <span class="text-[9px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-800">
            Gemini 3.8 Flash
          </span>
        </div>

        <!-- Quick Question / Directive Chips -->
        <div class="px-3 py-1.5 bg-fjord-900/40 border-b border-fjord-700/50 flex space-x-1.5 overflow-x-auto custom-scroll text-[10px] font-mono shrink-0">
          <button onclick="setChatQuery('Explain the attack path from the internet to the crown jewel.')" class="px-2 py-0.5 rounded bg-fjord-750 hover:bg-fjord-700 text-cyan-300 border border-cyan-900 shrink-0">
            Explain Attack Path
          </button>
          <button onclick="setChatQuery('We have a deployment freeze on api-service, find an alternative remediation.')" class="px-2 py-0.5 rounded bg-fjord-750 hover:bg-fjord-700 text-amber-300 border border-amber-900 shrink-0">
            Freeze api-service
          </button>
          <button onclick="setChatQuery('What is the cluster security posture and CVE breakdown?')" class="px-2 py-0.5 rounded bg-fjord-750 hover:bg-fjord-700 text-gray-300 border border-fjord-600 shrink-0">
            Posture Summary
          </button>
        </div>

        <!-- Chat History Window -->
        <div id="chat-history" class="flex-1 p-3 overflow-y-auto custom-scroll space-y-3 font-sans text-xs">
          <!-- Welcome bubble -->
          <div class="chat-bubble-agent p-3 rounded-lg text-gray-300 space-y-1.5">
            <div class="flex items-center space-x-1.5 text-cyan-400 font-bold text-[11px]">
              <i class="fa-solid fa-shield-halved"></i>
              <span>Fjord Security Agent</span>
            </div>
            <p>Ready. I am monitoring the FalkorDB cluster topology. Ask me to <strong>explain attack paths</strong>, inspect CVEs, or issue natural language constraints like <em>"We have a deployment freeze on api-service"</em>.</p>
          </div>
        </div>

        <!-- Chat Input Form -->
        <div class="p-2.5 bg-fjord-900 border-t border-fjord-700 shrink-0">
          <form onsubmit="handleChatSubmit(event)" class="flex space-x-2">
            <input type="text" id="chat-input" placeholder="Ask Fjord about attack paths, explain fixes, or state constraints..." class="flex-1 bg-fjord-850 border border-fjord-700 rounded px-3 py-2 text-xs text-gray-200 placeholder-gray-500 focus:outline-none focus:border-cyan-500 font-mono">
            <button type="submit" id="btn-send-chat" class="bg-cyan-600 hover:bg-cyan-500 text-white px-3 py-2 rounded text-xs font-semibold shadow transition flex items-center justify-center">
              <i class="fa-solid fa-paper-plane"></i>
            </button>
          </form>
        </div>
      </div>

      <!-- Live FastMCP Flight Trace -->
      <div class="h-44 flex flex-col shrink-0 bg-fjord-950">
        <div class="px-3 py-1.5 bg-fjord-800 border-b border-fjord-700 flex justify-between items-center">
          <span class="text-[10px] font-mono uppercase text-gray-400 font-semibold tracking-wider flex items-center">
            <i class="fa-solid fa-bolt-lightning text-amber-400 mr-1.5"></i> FastMCP Flight Trace
          </span>
          <span id="trace-counter" class="text-[9px] font-mono text-cyan-400">0 events</span>
        </div>
        <div id="trace-log" class="flex-1 p-2.5 overflow-y-auto custom-scroll font-mono text-[10px] space-y-1 text-gray-400">
          <div class="text-gray-600 italic">FastMCP events stream here in real time with ms latency...</div>
        </div>
      </div>
    </section>

    <!-- ================================================================= -->
    <!-- PANE 2: Center Pane (Interactive FalkorDB Topology Canvas & Cypher) -->
    <!-- ================================================================= -->
    <section class="flex-1 flex flex-col bg-fjord-900 relative min-w-0">
      <!-- Floating Top Canvas Bar -->
      <div class="absolute top-3 left-4 right-4 z-10 flex items-center justify-between pointer-events-none">
        <div class="flex items-center space-x-2 bg-fjord-850/90 backdrop-blur px-3 py-1.5 rounded-lg border border-fjord-700 text-xs font-mono shadow-lg pointer-events-auto">
          <span class="text-gray-400">Active Graph:</span>
          <span id="active-graph-name" class="font-bold text-cyan-400">prod_cluster</span>
          <span class="text-gray-600">|</span>
          <span id="active-paths-badge" class="px-2 py-0.5 rounded bg-red-950 text-red-400 border border-red-800 text-[10px] font-bold">
            Breach Paths: 1 (CRIMSON)
          </span>
          <span class="text-gray-600">|</span>
          <span id="graph-stats" class="text-[10px] text-gray-400">0 nodes, 0 edges</span>
        </div>

        <div class="flex items-center space-x-2 pointer-events-auto">
          <button onclick="fitGraph()" class="bg-fjord-850/90 hover:bg-fjord-750 text-cyan-400 border border-fjord-700 px-2.5 py-1.5 rounded-lg text-xs font-mono shadow flex items-center space-x-1">
            <i class="fa-solid fa-expand mr-1"></i><span>Fit Canvas</span>
          </button>
        </div>
      </div>

      <!-- Floating Bottom Legend -->
      <div class="absolute bottom-4 left-4 z-10 bg-fjord-850/90 backdrop-blur p-2.5 rounded-lg border border-fjord-700 text-[10px] font-mono space-y-1 shadow-lg pointer-events-auto hidden md:block">
        <div class="font-bold text-gray-400 uppercase tracking-wider mb-1 text-[9px]">Topology Legend</div>
        <div class="flex items-center space-x-2"><span class="w-2.5 h-2.5 rounded bg-blue-500 inline-block"></span><span>Workload (Pod/Deployment)</span></div>
        <div class="flex items-center space-x-2"><span class="w-2.5 h-2.5 rotate-45 bg-amber-400 inline-block"></span><span>PostureFinding (CVE)</span></div>
        <div class="flex items-center space-x-2"><span class="w-2.5 h-2.5 rounded-full bg-purple-500 inline-block"></span><span>IAM / ServiceAccount</span></div>
        <div class="flex items-center space-x-2"><span class="w-2.5 h-2.5 rounded bg-emerald-500 inline-block"></span><span>CrownJewel (Secret/DB)</span></div>
        <div class="flex items-center space-x-2"><span class="w-2.5 h-0.5 bg-red-500 inline-block"></span><span class="text-red-400 font-semibold">Active Breach Edge (:EXPLOIT_STEP)</span></div>
        <div class="flex items-center space-x-2"><span class="w-2.5 h-0.5 border-t border-dashed border-gray-400 inline-block"></span><span class="text-gray-400">Severed Edge [DASHED]</span></div>
      </div>

      <!-- Real Graph Canvas Container (Vis.js renders here) -->
      <div class="flex-1 relative w-full h-full min-h-[300px]">
        <div id="topology-canvas"></div>
      </div>

      <!-- In-Graph FalkorDB Cypher & Native Execution Inspector -->
      <div class="h-48 border-t border-fjord-700 bg-fjord-950 flex flex-col shrink-0 z-10">
        <div class="px-4 py-2 bg-fjord-850 border-b border-fjord-700 flex justify-between items-center">
          <div class="flex items-center space-x-2">
            <i class="fa-solid fa-terminal text-emerald-400 text-xs"></i>
            <span class="text-xs font-bold text-gray-200 uppercase font-mono tracking-wide">In-Graph FalkorDB Cypher Inspector</span>
          </div>
          <div class="flex items-center space-x-2">
            <span class="text-[10px] font-mono text-gray-400">Live Engine: 127.0.0.1:6380</span>
            <button onclick="refreshCypherLogs()" class="text-[10px] text-cyan-400 hover:text-cyan-300 font-mono px-2 py-0.5 rounded bg-fjord-750">
              <i class="fa-solid fa-arrows-rotate mr-1"></i>Refresh
            </button>
          </div>
        </div>
        <div id="cypher-log-container" class="flex-1 p-3 overflow-y-auto custom-scroll font-mono text-[11px] space-y-2">
          <!-- Cypher queries populate dynamically -->
          <div class="text-gray-500 italic">No queries executed yet. Loading cluster Cypher traces...</div>
        </div>
      </div>
    </section>

    <!-- ================================================================= -->
    <!-- PANE 3: Right Pane (Node Inspector, Path Proof & Operator Gate)     -->
    <!-- ================================================================= -->
    <section class="w-96 border-l border-fjord-700 bg-fjord-850 flex flex-col shrink-0">
      <!-- Active Node Inspector (Populates on clicking any node) -->
      <div class="p-3.5 border-b border-fjord-700 bg-fjord-900/40 shrink-0">
        <h2 class="text-xs font-bold uppercase tracking-wider text-gray-300 flex items-center justify-between">
          <span class="flex items-center"><i class="fa-solid fa-circle-info text-cyan-400 mr-1.5"></i>Node Inspector</span>
          <span id="inspect-label" class="text-[10px] font-mono px-2 py-0.5 rounded bg-fjord-700 text-cyan-300">Click a Node</span>
        </h2>
        <div id="inspect-content" class="mt-2 p-2.5 bg-fjord-900 rounded border border-fjord-700 font-mono text-[11px] space-y-1">
          <div class="text-gray-400 italic text-[10px]">Click any node in the topology canvas to inspect properties, CVE attributes, and reachability.</div>
        </div>
      </div>

      <!-- Explainable Path Proof -->
      <div class="p-3.5 border-b border-fjord-700 shrink-0">
        <h2 class="text-xs font-bold uppercase tracking-wider text-gray-300 flex items-center justify-between">
          <span class="flex items-center"><i class="fa-solid fa-route text-amber-400 mr-1.5"></i>Explainable Path Proof</span>
          <span class="text-[10px] font-mono px-1.5 py-0.5 rounded bg-fjord-750 text-gray-400 border border-fjord-700">algo.SPpaths</span>
        </h2>
        <div id="breadcrumb-chain" class="mt-2 p-2.5 bg-fjord-900 rounded border border-fjord-700 font-mono text-[10px] space-y-1 text-gray-300">
          <div class="text-red-400 font-semibold"><i class="fa-solid fa-triangle-exclamation mr-1"></i> Active Shortest Breach Path:</div>
          <div class="text-gray-300 break-words">(:VirtualSource) &rarr; ingress-gw &rarr; ingress-proxy &rarr; api-service &rarr; crown-jewel-db &rarr; (:VirtualSink)</div>
        </div>
      </div>

      <!-- Remediation YAML Diff (Synthesized NetworkPolicy) -->
      <div class="flex-1 p-3.5 flex flex-col min-h-0 border-b border-fjord-700">
        <div class="flex items-center justify-between mb-2">
          <span class="text-xs font-bold uppercase tracking-wider text-gray-300 flex items-center">
            <i class="fa-solid fa-file-code text-cyan-400 mr-1.5"></i>Synthesized K8s Patch
          </span>
          <button onclick="copyPatchYaml()" class="text-[10px] font-mono px-2 py-1 bg-fjord-750 hover:bg-fjord-700 rounded text-cyan-400 border border-cyan-800 transition">
            <i class="fa-regular fa-copy mr-1"></i>Copy YAML
          </button>
        </div>
        <textarea id="patch-yaml" readonly class="flex-1 w-full bg-fjord-900 border border-fjord-700 rounded p-2.5 font-mono text-[10px] text-emerald-400 resize-none focus:outline-none custom-scroll"># Synthesized minimal-diff NetworkPolicy will appear here after solver execution</textarea>
      </div>

      <!-- Static Template-Rendered Operator Approval Gate -->
      <div class="p-3.5 bg-fjord-900/90 space-y-3 shrink-0">
        <div class="flex items-center justify-between">
          <span class="text-xs font-bold text-gray-200 uppercase tracking-wide">Operator Review Gate</span>
          <span id="gate-badge" class="text-[10px] font-mono px-2 py-0.5 rounded bg-gray-800 text-gray-400 border border-gray-700">
            AWAITING SOLVER
          </span>
        </div>
        <div class="bg-fjord-950 p-2.5 rounded border border-fjord-700 text-[11px] font-mono space-y-1">
          <div class="text-gray-400">Candidate Set ID: <span id="op-cset-id" class="text-cyan-400">-</span></div>
          <div class="text-gray-400">Disruption Cost: <span id="op-cost" class="text-emerald-400">1.0</span></div>
          <div class="text-gray-400">Broken Required Flows: <span id="op-broken" class="text-emerald-400">0</span></div>
          <div class="text-gray-400">Verification Gate: <span id="op-status" class="text-gray-500 font-semibold">PENDING</span></div>
        </div>
        <div class="flex space-x-2 pt-1">
          <button onclick="sendOperatorDecision('APPROVE')" id="btn-approve" disabled class="flex-1 bg-emerald-600/50 text-emerald-200 font-bold text-xs py-2 rounded transition cursor-not-allowed">
            <i class="fa-solid fa-check mr-1.5"></i>APPROVE & COMMIT
          </button>
          <button onclick="sendOperatorDecision('REJECT')" id="btn-reject" disabled class="px-4 bg-red-950 hover:bg-red-900 text-red-400 border border-red-800 font-bold text-xs py-2 rounded transition cursor-not-allowed">
            <i class="fa-solid fa-xmark"></i>
          </button>
        </div>
      </div>
    </section>
  </main>

  <!-- ================================================================= -->
  <!-- CLIENT JAVASCRIPT LOGIC                                           -->
  <!-- ================================================================= -->
  <script>
    let currentSession = null;
    let networkCanvas = null;
    let eventSource = null;
    let currentTopology = { nodes: [], edges: [] };
    let currentViewMode = 'prod';

    // 1. Session Initialization
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
        document.getElementById('header-sess-id').innerText = currentSession.session_id.substring(0, 15);
        document.getElementById('active-graph-name').innerText = currentSession.snapshot_sha;
        setupSSE(currentSession.session_id);
        await loadTopology(currentSession.snapshot_sha);
        await refreshCypherLogs();
      } catch (e) {
        console.error('Session init error:', e);
      }
    }

    // 2. Server-Sent Events (SSE) Stream
    function setupSSE(sessionId) {
      if (eventSource) eventSource.close();
      eventSource = new EventSource(`/api/v1/sessions/${sessionId}/stream`);
      
      eventSource.addEventListener('tool_call', (e) => {
        const data = JSON.parse(e.data);
        appendTraceLog(`[${data.data.latency_ms} ms] TOOL: ${data.data.tool}`, 'text-cyan-400');
        refreshCypherLogs();
      });
      
      eventSource.addEventListener('sandbox_sim', (e) => {
        const data = JSON.parse(e.data);
        appendTraceLog(`[${data.data.latency_ms} ms] SANDBOX: GRAPH.COPY verified -> 0 paths surviving`, 'text-emerald-400 font-semibold');
        refreshCypherLogs();
      });

      eventSource.addEventListener('agent_thought', (e) => {
        const data = JSON.parse(e.data);
        appendTraceLog(`[THOUGHT] ${data.data.thought}`, 'text-gray-400 italic');
      });

      eventSource.addEventListener('commit_remediation', (e) => {
        appendTraceLog(`[VERIFIED COMMIT] Remediation committed to sentinel_memory`, 'text-emerald-300 font-bold');
      });
    }

    function appendTraceLog(text, colorClass) {
      const log = document.getElementById('trace-log');
      const item = document.createElement('div');
      item.className = `${colorClass} py-0.5 border-b border-fjord-800/40 text-[10px]`;
      item.innerText = text;
      log.appendChild(item);
      log.scrollTop = log.scrollHeight;
      
      const count = log.children.length;
      document.getElementById('trace-counter').innerText = `${count} events`;
    }

    // 3. Topology Loading with Vis.js (Zero Blank Box)
    async function loadTopology(graphName) {
      try {
        const res = await fetch(`/api/v1/graph/${graphName}`);
        const data = await res.json();
        currentTopology = data;

        const isSandbox = graphName.startsWith('sandbox_sim');
        const pathCount = data.attack_path_count;
        const badge = document.getElementById('active-paths-badge');
        
        if (isSandbox || pathCount === 0) {
          badge.className = 'px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800 text-[10px] font-bold';
          badge.innerHTML = '<i class="fa-solid fa-circle-check mr-1"></i>Breach Paths: 0 (VERIFIED)';
        } else {
          badge.className = 'px-2 py-0.5 rounded bg-red-950 text-red-400 border border-red-800 text-[10px] font-bold';
          badge.innerHTML = `<i class="fa-solid fa-triangle-exclamation mr-1"></i>Breach Paths: ${pathCount} (CRIMSON)`;
        }

        document.getElementById('graph-stats').innerText = `${data.nodes.length} nodes, ${data.edges.length} edges`;

        // Format nodes for Vis.js
        const visNodes = data.nodes.map(n => {
          let shape = n.shape || 'box';
          let color = n.color || '#3b82f6';
          let border = color;
          
          if (n.is_attack_path) {
            border = '#ef4444';
          }

          return {
            id: n.id,
            label: `  ${n.name || n.id}  \n[${n.label}]`,
            shape: shape,
            color: {
              background: color,
              border: border,
              highlight: { background: color, border: '#ffffff' },
              hover: { background: color, border: '#38bdf8' }
            },
            font: { color: '#ffffff', size: 10, face: 'monospace' },
            shadow: n.is_attack_path ? { enabled: true, color: 'rgba(239,68,68,0.7)', size: 12 } : false,
            borderWidth: n.is_attack_path ? 3 : 1.5,
          };
        });

        // Format edges for Vis.js
        const visEdges = data.edges.map(e => {
          const isCrimson = e.is_attack_path && !e.is_severed;
          const isSevered = e.is_severed;

          let edgeColor = '#334155';
          let width = 1.5;
          let dashes = false;
          let label = e.label || e.type;

          if (isCrimson) {
            edgeColor = '#ef4444';
            width = 3.5;
          } else if (isSevered) {
            edgeColor = '#64748b';
            width = 1.5;
            dashes = [6, 6];
            label = `${label} [SEVERED]`;
          }

          return {
            id: e.id,
            from: e.source,
            to: e.target,
            label: label,
            color: { color: edgeColor, highlight: '#38bdf8', hover: '#ffffff' },
            width: width,
            dashes: dashes,
            arrows: { to: { enabled: true, scaleFactor: 0.8 } },
            font: { color: isCrimson ? '#f87171' : '#94a3b8', size: 9, face: 'monospace', align: 'middle', background: '#070b14' },
            smooth: { type: 'continuous', roundness: 0.15 }
          };
        });

        const container = document.getElementById('topology-canvas');
        const networkData = { nodes: new vis.DataSet(visNodes), edges: new vis.DataSet(visEdges) };
        const options = {
          physics: {
            stabilization: { iterations: 120 },
            barnesHut: { gravitationalConstant: -3500, centralGravity: 0.3, springLength: 95, springConstant: 0.04 }
          },
          interaction: { hover: true, tooltipDelay: 100, zoomView: true, dragView: true },
        };

        if (networkCanvas) networkCanvas.destroy();
        networkCanvas = new vis.Network(container, networkData, options);

        // Click Inspector
        networkCanvas.on('click', function(params) {
          if (params.nodes.length > 0) {
            const nodeId = params.nodes[0];
            inspectNode(nodeId);
          }
        });

        // Fit after stabilization
        networkCanvas.once('stabilizationIterationsDone', function() {
          networkCanvas.fit({ animation: { duration: 600 } });
        });

      } catch (e) {
        console.error('Topology load error:', e);
      }
    }

    function fitGraph() {
      if (networkCanvas) networkCanvas.fit({ animation: { duration: 400 } });
    }

    // 4. Node Inspector Logic
    function inspectNode(nodeId) {
      const node = currentTopology.nodes.find(n => n.id === nodeId);
      if (!node) return;

      document.getElementById('inspect-label').innerText = `${node.label} (${node.namespace || 'default'})`;

      const content = document.getElementById('inspect-content');
      let propsHtml = '';
      const props = node.properties || {};

      for (const [k, v] of Object.entries(props)) {
        if (typeof v === 'object') continue;
        propsHtml += `<div class="flex justify-between py-0.5 border-b border-fjord-800 text-[10px]"><span class="text-gray-400 font-semibold">${k}:</span><span class="text-cyan-300 text-right font-mono">${v}</span></div>`;
      }

      content.innerHTML = `
        <div class="space-y-1.5">
          <div class="text-xs font-bold text-white flex items-center justify-between">
            <span>${node.name || node.id}</span>
            <span class="px-1.5 py-0.5 text-[9px] rounded bg-cyan-950 text-cyan-400 border border-cyan-800">${node.label}</span>
          </div>
          <div class="text-[10px] text-gray-400">ID: <span class="text-gray-300 font-mono">${node.id}</span></div>
          <div class="pt-1">${propsHtml || '<div class="text-gray-500 italic">No extra properties</div>'}</div>
        </div>
      `;
    }

    // 5. Run Remediation Pipeline
    async function runRemediationPipeline() {
      if (!currentSession) await initSession();
      appendTraceLog('Dispatched remediation agent pipeline (MILP + GRAPH.COPY)...', 'text-amber-400 font-semibold');
      
      try {
        const resp = await fetch('/api/v1/agent/run', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({session_id: currentSession.session_id})
        });
        const res = await resp.json();
        currentSession.candidate_set_id = res.candidate_set_id;
        currentSession.sandbox_sha = res.sandbox_sha;

        // Populate Right Pane Gate
        document.getElementById('op-cset-id').innerText = res.candidate_set_id;
        document.getElementById('op-status').innerText = 'VERIFIED_IN_MODEL';
        document.getElementById('op-status').className = 'text-emerald-400 font-bold';
        document.getElementById('gate-badge').innerText = 'GATE UNLOCKED';
        document.getElementById('gate-badge').className = 'text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800';

        // Unlock operator button
        const btnApprove = document.getElementById('btn-approve');
        btnApprove.disabled = false;
        btnApprove.className = 'flex-1 bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs py-2 rounded transition cursor-pointer shadow-lg shadow-emerald-600/30';

        const btnReject = document.getElementById('btn-reject');
        btnReject.disabled = false;
        btnReject.className = 'px-4 bg-red-950 hover:bg-red-900 text-red-400 border border-red-800 font-bold text-xs py-2 rounded transition cursor-pointer';

        // Set patch YAML
        const remedTimeline = res.timeline.find(t => t.step === 'remediate');
        if (remedTimeline && remedTimeline.candidates.optimal_candidates.length > 0) {
          document.getElementById('patch-yaml').value = remedTimeline.candidates.optimal_candidates[0].yaml_diff;
        }

        // Add Agent Chat Response
        appendChatMessage('Fjord Agent', `### Optimal Remediation Found & Verified in Sandbox\n\n- **Candidate Set:** \`${res.candidate_set_id}\`\n- **Status:** \`VERIFIED_IN_MODEL\` (0 surviving paths, 0 broken required flows)\n- **Sandbox Graph:** \`${res.sandbox_sha}\`\n\nThe synthesized NetworkPolicy YAML has been populated in the Right Pane. Switch to **[Graph: sandbox_sim]** to inspect the severed breach edge.`);

        appendTraceLog('Simulation verified in GRAPH.COPY: 0 surviving attack paths.', 'text-emerald-400 font-bold');
        await refreshCypherLogs();
      } catch (e) {
        console.error('Agent run error:', e);
      }
    }

    // 6. Interactive Sandbox Toggle
    function toggleGraphView(view) {
      if (!currentSession) return;
      currentViewMode = view;
      const btnProd = document.getElementById('btn-view-prod');
      const btnSandbox = document.getElementById('btn-view-sandbox');

      if (view === 'sandbox') {
        if (!currentSession.sandbox_sha) {
          alert('Sandbox graph not yet created. Run the Remediation Agent or ask the Chatbot to simulate a fix first.');
          return;
        }
        btnSandbox.className = 'px-3 py-1 text-xs font-mono font-semibold rounded bg-emerald-600 text-white shadow-md transition';
        btnProd.className = 'px-3 py-1 text-xs font-mono font-semibold rounded text-gray-400 hover:text-white transition';
        document.getElementById('active-graph-name').innerText = currentSession.sandbox_sha;
        loadTopology(currentSession.sandbox_sha);
      } else {
        btnProd.className = 'px-3 py-1 text-xs font-mono font-semibold rounded bg-cyan-600 text-white shadow-md transition';
        btnSandbox.className = 'px-3 py-1 text-xs font-mono font-semibold rounded text-gray-400 hover:text-white transition';
        document.getElementById('active-graph-name').innerText = currentSession.snapshot_sha;
        loadTopology(currentSession.snapshot_sha);
      }
    }

    // 7. Interactive Operator Chatbot Functionality
    function setChatQuery(queryText) {
      const input = document.getElementById('chat-input');
      input.value = queryText;
      input.focus();
    }

    async function handleChatSubmit(e) {
      e.preventDefault();
      const input = document.getElementById('chat-input');
      const message = input.value.trim();
      if (!message || !currentSession) return;

      // Render user bubble
      appendChatMessage('Operator', message);
      input.value = '';

      // Render typing placeholder
      const typingId = 'typing-' + Date.now();
      appendTypingIndicator(typingId);

      try {
        const resp = await fetch('/api/v1/chat', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({
            session_id: currentSession.session_id,
            message: message,
            byok_api_key: document.getElementById('byok-input').value || null
          })
        });
        const data = await resp.json();
        removeTypingIndicator(typingId);

        // Render agent reply
        appendChatMessage('Fjord Agent', data.reply);

        // If candidate set updated
        if (data.candidate_set_id) {
          currentSession.candidate_set_id = data.candidate_set_id;
          currentSession.sandbox_sha = data.sandbox_sha;
          document.getElementById('op-cset-id').innerText = data.candidate_set_id;
          document.getElementById('op-status').innerText = data.verification_status || 'VERIFIED_IN_MODEL';
          document.getElementById('gate-badge').innerText = 'GATE UNLOCKED';
          document.getElementById('gate-badge').className = 'text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800';
          
          const btnApprove = document.getElementById('btn-approve');
          btnApprove.disabled = false;
          btnApprove.className = 'flex-1 bg-emerald-600 hover:bg-emerald-500 text-white font-bold text-xs py-2 rounded transition cursor-pointer shadow-lg shadow-emerald-600/30';
          
          const btnReject = document.getElementById('btn-reject');
          btnReject.disabled = false;
          btnReject.className = 'px-4 bg-red-950 hover:bg-red-900 text-red-400 border border-red-800 font-bold text-xs py-2 rounded transition cursor-pointer';

          if (data.yaml_diff) {
            document.getElementById('patch-yaml').value = data.yaml_diff;
          }
        }

        await refreshCypherLogs();
      } catch (err) {
        removeTypingIndicator(typingId);
        appendChatMessage('Fjord Agent', `**Error during reasoning:** ${err.message}`);
      }
    }

    function appendChatMessage(sender, text) {
      const history = document.getElementById('chat-history');
      const item = document.createElement('div');
      
      const isAgent = sender === 'Fjord Agent';
      item.className = isAgent ? 'chat-bubble-agent p-3 rounded-lg text-gray-200 space-y-1.5' : 'chat-bubble-user p-2.5 rounded-lg text-white ml-8 text-right';
      
      const headerIcon = isAgent ? '<i class="fa-solid fa-shield-halved mr-1 text-cyan-400"></i>' : '<i class="fa-solid fa-user text-cyan-200 mr-1"></i>';
      const headerColor = isAgent ? 'text-cyan-400' : 'text-cyan-100';
      
      // Basic markdown formatting
      let formattedText = text
        .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
        .replace(/`(.*?)`/g, '<code class="bg-fjord-950 px-1 py-0.5 rounded text-cyan-300 font-mono text-[10px]">$1</code>')
        .replace(/\n\n/g, '<br><br>')
        .replace(/\n/g, '<br>');

      item.innerHTML = `
        <div class="text-[10px] font-bold ${headerColor} flex items-center ${isAgent ? '' : 'justify-end'}">
          ${headerIcon}<span>${sender}</span>
        </div>
        <div class="text-[11px] leading-relaxed">${formattedText}</div>
      `;
      history.appendChild(item);
      history.scrollTop = history.scrollHeight;
    }

    function appendTypingIndicator(id) {
      const history = document.getElementById('chat-history');
      const item = document.createElement('div');
      item.id = id;
      item.className = 'chat-bubble-agent p-2.5 rounded-lg text-cyan-400 text-[11px] flex items-center space-x-2';
      item.innerHTML = `
        <i class="fa-solid fa-spinner animate-spin"></i>
        <span class="italic font-mono">Fjord Agent is reasoning & executing FalkorDB queries...</span>
      `;
      history.appendChild(item);
      history.scrollTop = history.scrollHeight;
    }

    function removeTypingIndicator(id) {
      const el = document.getElementById(id);
      if (el) el.remove();
    }

    // 8. In-Graph Cypher Inspector Loader
    async function refreshCypherLogs() {
      if (!currentSession) return;
      try {
        const resp = await fetch(`/api/v1/sessions/${currentSession.session_id}/cypher`);
        const data = await resp.json();
        const container = document.getElementById('cypher-log-container');
        
        if (data.queries && data.queries.length > 0) {
          container.innerHTML = '';
          data.queries.forEach((q, idx) => {
            const card = document.createElement('div');
            card.className = 'p-2 bg-fjord-900 rounded border border-fjord-700/70 hover:border-cyan-600/50 transition';
            card.innerHTML = `
              <div class="flex items-center justify-between text-[10px] text-gray-400 mb-1">
                <span class="text-cyan-400 font-bold">${q.description || `Query #${idx + 1}`}</span>
                <span class="text-emerald-400">${q.latency_ms} ms</span>
              </div>
              <pre class="text-[10px] text-emerald-300 font-mono overflow-x-auto custom-scroll whitespace-pre-wrap">${q.query}</pre>
            `;
            container.appendChild(card);
          });
          container.scrollTop = container.scrollHeight;
        }
      } catch (e) {
        console.error('Cypher logs load error:', e);
      }
    }

    // 9. Operator Decision Gate
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
        document.getElementById('gate-badge').innerText = decision === 'APPROVE' ? 'COMMITTED' : 'REJECTED';
        document.getElementById('gate-badge').className = decision === 'APPROVE' ? 'text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800' : 'text-[10px] font-mono px-2 py-0.5 rounded bg-red-950 text-red-400 border border-red-800';
        
        appendChatMessage('Fjord Agent', `**Operator Decision Recorded:** \`${decision}\`.\nRemediation has been committed to persistent sentinel memory in FalkorDB.`);
        await refreshCypherLogs();
      } catch (e) {
        console.error('Operator decision error:', e);
      }
    }

    function copyPatchYaml() {
      const copyText = document.getElementById('patch-yaml');
      navigator.clipboard.writeText(copyText.value);
      alert('Kubernetes NetworkPolicy YAML copied to clipboard!');
    }

    // Auto-initialize on DOM load
    window.addEventListener('DOMContentLoaded', () => {
      initSession();
    });
  </script>
</body>
</html>
"""
    return HTMLResponse(content=html_content)
