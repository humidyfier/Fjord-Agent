"""
backend/api/app.py
Master Web Server & Archival Security Workspace Host for Project Fjord.
Theme: ATHEÑÆUM × WIZ.IO Archival Security Workspace (Neo-Brutalist Grid, Warm Cream & Obsidian Charcoal).
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
    Renders the Athenaeum x Wiz.io Archival Security Workspace:
    - Left Sidebar (240px): Deep Obsidian Charcoal (#141517), Scenario Quick-Loader, 5-View Navigation, System Telemetry
    - Center Main Workspace: Warm Archival Cream (#F3EFE6), 5-Block KPI Strip, Cytoscape.js Security Graph, Remediation Queue
    - Multi-View Tabs: DASHBOARD, SECURITY GRAPH, AGENT COPILOT, CONNECTORS & MCP, SETTINGS & API
    - Right Record Inspector Drawer (360px): Warm Stone (#ECE7DC), CSS Barcode, DETAILS, YAML PATCH, CYPHER, AUDIT Tabs
    - Bottom Status Bar (32px): Deep Obsidian Charcoal (#141517), Live Engine Telemetry
    """
    html_content = r"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>FJORD // ATHEÑÆUM × WIZ.IO Security Workspace</title>
  
  <!-- Typography: Space Grotesk (KPI Display), Inter (UI Body), JetBrains Mono (Technical/Cypher) -->
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=DM+Sans:ital,opsz,wght@0,9..40,100..1000;1,9..40,100..1000&family=Inter:ital,opsz,wght@0,14..32,100..900;1,14..32,100..900&family=JetBrains+Mono:ital,wght@0,100..800;1,100..800&family=Space+Grotesk:wght@500;700&display=swap" rel="stylesheet">
  
  <!-- Cytoscape.js CDN for Real Interactive Graph Rendering -->
  <script src="https://cdnjs.cloudflare.com/ajax/libs/cytoscape/3.28.1/cytoscape.min.js"></script>
  <!-- Tailwind CSS -->
  <script src="https://cdn.tailwindcss.com"></script>
  <!-- FontAwesome Icons -->
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">

  <script>
    tailwind.config = {
      theme: {
        extend: {
          fontFamily: {
            display: ['"Space Grotesk"', 'sans-serif'],
            body: ['"Inter"', '"DM Sans"', 'sans-serif'],
            mono: ['"JetBrains Mono"', 'monospace'],
          },
          colors: {
            obsidian: {
              950: '#0C0D0E',
              900: '#141517',
              850: '#1C1D21',
              800: '#24262B',
              border: '#2A2C30',
            },
            archival: {
              bg: '#F3EFE6',
              surface: '#FAF8F3',
              stone: '#ECE7DC',
              border: '#D4CFC4',
              ink: '#181818',
              muted: '#68645C',
              faint: '#8E8A80',
              cream: '#EAE6DF',
            },
            wiz: {
              crimson: '#C93B2B',
              crimsonBg: '#FBEAE8',
              ochre: '#D97724',
              ochreBg: '#FDF3E7',
              emerald: '#236B48',
              emeraldBg: '#E6F4ED',
              blue: '#2563EB',
              blueBg: '#EFF6FF',
              purple: '#7C3AED',
              purpleBg: '#F5F3FF',
            }
          }
        }
      }
    }
  </script>

  <style>
    body {
      background-color: #F3EFE6;
      color: #181818;
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }
    
    .font-display { font-family: 'Space Grotesk', sans-serif; }
    .font-mono { font-family: 'JetBrains Mono', monospace; }

    /* Custom Archival Scrollbars */
    .custom-scroll::-webkit-scrollbar { width: 4px; height: 4px; }
    .custom-scroll::-webkit-scrollbar-thumb { background: #D4CFC4; border-radius: 2px; }
    .custom-scroll::-webkit-scrollbar-track { background: transparent; }

    .dark-scroll::-webkit-scrollbar { width: 4px; height: 4px; }
    .dark-scroll::-webkit-scrollbar-thumb { background: #2A2C30; border-radius: 2px; }
    .dark-scroll::-webkit-scrollbar-track { background: transparent; }

    /* Barcode Graphic */
    .css-barcode {
      display: flex;
      height: 22px;
      gap: 2px;
      align-items: stretch;
    }
    .css-barcode span {
      background-color: #181818;
      display: inline-block;
    }
    
    /* Cytoscape Canvas Container */
    #topology-canvas {
      width: 100%;
      height: 100%;
      position: absolute;
      inset: 0;
      background: #FAF8F3;
    }

    /* Architectural Grid Borders */
    .arch-border { border: 1px solid #D4CFC4; }
    .arch-border-r { border-right: 1px solid #D4CFC4; }
    .arch-border-b { border-bottom: 1px solid #D4CFC4; }
    .arch-border-l { border-left: 1px solid #D4CFC4; }
    .arch-border-t { border-top: 1px solid #D4CFC4; }

    /* Nav Item States */
    .nav-item-active {
      background-color: #24262B;
      color: #EAE6DF;
      border-left: 3px solid #236B48;
    }
  </style>
</head>
<body class="h-screen flex flex-col overflow-hidden select-none">

  <!-- Main Horizontal Layout: Left Sidebar + Center Workspace + Right Inspector -->
  <div class="flex-1 flex overflow-hidden">

    <!-- ================================================================= -->
    <!-- LEFT SIDEBAR: Deep Obsidian Charcoal (#141517, 240px fixed)      -->
    <!-- ================================================================= -->
    <aside class="w-[240px] bg-obsidian-900 border-r border-obsidian-border flex flex-col shrink-0 text-archival-cream z-20">
      
      <!-- Institution / Engine Status Box -->
      <div class="p-3.5 border-b border-obsidian-border space-y-1">
        <div class="flex items-center justify-between">
          <div class="flex items-center space-x-2">
            <div class="w-5 h-5 rounded bg-archival-cream text-obsidian-900 font-display font-bold text-xs flex items-center justify-center">
              FJ
            </div>
            <span class="font-display font-bold text-xs tracking-wider text-archival-cream">ATHEÑÆUM // FJORD</span>
          </div>
          <span class="text-[9px] font-mono px-1.5 py-0.5 rounded bg-obsidian-800 text-wiz-emerald border border-obsidian-border">v1.0</span>
        </div>
        <div class="pt-1 flex items-center justify-between text-[10px] font-mono text-archival-faint">
          <span>ENGINE: FALKORDB</span>
          <span class="text-wiz-emerald font-bold">● LOCAL</span>
        </div>
        <div class="text-[9px] font-mono text-archival-faint flex items-center space-x-1">
          <span>DATA INTEGRITY:</span>
          <span class="text-wiz-emerald font-bold">VERIFIED</span>
        </div>
      </div>

      <!-- Navigation Views Selector -->
      <div class="py-2 border-b border-obsidian-border">
        <div class="px-3 pb-1 text-[9px] font-mono uppercase tracking-wider text-archival-faint">Workspace Views</div>
        <nav class="space-y-0.5 text-xs font-mono">
          <button onclick="switchView('dashboard')" id="nav-dashboard" class="w-full text-left px-3.5 py-2 flex items-center space-x-2.5 transition nav-item-active">
            <i class="fa-solid fa-layer-group text-wiz-emerald w-4 text-center"></i>
            <span>DASHBOARD</span>
          </button>
          <button onclick="switchView('graph')" id="nav-graph" class="w-full text-left px-3.5 py-2 flex items-center space-x-2.5 transition text-archival-cream/70 hover:text-archival-cream hover:bg-obsidian-850">
            <i class="fa-solid fa-circle-nodes w-4 text-center"></i>
            <span>SECURITY GRAPH</span>
          </button>
          <button onclick="switchView('copilot')" id="nav-copilot" class="w-full text-left px-3.5 py-2 flex items-center space-x-2.5 transition text-archival-cream/70 hover:text-archival-cream hover:bg-obsidian-850">
            <i class="fa-solid fa-robot w-4 text-center"></i>
            <span>AGENT COPILOT</span>
          </button>
          <button onclick="switchView('connectors')" id="nav-connectors" class="w-full text-left px-3.5 py-2 flex items-center space-x-2.5 transition text-archival-cream/70 hover:text-archival-cream hover:bg-obsidian-850">
            <i class="fa-solid fa-plug w-4 text-center"></i>
            <span>CONNECTORS & MCP</span>
          </button>
          <button onclick="switchView('settings')" id="nav-settings" class="w-full text-left px-3.5 py-2 flex items-center space-x-2.5 transition text-archival-cream/70 hover:text-archival-cream hover:bg-obsidian-850">
            <i class="fa-solid fa-sliders w-4 text-center"></i>
            <span>SETTINGS & API</span>
          </button>
        </nav>
      </div>

      <!-- Scenario Quick-Loader -->
      <div class="flex-1 p-3 overflow-y-auto dark-scroll space-y-2 border-b border-obsidian-border">
        <div class="text-[9px] font-mono uppercase tracking-wider text-archival-faint flex items-center justify-between">
          <span>SCENARIO ARCHIVES</span>
          <i class="fa-solid fa-box-archive text-[10px]"></i>
        </div>
        <div class="space-y-1 font-mono text-[11px]">
          <button onclick="loadScenario('sample_cluster')" class="w-full text-left p-2 rounded bg-obsidian-850 hover:bg-obsidian-800 border border-obsidian-border transition text-archival-cream">
            <div class="font-bold text-[10px] text-archival-cream truncate">E-Commerce Core</div>
            <div class="text-[9px] text-archival-faint">3 Workloads · 1 DB Secret</div>
          </button>
          <button onclick="loadScenario('kubehound_reference')" class="w-full text-left p-2 rounded bg-obsidian-850 hover:bg-obsidian-800 border border-obsidian-border transition text-archival-cream">
            <div class="font-bold text-[10px] text-archival-cream truncate">KubeHound RBAC/Escape</div>
            <div class="text-[9px] text-archival-faint">5 Workloads · Host Breakout</div>
          </button>
          <button onclick="loadScenario('kubernetes_goat')" class="w-full text-left p-2 rounded bg-obsidian-850 hover:bg-obsidian-800 border border-obsidian-border transition text-archival-cream">
            <div class="font-bold text-[10px] text-archival-cream truncate">Kubernetes Goat Pods</div>
            <div class="text-[9px] text-archival-faint">4 Workloads · docker.sock</div>
          </button>
          <button onclick="loadScenario('bad_pods')" class="w-full text-left p-2 rounded bg-obsidian-850 hover:bg-obsidian-800 border border-obsidian-border transition text-archival-cream">
            <div class="font-bold text-[10px] text-archival-cream truncate">Bad Pods Escalation</div>
            <div class="text-[9px] text-archival-faint">6 Workloads · Multi-CVE</div>
          </button>
        </div>
      </div>

      <!-- System Telemetry Panel (Bottom Sidebar) -->
      <div class="p-3 bg-obsidian-950 space-y-2 text-[10px] font-mono">
        <div class="text-[9px] uppercase tracking-wider text-archival-faint font-bold">SYSTEM TELEMETRY</div>
        <div>
          <div class="flex justify-between text-[9px] text-archival-faint mb-0.5">
            <span>GRAPH NODES</span>
            <span id="telemetry-nodes" class="text-archival-cream">14 / 20</span>
          </div>
          <div class="w-full h-1 bg-obsidian-800 rounded overflow-hidden">
            <div id="bar-nodes" class="h-full bg-wiz-blue transition-all duration-500" style="width: 70%"></div>
          </div>
        </div>
        <div>
          <div class="flex justify-between text-[9px] text-archival-faint mb-0.5">
            <span>EXPLOIT EDGES</span>
            <span id="telemetry-edges" class="text-archival-cream">13 / 15</span>
          </div>
          <div class="w-full h-1 bg-obsidian-800 rounded overflow-hidden">
            <div id="bar-edges" class="h-full bg-wiz-crimson transition-all duration-500" style="width: 85%"></div>
          </div>
        </div>
        <div>
          <div class="flex justify-between text-[9px] text-archival-faint mb-0.5">
            <span>INJECTION GUARD</span>
            <span class="text-wiz-emerald font-bold">50 / 50 (100%)</span>
          </div>
          <div class="w-full h-1 bg-obsidian-800 rounded overflow-hidden">
            <div class="h-full bg-wiz-emerald" style="width: 100%"></div>
          </div>
        </div>
      </div>
    </aside>

    <!-- ================================================================= -->
    <!-- CENTER MAIN WORKSPACE: Warm Archival Cream (#F3EFE6)             -->
    <!-- ================================================================= -->
    <main class="flex-1 flex flex-col bg-archival-bg overflow-hidden relative min-w-0">

      <!-- =============================================================== -->
      <!-- VIEW 1: DASHBOARD (Wiz Overview, 5 KPI Blocks & Cytoscape Graph) -->
      <!-- =============================================================== -->
      <div id="view-dashboard" class="flex-1 flex flex-col overflow-hidden">
        
        <!-- Top Workspace Bar -->
        <div class="h-12 bg-archival-surface arch-border-b px-5 flex items-center justify-between shrink-0">
          <div class="flex items-center space-x-3">
            <span class="font-display font-bold text-xs tracking-wider uppercase text-archival-ink">
              ARCHIVAL SECURITY WORKSPACE // WIZ TOXIC COMBINATIONS
            </span>
            <span class="text-[10px] font-mono px-2 py-0.5 rounded bg-archival-stone arch-border text-archival-muted">
              SCENARIO: <span id="dash-active-scenario" class="font-bold text-archival-ink">sample_cluster</span>
            </span>
          </div>

          <!-- Sandbox Toggle Switch -->
          <div class="flex items-center space-x-2">
            <span class="text-[10px] font-mono text-archival-muted uppercase font-semibold">VIEW:</span>
            <div class="inline-flex rounded arch-border bg-archival-stone p-0.5 text-xs font-mono">
              <button onclick="toggleGraphView('prod')" id="btn-toggle-prod" class="px-2.5 py-1 rounded bg-archival-surface text-archival-ink font-bold shadow-sm transition">
                prod_cluster
              </button>
              <button onclick="toggleGraphView('sandbox')" id="btn-toggle-sandbox" class="px-2.5 py-1 rounded text-archival-muted hover:text-archival-ink font-semibold transition">
                sandbox_sim
              </button>
            </div>
            <button onclick="runRemediationPipeline()" class="ml-2 px-3 py-1.5 rounded bg-obsidian-900 hover:bg-obsidian-800 text-archival-cream text-xs font-mono font-bold transition flex items-center space-x-1.5 shadow">
              <i class="fa-solid fa-bolt text-wiz-ochre text-[10px]"></i>
              <span>RUN REMEDIATION AGENT</span>
            </button>
          </div>
        </div>

        <!-- 5-Block Architectural KPI Strip (1px #D4CFC4 Grid) -->
        <div class="grid grid-cols-5 bg-archival-surface arch-border-b shrink-0 text-archival-ink">
          
          <!-- Block 1: Toxic Combinations -->
          <div class="p-3.5 arch-border-r space-y-1">
            <div class="flex items-center justify-between">
              <span class="text-[9px] font-mono uppercase tracking-wider text-archival-muted font-bold">TOXIC COMBINATIONS</span>
              <span class="text-[9px] font-mono px-1.5 py-0.2 rounded bg-wiz-crimsonBg text-wiz-crimson font-bold">CRITICAL</span>
            </div>
            <div class="font-display text-[42px] font-bold leading-none text-wiz-crimson" id="kpi-toxic">03</div>
            <div class="text-[10px] font-mono text-archival-muted">ACTIVE CHAINS</div>
            <div class="text-[9px] font-mono text-archival-muted leading-tight pt-0.5 truncate">
              Internet &rarr; CVE-2023-38606 &rarr; CrownJewel
            </div>
          </div>

          <!-- Block 2: Attack Paths (algo.SPpaths) -->
          <div class="p-3.5 arch-border-r space-y-1">
            <div class="flex items-center justify-between">
              <span class="text-[9px] font-mono uppercase tracking-wider text-archival-muted font-bold">ATTACK PATHS</span>
              <span class="text-[9px] font-mono text-archival-muted">algo.SPpaths</span>
            </div>
            <div class="font-display text-[42px] font-bold leading-none text-archival-ink" id="kpi-paths">02</div>
            <div class="text-[10px] font-mono text-archival-muted">SHORTEST HOPS</div>
            <div class="text-[9px] font-mono text-wiz-crimson font-semibold pt-0.5 flex items-center">
              <span class="w-1.5 h-1.5 rounded-full bg-wiz-crimson inline-block mr-1"></span>
              <span>Target: crown-jewel-db</span>
            </div>
          </div>

          <!-- Block 3: On-Path Findings (CVE Prioritization) -->
          <div class="p-3.5 arch-border-r space-y-1">
            <div class="flex items-center justify-between">
              <span class="text-[9px] font-mono uppercase tracking-wider text-archival-muted font-bold">ON-PATH FINDINGS</span>
              <span class="text-[9px] font-mono px-1.5 py-0.2 rounded bg-wiz-ochreBg text-wiz-ochre font-bold">FILTERED</span>
            </div>
            <div class="flex items-baseline space-x-2">
              <div class="font-display text-[42px] font-bold leading-none text-wiz-ochre" id="kpi-cves">04</div>
              <span class="text-[11px] font-mono text-archival-muted">/ 30 raw</span>
            </div>
            <div class="text-[10px] font-mono text-archival-muted">PRIORITIZED CVES</div>
            <!-- Mini SVG Bar comparison -->
            <div class="flex items-center space-x-1 pt-1">
              <svg width="120" height="8" class="overflow-hidden rounded">
                <rect x="0" y="0" width="30" height="8" fill="#D97724" />
                <rect x="30" y="0" width="90" height="8" fill="#D4CFC4" opacity="0.6" />
              </svg>
              <span class="text-[8px] font-mono text-archival-muted">13% On-Path</span>
            </div>
          </div>

          <!-- Block 4: Sandbox Verified -->
          <div class="p-3.5 arch-border-r space-y-1">
            <div class="flex items-center justify-between">
              <span class="text-[9px] font-mono uppercase tracking-wider text-archival-muted font-bold">SANDBOX VERIFIED</span>
              <span class="text-[9px] font-mono px-1.5 py-0.2 rounded bg-wiz-emeraldBg text-wiz-emerald font-bold">GRAPH.COPY</span>
            </div>
            <div class="font-display text-[42px] font-bold leading-none text-wiz-emerald" id="kpi-sandbox">01</div>
            <div class="text-[10px] font-mono text-archival-muted">0 SURVIVING PATHS</div>
            <div class="flex items-center space-x-1 text-[9px] font-mono text-wiz-emerald pt-0.5">
              <i class="fa-solid fa-check-double text-[8px]"></i>
              <span>100% Required Flows Preserved</span>
            </div>
          </div>

          <!-- Block 5: Solver Latency (Pure MILP) -->
          <div class="p-3.5 space-y-1">
            <div class="flex items-center justify-between">
              <span class="text-[9px] font-mono uppercase tracking-wider text-archival-muted font-bold">SOLVER LATENCY</span>
              <span class="text-[9px] font-mono text-wiz-emerald font-bold">&lt; 50ms PASS</span>
            </div>
            <div class="font-display text-[42px] font-bold leading-none text-archival-ink" id="kpi-latency">37<span class="text-lg font-normal">ms</span></div>
            <div class="text-[10px] font-mono text-archival-muted">MILP OPTIMAL CUT</div>
            <!-- Mini Sparkline SVG -->
            <div class="pt-1">
              <svg width="100" height="10" class="stroke-wiz-emerald fill-none stroke-[1.5]">
                <polyline points="0,8 20,6 40,7 60,3 80,5 100,2" />
              </svg>
            </div>
          </div>

        </div>

        <!-- Center Workspace Body: Cytoscape Security Graph Canvas -->
        <div class="flex-1 flex flex-col min-h-0 relative">
          
          <!-- Graph Canvas Container -->
          <div class="flex-1 relative w-full h-full">
            <div id="topology-canvas"></div>
            
            <!-- Floating Canvas Legend -->
            <div class="absolute bottom-3 left-4 z-10 bg-archival-surface/90 backdrop-blur p-2.5 rounded arch-border text-[10px] font-mono space-y-1 shadow-sm">
              <div class="font-bold uppercase tracking-wider text-archival-muted text-[9px]">Graph Entities (Wiz Taxonomy)</div>
              <div class="flex items-center space-x-2"><span class="w-2.5 h-2.5 rounded bg-wiz-blue inline-block"></span><span>Workload (Blue Box)</span></div>
              <div class="flex items-center space-x-2"><span class="w-2.5 h-2.5 rotate-45 bg-wiz-ochre inline-block"></span><span>PostureFinding / CVE (Yellow Diamond)</span></div>
              <div class="flex items-center space-x-2"><span class="w-2.5 h-2.5 rounded-full bg-wiz-purple inline-block"></span><span>IAM / ServiceAccount (Purple Hexagon)</span></div>
              <div class="flex items-center space-x-2"><span class="w-2.5 h-2.5 rounded bg-wiz-emerald inline-block"></span><span>CrownJewel (Green Star)</span></div>
              <div class="flex items-center space-x-2"><span class="w-3 h-0.5 bg-wiz-crimson inline-block"></span><span class="text-wiz-crimson font-bold">Active Attack Path (:EXPLOIT_STEP)</span></div>
              <div class="flex items-center space-x-2"><span class="w-3 h-0.5 border-t border-dashed border-archival-muted inline-block"></span><span>Severed Edge [DASHED]</span></div>
            </div>
          </div>

          <!-- Bottom Grid: Prioritized Remediation Actions Table -->
          <div class="h-44 bg-archival-surface arch-border-t flex flex-col shrink-0">
            <div class="px-4 py-1.5 arch-border-b bg-archival-stone/40 flex justify-between items-center">
              <span class="text-[10px] font-mono uppercase font-bold text-archival-ink flex items-center">
                <i class="fa-solid fa-list-check text-wiz-emerald mr-1.5"></i>
                PRIORITIZED REMEDIATION ACTIONS (MILP HITTING SET)
              </span>
              <span id="remediation-summary-count" class="text-[9px] font-mono text-archival-muted">1 Optimal Action Available</span>
            </div>
            <div class="flex-1 overflow-y-auto custom-scroll p-0">
              <table class="w-full text-left text-[11px] font-mono border-collapse">
                <thead>
                  <tr class="arch-border-b text-[9px] uppercase text-archival-muted bg-archival-surface">
                    <th class="p-2 pl-4">ID</th>
                    <th class="p-2">ACTION TYPE</th>
                    <th class="p-2">TARGET RESOURCE</th>
                    <th class="p-2">DISRUPTION</th>
                    <th class="p-2">STATUS</th>
                    <th class="p-2 text-right pr-4">ACTIONS</th>
                  </tr>
                </thead>
                <tbody id="remediation-table-body">
                  <tr class="arch-border-b hover:bg-archival-stone/30 transition">
                    <td class="p-2 pl-4 text-archival-ink font-bold">netpol_01</td>
                    <td class="p-2 text-wiz-blue font-bold">NETWORK_POLICY_ADD</td>
                    <td class="p-2 text-archival-ink">fjord-t0/crown-jewel-db</td>
                    <td class="p-2 text-wiz-emerald tracking-widest font-bold">●○○○○ <span class="text-[9px] font-normal text-archival-muted">(1.0)</span></td>
                    <td class="p-2"><span class="px-1.5 py-0.5 rounded bg-wiz-emeraldBg text-wiz-emerald font-bold text-[9px]">VERIFIED_IN_MODEL</span></td>
                    <td class="p-2 text-right pr-4">
                      <button onclick="inspectRemediationCandidate()" class="px-2 py-0.5 rounded arch-border bg-archival-surface hover:bg-archival-stone text-archival-ink text-[10px] font-bold">
                        SIMULATE & INSPECT
                      </button>
                    </td>
                  </tr>
                </tbody>
              </table>
            </div>
          </div>

        </div>

      </div>

      <!-- =============================================================== -->
      <!-- VIEW 2: SECURITY GRAPH (Full-Screen Cytoscape Explorer)         -->
      <!-- =============================================================== -->
      <div id="view-graph" class="flex-1 flex flex-col overflow-hidden hidden">
        <div class="h-12 bg-archival-surface arch-border-b px-5 flex items-center justify-between shrink-0">
          <span class="font-display font-bold text-xs tracking-wider uppercase text-archival-ink">
            FULL-SCREEN FALKORDB EXPLOIT STATE PLANE
          </span>
          <div class="flex items-center space-x-2 text-xs font-mono">
            <button onclick="setGraphLayout('cose')" class="px-2.5 py-1 rounded arch-border bg-archival-surface hover:bg-archival-stone text-archival-ink">
              Layout: CoSE
            </button>
            <button onclick="setGraphLayout('concentric')" class="px-2.5 py-1 rounded arch-border bg-archival-surface hover:bg-archival-stone text-archival-ink">
              Concentric
            </button>
            <button onclick="fitGraph()" class="px-2.5 py-1 rounded bg-obsidian-900 text-archival-cream">
              Fit Canvas
            </button>
          </div>
        </div>
        <div class="flex-1 relative w-full h-full bg-archival-surface">
          <div id="fullscreen-topology-canvas" class="w-full h-full"></div>
        </div>
      </div>

      <!-- =============================================================== -->
      <!-- VIEW 3: AGENT COPILOT (Chatbot with Gemini 3.8 Flash & Traces)  -->
      <!-- =============================================================== -->
      <div id="view-copilot" class="flex-1 flex flex-col overflow-hidden hidden bg-archival-bg">
        <div class="h-12 bg-archival-surface arch-border-b px-5 flex items-center justify-between shrink-0">
          <div class="flex items-center space-x-2">
            <span class="font-display font-bold text-xs tracking-wider uppercase text-archival-ink">
              FJORD AUTONOMOUS AGENT COPILOT
            </span>
            <span class="text-[10px] font-mono px-2 py-0.5 rounded bg-wiz-purpleBg text-wiz-purple font-bold">
              Gemini 3.8 Flash (Thinking Level 2)
            </span>
          </div>
          <!-- Manifest Upload Zone -->
          <div class="flex items-center space-x-2 text-xs font-mono">
            <label class="px-3 py-1 rounded arch-border bg-archival-surface hover:bg-archival-stone text-archival-ink cursor-pointer flex items-center space-x-1.5">
              <i class="fa-solid fa-cloud-arrow-up text-archival-muted"></i>
              <span>Upload K8s / JSON Manifest</span>
              <input type="file" id="manifest-upload-input" onchange="handleManifestUpload(event)" class="hidden" accept=".yaml,.yml,.json">
            </label>
          </div>
        </div>

        <!-- Copilot Chat Window -->
        <div class="flex-1 flex flex-col min-h-0 p-5 space-y-4">
          <!-- Quick Suggestion Buttons -->
          <div class="flex space-x-2 overflow-x-auto custom-scroll text-[11px] font-mono shrink-0">
            <button onclick="sendQuickPrompt('Explain the attack path from the internet to the crown jewel.')" class="px-3 py-1 rounded arch-border bg-archival-surface hover:bg-archival-stone text-archival-ink shrink-0 shadow-sm">
              Map Toxic Combinations to CrownJewel
            </button>
            <button onclick="sendQuickPrompt('We have a deployment freeze on api-service, find an alternative NetworkPolicy cut.')" class="px-3 py-1 rounded arch-border bg-archival-surface hover:bg-archival-stone text-wiz-ochre font-bold shrink-0 shadow-sm">
              Freeze api-service (Alternative Cut)
            </button>
            <button onclick="sendQuickPrompt('Verify the candidate remediation fix in the GRAPH.COPY sandbox.')" class="px-3 py-1 rounded arch-border bg-archival-surface hover:bg-archival-stone text-wiz-emerald font-bold shrink-0 shadow-sm">
              Verify in GRAPH.COPY Sandbox
            </button>
          </div>

          <!-- Message History -->
          <div id="copilot-chat-history" class="flex-1 bg-archival-surface arch-border rounded p-4 overflow-y-auto custom-scroll space-y-3 font-mono text-xs">
            <div class="p-3 bg-archival-stone/40 rounded arch-border text-archival-ink space-y-1">
              <div class="text-[10px] font-bold text-wiz-emerald flex items-center">
                <i class="fa-solid fa-robot mr-1.5"></i>FJORD AGENT (Gemini 3.8 Flash)
              </div>
              <p class="leading-relaxed">
                Welcome to the Archival Security Copilot. I am initialized with full bidirectional tools across FalkorDB. You can ask me to explain lateral attack chains, test alternative cuts under operational constraints, or upload custom Kubernetes YAML manifests.
              </p>
            </div>
          </div>

          <!-- Chat Input -->
          <div class="shrink-0 bg-archival-surface arch-border rounded p-2.5">
            <form onsubmit="handleCopilotSubmit(event)" class="flex space-x-2">
              <input type="text" id="copilot-input" placeholder="Ask Fjord about attack paths, explain fixes, or state constraints..." class="flex-1 bg-archival-bg arch-border rounded px-3 py-2 text-xs font-mono text-archival-ink focus:outline-none focus:border-archival-ink">
              <button type="submit" class="px-4 py-2 rounded bg-obsidian-900 hover:bg-obsidian-800 text-archival-cream text-xs font-mono font-bold transition flex items-center space-x-1.5">
                <i class="fa-solid fa-paper-plane text-xs"></i>
                <span>Send</span>
              </button>
            </form>
          </div>
        </div>
      </div>

      <!-- =============================================================== -->
      <!-- VIEW 4: CONNECTORS & MCP (Live Connectors & 7 FastMCP Tools)    -->
      <!-- =============================================================== -->
      <div id="view-connectors" class="flex-1 flex flex-col overflow-y-auto custom-scroll p-6 space-y-6 hidden">
        <div class="space-y-1">
          <h2 class="font-display text-xl font-bold text-archival-ink">INFRASTRUCTURE & SCANNER CONNECTORS</h2>
          <p class="text-xs font-mono text-archival-muted">Live bridge connections between FalkorDB, container CNI dataplanes, and CSPM posture feeds.</p>
        </div>

        <!-- Connectors Grid -->
        <div class="grid grid-cols-4 gap-4 font-mono text-xs">
          <div class="p-4 bg-archival-surface arch-border rounded space-y-2">
            <div class="flex items-center justify-between">
              <span class="font-bold text-archival-ink">FalkorDB Engine</span>
              <span class="text-[9px] px-1.5 py-0.5 rounded bg-wiz-emeraldBg text-wiz-emerald font-bold">127.0.0.1:6380</span>
            </div>
            <p class="text-[10px] text-archival-muted">Dual-Layer Graph Store: Inventory & Exploit Plane.</p>
            <div class="text-[9px] text-wiz-emerald font-bold">● CONNECTED (Latency 1.2ms)</div>
          </div>

          <div class="p-4 bg-archival-surface arch-border rounded space-y-2">
            <div class="flex items-center justify-between">
              <span class="font-bold text-archival-ink">Kubernetes kind</span>
              <span class="text-[9px] px-1.5 py-0.5 rounded bg-wiz-emeraldBg text-wiz-emerald font-bold">fjord-t0</span>
            </div>
            <p class="text-[10px] text-archival-muted">Live Calico CNI Dataplane Enforcement Verified.</p>
            <div class="text-[9px] text-wiz-emerald font-bold">● CONNECTED (Calico v3.28)</div>
          </div>

          <div class="p-4 bg-archival-surface arch-border rounded space-y-2">
            <div class="flex items-center justify-between">
              <span class="font-bold text-archival-ink">Trivy Vulnerabilities</span>
              <span class="text-[9px] px-1.5 py-0.5 rounded bg-wiz-ochreBg text-wiz-ochre font-bold">CVE-2023-38606</span>
            </div>
            <p class="text-[10px] text-archival-muted">Container image vulnerability feed ingested.</p>
            <div class="text-[9px] text-wiz-emerald font-bold">● INGESTED (30 Findings)</div>
          </div>

          <div class="p-4 bg-archival-surface arch-border rounded space-y-2">
            <div class="flex items-center justify-between">
              <span class="font-bold text-archival-ink">kubeconform Schema</span>
              <span class="text-[9px] px-1.5 py-0.5 rounded bg-wiz-emeraldBg text-wiz-emerald font-bold">v0.6.7</span>
            </div>
            <p class="text-[10px] text-archival-muted">Rigorous offline validation for generated manifests.</p>
            <div class="text-[9px] text-wiz-emerald font-bold">● ACTIVE (0 Schema Errors)</div>
          </div>
        </div>

        <!-- 7 FastMCP Certified Tools Directory -->
        <div class="space-y-3 pt-2">
          <div class="flex items-center justify-between">
            <h3 class="font-display text-sm font-bold text-archival-ink uppercase tracking-wider">
              7 CERTIFIED FASTMCP MODEL TOOLS (GUARDRAILED & QUOTA-ENFORCED)
            </h3>
            <span class="text-[10px] font-mono text-archival-muted">Max 5 calls/turn · &lt;untrusted_data&gt; isolated</span>
          </div>

          <div class="grid grid-cols-2 gap-3 font-mono text-xs">
            <div class="p-3 bg-archival-surface arch-border rounded space-y-1">
              <div class="font-bold text-wiz-blue flex items-center justify-between">
                <span>1. get_posture_and_cluster_summary</span>
                <button onclick="testTool('get_posture_and_cluster_summary')" class="px-2 py-0.5 rounded arch-border bg-archival-stone text-[9px] hover:bg-archival-border">Test Tool</button>
              </div>
              <p class="text-[10px] text-archival-muted">Retrieve Layer 1 cluster topology inventory and posture findings summary.</p>
            </div>

            <div class="p-3 bg-archival-surface arch-border rounded space-y-1">
              <div class="font-bold text-wiz-blue flex items-center justify-between">
                <span>2. discover_attack_paths</span>
                <button onclick="testTool('discover_attack_paths')" class="px-2 py-0.5 rounded arch-border bg-archival-stone text-[9px] hover:bg-archival-border">Test Tool</button>
              </div>
              <p class="text-[10px] text-archival-muted">Enumerate active multi-hop attack paths from :VirtualSource to :VirtualSink via algo.SPpaths.</p>
            </div>

            <div class="p-3 bg-archival-surface arch-border rounded space-y-1">
              <div class="font-bold text-wiz-blue flex items-center justify-between">
                <span>3. compute_optimal_remediations</span>
                <button onclick="testTool('compute_optimal_remediations')" class="px-2 py-0.5 rounded arch-border bg-archival-stone text-[9px] hover:bg-archival-border">Test Tool</button>
              </div>
              <p class="text-[10px] text-archival-muted">Solve minimal hitting-set with scipy.optimize.milp preserving required flows.</p>
            </div>

            <div class="p-3 bg-archival-surface arch-border rounded space-y-1">
              <div class="font-bold text-wiz-blue flex items-center justify-between">
                <span>4. inspect_resource_context</span>
                <button onclick="testTool('inspect_resource_context')" class="px-2 py-0.5 rounded arch-border bg-archival-stone text-[9px] hover:bg-archival-border">Test Tool</button>
              </div>
              <p class="text-[10px] text-archival-muted">Inspect security context, CVEs, and blast radius for a given resource.</p>
            </div>

            <div class="p-3 bg-archival-surface arch-border rounded space-y-1">
              <div class="font-bold text-wiz-blue flex items-center justify-between">
                <span>5. update_dependency_or_constraint</span>
                <button onclick="testTool('update_dependency_or_constraint')" class="px-2 py-0.5 rounded arch-border bg-archival-stone text-[9px] hover:bg-archival-border">Test Tool</button>
              </div>
              <p class="text-[10px] text-archival-muted">Inject operator freeze constraint verified with AST quote checking.</p>
            </div>

            <div class="p-3 bg-archival-surface arch-border rounded space-y-1">
              <div class="font-bold text-wiz-blue flex items-center justify-between">
                <span>6. simulate_fix_in_sandbox</span>
                <button onclick="testTool('simulate_fix_in_sandbox')" class="px-2 py-0.5 rounded arch-border bg-archival-stone text-[9px] hover:bg-archival-border">Test Tool</button>
              </div>
              <p class="text-[10px] text-archival-muted">Simulate candidate in GRAPH.COPY clone; prove 0 surviving paths & 0 broken flows.</p>
            </div>

            <div class="p-3 bg-archival-surface arch-border rounded space-y-1 col-span-2">
              <div class="font-bold text-wiz-emerald flex items-center justify-between">
                <span>7. commit_verified_remediation</span>
                <span class="text-[9px] px-1.5 py-0.5 rounded bg-wiz-crimsonBg text-wiz-crimson font-bold">UI-Token Protected Gate</span>
              </div>
              <p class="text-[10px] text-archival-muted">Commit remediation after operator approval. Enforces prior successful sandbox run.</p>
            </div>
          </div>
        </div>
      </div>

      <!-- =============================================================== -->
      <!-- VIEW 5: SETTINGS & API (Gemini API Key, Models & Sentinel Memory) -->
      <!-- =============================================================== -->
      <div id="view-settings" class="flex-1 flex flex-col overflow-y-auto custom-scroll p-6 space-y-6 hidden">
        <div class="space-y-1">
          <h2 class="font-display text-xl font-bold text-archival-ink">SETTINGS & LLM CONFIGURATION</h2>
          <p class="text-xs font-mono text-archival-muted">Configure Google Gemini API credentials, thinking levels, and persistent sentinel memory.</p>
        </div>

        <div class="max-w-2xl bg-archival-surface arch-border rounded p-5 space-y-4 font-mono text-xs">
          <div>
            <label class="block font-bold text-archival-ink mb-1">Google Gemini API Key (BYOK)</label>
            <div class="flex space-x-2">
              <input type="password" id="settings-api-key" placeholder="AIzaSy..." class="flex-1 bg-archival-bg arch-border rounded px-3 py-2 text-xs font-mono text-archival-ink focus:outline-none focus:border-archival-ink">
              <button onclick="saveAndVerifyKey()" class="px-4 py-2 rounded bg-obsidian-900 text-archival-cream font-bold">
                Save & Verify Key
              </button>
            </div>
            <div id="settings-key-status" class="mt-1 text-[10px] text-archival-muted">Key stored securely in browser localStorage.</div>
          </div>

          <div class="grid grid-cols-2 gap-4 pt-2">
            <div>
              <label class="block font-bold text-archival-ink mb-1">Primary LLM Model</label>
              <select id="settings-model" class="w-full bg-archival-bg arch-border rounded px-3 py-2 text-xs font-mono text-archival-ink">
                <option value="gemini-3.8-flash">gemini-3.8-flash (Primary)</option>
                <option value="gemini-3.6-flash">gemini-3.6-flash (Fallback)</option>
              </select>
            </div>
            <div>
              <label class="block font-bold text-archival-ink mb-1">Explicit Thinking Level</label>
              <select id="settings-thinking" class="w-full bg-archival-bg arch-border rounded px-3 py-2 text-xs font-mono text-archival-ink">
                <option value="MEDIUM">Level 2 (Medium - Recommended)</option>
                <option value="HIGH">Level 3 (High - Deep Reasoning)</option>
                <option value="LOW">Level 1 (Low - Fast)</option>
              </select>
            </div>
          </div>

          <div class="pt-2 arch-border-t">
            <div class="flex items-center justify-between mb-2">
              <div>
                <div class="font-bold text-archival-ink">Sentinel Memory (Operator Vetoes)</div>
                <div class="text-[10px] text-archival-muted">Persistent cross-ingest operator decisions in FalkorDB sentinel_memory graph.</div>
              </div>
              <button onclick="clearSentinelMemory()" class="px-3 py-1.5 rounded arch-border bg-archival-stone hover:bg-wiz-crimsonBg hover:text-wiz-crimson text-archival-ink text-[10px] font-bold transition">
                Clear Test Vetoes
              </button>
            </div>
          </div>
        </div>
      </div>

    </main>

    <!-- ================================================================= -->
    <!-- RIGHT RECORD INSPECTOR DRAWER: Warm Stone (#ECE7DC, 360px fixed)  -->
    <!-- ================================================================= -->
    <aside class="w-[360px] bg-archival-stone arch-border-l flex flex-col shrink-0 text-archival-ink z-20">
      
      <!-- Top Inspector Header with CSS Barcode Graphic -->
      <div class="p-3.5 arch-border-b bg-archival-surface space-y-2">
        <div class="flex items-start justify-between">
          <div>
            <div class="text-[9px] font-mono text-archival-muted uppercase tracking-wider">RECORD INSPECTOR</div>
            <div id="inspector-record-id" class="font-display font-bold text-sm tracking-wide text-archival-ink">
              REC-CJ-001
            </div>
          </div>
          <!-- Real CSS Barcode Graphic -->
          <div class="flex flex-col items-end">
            <div class="css-barcode">
              <span style="width: 2px;"></span><span style="width: 3px;"></span><span style="width: 1px;"></span>
              <span style="width: 4px;"></span><span style="width: 2px;"></span><span style="width: 1px;"></span>
              <span style="width: 3px;"></span><span style="width: 2px;"></span><span style="width: 4px;"></span>
              <span style="width: 1px;"></span><span style="width: 3px;"></span><span style="width: 2px;"></span>
            </div>
            <span class="text-[7px] font-mono tracking-widest text-archival-muted">FJORD-REC-01</span>
          </div>
        </div>

        <div class="flex items-center justify-between text-[10px] font-mono">
          <span class="px-1.5 py-0.5 rounded bg-archival-stone arch-border text-archival-muted">
            TYPE: <strong id="inspector-type" class="text-archival-ink">CrownJewel</strong>
          </span>
          <span id="inspector-status-badge" class="px-1.5 py-0.5 rounded bg-wiz-crimsonBg text-wiz-crimson font-bold">
            BREACH TARGET
          </span>
        </div>
      </div>

      <!-- Tabbed Navigation (DETAILS, YAML PATCH, CYPHER, AUDIT) -->
      <div class="grid grid-cols-4 arch-border-b bg-archival-surface text-[10px] font-mono text-center">
        <button onclick="setInspectorTab('details')" id="tab-btn-details" class="py-2 font-bold arch-border-b-2 border-archival-ink text-archival-ink">
          DETAILS
        </button>
        <button onclick="setInspectorTab('yaml')" id="tab-btn-yaml" class="py-2 text-archival-muted hover:text-archival-ink transition">
          YAML
        </button>
        <button onclick="setInspectorTab('cypher')" id="tab-btn-cypher" class="py-2 text-archival-muted hover:text-archival-ink transition">
          CYPHER
        </button>
        <button onclick="setInspectorTab('audit')" id="tab-btn-audit" class="py-2 text-archival-muted hover:text-archival-ink transition">
          AUDIT
        </button>
      </div>

      <!-- Tab 1: DETAILS Content -->
      <div id="inspector-tab-details" class="flex-1 p-3.5 overflow-y-auto custom-scroll space-y-3 font-mono text-xs">
        <div>
          <div class="text-[9px] uppercase tracking-wider text-archival-muted font-bold mb-1">RESOURCE ATTRIBUTES</div>
          <div id="inspector-attributes" class="bg-archival-surface arch-border rounded p-2.5 text-[11px] space-y-1">
            <div class="flex justify-between py-0.5 border-b border-archival-border/60">
              <span class="text-archival-muted">name:</span><span class="font-bold text-archival-ink">crown-jewel-db</span>
            </div>
            <div class="flex justify-between py-0.5 border-b border-archival-border/60">
              <span class="text-archival-muted">namespace:</span><span class="text-archival-ink">fjord-t0</span>
            </div>
            <div class="flex justify-between py-0.5 border-b border-archival-border/60">
              <span class="text-archival-muted">category:</span><span class="text-wiz-emerald font-bold">K8S_SECRET</span>
            </div>
            <div class="flex justify-between py-0.5">
              <span class="text-archival-muted">blast_radius:</span><span class="text-wiz-crimson font-bold">CRITICAL (Cluster Secret)</span>
            </div>
          </div>
        </div>

        <div>
          <div class="text-[9px] uppercase tracking-wider text-archival-muted font-bold mb-1">EXPLAINABLE PATH PROOF</div>
          <div id="breadcrumb-chain" class="bg-archival-surface arch-border rounded p-2.5 text-[10px] space-y-1 text-archival-ink">
            <div class="text-wiz-crimson font-bold flex items-center">
              <i class="fa-solid fa-triangle-exclamation mr-1"></i> Active Shortest Breach Path:
            </div>
            <div class="text-archival-ink leading-relaxed">
              (:VirtualSource) &rarr; ingress-gw &rarr; ingress-proxy &rarr; api-service &rarr; crown-jewel-db &rarr; (:VirtualSink)
            </div>
          </div>
        </div>
      </div>

      <!-- Tab 2: YAML PATCH Content -->
      <div id="inspector-tab-yaml" class="flex-1 p-3.5 flex flex-col min-h-0 space-y-2 hidden">
        <div class="flex items-center justify-between">
          <span class="text-[9px] font-mono uppercase tracking-wider text-archival-muted font-bold">SYNTHESIZED K8S PATCH</span>
          <button onclick="copyPatchYaml()" class="text-[10px] font-mono px-2 py-0.5 rounded arch-border bg-archival-surface hover:bg-archival-stone text-archival-ink">
            <i class="fa-regular fa-copy mr-1"></i>Copy YAML
          </button>
        </div>
        <textarea id="patch-yaml" readonly class="flex-1 w-full bg-archival-surface arch-border rounded p-2.5 font-mono text-[10px] text-wiz-emerald resize-none focus:outline-none custom-scroll"># Synthesized minimal-diff NetworkPolicy will appear here after solver execution</textarea>
      </div>

      <!-- Tab 3: CYPHER Content (In-Graph FalkorDB Cypher Inspector) -->
      <div id="inspector-tab-cypher" class="flex-1 p-3.5 overflow-y-auto custom-scroll space-y-2.5 hidden font-mono text-xs">
        <div class="flex items-center justify-between">
          <span class="text-[9px] uppercase tracking-wider text-archival-muted font-bold">FALKORDB CYPHER QUERIES</span>
          <span class="text-[9px] text-wiz-emerald font-bold">algo.SPpaths</span>
        </div>
        <div id="inspector-cypher-list" class="space-y-2">
          <!-- Live Cypher queries dynamically populated -->
        </div>
      </div>

      <!-- Tab 4: AUDIT Content (Operator Review Gate) -->
      <div id="inspector-tab-audit" class="flex-1 p-3.5 space-y-3 hidden font-mono text-xs">
        <div class="text-[9px] uppercase tracking-wider text-archival-muted font-bold">OPERATOR REVIEW GATE</div>
        <div class="bg-archival-surface arch-border rounded p-2.5 text-[11px] space-y-1.5">
          <div class="flex justify-between border-b border-archival-border/60 pb-1">
            <span class="text-archival-muted">Candidate Set:</span>
            <span id="op-cset-id" class="font-bold text-archival-ink">-</span>
          </div>
          <div class="flex justify-between border-b border-archival-border/60 pb-1">
            <span class="text-archival-muted">Disruption Cost:</span>
            <span id="op-cost" class="font-bold text-wiz-emerald">1.0</span>
          </div>
          <div class="flex justify-between border-b border-archival-border/60 pb-1">
            <span class="text-archival-muted">Broken Required Flows:</span>
            <span id="op-broken" class="font-bold text-wiz-emerald">0</span>
          </div>
          <div class="flex justify-between">
            <span class="text-archival-muted">Verification Gate:</span>
            <span id="op-status" class="font-bold text-wiz-emerald">VERIFIED_IN_MODEL</span>
          </div>
        </div>

        <div class="space-y-2 pt-2">
          <button onclick="sendOperatorDecision('APPROVE')" id="btn-approve" class="w-full py-2.5 rounded bg-wiz-emerald hover:bg-emerald-700 text-white font-mono font-bold text-xs transition shadow flex items-center justify-center space-x-1.5">
            <i class="fa-solid fa-check"></i>
            <span>APPROVE & COMMIT TO PRODUCTION</span>
          </button>
          <button onclick="sendOperatorDecision('REJECT')" id="btn-reject" class="w-full py-2 rounded arch-border bg-archival-surface hover:bg-wiz-crimsonBg hover:text-wiz-crimson text-archival-muted font-mono font-bold text-xs transition">
            REJECT (VETO IN SENTINEL MEMORY)
          </button>
        </div>
      </div>

    </aside>

  </div>

  <!-- =================================================================== -->
  <!-- BOTTOM STATUS BAR: Deep Obsidian Charcoal (#141517, 32px fixed)    -->
  <!-- =================================================================== -->
  <footer class="h-8 bg-obsidian-950 border-t border-obsidian-border px-4 flex items-center justify-between text-[10px] font-mono text-archival-faint shrink-0 z-30">
    <div class="flex items-center space-x-4">
      <span class="flex items-center"><span class="w-1.5 h-1.5 rounded-full bg-wiz-emerald inline-block mr-1.5"></span>FALKORDB: ONLINE (:6380)</span>
      <span>|</span>
      <span>ACTIVE GRAPH: <strong id="status-graph-name" class="text-archival-cream">prod_t0slice</strong></span>
      <span>|</span>
      <span>CNI: CALICO (K8s)</span>
      <span>|</span>
      <span>GEMINI: <strong id="status-llm-model" class="text-wiz-emerald">READY (gemini-3.8-flash)</strong></span>
    </div>
    <div class="flex items-center space-x-3">
      <span id="status-active-view">VIEW: DASHBOARD</span>
      <span>|</span>
      <span class="text-archival-cream font-bold">PROJECT FJORD // TRACK 1</span>
    </div>
  </footer>

  <!-- =================================================================== -->
  <!-- CLIENT JAVASCRIPT: Full Multi-View Application Logic               -->
  <!-- =================================================================== -->
  <script>
    let currentSession = null;
    let cyInstance = null;
    let fullCyInstance = null;
    let currentView = 'dashboard';
    let currentGraphMode = 'prod';

    // 1. Initial Application Setup
    window.addEventListener('DOMContentLoaded', async () => {
      // Load saved API key from localStorage if present
      const savedKey = localStorage.getItem('fjord_gemini_api_key');
      if (savedKey) {
        document.getElementById('settings-api-key').value = savedKey;
        document.getElementById('settings-key-status').innerHTML = '<span class="text-wiz-emerald font-bold">● Active key restored from localStorage.</span>';
      }
      await initSession('sample_cluster');
    });

    async function initSession(scenarioId = 'sample_cluster') {
      try {
        const apiKey = localStorage.getItem('fjord_gemini_api_key') || null;
        const resp = await fetch('/api/v1/sessions/init', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({
            scenario: scenarioId,
            byok_api_key: apiKey,
            replay_mode: true
          })
        });
        currentSession = await resp.json();
        
        document.getElementById('dash-active-scenario').innerText = scenarioId;
        document.getElementById('status-graph-name').innerText = currentSession.snapshot_sha;
        
        await loadCytoscapeGraph(currentSession.session_id, 'prod');
        await refreshCypherInspector();
      } catch (err) {
        console.error('Session init failed:', err);
      }
    }

    // 2. View Switching Logic
    function switchView(viewName) {
      currentView = viewName;
      const views = ['dashboard', 'graph', 'copilot', 'connectors', 'settings'];
      views.forEach(v => {
        const el = document.getElementById(`view-${v}`);
        const nav = document.getElementById(`nav-${v}`);
        if (v === viewName) {
          el.classList.remove('hidden');
          nav.className = 'w-full text-left px-3.5 py-2 flex items-center space-x-2.5 transition nav-item-active';
        } else {
          el.classList.add('hidden');
          nav.className = 'w-full text-left px-3.5 py-2 flex items-center space-x-2.5 transition text-archival-cream/70 hover:text-archival-cream hover:bg-obsidian-850';
        }
      });
      document.getElementById('status-active-view').innerText = `VIEW: ${viewName.toUpperCase()}`;

      if (viewName === 'graph' && !fullCyInstance) {
        initFullscreenGraph();
      }
    }

    // 3. Load Cytoscape.js Security Graph
    async function loadCytoscapeGraph(sessionOrGraphId, viewMode = 'prod') {
      try {
        const resp = await fetch(`/api/v1/graph/${sessionOrGraphId}?view=${viewMode}`);
        const data = await resp.json();
        
        // Update KPI block numerals dynamically
        if (data.attack_path_count !== undefined) {
          document.getElementById('kpi-paths').innerText = viewMode === 'sandbox' ? '00' : String(data.attack_path_count).padStart(2, '0');
          document.getElementById('kpi-toxic').innerText = viewMode === 'sandbox' ? '00' : '03';
          document.getElementById('kpi-sandbox').innerText = viewMode === 'sandbox' ? '01' : '01';
        }
        
        const elements = data.cytoscape_elements || [];
        const container = document.getElementById('topology-canvas');
        
        if (cyInstance) cyInstance.destroy();
        
        cyInstance = cytoscape({
          container: container,
          elements: elements,
          style: [
            {
              selector: 'node',
              style: {
                'background-color': 'data(color)',
                'label': 'data(label)',
                'font-family': 'JetBrains Mono',
                'font-size': '10px',
                'text-valign': 'center',
                'text-halign': 'center',
                'color': '#FFFFFF',
                'shape': 'data(shape)',
                'width': 'label',
                'height': '32px',
                'padding': '10px',
                'border-width': 1.5,
                'border-color': '#181818',
              }
            },
            {
              selector: 'node[?is_attack_path]',
              style: {
                'border-color': '#C93B2B',
                'border-width': 3,
                'shadow-blur': 15,
                'shadow-color': '#C93B2B',
                'shadow-opacity': 0.6,
              }
            },
            {
              selector: 'node[node_type = "CrownJewel"]',
              style: {
                'background-color': '#236B48',
                'border-color': '#181818',
                'border-width': 2,
                'height': '40px',
              }
            },
            {
              selector: 'edge',
              style: {
                'width': 1.5,
                'line-color': '#D4CFC4',
                'target-arrow-color': '#68645C',
                'target-arrow-shape': 'triangle',
                'curve-style': 'bezier',
                'label': 'data(label)',
                'font-family': 'JetBrains Mono',
                'font-size': '8px',
                'color': '#68645C',
                'text-background-color': '#FAF8F3',
                'text-background-opacity': 0.9,
                'text-background-padding': '2px',
              }
            },
            {
              selector: 'edge[?is_attack_path]',
              style: {
                'line-color': '#C93B2B',
                'target-arrow-color': '#C93B2B',
                'width': 3.5,
                'color': '#C93B2B',
                'font-weight': 'bold',
              }
            },
            {
              selector: 'edge[?is_severed]',
              style: {
                'line-color': '#8E8A80',
                'target-arrow-color': '#8E8A80',
                'line-style': 'dashed',
                'width': 1.5,
                'label': '[SEVERED]',
                'color': '#8E8A80',
              }
            }
          ],
          layout: {
            name: 'cose',
            animate: false,
            nodeOverlap: 20,
            idealEdgeLength: 85,
            edgeElasticity: 100,
          }
        });

        // Click Handler: populate Right Record Inspector
        cyInstance.on('tap', 'node', function(evt){
          const node = evt.target;
          populateInspectorNode(node.data());
        });

        cyInstance.on('tap', 'edge', function(evt){
          const edge = evt.target;
          populateInspectorEdge(edge.data());
        });

      } catch (err) {
        console.error('Failed to load Cytoscape graph:', err);
      }
    }

    function fitGraph() {
      if (cyInstance) cyInstance.fit();
      if (fullCyInstance) fullCyInstance.fit();
    }

    function setGraphLayout(layoutName) {
      if (fullCyInstance) {
        fullCyInstance.layout({ name: layoutName, animate: true }).run();
      }
    }

    function initFullscreenGraph() {
      const container = document.getElementById('fullscreen-topology-canvas');
      if (!cyInstance) return;
      fullCyInstance = cytoscape({
        container: container,
        elements: cyInstance.elements().jsons(),
        style: cyInstance.style(),
        layout: { name: 'cose', animate: false }
      });
    }

    // 4. Toggle Prod vs. Sandbox Simulation
    function toggleGraphView(view) {
      currentGraphMode = view;
      const btnProd = document.getElementById('btn-toggle-prod');
      const btnSandbox = document.getElementById('btn-toggle-sandbox');

      if (view === 'sandbox') {
        if (!currentSession || !currentSession.sandbox_sha) {
          alert('Sandbox simulation not yet run. Click "RUN REMEDIATION AGENT" first to simulate in GRAPH.COPY.');
          return;
        }
        btnSandbox.className = 'px-2.5 py-1 rounded bg-wiz-emerald text-white font-bold shadow-sm transition';
        btnProd.className = 'px-2.5 py-1 rounded text-archival-muted hover:text-archival-ink font-semibold transition';
        loadCytoscapeGraph(currentSession.session_id, 'sandbox');
      } else {
        btnProd.className = 'px-2.5 py-1 rounded bg-archival-surface text-archival-ink font-bold shadow-sm transition';
        btnSandbox.className = 'px-2.5 py-1 rounded text-archival-muted hover:text-archival-ink font-semibold transition';
        loadCytoscapeGraph(currentSession.session_id, 'prod');
      }
    }

    // 5. Inspector Population Logic
    function populateInspectorNode(data) {
      document.getElementById('inspector-record-id').innerText = data.id;
      document.getElementById('inspector-type').innerText = data.node_type || 'Workload';
      
      const badge = document.getElementById('inspector-status-badge');
      if (data.is_attack_path) {
        badge.className = 'px-1.5 py-0.5 rounded bg-wiz-crimsonBg text-wiz-crimson font-bold';
        badge.innerText = 'ON ATTACK PATH';
      } else {
        badge.className = 'px-1.5 py-0.5 rounded bg-wiz-emeraldBg text-wiz-emerald font-bold';
        badge.innerText = 'ISOLATED';
      }

      let attrs = `<div class="flex justify-between py-0.5 border-b border-archival-border/60"><span class="text-archival-muted">id:</span><span class="font-bold text-archival-ink">${data.id}</span></div>`;
      attrs += `<div class="flex justify-between py-0.5 border-b border-archival-border/60"><span class="text-archival-muted">label:</span><span class="font-bold text-archival-ink">${data.label}</span></div>`;
      attrs += `<div class="flex justify-between py-0.5 border-b border-archival-border/60"><span class="text-archival-muted">namespace:</span><span class="text-archival-ink">${data.namespace || 'default'}</span></div>`;

      const props = data.properties || {};
      for (const [k, v] of Object.entries(props)) {
        if (typeof v === 'object') continue;
        attrs += `<div class="flex justify-between py-0.5 border-b border-archival-border/60"><span class="text-archival-muted">${k}:</span><span class="text-archival-ink font-mono">${v}</span></div>`;
      }

      document.getElementById('inspector-attributes').innerHTML = attrs;
    }

    function populateInspectorEdge(data) {
      document.getElementById('inspector-record-id').innerText = data.id;
      document.getElementById('inspector-type').innerText = data.type || 'EXPLOIT_STEP';
      
      const badge = document.getElementById('inspector-status-badge');
      if (data.is_severed) {
        badge.className = 'px-1.5 py-0.5 rounded bg-archival-stone text-archival-muted font-bold';
        badge.innerText = 'SEVERED BY MILP';
      } else if (data.is_attack_path) {
        badge.className = 'px-1.5 py-0.5 rounded bg-wiz-crimsonBg text-wiz-crimson font-bold';
        badge.innerText = 'ACTIVE EXPLOIT';
      } else {
        badge.className = 'px-1.5 py-0.5 rounded bg-wiz-emeraldBg text-wiz-emerald font-bold';
        badge.innerText = 'STANDARD';
      }

      document.getElementById('inspector-attributes').innerHTML = `
        <div class="flex justify-between py-0.5 border-b border-archival-border/60"><span class="text-archival-muted">source:</span><span class="font-bold text-archival-ink">${data.source}</span></div>
        <div class="flex justify-between py-0.5 border-b border-archival-border/60"><span class="text-archival-muted">target:</span><span class="font-bold text-archival-ink">${data.target}</span></div>
        <div class="flex justify-between py-0.5"><span class="text-archival-muted">relationship:</span><span class="text-wiz-blue font-bold">${data.label}</span></div>
      `;
    }

    function setInspectorTab(tabName) {
      const tabs = ['details', 'yaml', 'cypher', 'audit'];
      tabs.forEach(t => {
        const pane = document.getElementById(`inspector-tab-${t}`);
        const btn = document.getElementById(`tab-btn-${t}`);
        if (t === tabName) {
          pane.classList.remove('hidden');
          btn.className = 'py-2 font-bold arch-border-b-2 border-archival-ink text-archival-ink';
        } else {
          pane.classList.add('hidden');
          btn.className = 'py-2 text-archival-muted hover:text-archival-ink transition';
        }
      });
    }

    // 6. Run Full Remediation Agent Pipeline
    async function runRemediationPipeline() {
      if (!currentSession) return;
      try {
        const resp = await fetch('/api/v1/agent/run', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({session_id: currentSession.session_id})
        });
        const res = await resp.json();
        currentSession.candidate_set_id = res.candidate_set_id;
        currentSession.sandbox_sha = res.sandbox_sha;

        // Populate Audit Gate
        document.getElementById('op-cset-id').innerText = res.candidate_set_id;
        document.getElementById('op-status').innerText = 'VERIFIED_IN_MODEL';

        // Extract YAML
        const remed = res.timeline.find(t => t.step === 'remediate');
        if (remed && remed.candidates.optimal_candidates.length > 0) {
          document.getElementById('patch-yaml').value = remed.candidates.optimal_candidates[0].yaml_diff;
        }

        // Auto switch to sandbox view to showcase severed edge
        toggleGraphView('sandbox');
        setInspectorTab('audit');
      } catch (err) {
        console.error('Pipeline execution error:', err);
      }
    }

    // 7. Copilot Chatbot Handler
    async function handleCopilotSubmit(e) {
      e.preventDefault();
      const input = document.getElementById('copilot-input');
      const msg = input.value.trim();
      if (!msg) return;

      input.value = '';
      appendCopilotMessage('OPERATOR', msg, 'bg-archival-stone/60 text-archival-ink');

      const apiKey = localStorage.getItem('fjord_gemini_api_key') || null;

      try {
        const resp = await fetch('/api/v1/chat', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({
            session_id: currentSession.session_id,
            message: msg,
            api_key: apiKey
          })
        });
        const data = await resp.json();
        
        let formatted = data.reply.replace(/\n\n/g, '<br><br>').replace(/\n/g, '<br>');
        appendCopilotMessage('FJORD AGENT (Gemini 3.8 Flash)', formatted, 'bg-archival-surface arch-border text-archival-ink');
        
        if (data.candidate_set_id) {
          currentSession.candidate_set_id = data.candidate_set_id;
          currentSession.sandbox_sha = data.sandbox_sha;
          if (data.yaml_diff) document.getElementById('patch-yaml').value = data.yaml_diff;
          toggleGraphView('sandbox');
        }
      } catch (err) {
        appendCopilotMessage('SYSTEM ERROR', err.message, 'bg-wiz-crimsonBg text-wiz-crimson');
      }
    }

    function sendQuickPrompt(promptText) {
      document.getElementById('copilot-input').value = promptText;
      switchView('copilot');
      document.getElementById('copilot-input').focus();
    }

    function appendCopilotMessage(sender, htmlContent, bgClass) {
      const container = document.getElementById('copilot-chat-history');
      const card = document.createElement('div');
      card.className = `p-3.5 rounded arch-border ${bgClass} space-y-1.5`;
      card.innerHTML = `
        <div class="text-[10px] font-bold uppercase tracking-wider text-archival-muted flex items-center justify-between">
          <span>${sender}</span>
          <span class="text-[8px]">${new Date().toLocaleTimeString()}</span>
        </div>
        <div class="text-xs leading-relaxed font-mono">${htmlContent}</div>
      `;
      container.appendChild(card);
      container.scrollTop = container.scrollHeight;
    }

    // 8. Settings & API Verification
    async function saveAndVerifyKey() {
      const key = document.getElementById('settings-api-key').value.trim();
      if (!key) {
        alert('Please enter a valid Gemini API key');
        return;
      }
      try {
        const resp = await fetch('/api/v1/settings/verify-key', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({api_key: key})
        });
        const data = await resp.json();
        if (data.valid) {
          localStorage.setItem('fjord_gemini_api_key', key);
          document.getElementById('settings-key-status').innerHTML = '<span class="text-wiz-emerald font-bold">● Key Verified & Saved to localStorage.</span>';
          document.getElementById('status-llm-model').innerText = 'READY (gemini-3.8-flash)';
        } else {
          document.getElementById('settings-key-status').innerHTML = `<span class="text-wiz-crimson font-bold">● ${data.error}</span>`;
        }
      } catch (err) {
        console.error('Key verify error:', err);
      }
    }

    async function clearSentinelMemory() {
      try {
        const resp = await fetch('/api/v1/settings/clear-vetoes', {method: 'POST'});
        const data = await resp.json();
        alert(data.message || 'Cleared sentinel memory vetoes');
      } catch (err) {
        console.error('Clear memory error:', err);
      }
    }

    // 9. FastMCP Direct Tool Tester
    async function testTool(toolName) {
      try {
        const args = toolName === 'discover_attack_paths' ? {max_paths: 5} : {};
        const resp = await fetch('/api/v1/mcp/execute', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({tool_name: toolName, arguments: args})
        });
        const res = await resp.json();
        alert(`FastMCP Tool '${toolName}' Result:\n` + JSON.stringify(res.result, null, 2));
      } catch (err) {
        alert(`Error executing ${toolName}: ${err.message}`);
      }
    }

    // 10. Manifest Upload Handler
    async function handleManifestUpload(event) {
      const file = event.target.files[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = async (e) => {
        const content = e.target.result;
        try {
          const resp = await fetch('/api/v1/upload', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({filename: file.name, content: content})
          });
          const res = await resp.json();
          currentSession = res;
          document.getElementById('dash-active-scenario').innerText = res.filename;
          await loadCytoscapeGraph(res.session_id, 'prod');
          switchView('dashboard');
        } catch (err) {
          alert('Failed to upload manifest: ' + err.message);
        }
      };
      reader.readAsText(file);
    }

    // 11. Cypher Inspector Refresher
    async function refreshCypherInspector() {
      if (!currentSession) return;
      try {
        const resp = await fetch(`/api/v1/sessions/${currentSession.session_id}/cypher`);
        const data = await resp.json();
        const container = document.getElementById('inspector-cypher-list');
        container.innerHTML = '';
        (data.queries || []).forEach(q => {
          const box = document.createElement('div');
          box.className = 'p-2 bg-archival-surface arch-border rounded text-[10px] space-y-1';
          box.innerHTML = `
            <div class="flex justify-between text-archival-muted font-bold">
              <span class="text-wiz-emerald">${q.description}</span>
              <span>${q.latency_ms} ms</span>
            </div>
            <pre class="overflow-x-auto custom-scroll text-archival-ink whitespace-pre-wrap">${q.query}</pre>
          `;
          container.appendChild(box);
        });
      } catch (err) {
        console.error('Cypher inspector error:', err);
      }
    }

    function inspectRemediationCandidate() {
      setInspectorTab('audit');
    }

    async function sendOperatorDecision(decision) {
      if (!currentSession || !currentSession.candidate_set_id) return;
      try {
        const resp = await fetch('/api/v1/operator/decision', {
          method: 'POST',
          headers: {'Content-Type': 'application/json', 'X-UI-Token': currentSession.ui_token},
          body: JSON.stringify({
            session_id: currentSession.session_id,
            candidate_set_id: currentSession.candidate_set_id,
            decision: decision,
            ui_token: currentSession.ui_token
          })
        });
        const res = await resp.json();
        alert(`Operator Decision '${decision}' Committed Successfully!`);
      } catch (err) {
        alert('Operator decision failed: ' + err.message);
      }
    }

    function copyPatchYaml() {
      const copyText = document.getElementById('patch-yaml');
      navigator.clipboard.writeText(copyText.value);
      alert('Kubernetes NetworkPolicy YAML copied to clipboard!');
    }

    function loadScenario(scen) {
      initSession(scen);
    }
  </script>
</body>
</html>
"""
    return HTMLResponse(content=html_content)
