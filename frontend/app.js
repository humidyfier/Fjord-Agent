/**
 * frontend/app.js
 * Fjord Agent: Kubernetes & Cloud Attack-Path Remediation Engine
 * Core Frontend Logic: 2D Cytoscape (Horizontal Dagre) + 3D WebGL Force Graph,
 * 5 Interactive Drill-Down KPIs, Retractable Inspector, Chatbot, and FastMCP Tool Runner.
 */

// Global State
let currentSessionId = null;
let currentSnapshotSha = null;
let currentUiToken = null;
let currentScenario = 'sample_cluster';
let currentGraphView = 'prod'; // 'prod' or 'sandbox'
let currentCanvasMode = '2d';   // '2d' or '3d'
let currentLayer = 'layer1';    // 'layer1' or 'layer2'
let isInspectorCollapsed = false;

let cy = null;
let graph3d = null;
let rawGraphData = { nodes: [], edges: [], cytoscape_elements: [] };
let selectedEntity = null;
let scanHistory = [];

// Initialize on DOM Ready
document.addEventListener('DOMContentLoaded', async () => {
  await fetchSystemHealth();
  await loadScenario(currentScenario);
  setupResizeObserver();
});

// ============================================================================
// SYSTEM TELEMETRY & HEALTH
// ============================================================================
async function fetchSystemHealth() {
  try {
    const res = await fetch('/api/v1/health');
    const data = await res.json();
    
    // Update Sidebar Telemetry
    const statusEl = document.getElementById('sidebar-falkordb-status');
    if (statusEl) {
      statusEl.textContent = data.falkordb_status || '● ONLINE :6380';
      statusEl.className = data.falkordb_connected ? 'text-wiz-emerald font-bold' : 'text-wiz-crimson font-bold';
    }
    
    const provEl = document.getElementById('telemetry-llm-provider');
    if (provEl) provEl.textContent = data.llm_provider || 'Google Gemini';
    
    const modEl = document.getElementById('telemetry-llm-model');
    if (modEl) modEl.textContent = data.llm_model || 'gemini-3.8-flash';

    const snapEl = document.getElementById('telemetry-snapshot-id');
    if (snapEl && data.active_snapshot) snapEl.textContent = data.active_snapshot;

    const promptEl = document.getElementById('system-prompt-display');
    if (promptEl && data.system_prompt) promptEl.textContent = data.system_prompt;

  } catch (err) {
    console.warn('Failed to fetch system health:', err);
  }
}

// ============================================================================
// WORKSPACE RESET
// ============================================================================
async function resetWorkspaceState() {
  if (!confirm('Are you sure you want to reset the Fjord workspace? This clears active sessions.')) return;
  try {
    await fetch('/api/v1/sessions/reset', { method: 'POST' });
    scanHistory = [];
    updateScanHistoryUI();
    await loadScenario('sample_cluster');
  } catch (err) {
    console.error('Reset failed:', err);
  }
}

// ============================================================================
// SCENARIO & SESSION INITIALIZATION
// ============================================================================
async function loadScenario(scenarioId) {
  currentScenario = scenarioId;
  const scenBadge = document.getElementById('dash-active-scenario');
  if (scenBadge) scenBadge.textContent = scenarioId;

  try {
    const res = await fetch('/api/v1/sessions/init', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ scenario: scenarioId, replay_mode: true })
    });
    const data = await res.json();
    
    currentSessionId = data.session_id;
    currentSnapshotSha = data.snapshot_sha;
    currentUiToken = data.ui_token;

    // Update Telemetry
    const snapEl = document.getElementById('telemetry-snapshot-id');
    if (snapEl) snapEl.textContent = currentSnapshotSha;
    const sessFooter = document.getElementById('footer-session-id');
    if (sessFooter) sessFooter.textContent = currentSessionId;

    // Track in Scan History
    addToScanHistory(scenarioId, currentSnapshotSha);

    // Fetch and render graph topology
    await fetchGraphTopology();

  } catch (err) {
    console.error(`Error loading scenario ${scenarioId}:`, err);
  }
}

function addToScanHistory(name, snapshotId) {
  const existing = scanHistory.find(s => s.name === name);
  if (!existing) {
    scanHistory.unshift({ name, snapshotId, time: new Date().toLocaleTimeString() });
    updateScanHistoryUI();
  }
}

function updateScanHistoryUI() {
  const list = document.getElementById('scan-history-list');
  const countBadge = document.getElementById('scan-history-count');
  if (!list) return;

  if (countBadge) countBadge.textContent = scanHistory.length;
  list.innerHTML = '';

  scanHistory.forEach(s => {
    const isActive = s.name === currentScenario;
    const btn = document.createElement('button');
    btn.onclick = () => loadScenario(s.name);
    btn.className = `w-full text-left p-2 rounded bg-obsidian-850 hover:bg-obsidian-800 border ${isActive ? 'border-wiz-emerald/60' : 'border-obsidian-border'} transition text-archival-cream`;
    btn.innerHTML = `
      <div class="font-bold text-[10px] ${isActive ? 'text-wiz-emerald' : 'text-archival-cream'} flex items-center justify-between">
        <span class="truncate">${s.name}</span>
        ${isActive ? '<span class="text-[8px] px-1 bg-obsidian-800 text-wiz-emerald rounded">ACTIVE</span>' : ''}
      </div>
      <div class="text-[9px] text-archival-faint">${s.snapshotId} · ${s.time}</div>
    `;
    list.appendChild(btn);
  });
}

// ============================================================================
// GRAPH TOPOLOGY FETCH & RENDER
// ============================================================================
async function fetchGraphTopology() {
  if (!currentSessionId) return;
  try {
    const res = await fetch(`/api/v1/graph/${currentSessionId}?view=${currentGraphView}`);
    rawGraphData = await res.json();

    // Update KPI Counters
    updateKPIsFromGraph(rawGraphData);

    // Update Node Count Badge
    const countBadge = document.getElementById('canvas-node-count-badge');
    if (countBadge) {
      countBadge.textContent = `${rawGraphData.nodes.length} Nodes · ${rawGraphData.edges.length} Edges`;
    }

    // Render in current mode
    if (currentCanvasMode === '2d') {
      renderCytoscape2D(rawGraphData);
    } else {
      renderForceGraph3D(rawGraphData);
    }

  } catch (err) {
    console.error('Error fetching graph topology:', err);
  }
}

function updateKPIsFromGraph(data) {
  const attackEdges = data.edges.filter(e => e.is_attack_path);
  const severedEdges = data.edges.filter(e => e.is_severed);
  const toxicCount = (data.attack_path_count > 0 && currentGraphView === 'prod') ? data.attack_path_count : 0;

  const toxicEl = document.getElementById('kpi-toxic-count');
  if (toxicEl) toxicEl.textContent = toxicCount;

  const pathEl = document.getElementById('kpi-path-count');
  if (pathEl) pathEl.textContent = data.attack_path_count || (toxicCount > 0 ? 1 : 0);

  const sandStatusEl = document.getElementById('kpi-sandbox-status');
  if (sandStatusEl) {
    sandStatusEl.textContent = currentGraphView === 'sandbox' || severedEdges.length > 0 ? '100%' : 'PENDING';
    sandStatusEl.className = currentGraphView === 'sandbox' || severedEdges.length > 0 ? 'font-display font-bold text-3xl tracking-tight text-wiz-emerald' : 'font-display font-bold text-3xl tracking-tight text-archival-muted';
  }
}

// ============================================================================
// 2D CYTOSCAPE (HORIZONTAL DAGRE LEFT-TO-RIGHT BLUEPRINT)
// ============================================================================
function renderCytoscape2D(data) {
  const container = document.getElementById('topology-canvas');
  if (!container) return;

  // Filter for Layer 2 if active
  let elements = data.cytoscape_elements || [];
  if (currentLayer === 'layer2') {
    elements = elements.filter(el => {
      if (el.group === 'nodes') return el.data.is_attack_path;
      if (el.group === 'edges') return el.data.is_attack_path || el.data.is_severed;
      return true;
    });
  }

  // Cytoscape Stylesheet
  const cyStyles = [
    {
      selector: 'node',
      style: {
        'shape': 'round-rectangle',
        'width': 130,
        'height': 44,
        'background-color': 'data(color)',
        'border-width': 1.5,
        'border-color': '#181818',
        'label': 'data(label)',
        'color': '#181818',
        'font-family': 'JetBrains Mono, monospace',
        'font-size': '10px',
        'font-weight': 'bold',
        'text-valign': 'center',
        'text-halign': 'center',
        'text-wrap': 'ellipsis',
        'text-max-width': '120px',
        'shadow-blur': 4,
        'shadow-color': 'rgba(0,0,0,0.08)',
        'shadow-offset-y': 2,
      }
    },
    {
      selector: 'node[node_type = "CrownJewel"]',
      style: {
        'shape': 'star',
        'width': 60,
        'height': 60,
        'background-color': '#236B48',
        'color': '#FAF8F3',
        'border-color': '#181818',
        'border-width': 2,
      }
    },
    {
      selector: 'node[node_type = "PostureFinding"], node[node_type = "Vulnerability"]',
      style: {
        'shape': 'diamond',
        'width': 44,
        'height': 44,
        'background-color': '#D97724',
        'color': '#181818',
      }
    },
    {
      selector: 'node[node_type = "EntryPoint"]',
      style: {
        'shape': 'ellipse',
        'width': 110,
        'height': 44,
        'background-color': '#F97316',
        'color': '#FAF8F3',
      }
    },
    {
      selector: 'node[?is_attack_path]',
      style: {
        'border-color': '#C93B2B',
        'border-width': 3,
        'shadow-blur': 12,
        'shadow-color': 'rgba(201, 59, 43, 0.4)',
      }
    },
    {
      selector: 'edge',
      style: {
        'width': 2,
        'line-color': '#A8A29E',
        'target-arrow-color': '#A8A29E',
        'target-arrow-shape': 'triangle',
        'curve-style': 'bezier',
        'arrow-scale': 1.1,
        'label': 'data(type)',
        'font-family': 'JetBrains Mono, monospace',
        'font-size': '8px',
        'text-rotation': 'autorotate',
        'text-margin-y': -8,
        'color': '#68645C',
      }
    },
    {
      selector: 'edge[?is_attack_path]',
      style: {
        'width': 3.5,
        'line-color': '#C93B2B',
        'target-arrow-color': '#C93B2B',
        'line-style': 'dashed',
        'line-dash-pattern': [6, 3],
        'color': '#C93B2B',
        'font-weight': 'bold',
      }
    },
    {
      selector: 'edge[?is_severed]',
      style: {
        'width': 2.5,
        'line-color': '#8E8A80',
        'target-arrow-color': '#8E8A80',
        'line-style': 'dotted',
        'label': 'data(label)',
        'color': '#8E8A80',
      }
    },
    {
      selector: ':selected',
      style: {
        'border-color': '#2563EB',
        'border-width': 3,
        'line-color': '#2563EB',
        'target-arrow-color': '#2563EB',
      }
    }
  ];

  // Initialize Cytoscape with Dagre Left-to-Right layout
  if (cy) {
    cy.destroy();
  }

  cy = cytoscape({
    container: container,
    elements: elements,
    style: cyStyles,
    layout: {
      name: 'breadthfirst',
      directed: true,
      spacingFactor: 1.25,
      padding: 30,
      roots: 'node[node_type = "EntryPoint"]'
    },
    wheelSensitivity: 0.3,
    minZoom: 0.2,
    maxZoom: 3.0,
  });

  // Node & Edge Click Listeners
  cy.on('tap', 'node', (evt) => {
    const node = evt.target;
    const nid = node.id();
    const nodeObj = data.nodes.find(n => n.id === nid) || { id: nid, label: node.data('node_type') };
    inspectEntity(nodeObj, 'node');
  });

  cy.on('tap', 'edge', (evt) => {
    const edge = evt.target;
    const eid = edge.id();
    const edgeObj = data.edges.find(e => e.id === eid) || { id: eid, label: edge.data('label') };
    inspectEntity(edgeObj, 'edge');
  });

  cy.fit(null, 30);
}

// ============================================================================
// 3D FORCE WEBGL GRAPH (NEO4J-STYLE DIRECTIONAL PARTICLES)
// ============================================================================
function renderForceGraph3D(data) {
  const container = document.getElementById('3d-graph-container');
  if (!container) return;

  container.innerHTML = '';

  const gData = {
    nodes: data.nodes.map(n => ({
      id: n.id,
      name: n.name || n.id,
      label: n.label,
      color: n.color || '#3b82f6',
      val: n.label === 'CrownJewel' ? 12 : (n.is_attack_path ? 9 : 6),
      is_attack_path: n.is_attack_path,
    })),
    links: data.edges.map(e => ({
      source: e.source,
      target: e.target,
      label: e.label,
      is_attack_path: e.is_attack_path,
      is_severed: e.is_severed,
    }))
  };

  graph3d = ForceGraph3D()(container)
    .graphData(gData)
    .nodeLabel(n => `${n.label}: ${n.name}`)
    .nodeColor(n => n.color)
    .nodeRelSize(4)
    .linkColor(e => e.is_severed ? '#8E8A80' : (e.is_attack_path ? '#C93B2B' : '#4B5563'))
    .linkWidth(e => e.is_attack_path ? 3 : 1)
    .linkDirectionalParticles(e => e.is_attack_path ? 4 : 0)
    .linkDirectionalParticleSpeed(0.008)
    .linkDirectionalParticleWidth(3)
    .linkDirectionalParticleColor(() => '#FF4D4D')
    .onNodeClick(node => {
      // Camera fly-to
      const distance = 40;
      const distRatio = 1 + distance / Math.hypot(node.x, node.y, node.z);
      graph3d.cameraPosition(
        { x: node.x * distRatio, y: node.y * distRatio, z: node.z * distRatio },
        node,
        2000
      );
      const nodeObj = data.nodes.find(n => n.id === node.id) || node;
      inspectEntity(nodeObj, 'node');
    });

  graph3d.width(container.clientWidth);
  graph3d.height(container.clientHeight);
}

// ============================================================================
// CANVAS MODE & LAYER SWITCHERS
// ============================================================================
function switchCanvasMode(mode) {
  currentCanvasMode = mode;
  const btn2d = document.getElementById('btn-canvas-2d');
  const btn3d = document.getElementById('btn-canvas-3d');
  const view2d = document.getElementById('canvas-viewport-2d');
  const view3d = document.getElementById('canvas-viewport-3d');

  if (mode === '2d') {
    btn2d.className = 'px-2 py-0.5 rounded bg-archival-stone text-archival-ink font-bold shadow-xs';
    btn3d.className = 'px-2 py-0.5 rounded text-archival-muted hover:text-archival-ink';
    view2d.classList.remove('hidden');
    view3d.classList.add('hidden');
    if (cy) cy.resize();
  } else {
    btn3d.className = 'px-2 py-0.5 rounded bg-archival-stone text-archival-ink font-bold shadow-xs';
    btn2d.className = 'px-2 py-0.5 rounded text-archival-muted hover:text-archival-ink';
    view3d.classList.remove('hidden');
    view2d.classList.add('hidden');
    renderForceGraph3D(rawGraphData);
  }
}

function setGraphLayer(layer) {
  currentLayer = layer;
  const l1 = document.getElementById('btn-layer1');
  const l2 = document.getElementById('btn-layer2');
  if (layer === 'layer1') {
    l1.className = 'px-2 py-0.5 rounded bg-archival-stone text-archival-ink font-bold';
    l2.className = 'px-2 py-0.5 rounded text-archival-muted hover:text-archival-ink';
  } else {
    l2.className = 'px-2 py-0.5 rounded bg-archival-stone text-archival-ink font-bold';
    l1.className = 'px-2 py-0.5 rounded text-archival-muted hover:text-archival-ink';
  }
  fetchGraphTopology();
}

function fitCanvasView() {
  if (currentCanvasMode === '2d' && cy) {
    cy.fit(null, 30);
  } else if (graph3d) {
    graph3d.zoomToFit(1000);
  }
}

function zoomCanvas(factor) {
  if (currentCanvasMode === '2d' && cy) {
    cy.zoom({
      level: cy.zoom() * factor,
      renderedPosition: { x: cy.width() / 2, y: cy.height() / 2 }
    });
  }
}

function toggleGraphView(view) {
  currentGraphView = view;
  const prodBtn = document.getElementById('btn-toggle-prod');
  const sandBtn = document.getElementById('btn-toggle-sandbox');
  if (view === 'prod') {
    prodBtn.className = 'px-2.5 py-1 rounded bg-archival-surface text-archival-ink font-bold shadow-sm transition';
    sandBtn.className = 'px-2.5 py-1 rounded text-archival-muted hover:text-archival-ink font-semibold transition';
  } else {
    sandBtn.className = 'px-2.5 py-1 rounded bg-archival-surface text-archival-ink font-bold shadow-sm transition';
    prodBtn.className = 'px-2.5 py-1 rounded text-archival-muted hover:text-archival-ink font-semibold transition';
  }
  fetchGraphTopology();
}

// ============================================================================
// 5 INTERACTIVE TOP KPI CARDS (CLICK-TO-DRILL-DOWN)
// ============================================================================
function drillDownToxicCombinations() {
  setGraphLayer('layer2');
  switchInspectorTab('vuln');
  expandInspector();
  const title = document.getElementById('inspector-title');
  if (title) title.textContent = 'TOXIC COMBINATION: Multi-Factor Chain';
  const sub = document.getElementById('inspector-subtitle');
  if (sub) sub.textContent = 'Exposure (Ingress) + CVE (Remote Code Execution) + DB Access';
}

function drillDownAttackPaths() {
  if (cy) {
    const attackNodes = cy.nodes('[?is_attack_path]');
    cy.animate({ fit: { eles: attackNodes, padding: 50 }, duration: 800 });
  }
  switchInspectorTab('cypher');
  expandInspector();
  setCypherTemplate('paths');
}

function drillDownOnPathFindings() {
  const modal = document.getElementById('modal-findings');
  if (modal) modal.classList.remove('hidden');
}

function closeFindingsModal() {
  const modal = document.getElementById('modal-findings');
  if (modal) modal.classList.add('hidden');
}

function drillDownSandboxVerified() {
  toggleGraphView('sandbox');
  switchInspectorTab('approval');
  expandInspector();
}

function drillDownSolverLatency() {
  const modal = document.getElementById('modal-solver');
  if (modal) modal.classList.remove('hidden');
}

function closeSolverModal() {
  const modal = document.getElementById('modal-solver');
  if (modal) modal.classList.add('hidden');
}

// ============================================================================
// RETRACTABLE RIGHT INSPECTOR DRAWER
// ============================================================================
function toggleRightInspector() {
  isInspectorCollapsed = !isInspectorCollapsed;
  const drawer = document.getElementById('right-inspector-drawer');
  const label = document.getElementById('inspector-toggle-label');
  
  if (isInspectorCollapsed) {
    drawer.classList.add('collapsed');
    if (label) label.textContent = '« Inspector';
  } else {
    drawer.classList.remove('collapsed');
    if (label) label.textContent = '» Hide Inspector';
  }

  setTimeout(() => {
    if (cy) cy.resize();
    if (graph3d) {
      const c = document.getElementById('3d-graph-container');
      if (c) {
        graph3d.width(c.clientWidth);
        graph3d.height(c.clientHeight);
      }
    }
  }, 300);
}

function expandInspector() {
  if (isInspectorCollapsed) {
    toggleRightInspector();
  }
}

function switchInspectorTab(tabKey) {
  const tabs = ['vuln', 'yaml', 'cypher', 'approval'];
  tabs.forEach(t => {
    const content = document.getElementById(`inspector-tab-${t}`);
    const btn = document.getElementById(`tab-btn-${t}`);
    if (t === tabKey) {
      if (content) content.classList.remove('hidden');
      if (btn) btn.className = 'flex-1 py-2 text-center inspector-tab-active transition';
    } else {
      if (content) content.classList.add('hidden');
      if (btn) btn.className = 'flex-1 py-2 text-center text-archival-muted hover:text-archival-ink transition';
    }
  });
}

function inspectEntity(entity, type) {
  selectedEntity = entity;
  expandInspector();

  const title = document.getElementById('inspector-title');
  const subtitle = document.getElementById('inspector-subtitle');
  const badge = document.getElementById('inspector-entity-badge');

  if (title) title.textContent = entity.name || entity.id;
  if (subtitle) subtitle.textContent = `${entity.label || type} · ${entity.namespace || 'default'}`;
  if (badge) badge.textContent = (entity.label || type).toUpperCase();
}

function inspectRemediationCandidate() {
  switchInspectorTab('yaml');
  expandInspector();
}

// ============================================================================
// INSPECTOR ACTIONS: COPY, DOWNLOAD, VALIDATE, CYPHER, OPERATOR GATE
// ============================================================================
function copyYamlPatch() {
  const code = document.getElementById('yaml-patch-code');
  if (code) {
    navigator.clipboard.writeText(code.textContent);
    alert('NetworkPolicy YAML copied to clipboard!');
  }
}

function downloadYamlPatch() {
  const code = document.getElementById('yaml-patch-code');
  if (!code) return;
  const blob = new Blob([code.textContent], { type: 'text/yaml' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'fjord-networkpolicy.yaml';
  a.click();
}

async function validateWithKubeconform() {
  const code = document.getElementById('yaml-patch-code');
  const statusBox = document.getElementById('kubeconform-status-box');
  if (!code || !statusBox) return;

  statusBox.classList.remove('hidden');
  statusBox.textContent = 'Validating manifest with kubeconform...';
  statusBox.className = 'p-2 rounded arch-border bg-archival-stone text-archival-ink text-[10px] font-bold';

  try {
    const res = await fetch('/api/v1/validate-yaml', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ yaml_content: code.textContent })
    });
    const data = await res.json();
    if (data.valid) {
      statusBox.className = 'p-2 rounded arch-border bg-wiz-emeraldBg text-wiz-emerald text-[10px] font-bold';
      statusBox.textContent = `✓ Validated (${data.tool}): ${data.details}`;
    } else {
      statusBox.className = 'p-2 rounded arch-border bg-wiz-crimsonBg text-wiz-crimson text-[10px] font-bold';
      statusBox.textContent = `✗ Schema Error: ${data.errors.join(', ')}`;
    }
  } catch (err) {
    statusBox.textContent = 'Validation error: ' + err.message;
  }
}

// Interactive Cypher Query Runner
async function executeInteractiveCypher() {
  const input = document.getElementById('cypher-query-input');
  const table = document.getElementById('cypher-result-table');
  const latBadge = document.getElementById('cypher-result-latency');
  if (!input || !table) return;

  table.innerHTML = '<span class="text-archival-muted">Executing query against FalkorDB...</span>';

  try {
    const res = await fetch('/api/v1/cypher', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        query: input.value,
        session_id: currentSessionId,
        graph_name: currentSnapshotSha
      })
    });
    const data = await res.json();

    if (latBadge) latBadge.textContent = `${data.latency_ms || 0} ms`;

    if (data.status === 'SUCCESS') {
      if (data.rows.length === 0) {
        table.innerHTML = '<span class="text-archival-faint">Query succeeded. 0 rows returned.</span>';
        return;
      }

      let html = '<table class="w-full text-left text-[9px] border-collapse"><thead class="bg-archival-stone arch-border-b font-bold"><tr>';
      data.columns.forEach(col => html += `<th class="p-1">${col}</th>`);
      html += '</tr></thead><tbody class="divide-y divide-archival-border">';
      data.rows.slice(0, 15).forEach(row => {
        html += '<tr>';
        row.forEach(val => html += `<td class="p-1 truncate max-w-[120px] font-mono">${val}</td>`);
        html += '</tr>';
      });
      html += '</tbody></table>';
      table.innerHTML = html;
    } else {
      table.innerHTML = `<span class="text-wiz-crimson font-bold">Error: ${data.error}</span>`;
    }

  } catch (err) {
    table.innerHTML = `<span class="text-wiz-crimson">Request failed: ${err.message}</span>`;
  }
}

function setCypherTemplate(type) {
  const input = document.getElementById('cypher-query-input');
  if (!input) return;
  if (type === 'paths') {
    input.value = "MATCH (s:VirtualSource)-[r:EXPLOIT_STEP*]->(d:VirtualSink) RETURN r";
  } else if (type === 'cves') {
    input.value = "MATCH (w:Workload)-[:HAS_VULNERABILITY]->(v) RETURN w.id, v.id, v.severity";
  }
  executeInteractiveCypher();
}

// Operator Decision Actions
async function approveAndCommitRemediation() {
  if (!currentSessionId || !currentUiToken) {
    alert('No active session token available.');
    return;
  }
  const btn = document.getElementById('btn-approve-commit');
  if (btn) btn.textContent = 'COMMITTING REMEDIATION...';

  try {
    const res = await fetch('/api/v1/operator/decision', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        session_id: currentSessionId,
        candidate_set_id: 'cset_isolated_db',
        decision: 'APPROVE',
        ui_token: currentUiToken,
      })
    });
    const data = await res.json();
    if (btn) btn.textContent = '✓ REMEDIATION COMMITTED';
    alert('Operator decision approved! NetworkPolicy patch committed to cluster.');
  } catch (err) {
    alert('Commit error: ' + err.message);
  }
}

async function vetoAndResolveCandidate() {
  if (!currentSessionId || !currentUiToken) return;
  const btn = document.getElementById('btn-veto-resolve');
  if (btn) btn.textContent = 'RECORDING VETO & RE-SOLVING...';

  try {
    const res = await fetch('/api/v1/operator/veto-and-resolve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        session_id: currentSessionId,
        candidate_set_id: 'cset_isolated_db',
        reason: 'Operator vetoed isolate-crown-jewel-db candidate',
        ui_token: currentUiToken,
      })
    });
    const data = await res.json();
    if (btn) btn.textContent = '✓ ALTERNATIVE RESOLVED';
    alert(`Candidate vetoed! New alternative candidate generated: ${data.new_candidate_set_id}`);
    await fetchGraphTopology();
  } catch (err) {
    alert('Veto error: ' + err.message);
  }
}

// ============================================================================
// RUN REMEDIATION PIPELINE
// ============================================================================
async function runRemediationPipeline() {
  if (!currentSessionId) return;
  try {
    const res = await fetch('/api/v1/agent/run', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ session_id: currentSessionId })
    });
    const data = await res.json();
    
    // Switch to sandbox view to display severed edges
    toggleGraphView('sandbox');

    // Update Pill
    const pill = document.getElementById('remediation-status-pill');
    if (pill) pill.textContent = data.status || 'VERIFIED_IN_MODEL';

  } catch (err) {
    console.error('Error running remediation pipeline:', err);
  }
}

// ============================================================================
// CHATBOT CONSOLE & COPILOT
// ============================================================================
async function handleChatSubmit(e) {
  e.preventDefault();
  const input = document.getElementById('chat-input');
  if (!input || !input.value.trim()) return;
  const msg = input.value.trim();
  input.value = '';
  await sendChatMessage(msg);
}

function sendQuickPrompt(promptText) {
  switchView('copilot');
  sendChatMessage(promptText);
}

async function sendChatMessage(msg) {
  const thread = document.getElementById('chat-messages');
  if (!thread) return;

  // Append User Bubble
  const userDiv = document.createElement('div');
  userDiv.className = 'p-3 rounded arch-border bg-archival-stone/40 ml-6 space-y-1';
  userDiv.innerHTML = `
    <div class="flex items-center justify-between text-[10px] text-archival-faint font-bold">
      <span class="text-archival-ink">SECURITY OPERATOR</span>
      <span>${new Date().toLocaleTimeString()}</span>
    </div>
    <div class="text-archival-ink">${msg}</div>
  `;
  thread.appendChild(userDiv);
  thread.scrollTop = thread.scrollHeight;

  // Append Pending Agent Bubble
  const agentDiv = document.createElement('div');
  agentDiv.className = 'p-3 rounded arch-border bg-archival-surface mr-6 space-y-1.5';
  agentDiv.innerHTML = `
    <div class="flex items-center justify-between text-[10px] text-archival-faint font-bold">
      <span class="text-wiz-emerald">FJORD AGENT</span>
      <span class="text-wiz-blue animate-pulse">ANALYZING FALKORDB GRAPH...</span>
    </div>
    <div class="text-archival-muted text-[11px] font-mono">Dispatched model reasoning turn...</div>
  `;
  thread.appendChild(agentDiv);
  thread.scrollTop = thread.scrollHeight;

  try {
    const res = await fetch('/api/v1/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        session_id: currentSessionId,
        message: msg,
      })
    });
    const data = await res.json();

    // Render Agent Reply
    let replyHtml = `<p class="leading-relaxed whitespace-pre-wrap">${data.reply}</p>`;
    
    // Add Tool Badges if any
    if (data.tools_called && data.tools_called.length > 0) {
      replyHtml += '<div class="mt-2 pt-2 arch-border-t space-y-1 text-[10px] text-archival-faint font-bold">';
      replyHtml += '<div>EXECUTED FASTMCP TOOLS:</div><div class="flex flex-wrap gap-1">';
      data.tools_called.forEach(t => {
        replyHtml += `<span class="px-1.5 py-0.5 rounded bg-archival-stone arch-border text-wiz-blue">${t.tool} (${t.latency_ms || 5}ms)</span>`;
      });
      replyHtml += '</div></div>';
    }

    agentDiv.innerHTML = `
      <div class="flex items-center justify-between text-[10px] text-archival-faint font-bold">
        <span class="text-wiz-emerald">FJORD AGENT</span>
        <span>${new Date().toLocaleTimeString()}</span>
      </div>
      <div class="text-archival-ink space-y-1.5">${replyHtml}</div>
    `;

    // Add to Flight Trace Feed
    addFlightTrace(msg, data.tools_called || []);

  } catch (err) {
    agentDiv.innerHTML = `<span class="text-wiz-crimson font-bold">Error communicating with agent: ${err.message}</span>`;
  }
}

function addFlightTrace(prompt, tools) {
  const feed = document.getElementById('flight-trace-feed');
  if (!feed) return;
  tools.forEach(t => {
    const item = document.createElement('div');
    item.className = 'p-2 rounded arch-border bg-archival-bg space-y-1';
    item.innerHTML = `
      <div class="flex justify-between text-[9px] text-archival-faint">
        <span class="font-bold text-archival-ink">${t.tool}</span>
        <span class="text-wiz-emerald font-bold">${t.latency_ms || 4} ms</span>
      </div>
      <div class="text-[10px] text-archival-muted truncate">FalkorDB query ro_query ${currentSnapshotSha}</div>
    `;
    feed.prepend(item);
  });
}

// ============================================================================
// CONNECTORS & MCP VIEW
// ============================================================================
async function syncLiveK8sCluster() {
  const btn = document.getElementById('btn-k8s-sync');
  if (btn) btn.textContent = 'SYNCING K8S CLUSTER...';

  try {
    const res = await fetch('/api/v1/connectors/k8s-sync', { method: 'POST' });
    const data = await res.json();
    
    currentSessionId = data.session_id;
    currentSnapshotSha = data.snapshot_sha;
    currentUiToken = data.ui_token;

    addToScanHistory(data.cluster_type, currentSnapshotSha);
    await fetchGraphTopology();

    if (btn) btn.textContent = '✓ CLUSTER SYNCED';
    alert(`${data.message}\nCluster: ${data.cluster_type} (${data.namespace})`);
  } catch (err) {
    alert('K8s sync failed: ' + err.message);
  }
}

async function testMCPTool(toolName, args) {
  const out = document.getElementById('mcp-test-output');
  const lat = document.getElementById('mcp-test-latency');
  if (out) out.textContent = `Executing ${toolName}...`;

  try {
    const res = await fetch('/api/v1/mcp/execute', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        tool_name: toolName,
        arguments: args.snapshot_sha === 'current' ? { snapshot_sha: currentSnapshotSha, candidate_set_id: 'cset_isolated_db' } : (args.graph_name ? args : { ...args, graph_name: currentSnapshotSha })
      })
    });
    const data = await res.json();
    if (lat) lat.textContent = 'SUCCESS';
    if (out) out.textContent = JSON.stringify(data, null, 2);
  } catch (err) {
    if (out) out.textContent = 'Execution Error: ' + err.message;
  }
}

// ============================================================================
// UPLOAD MANIFEST MODAL
// ============================================================================
function openUploadModal() {
  const m = document.getElementById('modal-upload');
  if (m) m.classList.remove('hidden');
}

function closeUploadModal() {
  const m = document.getElementById('modal-upload');
  if (m) m.classList.add('hidden');
}

async function submitManifestUpload() {
  const name = document.getElementById('upload-filename').value;
  const content = document.getElementById('upload-content').value;
  if (!content.trim()) {
    alert('Please paste manifest content.');
    return;
  }

  try {
    const res = await fetch('/api/v1/upload', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ filename: name, yaml_content: content })
    });
    const data = await res.json();

    currentSessionId = data.session_id;
    currentSnapshotSha = data.snapshot_sha;
    currentUiToken = data.ui_token;

    addToScanHistory(`Upload: ${name}`, currentSnapshotSha);
    closeUploadModal();
    await fetchGraphTopology();
    alert(`Manifest '${name}' successfully ingested into FalkorDB graph ${currentSnapshotSha}!`);
  } catch (err) {
    alert('Upload failed: ' + err.message);
  }
}

// ============================================================================
// SETTINGS & MULTI-PROVIDER LLM
// ============================================================================
function handleProviderChange() {
  const prov = document.getElementById('setting-provider').value;
  const baseEl = document.getElementById('setting-base-url');
  const modEl = document.getElementById('setting-model');

  if (prov === 'Google Gemini') {
    if (baseEl) baseEl.value = 'https://generativelanguage.googleapis.com';
    if (modEl) modEl.value = 'gemini-3.8-flash';
  } else if (prov.includes('OpenAI')) {
    if (baseEl) baseEl.value = 'https://api.openai.com/v1';
    if (modEl) modEl.value = 'gpt-4o';
  } else if (prov.includes('Anthropic')) {
    if (baseEl) baseEl.value = 'https://api.anthropic.com/v1';
    if (modEl) modEl.value = 'claude-3-7-sonnet';
  }
}

async function saveLLMConfiguration() {
  const prov = document.getElementById('setting-provider').value;
  const model = document.getElementById('setting-model').value;
  const baseUrl = document.getElementById('setting-base-url').value;
  const key = document.getElementById('setting-api-key').value;

  try {
    const res = await fetch('/api/v1/settings/llm', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        provider: prov,
        model: model,
        base_url: baseUrl,
        api_key: key
      })
    });
    const data = await res.json();
    alert(data.message);
    await fetchSystemHealth();
  } catch (err) {
    alert('Failed to save settings: ' + err.message);
  }
}

async function clearOperatorVetoes() {
  try {
    const res = await fetch('/api/v1/settings/clear-vetoes', { method: 'POST' });
    const data = await res.json();
    alert(data.message || 'Cleared operator veto records.');
  } catch (err) {
    alert('Clear failed: ' + err.message);
  }
}

// ============================================================================
// NAVIGATION & ACCORDIONS
// ============================================================================
function switchView(viewKey) {
  const views = ['dashboard', 'graph', 'copilot', 'connectors', 'settings'];
  views.forEach(v => {
    const el = document.getElementById(`view-${v}`);
    const navBtn = document.getElementById(`nav-${v}`);
    if (v === viewKey) {
      if (el) el.classList.remove('hidden');
      if (navBtn) navBtn.className = 'w-full text-left px-3.5 py-2 flex items-center space-x-2.5 transition nav-item-active';
    } else {
      if (el) el.classList.add('hidden');
      if (navBtn) navBtn.className = 'w-full text-left px-3.5 py-2 flex items-center space-x-2.5 transition text-archival-cream/70 hover:text-archival-cream hover:bg-obsidian-850';
    }
  });

  if (viewKey === 'graph') {
    setTimeout(() => {
      const fullCanvas = document.getElementById('full-topology-canvas');
      if (fullCanvas && cy) {
        cytoscape({
          container: fullCanvas,
          elements: rawGraphData.cytoscape_elements || [],
          style: cy.style().json(),
          layout: { name: 'breadthfirst', directed: true, spacingFactor: 1.3 }
        });
      }
    }, 100);
  }
}

function toggleSection(sectionId) {
  const el = document.getElementById(sectionId);
  const chevron = document.getElementById('fixtures-chevron');
  if (el) {
    el.classList.toggle('hidden');
    if (chevron) {
      chevron.style.transform = el.classList.contains('hidden') ? 'rotate(-90deg)' : 'rotate(0deg)';
    }
  }
}

function setupResizeObserver() {
  window.addEventListener('resize', () => {
    if (cy) cy.resize();
    if (graph3d) {
      const c = document.getElementById('3d-graph-container');
      if (c) {
        graph3d.width(c.clientWidth);
        graph3d.height(c.clientHeight);
      }
    }
  });
}
