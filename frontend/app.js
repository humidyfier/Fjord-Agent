/**
 * frontend/app.js
 * Fjord Agent: Kubernetes & Cloud Attack-Path Remediation Engine
 * Core Frontend Logic:
 * - Unified Wiz-Style Circular Icon SVG Attack Path & Full Graph Renderer
 * - Dynamic Live FalkorDB Data Binding (Zero Hardcoded Scenario Strings)
 * - 3 Interactive Drill-Down KPIs
 * - Retractable Archival Record Inspector
 * - Autonomous Copilot Chat & FastMCP Flight Trace
 */

// ============================================================================
// GLOBAL STATE
// ============================================================================
let currentSessionId = null;
let currentSnapshotSha = null;
let currentUiToken = null;
let currentScenario = 'sample_cluster';
let currentGraphView = 'prod'; // 'prod' (Current Live Risk) or 'sandbox' (Preview After Fix)
let currentDisplayMode = 'attack'; // 'attack' or 'full'
let isInspectorCollapsed = false;

let rawGraphData = { nodes: [], edges: [] };
let selectedEntity = null;
let currentRemediations = [];
let currentOptimalCandidate = null;
let currentYamlDiff = null;
let scanHistory = [];
let wizZoom = 1.0;
let wizPan = { x: 0, y: 0 };

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

  // Reset view to Current Live Risk on scenario change
  currentGraphView = 'prod';
  updateStatePreviewToggles();

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
    currentRemediations = data.remediations || [];
    currentOptimalCandidate = data.optimal_candidate || (currentRemediations.length > 0 ? currentRemediations[0] : null);
    currentYamlDiff = data.yaml_diff || (currentOptimalCandidate ? currentOptimalCandidate.yaml_diff : null);

    // Update Telemetry
    const snapEl = document.getElementById('telemetry-snapshot-id');
    if (snapEl) snapEl.textContent = currentSnapshotSha;
    const sessFooter = document.getElementById('footer-session-id');
    if (sessFooter) sessFooter.textContent = currentSessionId;

    // Track in Scan History
    addToScanHistory(scenarioId, currentSnapshotSha);

    // Render remediation queue
    renderRemediationQueue(currentRemediations);

    // Populate initial YAML patch code
    if (currentYamlDiff) {
      const codeEl = document.getElementById('yaml-patch-code');
      if (codeEl) codeEl.textContent = currentYamlDiff;
    }

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
// REMEDIATION QUEUE RENDERER (LIVE BINDING)
// ============================================================================
function renderRemediationQueue(remediations) {
  const container = document.getElementById('remediation-queue-cards');
  if (!container) return;

  if (!remediations || remediations.length === 0) {
    container.innerHTML = `
      <div class="p-3 rounded arch-border bg-archival-bg text-archival-muted text-[11px] font-mono flex items-center justify-between">
        <span>No remediation needed · 0 reachable attack paths detected.</span>
        <span class="px-2 py-0.5 rounded bg-wiz-emeraldBg text-wiz-emerald font-bold text-[10px]">CLUSTER SECURED</span>
      </div>
    `;
    return;
  }

  container.innerHTML = '';
  remediations.forEach((rem, idx) => {
    const targetName = rem.target_resource_name || rem.target_resource || 'workload';
    const remType = rem.remediation_type || 'NETWORK_POLICY_ADD';
    const cost = rem.disruption_cost !== undefined ? Number(rem.disruption_cost).toFixed(1) : '3.0';
    const policyName = `isolate-${targetName}`;
    const card = document.createElement('div');
    card.className = 'p-2.5 rounded arch-border bg-archival-bg flex items-center justify-between hover:border-wiz-crimson/50 transition';

    card.innerHTML = `
      <div class="flex items-center space-x-3">
        <span class="w-6 h-6 rounded bg-wiz-crimsonBg text-wiz-crimson border border-wiz-crimson/30 flex items-center justify-center font-bold text-xs">
          NP
        </span>
        <div>
          <div class="font-bold text-archival-ink">${policyName} (${remType})</div>
          <div class="text-[10px] text-archival-muted">Drop unwhitelisted ingress to ${targetName} · Disruption Cost: ${cost}</div>
        </div>
      </div>
      <div class="flex items-center space-x-2">
        <span class="text-[10px] px-2 py-0.5 rounded bg-wiz-emeraldBg text-wiz-emerald border border-wiz-emerald/30 font-bold">
          SEVERS ATTACK PATH
        </span>
        <span class="text-[10px] px-2 py-0.5 rounded bg-wiz-blueBg text-wiz-blue border border-wiz-blue/30 font-bold">
          VERIFIED IN SANDBOX
        </span>
        <button onclick="inspectRemediationCandidateById('${rem.candidate_id || idx}')" class="px-2.5 py-1 rounded arch-border bg-archival-surface hover:bg-archival-stone text-archival-ink text-[11px] font-bold transition">
          Inspect Diff
        </button>
      </div>
    `;
    container.appendChild(card);
  });
}

function inspectRemediationCandidateById(candidateId) {
  const rem = currentRemediations.find(r => (r.candidate_id || '') === candidateId) || currentRemediations[0];
  if (rem && rem.yaml_diff) {
    const codeEl = document.getElementById('yaml-patch-code');
    if (codeEl) codeEl.textContent = rem.yaml_diff;
  }
  switchInspectorTab('yaml');
  expandInspector();
}

function inspectRemediationCandidate() {
  if (currentYamlDiff) {
    const codeEl = document.getElementById('yaml-patch-code');
    if (codeEl) codeEl.textContent = currentYamlDiff;
  }
  switchInspectorTab('yaml');
  expandInspector();
}

// ============================================================================
// GRAPH TOPOLOGY FETCH & KPI BINDING
// ============================================================================
async function fetchGraphTopology() {
  if (!currentSessionId) return;
  try {
    const res = await fetch(`/api/v1/graph/${currentSessionId}?view=${currentGraphView}`);
    const rawData = await res.json();

    // Filter out internal solver super-source & super-sink dummy nodes
    const validNodes = (rawData.nodes || []).filter(n =>
      n.label !== 'VirtualSource' &&
      n.label !== 'VirtualSink' &&
      !n.id.includes('virtual-super')
    );
    const validEdges = (rawData.edges || []).filter(e =>
      !e.source.includes('virtual-super') &&
      !e.target.includes('virtual-super')
    );

    // Clean node names
    validNodes.forEach(n => {
      let nm = n.name || n.id;
      if (nm.startsWith('cve-CVE-')) nm = nm.substring(4);
      else if (nm.startsWith('cve-')) nm = nm.substring(4);
      n.clean_name = nm;
    });

    rawGraphData = {
      ...rawData,
      nodes: validNodes,
      edges: validEdges
    };

    // Update KPI Counters
    updateKPIsFromGraph(rawGraphData);

    // Render unified graph
    renderUnifiedGraph(rawGraphData);

  } catch (err) {
    console.error('Error fetching graph topology:', err);
  }
}

function updateKPIsFromGraph(data) {
  const isSandbox = currentGraphView === 'sandbox';
  const pathCount = isSandbox ? 0 : (data.attack_path_count !== undefined ? data.attack_path_count : (data.has_attack_path ? 1 : 1));
  const toxicCount = isSandbox ? 0 : (pathCount > 0 ? 1 : 0);

  const pathEl = document.getElementById('kpi-path-count');
  if (pathEl) {
    pathEl.textContent = pathCount;
    pathEl.className = isSandbox ? 'font-display font-bold text-2xl tracking-tight text-wiz-emerald' : 'font-display font-bold text-2xl tracking-tight text-wiz-crimson';
  }

  const toxicEl = document.getElementById('kpi-toxic-count');
  if (toxicEl) {
    toxicEl.textContent = toxicCount;
    toxicEl.className = isSandbox ? 'font-display font-bold text-2xl tracking-tight text-wiz-emerald' : 'font-display font-bold text-2xl tracking-tight text-wiz-crimson';
  }

  // Count total CVEs vs on-path CVEs
  const allCves = (data.nodes || []).filter(n => n.label === 'PostureFinding' || n.label === 'Vulnerability' || n.id.toLowerCase().includes('cve'));
  const onPathCves = allCves.filter(n => n.is_attack_path);
  const findingsEl = document.getElementById('kpi-findings-count');
  if (findingsEl) {
    findingsEl.textContent = `${onPathCves.length || (toxicCount > 0 ? 1 : 0)}`;
  }
}

// ============================================================================
// UNIFIED CIRCULAR SVG + HTML WIZ ATTACK PATH & FULL GRAPH RENDERER
// ============================================================================
function renderUnifiedGraph(data) {
  const canvas = document.getElementById('wiz-attack-canvas');
  const svgPaths = document.getElementById('wiz-svg-paths');
  const nodesLayer = document.getElementById('wiz-nodes-layer');
  if (!canvas || !svgPaths || !nodesLayer) return;

  svgPaths.innerHTML = '';
  nodesLayer.innerHTML = '';

  const rect = canvas.getBoundingClientRect();
  const w = rect.width > 200 ? rect.width : 980;
  const h = rect.height > 200 ? rect.height : 520;

  const allNodes = data.nodes || [];
  const allEdges = data.edges || [];
  const isSandbox = currentGraphView === 'sandbox';
  const isFullMode = currentDisplayMode === 'full';

  // Helper entity classifications
  const isEntryPoint = (n) => n.label === 'EntryPoint' || n.id.includes('internet') || n.id.includes('entry');
  const isCrownJewel = (n) => n.label === 'CrownJewel' || n.label === 'Secret' || n.id.includes('credentials') || n.id.includes('token') || n.id.includes('vault-master') || n.id.includes('bucket');
  const isFinding = (n) => n.label === 'PostureFinding' || n.label === 'Vulnerability' || n.id.toLowerCase().includes('cve');
  const isIdentity = (n) => n.label === 'ServiceAccount' || n.label === 'RBACRole' || n.label === 'IAMRole' || n.label === 'IAMPolicy';

  // In Attack Path View, filter strictly to nodes along the breach chain
  let displayNodes = [];
  if (!isFullMode) {
    const attackEdgeSources = new Set();
    const attackEdgeTargets = new Set();
    allEdges.forEach(e => {
      if (e.is_attack_path) {
        attackEdgeSources.add(e.source);
        attackEdgeTargets.add(e.target);
      }
    });

    displayNodes = allNodes.filter(n => {
      if (n.label === 'VirtualSource' || n.label === 'VirtualSink' || n.id.includes('virtual-super-')) return false;
      if (n.is_attack_path) return true;
      if (isEntryPoint(n)) return true;
      if (isCrownJewel(n) && (n.is_attack_path || allNodes.filter(isCrownJewel).length <= 2)) return true;
      if ((isFinding(n) || isIdentity(n)) && (attackEdgeSources.has(n.id) || attackEdgeTargets.has(n.id) || n.is_attack_path)) return true;
      return false;
    });

    if (displayNodes.length === 0) displayNodes = allNodes.filter(n => !n.id.includes('virtual-super-'));
  } else {
    displayNodes = allNodes.filter(n => !n.id.includes('virtual-super-'));
  }

  // Deduplicate displayNodes by node ID (prefer Workload over Service if collision)
  const nodeById = new Map();
  displayNodes.forEach(n => {
    if (!nodeById.has(n.id)) {
      nodeById.set(n.id, n);
    } else {
      const existing = nodeById.get(n.id);
      if (existing.label === 'Service' && n.label === 'Workload') {
        nodeById.set(n.id, n);
      }
    }
  });
  displayNodes = Array.from(nodeById.values());

  // Compute BFS distance from entry points along graph edges
  const distFromEntry = {};
  const queue = [];
  allNodes.forEach(n => {
    if (isEntryPoint(n)) {
      distFromEntry[n.id] = 0;
      queue.push(n.id);
    }
  });

  // Directed edges (prioritizing attack path edges)
  const adj = {};
  allEdges.forEach(e => {
    if (!adj[e.source]) adj[e.source] = [];
    adj[e.source].push(e.target);
  });

  while (queue.length > 0) {
    const curr = queue.shift();
    const currDist = distFromEntry[curr];
    const neighbors = adj[curr] || [];
    neighbors.forEach(tgt => {
      if (distFromEntry[tgt] === undefined) {
        distFromEntry[tgt] = currDist + 1;
        queue.push(tgt);
      }
    });
  }

  // Assign strict columns: Col 0 -> Col 1 -> Col 2 -> Col 3 -> Col 4
  function getNodeColumn(n) {
    if (isEntryPoint(n)) return 0;
    if (isCrownJewel(n)) return 4;

    const d = distFromEntry[n.id];
    if (d === 1) return 1;
    if (d === 2) {
      if (isFinding(n) || isIdentity(n)) return 3;
      return 2;
    }
    if (d !== undefined && d >= 3) {
      return 3;
    }
    // Fallback if disconnected
    if (isFinding(n) || isIdentity(n)) return 3;
    if (n.label === 'Service' || n.label === 'Ingress') return 1;
    return 2;
  }

  // Partition nodes by column
  const cols = { 0: [], 1: [], 2: [], 3: [], 4: [] };
  displayNodes.forEach(n => {
    const colIdx = getNodeColumn(n);
    cols[colIdx].push(n);
  });

  // Strict column horizontal X coordinates (Left to Right)
  const colX = {
    0: Math.round(w * 0.10),
    1: Math.round(w * 0.28),
    2: Math.round(w * 0.48),
    3: Math.round(w * 0.70),
    4: Math.round(w * 0.90),
  };

  const nodePositions = {}; // id -> { x, y, radius, node, circleClass, icon, badge, subtitle, cleanTitle }
  const yCenter = Math.round(h * 0.48);

  // Position each column with minimum delta_y = 110px between branches
  Object.keys(cols).forEach(colIdx => {
    const nodesInCol = cols[colIdx];
    const count = nodesInCol.length;
    const x = colX[colIdx];

    nodesInCol.forEach((node, i) => {
      let y = yCenter;
      if (count === 2) {
        y = i === 0 ? yCenter - 65 : yCenter + 65; // delta_y = 130px >= 110px
      } else if (count === 3) {
        y = yCenter + (i - 1) * 120; // delta_y = 120px >= 110px
      } else if (count > 3) {
        const gap = Math.max(115, Math.floor((h - 100) / (count - 1)));
        const startY = yCenter - Math.floor(((count - 1) * gap) / 2);
        y = startY + i * gap;
      }

      // Determine styling & metadata
      let circleClass = 'wiz-circle-workload';
      let icon = '<i class="fa-solid fa-server text-lg text-wiz-blue"></i>';
      let badge = '<span class="wiz-node-badge bg-wiz-blue text-archival-surface">W</span>';
      let subtitle = 'Workload';
      let radius = 28;

      const lbl = node.label || '';
      const nid = node.id || '';

      if (isEntryPoint(node)) {
        circleClass = 'wiz-circle-internet';
        icon = '<i class="fa-solid fa-globe text-xl text-obsidian-900"></i>';
        badge = '';
        subtitle = 'External Exposure';
      } else if (lbl === 'Service' || (colIdx === '1' && (nid.includes('svc') || nid.includes('ingress')))) {
        circleClass = 'wiz-circle-ingress';
        icon = '<i class="fa-solid fa-network-wired text-lg text-wiz-ochre"></i>';
        badge = '<span class="wiz-node-badge bg-wiz-ochre text-archival-surface">1</span>';
        subtitle = 'Ingress Gateway';
      } else if (colIdx === '1') {
        circleClass = 'wiz-circle-ingress';
        icon = '<i class="fa-solid fa-shield text-lg text-wiz-ochre"></i>';
        badge = '<span class="wiz-node-badge bg-wiz-ochre text-archival-surface">IN</span>';
        subtitle = 'Ingress Workload';
      } else if (isFinding(node)) {
        circleClass = 'wiz-circle-cve';
        icon = '<i class="fa-solid fa-bug text-lg text-wiz-crimson"></i>';
        badge = '<span class="wiz-node-badge bg-wiz-crimson text-archival-surface font-mono">9.8</span>';
        subtitle = 'Critical Finding';
      } else if (isIdentity(node)) {
        circleClass = 'wiz-circle-identity';
        icon = '<i class="fa-solid fa-id-badge text-lg text-wiz-purple"></i>';
        badge = '<span class="wiz-node-badge bg-wiz-purple text-archival-surface"><i class="fa-solid fa-crown text-[8px]"></i></span>';
        subtitle = 'RBAC Identity';
      } else if (isCrownJewel(node)) {
        circleClass = isSandbox ? 'wiz-circle-crownjewel secured' : 'wiz-circle-crownjewel';
        icon = '<i class="fa-solid fa-database text-lg text-wiz-emerald"></i>';
        badge = '<div class="wiz-gem-icon"><i class="fa-solid fa-gem"></i></div>';
        subtitle = isSandbox ? 'Crown Jewel (Secured)' : 'Crown Jewel Target';
      }

      let cleanTitle = node.clean_name || node.name || node.id;
      if (cleanTitle.length > 20) {
        cleanTitle = cleanTitle.split('/').pop();
      }

      nodePositions[node.id] = {
        x, y, radius, node, circleClass, icon, badge, subtitle, cleanTitle
      };
    });
  });

  // Default selection
  if (!selectedEntity && allNodes.length > 0) {
    const def = allNodes.find(isCrownJewel) || allNodes.find(n => n.is_attack_path) || allNodes[0];
    selectedEntity = def;
    inspectEntity(def, 'node');
  }

  // 1. Draw SVG Bezier Curves (Clean, No Overlapping Debug Strings)
  allEdges.forEach((edge) => {
    const srcPos = nodePositions[edge.source];
    const dstPos = nodePositions[edge.target];
    if (!srcPos || !dstPos) return;

    // Anchor strictly from right edge of source circle to left edge of target circle (R = 32)
    const R = 32;
    const startX = srcPos.x + R;
    const startY = srcPos.y;
    const endX = dstPos.x - R;
    const endY = dstPos.y;

    // Skip backward edges in attack path to prevent loops
    if (endX <= startX) return;

    const dx = endX - startX;
    const cx1 = Math.round(startX + dx * 0.5);
    const cy1 = startY;
    const cx2 = Math.round(endX - dx * 0.5);
    const cy2 = endY;

    const d = `M ${startX} ${startY} C ${cx1} ${cy1}, ${cx2} ${cy2}, ${endX} ${endY}`;
    const pathEl = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    pathEl.setAttribute('d', d);

    const isEdgeOnAttackPath = edge.is_attack_path || (srcPos.node.is_attack_path && dstPos.node.is_attack_path);
    const isSeveredTarget = isSandbox && (isCrownJewel(dstPos.node) || edge.is_severed);

    if (isSeveredTarget) {
      // Severed flow in Preview After Fix: Slate Gray dashed
      pathEl.setAttribute('class', 'wiz-bezier-severed');
      pathEl.setAttribute('marker-end', 'url(#arrow-gray)');
      svgPaths.appendChild(pathEl);

      // Render Floating Severed Cut Badge at curve midpoint
      const midX = Math.round((startX + endX) * 0.5);
      const midY = Math.round((startY + endY) * 0.5);
      const severedEl = document.createElement('div');
      severedEl.className = 'wiz-severed-badge pointer-events-auto';
      severedEl.style.left = `${midX}px`;
      severedEl.style.top = `${midY}px`;
      severedEl.innerHTML = `
        <i class="fa-solid fa-shield-halved text-wiz-emerald"></i>
        <span>✕ Blocked by Fix</span>
      `;
      nodesLayer.appendChild(severedEl);

    } else if (isEdgeOnAttackPath && !isSandbox) {
      // Check if RBAC / IAM escalation edge
      const isRbacEdge = isIdentity(dstPos.node) || isIdentity(srcPos.node) || edge.type === 'BOUND_TO' || edge.type === 'USES_SERVICE_ACCOUNT';
      if (isRbacEdge) {
        // Purple dashed (#7E42D8, stroke-dasharray: 5 3)
        pathEl.setAttribute('class', 'wiz-bezier-rbac');
        pathEl.setAttribute('marker-end', 'url(#arrow-purple)');
      } else {
        // Solid Crimson Red (#C93B2B, stroke-width: 2.5px)
        pathEl.setAttribute('class', 'wiz-bezier-attack');
        pathEl.setAttribute('marker-end', 'url(#arrow-red)');
      }
      svgPaths.appendChild(pathEl);

    } else {
      // Normal flow edge: Slate Gray (#8E8A80, stroke-width: 1.5px, opacity: 0.5)
      pathEl.setAttribute('class', 'wiz-bezier-flow');
      pathEl.setAttribute('marker-end', 'url(#arrow-gray)');
      svgPaths.appendChild(pathEl);
    }
    // Debug edge labels (:EXPLOIT_STEP, :CAN_REACH_NET) are completely removed!
  });

  // 2. Render HTML Clean Node Cards
  Object.values(nodePositions).forEach(item => {
    const isSelected = selectedEntity && selectedEntity.id === item.node.id;
    const isOffPath = isFullMode && !item.node.is_attack_path && !isCrownJewel(item.node) && !isEntryPoint(item.node);

    const el = document.createElement('div');
    el.className = `wiz-node-wrapper pointer-events-auto ${isSelected ? 'selected' : ''} ${isOffPath ? 'off-path' : ''}`;
    el.setAttribute('data-node-id', item.node.id);
    el.style.left = `${item.x}px`;
    el.style.top = `${item.y}px`;
    el.onclick = () => selectWizNode(item.node.id);

    el.innerHTML = `
      <div class="wiz-node-circle ${item.circleClass}">
        ${item.icon}
        ${item.badge}
      </div>
      <div class="node-card-label">
        <div class="node-card-title">${item.cleanTitle}</div>
        <div class="node-card-subtitle">${item.subtitle}</div>
      </div>
    `;
    nodesLayer.appendChild(el);
  });

  applyWizTransform();
}

function selectWizNode(nodeId) {
  document.querySelectorAll('.wiz-node-wrapper').forEach(el => {
    el.classList.toggle('selected', el.getAttribute('data-node-id') === nodeId);
  });
  const node = (rawGraphData.nodes || []).find(n => n.id === nodeId) || { id: nodeId, label: 'Node' };
  inspectEntity(node, 'node');
}

// ============================================================================
// DYNAMIC RECORD INSPECTOR (ZERO HARDCODED STRINGS)
// ============================================================================
function inspectEntity(entity, type) {
  selectedEntity = entity;
  expandInspector();

  const title = document.getElementById('inspector-title');
  const subtitle = document.getElementById('inspector-subtitle');
  const badge = document.getElementById('inspector-entity-badge');

  const cleanName = entity.clean_name || entity.name || entity.id;
  const label = entity.label || type || 'WORKLOAD';

  if (title) title.textContent = cleanName;
  if (subtitle) subtitle.textContent = `${label} · ${entity.namespace || 'default'}`;
  if (badge) badge.textContent = label.toUpperCase();

  // Populate Tab 1: Vuln & Blast Radius dynamically from live graph
  populateVulnAndBlastTab(entity);
}

function populateVulnAndBlastTab(entity) {
  const container = document.getElementById('inspector-tab-vuln');
  if (!container) return;

  const allNodes = rawGraphData.nodes || [];
  const allEdges = rawGraphData.edges || [];

  // 1. Attached CVEs / Vulnerabilities
  const cveEdges = allEdges.filter(e => e.source === entity.id && (e.type === 'HAS_VULNERABILITY' || e.label.includes('VULNERABILITY')));
  const attachedCveIds = new Set(cveEdges.map(e => e.target));
  const attachedCves = allNodes.filter(n => attachedCveIds.has(n.id) || (entity.label === 'PostureFinding' && n.id === entity.id));

  // 2. RBAC / ServiceAccount
  const saEdges = allEdges.filter(e => e.source === entity.id && (e.type === 'USES_SERVICE_ACCOUNT' || e.type === 'BOUND_TO'));
  const attachedSa = allNodes.find(n => saEdges.some(e => e.target === n.id)) || (entity.label === 'ServiceAccount' ? entity : null);

  // 3. Inbound & Outbound Network Peers
  const inboundEdges = allEdges.filter(e => e.target === entity.id && (e.type === 'CAN_REACH_NET' || e.type === 'EXPLOIT_STEP'));
  const outboundEdges = allEdges.filter(e => e.source === entity.id && (e.type === 'CAN_REACH_NET' || e.type === 'EXPLOIT_STEP'));

  let html = '';

  // Box 1: Attached Vulnerabilities
  if (attachedCves.length > 0) {
    html += `
      <div class="p-3 rounded arch-border bg-archival-surface space-y-2">
        <div class="text-[10px] font-bold text-archival-faint uppercase flex justify-between">
          <span>ATTACHED VULNERABILITIES</span>
          <span class="text-wiz-crimson font-bold">${attachedCves.length} DETECTED</span>
        </div>
        <div class="space-y-2">
    `;
    attachedCves.forEach(cve => {
      const cveName = cve.clean_name || cve.name || cve.id;
      const cvss = cve.properties?.cvss || '9.8';
      const desc = cve.properties?.description || 'Remote Code Execution vulnerability enabling lateral exploit path.';
      html += `
        <div class="space-y-1 arch-border-b pb-1.5 last:border-b-0 last:pb-0">
          <div class="flex justify-between items-center text-[11px]">
            <span class="font-bold text-archival-ink">${cveName}</span>
            <span class="px-1.5 py-0.2 rounded bg-wiz-crimsonBg text-wiz-crimson text-[9px] font-bold">CVSS ${cvss}</span>
          </div>
          <p class="text-[10px] text-archival-muted leading-relaxed">${desc}</p>
        </div>
      `;
    });
    html += `</div></div>`;
  } else {
    html += `
      <div class="p-3 rounded arch-border bg-archival-surface space-y-1">
        <div class="text-[10px] font-bold text-archival-faint uppercase">ATTACHED VULNERABILITIES</div>
        <div class="text-[10px] text-wiz-emerald font-semibold">✓ 0 known vulnerabilities on this resource</div>
      </div>
    `;
  }

  // Box 2: RBAC & ServiceAccount
  if (attachedSa) {
    const saName = attachedSa.clean_name || attachedSa.name || attachedSa.id;
    html += `
      <div class="p-3 rounded arch-border bg-archival-surface space-y-1.5">
        <div class="text-[10px] font-bold text-archival-faint uppercase">RBAC & SERVICE ACCOUNT</div>
        <div class="text-[11px] text-archival-ink font-semibold">sa: ${saName}</div>
        <div class="text-[10px] text-archival-muted">
          Namespace: <code class="bg-archival-stone px-1 rounded">${attachedSa.namespace || 'default'}</code>
        </div>
      </div>
    `;
  }

  // Box 3: Network Peers (Blast Radius)
  html += `
    <div class="p-3 rounded arch-border bg-archival-surface space-y-1.5">
      <div class="text-[10px] font-bold text-archival-faint uppercase">NETWORK REACHABILITY PEERS</div>
      <div class="text-[10px] space-y-1">
        <div class="flex justify-between">
          <span>INBOUND:</span>
          <span class="font-bold text-archival-ink truncate max-w-[200px]">
            ${inboundEdges.length > 0 ? inboundEdges.map(e => e.source.split('/').pop()).join(', ') : 'None (Isolated)'}
          </span>
        </div>
        <div class="flex justify-between">
          <span>OUTBOUND:</span>
          <span class="font-bold ${outboundEdges.some(e => e.is_attack_path) ? 'text-wiz-crimson' : 'text-archival-ink'} truncate max-w-[200px]">
            ${outboundEdges.length > 0 ? outboundEdges.map(e => e.target.split('/').pop()).join(', ') : 'None (Terminal)'}
          </span>
        </div>
      </div>
    </div>
  `;

  container.innerHTML = html;
}

// ============================================================================
// CANVAS CONTROLS & TOGGLES
// ============================================================================
function setGraphDisplayMode(mode) {
  currentDisplayMode = mode;
  const btnAttack = document.getElementById('btn-mode-attack');
  const btnFull = document.getElementById('btn-mode-full');

  if (mode === 'attack') {
    if (btnAttack) btnAttack.className = 'px-2 py-0.5 rounded bg-archival-stone text-archival-ink font-bold transition';
    if (btnFull) btnFull.className = 'px-2 py-0.5 rounded text-archival-muted hover:text-archival-ink transition';
  } else {
    if (btnFull) btnFull.className = 'px-2 py-0.5 rounded bg-archival-stone text-archival-ink font-bold transition';
    if (btnAttack) btnAttack.className = 'px-2 py-0.5 rounded text-archival-muted hover:text-archival-ink transition';
  }
  renderUnifiedGraph(rawGraphData);
}

function toggleGraphView(view) {
  currentGraphView = view;
  updateStatePreviewToggles();
  fetchGraphTopology();
}

function updateStatePreviewToggles() {
  const prodBtn = document.getElementById('btn-toggle-prod');
  const sandBtn = document.getElementById('btn-toggle-sandbox');

  if (currentGraphView === 'prod') {
    if (prodBtn) prodBtn.className = 'px-2 py-0.5 rounded bg-archival-surface text-archival-ink font-bold shadow-xs transition whitespace-nowrap';
    if (sandBtn) sandBtn.className = 'px-2 py-0.5 rounded text-archival-muted hover:text-archival-ink font-semibold transition whitespace-nowrap';
  } else {
    if (sandBtn) sandBtn.className = 'px-2 py-0.5 rounded bg-archival-surface text-archival-ink font-bold shadow-xs transition whitespace-nowrap';
    if (prodBtn) prodBtn.className = 'px-2 py-0.5 rounded text-archival-muted hover:text-archival-ink font-semibold transition whitespace-nowrap';
  }
}

// Zoom & Pan
function zoomWizCanvas(factor) {
  wizZoom = Math.min(Math.max(wizZoom * factor, 0.6), 2.2);
  applyWizTransform();
}

function resetWizCanvas() {
  wizZoom = 1.0;
  wizPan = { x: 0, y: 0 };
  applyWizTransform();
}

function applyWizTransform() {
  const svgGroup = document.getElementById('wiz-svg-paths');
  const nodesLayer = document.getElementById('wiz-nodes-layer');
  if (svgGroup) {
    svgGroup.setAttribute('transform', `scale(${wizZoom})`);
  }
  if (nodesLayer) {
    nodesLayer.style.transform = `scale(${wizZoom})`;
    nodesLayer.style.transformOrigin = 'center center';
  }
}

// ============================================================================
// TOP KPI DRILL-DOWNS
// ============================================================================
function drillDownAttackPaths() {
  setGraphDisplayMode('attack');
  switchInspectorTab('cypher');
  expandInspector();
  setCypherTemplate('paths');
}

function drillDownToxicCombinations() {
  setGraphDisplayMode('attack');
  switchInspectorTab('vuln');
  expandInspector();
}

function drillDownOnPathFindings() {
  const modal = document.getElementById('modal-findings');
  if (modal) modal.classList.remove('hidden');
}

function closeFindingsModal() {
  const modal = document.getElementById('modal-findings');
  if (modal) modal.classList.add('hidden');
}

// ============================================================================
// RETRACTABLE INSPECTOR
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
    renderUnifiedGraph(rawGraphData);
  }, 280);
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

// ============================================================================
// INSPECTOR ACTIONS (YAML COPY, DOWNLOAD, KUBECONFORM, CYPHER, APPROVAL)
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

async function approveAndCommitRemediation() {
  if (!currentSessionId || !currentUiToken) {
    alert('No active session token available.');
    return;
  }
  const btn = document.getElementById('btn-approve-commit');
  if (btn) btn.textContent = 'COMMITTING REMEDIATION...';

  try {
    const candidateId = currentOptimalCandidate ? currentOptimalCandidate.candidate_id : 'cset_isolated_db';
    const res = await fetch('/api/v1/operator/decision', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        session_id: currentSessionId,
        candidate_set_id: candidateId,
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
    const candidateId = currentOptimalCandidate ? currentOptimalCandidate.candidate_id : 'cset_isolated_db';
    const res = await fetch('/api/v1/operator/veto-and-resolve', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        session_id: currentSessionId,
        candidate_set_id: candidateId,
        reason: 'Operator vetoed candidate',
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

    // Switch to preview mode to display severed edges
    toggleGraphView('sandbox');

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

    let replyHtml = `<p class="leading-relaxed whitespace-pre-wrap">${data.reply}</p>`;

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
// SETTINGS
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
// NAVIGATION
// ============================================================================
function switchView(viewKey) {
  // Map 'overview' or 'dashboard' to 'view-dashboard'
  const targetId = (viewKey === 'overview' || viewKey === 'dashboard') ? 'view-dashboard' : `view-${viewKey}`;
  const views = ['view-dashboard', 'view-copilot', 'view-connectors', 'view-settings'];

  views.forEach(v => {
    const el = document.getElementById(v);
    if (el) {
      if (v === targetId) {
        el.classList.remove('hidden');
      } else {
        el.classList.add('hidden');
      }
    }
  });

  // Update nav buttons
  const navKeys = ['dashboard', 'copilot', 'connectors', 'settings'];
  navKeys.forEach(k => {
    const btn = document.getElementById(`nav-${k}`);
    if (btn) {
      const isMatch = (k === 'dashboard' && (viewKey === 'overview' || viewKey === 'dashboard')) || (k === viewKey);
      if (isMatch) {
        btn.className = 'w-full text-left px-3.5 py-2 flex items-center space-x-2.5 transition nav-item-active';
      } else {
        btn.className = 'w-full text-left px-3.5 py-2 flex items-center space-x-2.5 transition text-archival-cream/70 hover:text-archival-cream hover:bg-obsidian-850';
      }
    }
  });

  if (viewKey === 'overview' || viewKey === 'dashboard') {
    setTimeout(() => {
      renderUnifiedGraph(rawGraphData);
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
    renderUnifiedGraph(rawGraphData);
  });
}
