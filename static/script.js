let data = [];
let cy;
let selectedNodes = [];
const typeColors = {
  system: '#64ffda',
  service: '#6bcf7f',    
  user: '#ffd93d',       
  orphan: '#ff9800',     
  exited: '#9e9e9e'  
};

async function loadData() {
  try {
    const urlParams = new URLSearchParams(window.location.search);
    const dataFile = urlParams.get('data');
    
    if (!dataFile) {
      throw new Error('No data file specified');
    }
    
    const response = await fetch(`/data/${dataFile}`);
    if (!response.ok) {
      throw new Error(`HTTP error! status: ${response.status}`);
    }
    
    data = await response.json();
    console.log(`Loaded ${data.length} processes`);
    return true;
  } catch (error) {
    console.error('Error loading data:', error);
    showToast('Failed to load process data: ' + error.message, 'error');
    return false;
  }
}

function classifyProcess(proc) {
  if (proc.ExitTime && proc.ExitTime !== "N/A") {
    return 'exited';
  }
  
  if (proc.pid === 4 || proc.ImageFileName === "System" || proc.ImageFileName === "Registry") {
    return 'system';
  }
  
  if (proc.ImageFileName.includes('svchost.exe') || 
      proc.ImageFileName.includes('services.exe') ||
      proc.ImageFileName.includes('lsass.exe') ||
      proc.ImageFileName.includes('csrss.exe') ||
      proc.ImageFileName.includes('wininit.exe') ||
      proc.ImageFileName.includes('winlogon.exe') ||
      proc.ImageFileName.includes('smss.exe') ||
      proc.SessionId === 0) {
    return 'service';
  }
  
  if (proc.SessionId > 0) {
    return 'user';
  }
  
  if (proc.ppid && !data.find(p => p.pid === proc.ppid)) {
    return 'orphan';
  }
  
  return 'service';
}

function analyzeProcessTree() {
  const processMap = new Map(data.map(p => [p.pid, { ...p, children: [] }]));
  const roots = [];
  const orphans = [];
  
  data.forEach(proc => {
    const processData = processMap.get(proc.pid);
    
    if (proc.ppid === 0 || !processMap.has(proc.ppid)) {
      if (proc.ppid === 0) {
        roots.push(processData);
      } else {
        orphans.push(processData);
      }
    } else {
      const parent = processMap.get(proc.ppid);
      if (parent) {
        parent.children.push(processData);
      }
    }
  });
  
  return { processMap, roots, orphans };
}

async function initializeCytoscape() {
  if (typeof cytoscape === 'undefined') {
    console.error('Cytoscape library not loaded!');
    showToast('Cytoscape library failed to load', 'error');
    return;
  }
  
  const dataLoaded = await loadData();
  if (!dataLoaded) {
    return;
  }
  
  if (typeof cytoscape.use === 'function') {
    try {
      if (window.cytoscapeDagre) {
        cytoscape.use(window.cytoscapeDagre);
      } else if (typeof cytoscapeDagre !== 'undefined') {
        cytoscape.use(cytoscapeDagre);
      }
    } catch (err) {
      console.warn('Could not register dagre extension, falling back to breadthfirst');
    }
  }
  
  const { processMap, roots, orphans } = analyzeProcessTree();
  const elements = [];
  
  data.forEach(proc => {
    const processType = classifyProcess(proc);
    const hasChildren = data.some(p => p.ppid === proc.pid);
    
    elements.push({
      data: {
        id: String(proc.pid),
        label: `${proc.ImageFileName}\n(PID: ${proc.pid})`,
        type: processType,
        hasChildren: hasChildren,
        name: proc.ImageFileName,
        pid: proc.pid,
        ppid: proc.ppid,
        offset: proc.Offset,
        threads: proc.Threads,
        handles: proc.Handles,
        sessionId: proc.SessionId,
        wow64: proc.Wow64,
        createTime: proc.CreateTime,
        exitTime: proc.ExitTime,
        fileOutput: proc.FileOutput,
        isRoot: proc.ppid === 0 || !data.find(p => p.pid === proc.ppid),
        isOrphan: proc.ppid !== 0 && !data.find(p => p.pid === proc.ppid),
        description: proc.description,
        suspicious: proc.suspicious,
        reason: proc.reason
      },
      classes: hasChildren ? 'parent-node' : 'leaf-node'
    });
    
    if (proc.ppid && data.find(p => p.pid === proc.ppid)) {
      elements.push({
        data: {
          id: `${proc.ppid}-${proc.pid}`,
          source: String(proc.ppid),
          target: String(proc.pid)
        }
      });
    }
  });
  
  cy = cytoscape({
    container: document.getElementById('cy'),
    elements: elements,
    style: [
      {
        selector: 'node',
        style: {
          'label': 'data(label)',
          'text-wrap': 'wrap',
          'text-max-width': 120,
          'text-valign': 'center',
          'text-halign': 'center',
          'background-color': function(node) {
            const type = node.data('type');
            return typeColors[type] || typeColors.service;
          },
          'shape': 'roundrectangle',
          'width': '130px',
          'height': '50px',
          'border-width': 2,
          'border-color': '#333',
          'font-size': '10px',
          'font-weight': '600',
          'color': function(node) { 
            return node.data('type') === 'exited' ? '#ffffff' : '#000'; 
          }
        }
      },
      {
        selector: '.parent-node',
        style: {
          'border-width': 3,
          'border-color': '#0066cc'
        }
      },
      {
        selector: '.leaf-node',
        style: {
          'border-style': 'dashed',
          'opacity': 0.9
        }
      },
      {
        selector: 'node:selected',
        style: {
          'border-color': '#ff6b6b',
          'border-width': '4px',
          'z-index': 999
        }
      },
      {
        selector: 'edge',
        style: {
          'width': 2,
          'line-color': '#666',
          'target-arrow-color': '#666',
          'target-arrow-shape': 'triangle',
          'curve-style': 'bezier'
        }
      },
      {
        selector: '.highlighted',
        style: {
          'background-color': '#ffd93d',
          'border-color': '#ffbe0b',
          'border-width': '4px',
          'z-index': 100
        }
      },
      {
        selector: '.child-highlighted',
        style: {
          'background-color': '#a8e6cf',
          'border-color': '#88d8a3',
          'border-width': '3px',
          'opacity': '0.9',
          'z-index': 50
        }
      },
      {
        selector: '.parent-highlighted',
        style: {
          'background-color': '#ffb3ba',
          'border-color': '#ff9aa2',
          'border-width': '3px',
          'opacity': '0.9',
          'z-index': 50
        }
      }
    ],
    layout: {
      name: (typeof cytoscapeDagre !== 'undefined' || window.cytoscapeDagre) ? 'dagre' : 'breadthfirst',
      rankDir: 'TB',
      nodeSep: 50,
      rankSep: 100,
      spacingFactor: 1.2
    },
    wheelSensitivity: 0.2,
    maxZoom: 5,
    minZoom: 0.1
  });

  setupEnhancedEventHandlers();
}

function setupEnhancedEventHandlers() {
  cy.on('tap', 'node', evt => {
    const node = evt.target;
    selectedNodes = [node];
    
    cy.elements().removeClass('highlighted child-highlighted parent-highlighted');
    node.addClass('highlighted');
    
    const children = node.outgoers().nodes();
    children.addClass('child-highlighted');
    
    const parent = node.incomers().nodes();
    parent.addClass('parent-highlighted');
    
    updateProcessDetails(node.data());
    document.getElementById('sidebar').classList.add('active');
    updateStatistics();
  });

  cy.on('dblclick', 'node', evt => {
    const node = evt.target;
    const subtree = node.union(node.successors());
    
    if (subtree.length > 1) {
      cy.animate({
        fit: {
          eles: subtree,
          padding: 100
        }
      }, { duration: 800 });
      
      showToast(`Focused on ${node.data('name')} and its ${subtree.length - 1} descendants`);
    } else {
      cy.animate({
        center: { eles: node },
        zoom: 2
      }, { duration: 500 });
      
      showToast(`${node.data('name')} is a leaf node with no children`);
    }
  });

  cy.on('cxttap', 'node', evt => {
    const nodeData = evt.target.data();
    const hasChildren = nodeData.hasChildren;
    const childCount = cy.getElementById(nodeData.id).outgoers().nodes().length;
    
    let message = `📋 ${nodeData.name} (PID: ${nodeData.pid})`;
    
    if (hasChildren) {
      message += `\n└─ Parent of ${childCount} process(es)`;
    } else {
      message += `\n└─ Leaf node (no children)`;
    }
    
    if (nodeData.type === 'orphan') {
      message += `\n⚠️ Orphaned process (parent not found)`;
    }
    
    if (nodeData.type === 'exited') {
      message += `\n💀 Exited process`;
    }
    
    showToast(message);
  });

  cy.on('tap', evt => {
    if (evt.target === cy) {
      selectedNodes = [];
      cy.elements().removeClass('highlighted child-highlighted parent-highlighted');
      document.getElementById('sidebar').classList.remove('active');
      updateStatistics();
    }
  });
}

function updateProcessDetails(data) {
  const detailsDiv = document.getElementById('processDetails');
  const childCount = cy.getElementById(data.id).outgoers().nodes().length;
  const parentNode = cy.getElementById(data.id).incomers().nodes();
  const parentName = parentNode.length > 0 ? parentNode[0].data('name') : 'None';
  
  detailsDiv.innerHTML = `
    <div class="process-info">
      <div class="info-header" style="background: ${typeColors[data.type]}; color: ${data.type === 'exited' ? '#fff' : '#000'}; padding: 10px; margin: -10px -10px 15px -10px; border-radius: 5px;">
        <h3 style="margin: 0; font-size: 14px;">${data.name}</h3>
        <small>${data.type.toUpperCase()} PROCESS ${data.hasChildren ? '(PARENT)' : '(LEAF)'}</small>
      </div>
      
      <div class="info-grid" style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-bottom: 15px;">
        <div class="info-item">
          <span class="info-label">PID:</span>
          <span class="info-value">${data.pid}</span>
        </div>
        <div class="info-item">
          <span class="info-label">PPID:</span>
          <span class="info-value">${data.ppid || 'N/A'}</span>
        </div>
        <div class="info-item">
          <span class="info-label">Threads:</span>
          <span class="info-value">${data.threads}</span>
        </div>
        <div class="info-item">
          <span class="info-label">Session:</span>
          <span class="info-value">${data.sessionId}</span>
        </div>
      </div>
      
      <div class="info-item" style="margin-bottom: 10px;">
        <span class="info-label">Parent Process:</span>
        <span class="info-value">${parentName}</span>
      </div>
      
      <div class="info-item" style="margin-bottom: 10px;">
        <span class="info-label">Child Processes:</span>
        <span class="info-value">${childCount}</span>
      </div>
      
      <div class="info-item" style="margin-bottom: 10px;">
        <span class="info-label">Created:</span>
        <span class="info-value" style="font-size: 11px;">${data.createTime}</span>
      </div>
      
      ${data.exitTime && data.exitTime !== 'N/A' ? `
        <div class="info-item" style="margin-bottom: 15px;">
          <span class="info-label">Exited:</span>
          <span class="info-value" style="font-size: 11px; color: #f44336;">${data.exitTime}</span>
        </div>
      ` : ''}
      
      <div class="info-item long-text">
        <span class="info-label">Description:</span>
        <span class="info-value">${data.description}</span>
      </div>
      
      <div class="info-item long-text suspicious">
        <span class="info-label">Suspicious:</span>
        <span class="info-value">${data.suspicious}</span>
      </div>
      
      <div class="info-item long-text reason">
        <span class="info-label">Reason:</span>
        <span class="info-value">${data.reason}</span>
      </div>
      
      <div class="info-item long-text memory-offset">
        <span class="info-label">Memory Offset:</span>
        <span class="info-value">${data.offset}</span>
      </div>
      
      ${data.isOrphan ? `
        <div style="background: rgba(255, 152, 0, 0.2); padding: 10px; border-radius: 5px; border-left: 3px solid #ff9800; margin-bottom: 10px;">
          <strong>⚠️ Orphaned Process</strong><br>
          <small>Parent process (PID: ${data.ppid}) not found in current data</small>
        </div>
      ` : ''}
      
      ${data.type === 'exited' ? `
        <div style="background: rgba(158, 158, 158, 0.2); padding: 10px; border-radius: 5px; border-left: 3px solid #9e9e9e;">
          <strong>💀 Exited Process</strong><br>
          <small>This process has terminated</small>
        </div>
      ` : ''}
    </div>
  `;
}

function updateStatistics() {
  const totalCount = data.length;
  const runningCount = data.filter(p => !p.ExitTime || p.ExitTime === "N/A").length;
  const exitedCount = data.filter(p => p.ExitTime && p.ExitTime !== "N/A").length;
  // const rootCount = data.filter(p => p.ppid === 0).length;
  const orphanCount = data.filter(p => p.ppid !== 0 && !data.find(parent => parent.pid === p.ppid)).length;
  const parentCount = data.filter(p => data.some(child => child.ppid === p.pid)).length;
  const leafCount = totalCount - parentCount;
  // const maxDepth = calculateMaxDepth();
  // const selectedCount = selectedNodes.length;
  
  document.getElementById('totalProcesses').textContent = totalCount;
  // document.getElementById('rootProcesses').textContent = rootCount;
  // document.getElementById('maxDepth').textContent = maxDepth;
  // document.getElementById('selectedCount').textContent = selectedCount;
}

function calculateMaxDepth() {
  const processMap = new Map(data.map(p => [p.pid, p]));
  let maxDepth = 0;
  
  function getDepth(pid, visited = new Set()) {
    if (visited.has(pid)) return 0;
    visited.add(pid);
    
    const process = processMap.get(pid);
    if (!process || process.ppid === 0) return 1;
    
    return 1 + getDepth(process.ppid, visited);
  }
  
  data.forEach(process => {
    maxDepth = Math.max(maxDepth, getDepth(process.pid));
  });
  
  return maxDepth;
}

function setupEventListeners() {
  document.getElementById('resetBtn').addEventListener('click', () => {
    cy.elements().removeClass('highlighted child-highlighted parent-highlighted');
    cy.fit();
    cy.center();
    selectedNodes = [];
    document.getElementById('sidebar').classList.remove('active');
    updateStatistics();
    showToast('View reset - showing full process tree');
  });

  document.getElementById('infoBtn').addEventListener('click', () => {
    document.getElementById('sidebar').classList.toggle('active');
  });

  document.getElementById('exportBtn').addEventListener('click', () => {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const png64 = cy.png({
      output: 'base64uri',
      full: true,
      scale: 2,
      bg: '#1a1a1a'
    });
    
    const link = document.createElement('a');
    link.href = png64;
    link.download = `process_tree_${timestamp}.png`;
    link.click();
    
    showToast('Process tree exported with timestamp');
  });

  let searchTimeout = null;
  document.getElementById('searchBox').addEventListener('input', (e) => {
    const query = e.target.value.toLowerCase().trim();

    clearTimeout(searchTimeout);
    cy.elements().removeClass('highlighted child-highlighted parent-highlighted');

    if (query.length === 0) {
      return;
    }

    const matchingNodes = cy.nodes().filter(node => {
      const data = node.data();
      return (data.name && data.name.toLowerCase().includes(query)) ||
             (data.pid && data.pid.toString().includes(query)) ||
             (data.type && data.type.toLowerCase().includes(query)) ||
             (data.offset && data.offset.toLowerCase().includes(query));
    });

    if (matchingNodes.length > 0) {
      matchingNodes.addClass('highlighted');

      const descendants = matchingNodes.successors().nodes();
      descendants.addClass('child-highlighted');

      const ancestors = matchingNodes.predecessors().nodes();
      ancestors.addClass('parent-highlighted');

      const allRelevantNodes = matchingNodes.union(descendants).union(ancestors);

      searchTimeout = setTimeout(() => {
        if (matchingNodes.length === 1 && descendants.length === 0) {
          cy.animate({
            center: { eles: matchingNodes },
            zoom: 1.5,
          }, { duration: 500 });
        } else {
          cy.animate({
            fit: { eles: allRelevantNodes, padding: 80 }
          }, { duration: 500 });
        }
      }, 300);

      let message = `Found ${matchingNodes.length} matching process(es)`;
      if (descendants.length > 0) {
        message += ` with ${descendants.length} descendant(s)`;
      }
      if (ancestors.length > 0) {
        message += ` and ${ancestors.length} ancestor(s)`;
      }
      showToast(message);
    } else {
      showToast('No matching processes found');
    }
  });

  document.addEventListener('keydown', (e) => {
    if (e.ctrlKey || e.metaKey) {
      switch (e.key) {
        case 'r':
          e.preventDefault();
          document.getElementById('resetBtn').click();
          break;
        case 'f':
          e.preventDefault();
          document.getElementById('searchBox').focus();
          break;
        case 's':
          e.preventDefault();
          document.getElementById('exportBtn').click();
          break;
      }
    }
    
    if (e.key === 'Escape') {
      document.getElementById('sidebar').classList.remove('active');
      document.getElementById('searchBox').value = '';
      cy.elements().removeClass('highlighted child-highlighted parent-highlighted');
    }
  });
}

function showToast(message, type = 'info', duration = 3000) {
  const toast = document.getElementById('toast');
  if (!toast) return;
  
  toast.textContent = message;
  toast.className = `toast show ${type}`;
  
  const colors = {
    info: '#2196f3',
    success: '#4caf50',
    warning: '#ff9800',
    error: '#f44336'
  };
  
  toast.style.backgroundColor = colors[type] || colors.info;
  
  setTimeout(() => {
    toast.classList.remove('show', type);
  }, duration);
}

document.addEventListener('DOMContentLoaded', init);

function init() {
  showLoading();
  setTimeout(async () => {
    try {
      await initializeCytoscape();
      updateStatistics();
      setupEventListeners();
      hideLoading();
      showToast('Process tree visualization loaded successfully!', 'success');
    } catch (error) {
      console.error('Initialization error:', error);
      hideLoading();
      showToast('Failed to initialize visualization. Check console for details.', 'error');
    }
  }, 1000);
}

function showLoading() {
  const loading = document.getElementById('loading');
  if (loading) loading.classList.remove('hidden');
}

function hideLoading() {
  const loading = document.getElementById('loading');
  if (loading) loading.classList.add('hidden');
}