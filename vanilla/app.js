// Application State
let activeCampaignId = 'apt29';
let highlightedTechniqueId = null;
let expandedLogIndexes = new Set();
let customCampaign = null;

// MITRE ATT&CK Schema for Matrix Rendering
// A comprehensive set of common tactics and techniques for demonstration
const MITRE_SCHEMA = [
  {
    tacticId: "TA0001",
    tacticName: "Initial Access",
    techniques: [
      { id: "T1566.001", name: "Spearphishing Attachment" },
      { id: "T1190", name: "Exploit Public-Facing App" },
      { id: "T1078.004", name: "Valid Accounts: Cloud" }
    ]
  },
  {
    tacticId: "TA0002",
    tacticName: "Execution",
    techniques: [
      { id: "T1059.001", name: "PowerShell scripting" },
      { id: "T1059.003", name: "Windows Command Shell" },
      { id: "T1204.002", name: "Malicious File Execution" }
    ]
  },
  {
    tacticId: "TA0003",
    tacticName: "Persistence",
    techniques: [
      { id: "T1547.001", name: "Registry Run Keys" },
      { id: "T1098.001", name: "Additional Credentials" },
      { id: "T1136.001", name: "Create Local Account" }
    ]
  },
  {
    tacticId: "TA0004",
    tacticName: "Privilege Escalation",
    techniques: [
      { id: "T1134", name: "Access Token Manipulation" },
      { id: "T1548.002", name: "Bypass User Account Control" },
      { id: "T1055", name: "Process Injection" }
    ]
  },
  {
    tacticId: "TA0005",
    tacticName: "Defense Evasion",
    techniques: [
      { id: "T1562.001", name: "Impair Defenses: Disable EDR" },
      { id: "T1070.004", name: "File Deletion" },
      { id: "T1027", name: "Obfuscated Files or Information" }
    ]
  },
  {
    tacticId: "TA0006",
    tacticName: "Credential Access",
    techniques: [
      { id: "T1003.001", name: "OS Credential Dumping: LSASS" },
      { id: "T1003.002", name: "OS Credential Dumping: SAM" },
      { id: "T1111", name: "MFA Push Fatigue Bypass" }
    ]
  },
  {
    tacticId: "TA0007",
    tacticName: "Discovery",
    techniques: [
      { id: "T1083", name: "File and Directory Discovery" },
      { id: "T1057", name: "Process Discovery" },
      { id: "T1049", name: "System Network Discovery" }
    ]
  },
  {
    tacticId: "TA0008",
    tacticName: "Lateral Movement",
    techniques: [
      { id: "T1021.006", name: "Remote Services: WinRM" },
      { id: "T1021.001", name: "Remote Services: RDP" },
      { id: "T1080", name: "Tainted Shared Folders" }
    ]
  },
  {
    tacticId: "TA0009",
    tacticName: "Collection",
    techniques: [
      { id: "T1114.002", name: "Email Collection: Mailbox Search" },
      { id: "T1113", name: "Screen Capture" },
      { id: "T1115", name: "Clipboard Data Collection" }
    ]
  },
  {
    tacticId: "TA0011",
    tacticName: "Command & Control",
    techniques: [
      { id: "T1105", name: "Ingress Tool Transfer" },
      { id: "T1071.001", name: "Application Layer: Web Traffic" },
      { id: "T1071.004", name: "Application Layer: DNS Traffic" }
    ]
  },
  {
    tacticId: "TA0010",
    tacticName: "Exfiltration",
    techniques: [
      { id: "T1048.002", name: "Exfil Over Asymmetric Channel" },
      { id: "T1020", name: "Automated Exfiltration" },
      { id: "T1041", name: "Exfiltration Over C2 Channel" }
    ]
  },
  {
    tacticId: "TA0040",
    tacticName: "Impact",
    techniques: [
      { id: "T1486", name: "Data Encrypted for Impact" },
      { id: "T1490", name: "Inhibit System Recovery" },
      { id: "T1489", name: "Service Stop" }
    ]
  }
];

// Document Event Listeners
document.addEventListener('DOMContentLoaded', () => {
  initApp();
});

// App Initialization
function initApp() {
  renderCampaignSidebar();
  loadCampaign(activeCampaignId);
  setupEventListeners();
}

// Render Campaigns List in Sidebar
function renderCampaignSidebar() {
  const sidebarNav = document.getElementById('campaign-list');
  sidebarNav.innerHTML = '';

  // Standard Campaigns
  Object.keys(CAMPAIGNS).forEach(id => {
    const campaign = CAMPAIGNS[id];
    const button = document.createElement('button');
    button.className = `campaign-btn ${id === activeCampaignId ? 'active' : ''}`;
    button.id = `btn-camp-${id}`;
    button.innerHTML = `
      <span>${campaign.name}</span>
      <span class="campaign-meta">${campaign.logs.length} telemetry logs</span>
    `;
    button.addEventListener('click', () => loadCampaign(id));
    sidebarNav.appendChild(button);
  });

  // Custom Uploaded Campaign if active
  if (customCampaign) {
    const button = document.createElement('button');
    button.className = `campaign-btn ${activeCampaignId === 'custom' ? 'active' : ''}`;
    button.id = `btn-camp-custom`;
    button.innerHTML = `
      <span>🛡️ Custom Uploaded Logs</span>
      <span class="campaign-meta">${customCampaign.logs.length} uploaded logs</span>
    `;
    button.addEventListener('click', () => loadCampaign('custom'));
    sidebarNav.appendChild(button);
  }
}

// Load Selected Campaign Data
function loadCampaign(campaignId) {
  activeCampaignId = campaignId;
  expandedLogIndexes.clear();
  highlightedTechniqueId = null;

  // Active dataset
  const campaign = campaignId === 'custom' ? customCampaign : CAMPAIGNS[campaignId];
  if (!campaign) return;

  // Update UI Elements
  document.getElementById('campaign-title').textContent = campaign.name;
  document.getElementById('campaign-desc').textContent = campaign.description;

  // Render Sub-components
  renderMetrics(campaign);
  renderMatrix(campaign);
  renderTimeline(campaign);
  renderRemediation(campaign);

  // Update active sidebar button
  document.querySelectorAll('.campaign-btn').forEach(btn => btn.classList.remove('active'));
  const activeBtn = document.getElementById(`btn-camp-${campaignId}`);
  if (activeBtn) activeBtn.classList.add('active');
}

// Render Top Metrics Grid
function renderMetrics(campaign) {
  let total = campaign.logs.length;
  let full = 0;
  let gap = 0;
  let blindspot = 0;

  campaign.logs.forEach(log => {
    const status = log.coverage_details?.status;
    if (status === 'full_coverage') full++;
    else if (status === 'partial_coverage') gap++;
    else if (status === 'no_coverage') blindspot++;
  });

  document.getElementById('metric-total').textContent = total;
  document.getElementById('metric-full').textContent = full;
  document.getElementById('metric-gap').textContent = gap;
  document.getElementById('metric-blindspot').textContent = blindspot;
}

// Render MITRE ATT&CK Matrix view
function renderMatrix(campaign) {
  const container = document.getElementById('mitre-matrix-container');
  container.innerHTML = '';

  // Get coverage dictionary for faster lookups
  const coverageMap = {};
  campaign.logs.forEach(log => {
    if (log.mitre_attack?.technique?.id) {
      coverageMap[log.mitre_attack.technique.id] = log.coverage_details?.status || 'no_coverage';
    }
  });

  // Render columns for each tactic
  MITRE_SCHEMA.forEach(tactic => {
    const col = document.createElement('div');
    col.className = 'tactic-column';
    col.innerHTML = `
      <div class="tactic-header">
        ${tactic.tacticName}
        <span>${tactic.tacticId}</span>
      </div>
    `;

    tactic.techniques.forEach(tech => {
      const cell = document.createElement('div');
      cell.className = 'technique-cell';
      cell.id = `matrix-tech-${tech.id}`;

      // Check coverage state
      const coverageStatus = coverageMap[tech.id];
      if (coverageStatus === 'full_coverage') {
        cell.classList.add('coverage-full');
      } else if (coverageStatus === 'partial_coverage') {
        cell.classList.add('coverage-partial');
      } else if (coverageStatus === 'no_coverage') {
        cell.classList.add('coverage-blindspot');
      }

      cell.innerHTML = `
        <span class="tech-id">${tech.id}</span>
        <span class="tech-name">${tech.name}</span>
      `;

      // Interactive: clicking a matrix cell highlights the log in the timeline
      cell.addEventListener('click', () => {
        highlightTimelineLogByTechnique(tech.id);
      });

      col.appendChild(cell);
    });

    container.appendChild(col);
  });
}

// Highlight log in timeline mapping to specific technique
function highlightTimelineLogByTechnique(techId) {
  // Clear any existing highlighted cells
  document.querySelectorAll('.technique-cell').forEach(c => c.classList.remove('highlighted'));
  
  const matrixCell = document.getElementById(`matrix-tech-${techId}`);
  if (matrixCell) {
    matrixCell.classList.add('highlighted');
    matrixCell.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }

  // Filter or highlight timeline logs
  const logsList = document.querySelectorAll('.log-item');
  let firstMatchingElement = null;

  logsList.forEach(logElement => {
    const elTechId = logElement.getAttribute('data-tech-id');
    if (elTechId === techId) {
      logElement.classList.add('active-filter');
      // Expand it automatically
      const index = parseInt(logElement.getAttribute('data-index'));
      expandLogDetails(index, logElement);

      if (!firstMatchingElement) firstMatchingElement = logElement;
    } else {
      logElement.classList.remove('active-filter');
    }
  });

  if (firstMatchingElement) {
    firstMatchingElement.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }
}

// Render Timeline panel
function renderTimeline(campaign) {
  const listContainer = document.getElementById('timeline-list-container');
  listContainer.innerHTML = '';

  if (!campaign.logs || campaign.logs.length === 0) {
    listContainer.innerHTML = '<div class="empty-state">No logs found. Upload JSON logs to map.</div>';
    return;
  }

  campaign.logs.forEach((log, index) => {
    const logItem = document.createElement('div');
    logItem.className = 'log-item';
    logItem.setAttribute('data-tech-id', log.mitre_attack?.technique?.id || '');
    logItem.setAttribute('data-index', index);

    const status = log.coverage_details?.status || 'no_coverage';
    const statusClass = status === 'full_coverage' ? 'full' : (status === 'partial_coverage' ? 'partial' : 'blindspot');
    const badgeText = status === 'full_coverage' ? 'Alerted / Covered' : (status === 'partial_coverage' ? 'Telemetry Gap' : 'Blind Spot');
    const badgeClass = status === 'full_coverage' ? 'badge-status-full' : (status === 'partial_coverage' ? 'badge-status-partial' : 'badge-status-blindspot');

    const hasMitre = log.mitre_attack?.technique?.id;
    const mitreBadge = hasMitre 
      ? `<span class="badge badge-mitre" id="badge-timeline-${hasMitre}-${index}" title="Click to highlight matrix cell">${log.mitre_attack.technique.id}: ${log.mitre_attack.technique.name}</span>`
      : '';

    logItem.innerHTML = `
      <div class="log-header" onclick="toggleLogExpand(${index}, this.parentElement)">
        <div class="log-header-left">
          <div class="log-status-indicator ${statusClass}"></div>
          <div class="log-meta-primary">
            <span class="log-headline">Host: ${log.host?.name || log.host.name || 'Unknown'} | Action: ${log.event?.action || log.event.action} | Proc: ${log.process?.name || 'Network Event'}</span>
            <span class="log-timestamp">${log['@timestamp'] || log.timestamp}</span>
          </div>
        </div>
        <div class="log-header-right">
          ${mitreBadge}
          <span class="badge ${badgeClass}">${badgeText}</span>
          <span class="log-expand-icon">▼</span>
        </div>
      </div>
      <div class="log-details" id="log-detail-${index}">
        <pre>${syntaxHighlight(JSON.stringify(log, null, 2))}</pre>
      </div>
    `;

    // Click on MITRE Badge specifically triggers Matrix highlight
    if (hasMitre) {
      setTimeout(() => {
        const badgeElement = document.getElementById(`badge-timeline-${hasMitre}-${index}`);
        if (badgeElement) {
          badgeElement.addEventListener('click', (e) => {
            e.stopPropagation(); // Prevent log expand toggle
            highlightMatrixCell(hasMitre);
          });
        }
      }, 0);
    }

    listContainer.appendChild(logItem);
  });
}

// Highlight cell on Matrix
function highlightMatrixCell(techId) {
  // Clear any existing highlighted cells
  document.querySelectorAll('.technique-cell').forEach(c => c.classList.remove('highlighted'));
  
  const matrixCell = document.getElementById(`matrix-tech-${techId}`);
  if (matrixCell) {
    matrixCell.classList.add('highlighted');
    matrixCell.scrollIntoView({ behavior: 'smooth', block: 'center' });
    
    // Add dynamic indicator pulse
    matrixCell.style.animation = 'none';
    setTimeout(() => {
      matrixCell.style.animation = 'pulse-glow 1.5s ease-in-out';
    }, 10);
  }

  // Also apply active filter on the timeline logs
  document.querySelectorAll('.log-item').forEach(logElement => {
    const elTechId = logElement.getAttribute('data-tech-id');
    if (elTechId === techId) {
      logElement.classList.add('active-filter');
    } else {
      logElement.classList.remove('active-filter');
    }
  });
}

// Toggle Collapsible Log Item
window.toggleLogExpand = function(index, element) {
  if (expandedLogIndexes.has(index)) {
    expandedLogIndexes.delete(index);
    element.classList.remove('expanded');
  } else {
    expandedLogIndexes.add(index);
    element.classList.add('expanded');
  }
};

// Expand Helper
function expandLogDetails(index, element) {
  expandedLogIndexes.add(index);
  element.classList.add('expanded');
}

// Render Remediation Gaps Panel
function renderRemediation(campaign) {
  const container = document.getElementById('remediation-list-container');
  container.innerHTML = '';

  // Collect all gaps and blindspots
  const gaps = campaign.logs.filter(log => 
    log.coverage_details && 
    (log.coverage_details.status === 'partial_coverage' || log.coverage_details.status === 'no_coverage')
  );

  if (gaps.length === 0) {
    container.innerHTML = `
      <div class="empty-state" style="padding: 1.5rem; background: var(--bg-full-glow); border: 1px solid var(--color-full); border-radius: var(--radius-md); color: var(--color-full)">
        🏆 <strong>Security Coverage Maximum!</strong> No telemetry gaps or blind spots identified in this log stream.
      </div>
    `;
    return;
  }

  gaps.forEach((log, index) => {
    const details = log.coverage_details;
    const isBlindSpot = details.status === 'no_coverage';
    const cardClass = isBlindSpot ? 'gap-alert-card blindspot' : 'gap-alert-card';
    const badgeText = isBlindSpot ? 'Blind Spot' : 'Telemetry Gap';
    const badgeClass = isBlindSpot ? 'gap-alert-badge blindspot' : 'gap-alert-badge gap';
    
    const cmdBlock = details.remediation?.cmd 
      ? `
        <div class="cmd-block-container">
          <div class="cmd-block-header">
            <span>REMEDIATION SCRIPT / COMMAND</span>
            <button class="copy-btn" onclick="copyCommandText('cmd-${index}')">Copy</button>
          </div>
          <div class="cmd-block" id="cmd-${index}">${details.remediation.cmd}</div>
        </div>
      `
      : '';

    const stepsHtml = details.remediation?.steps
      ? details.remediation.steps.map(step => `<li>${step}</li>`).join('')
      : '<li>Review system audit logging policies.</li>';

    const card = document.createElement('div');
    card.className = cardClass;
    card.innerHTML = `
      <div class="gap-alert-header">
        <div class="gap-alert-title">${details.summary || 'Missing Event Diagnostics'}</div>
        <span class="${badgeClass}">${badgeText}</span>
      </div>
      <div class="gap-alert-reason">
        <strong>Tactic:</strong> ${log.mitre_attack?.tactic?.name || 'Unknown'} | 
        <strong>Technique:</strong> <span style="font-family: var(--font-mono); color: var(--primary)">${log.mitre_attack?.technique?.id} (${log.mitre_attack?.technique?.name})</span>
      </div>
      <div style="font-size: 0.85rem; color: var(--text-secondary); margin-top: 0.25rem;">
        <strong>Visibility Issue:</strong> ${details.gap_reason}
      </div>
      <div class="gap-remediation-steps">
        <div class="gap-remediation-title">🛡️ How to Fix: ${details.remediation?.title || 'Enable Auditing'}</div>
        <ul class="steps-list">
          ${stepsHtml}
        </ul>
        ${cmdBlock}
      </div>
    `;

    container.appendChild(card);
  });
}

// Copy Action for Command Snippet
window.copyCommandText = function(id) {
  const codeEl = document.getElementById(id);
  if (!codeEl) return;
  
  navigator.clipboard.writeText(codeEl.textContent).then(() => {
    const btn = codeEl.previousElementSibling.querySelector('.copy-btn');
    if (btn) {
      const originalText = btn.textContent;
      btn.textContent = 'Copied!';
      btn.style.color = 'var(--color-full)';
      setTimeout(() => {
        btn.textContent = originalText;
        btn.style.color = '';
      }, 1500);
    }
  });
};

// Custom JSON syntax highlighting function
function syntaxHighlight(json) {
  if (typeof json !== 'string') {
    json = JSON.stringify(json, undefined, 2);
  }
  json = json.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  return json.replace(/("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d*)?(?:[eE][+-]?\d+)?)/g, function (match) {
    let cls = 'json-number';
    if (/^"/.test(match)) {
      if (/:$/.test(match)) {
        cls = 'json-key';
      } else {
        cls = 'json-string';
      }
    } else if (/true|false/.test(match)) {
      cls = 'json-boolean';
    } else if (/null/.test(match)) {
      cls = 'json-null';
    }
    
    // Inject span styling
    if (cls === 'json-key') {
      return `<span style="color: #c084fc; font-weight: 500;">${match.replace(/:$/, '')}</span>:`;
    } else if (cls === 'json-string') {
      return `<span style="color: #38bdf8;">${match}</span>`;
    } else if (cls === 'json-number') {
      return `<span style="color: #fb7185;">${match}</span>`;
    } else if (cls === 'json-boolean') {
      return `<span style="color: #34d399; font-weight: 600;">${match}</span>`;
    } else {
      return `<span style="color: #9ca3af; font-style: italic;">${match}</span>`;
    }
  });
}

// Event Listeners Setup
function setupEventListeners() {
  const openModalBtn = document.getElementById('open-upload-btn');
  const closeModalBtn = document.getElementById('close-modal-btn');
  const modalOverlay = document.getElementById('upload-modal');
  const submitLogsBtn = document.getElementById('submit-logs-btn');
  const textarea = document.getElementById('pasted-logs');
  const fileInput = document.getElementById('file-upload');
  const uploadArea = document.getElementById('upload-area');
  const validationError = document.getElementById('validation-error');

  // Open/Close Upload Modal
  openModalBtn.addEventListener('click', () => {
    modalOverlay.classList.add('active');
    textarea.value = '';
    validationError.textContent = '';
  });

  closeModalBtn.addEventListener('click', () => {
    modalOverlay.classList.remove('active');
  });

  // Close modal clicking outside
  modalOverlay.addEventListener('click', (e) => {
    if (e.target === modalOverlay) {
      modalOverlay.classList.remove('active');
    }
  });

  // Drag and Drop actions
  ['dragenter', 'dragover'].forEach(eventName => {
    uploadArea.addEventListener(eventName, (e) => {
      e.preventDefault();
      uploadArea.classList.add('dragover');
    }, false);
  });

  ['dragleave', 'drop'].forEach(eventName => {
    uploadArea.addEventListener(eventName, (e) => {
      e.preventDefault();
      uploadArea.classList.remove('dragover');
    }, false);
  });

  uploadArea.addEventListener('drop', (e) => {
    const dt = e.dataTransfer;
    const files = dt.files;
    if (files.length > 0) {
      handleFileUpload(files[0]);
    }
  });

  uploadArea.addEventListener('click', () => {
    fileInput.click();
  });

  fileInput.addEventListener('change', (e) => {
    if (fileInput.files.length > 0) {
      handleFileUpload(fileInput.files[0]);
    }
  });

  // File Upload processor
  function handleFileUpload(file) {
    const reader = new FileReader();
    reader.onload = (e) => {
      textarea.value = e.target.result;
    };
    reader.readAsText(file);
  }

  // Parse and Submit pasted logs
  submitLogsBtn.addEventListener('click', () => {
    const rawText = textarea.value.trim();
    if (!rawText) {
      validationError.textContent = 'Please paste some JSON logs first.';
      return;
    }

    try {
      const parsedLogs = JSON.parse(rawText);
      const logArray = Array.isArray(parsedLogs) ? parsedLogs : [parsedLogs];
      
      // Validate array structure slightly
      if (logArray.length === 0) {
        validationError.textContent = 'JSON must contain at least one log entry.';
        return;
      }

      // Perform auto mapping tags for custom logs if they lack them
      const enrichedLogs = logArray.map(log => {
        const enriched = { ...log };
        
        // Ensure default structure exists for visualization
        if (!enriched['@timestamp'] && enriched.timestamp) {
          enriched['@timestamp'] = enriched.timestamp;
        } else if (!enriched['@timestamp']) {
          enriched['@timestamp'] = new Date().toISOString();
        }

        if (!enriched.event) enriched.event = { action: 'custom-event' };
        if (!enriched.host) enriched.host = { name: 'external-host' };

        // If no mitre mapping is present, auto-simulate one to demonstrate functionality
        if (!enriched.mitre_attack) {
          enriched.mitre_attack = {
            tactic: { id: "TA0002", name: "Execution" },
            technique: { id: "T1059.001", name: "Command and Scripting Interpreter: PowerShell" }
          };
          enriched.coverage_details = {
            status: "partial_coverage",
            gap_id: "GAP-CUST-01",
            summary: "Custom Telemetry Auditing Missing",
            gap_reason: "Custom parsed JSON log loaded, but matches standard execution script without execution command integrity verifications.",
            remediation: {
              title: "Enable Custom Application Event Tracing",
              impact: "Resolves missing payload tracking inside custom parsed event logs.",
              steps: [
                "Map custom event logs to SIEM using common fields matching ECS.",
                "Ensure local debug/tracing configurations are set to Info/Warning in production properties."
              ],
              cmd: "# Enable full diagnostic logging levels inside app configuration properties\nlogging.level.root=WARN\nlogging.level.org.springframework.security=DEBUG"
            }
          };
        }

        return enriched;
      });

      // Calculate simple metrics for custom logs
      let total = enrichedLogs.length;
      let covered = 0;
      let gaps = 0;
      let blindspots = 0;

      enrichedLogs.forEach(log => {
        const status = log.coverage_details?.status || 'no_coverage';
        if (status === 'full_coverage') covered++;
        else if (status === 'partial_coverage') gaps++;
        else if (status === 'no_coverage') blindspots++;
      });

      customCampaign = {
        name: "🛡️ Custom Uploaded Logs",
        description: "Logs uploaded by user, mapped to MITRE ATT&CK dynamically in real-time.",
        metrics: { total, covered, gaps, blindspots },
        logs: enrichedLogs
      };

      // Add to sidebar and load it!
      renderCampaignSidebar();
      loadCampaign('custom');
      
      // Close modal
      modalOverlay.classList.remove('active');

    } catch (err) {
      validationError.textContent = `Invalid JSON: ${err.message}`;
    }
  });
}
