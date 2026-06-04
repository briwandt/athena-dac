"use client";

import { useState, useEffect, useRef } from "react";
import elasticDetections from "../src/data/elastic_detections.json";
import telemetryInventory from "../src/data/telemetry_inventory.json";
import { CAMPAIGNS, Campaign, LogEntry } from "../src/data/campaigns";

// MITRE ATT&CK Matrix Layout (12 core tactics and common techniques)
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
      { id: "T1027", name: "Obfuscated Files or Info" }
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

// Utility: JSON syntax highlighting function
function syntaxHighlight(jsonStr: string) {
  let json = jsonStr.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
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
    
    if (cls === 'json-key') {
      return `<span class="text-purple-400 font-medium">${match.replace(/:$/, '')}</span>:`;
    } else if (cls === 'json-string') {
      return `<span class="text-sky-400">${match}</span>`;
    } else if (cls === 'json-number') {
      return `<span class="text-rose-400">${match}</span>`;
    } else if (cls === 'json-boolean') {
      return `<span class="text-emerald-400 font-semibold">${match}</span>`;
    } else {
      return `<span class="text-slate-500 italic">${match}</span>`;
    }
  });
}

export default function Home() {
  const [activeTab, setActiveTab] = useState<'sandbox' | 'detections' | 'telemetry'>('sandbox');
  const [activeCampaignId, setActiveCampaignId] = useState<string>('apt29');
  const [highlightedTechId, setHighlightedTechId] = useState<string | null>(null);
  const [expandedLogIndexes, setExpandedLogIndexes] = useState<Set<number>>(new Set());
  const [customCampaign, setCustomCampaign] = useState<Campaign | null>(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [pastedLogsText, setPastedLogsText] = useState("");
  const [validationError, setValidationError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // References for scrolling elements
  const timelineItemRefs = useRef<Record<string, HTMLDivElement | null>>({});
  const matrixCellRefs = useRef<Record<string, HTMLDivElement | null>>({});

  // Active Campaign Object
  const campaign: Campaign = activeCampaignId === 'custom' && customCampaign 
    ? customCampaign 
    : CAMPAIGNS[activeCampaignId] || CAMPAIGNS.apt29;

  // Active coverage metrics
  const totalLogs = campaign.logs.length;
  const coveredLogs = campaign.logs.filter(l => l.coverage_details.status === 'full_coverage').length;
  const gapLogs = campaign.logs.filter(l => l.coverage_details.status === 'partial_coverage').length;
  const blindspotLogs = campaign.logs.filter(l => l.coverage_details.status === 'no_coverage').length;

  // Sync log expand sets
  const toggleLogExpand = (index: number) => {
    const next = new Set(expandedLogIndexes);
    if (next.has(index)) {
      next.delete(index);
    } else {
      next.add(index);
    }
    setExpandedLogIndexes(next);
  };

  // Interaction handlers
  const handleMatrixCellClick = (techId: string) => {
    setHighlightedTechId(techId);

    // Expand and highlight corresponding timeline item
    const matchingLogIndex = campaign.logs.findIndex(l => l.mitre_attack?.technique?.id === techId);
    if (matchingLogIndex !== -1) {
      const next = new Set(expandedLogIndexes);
      next.add(matchingLogIndex);
      setExpandedLogIndexes(next);

      setTimeout(() => {
        const item = timelineItemRefs.current[`log-${matchingLogIndex}`];
        if (item) {
          item.scrollIntoView({ behavior: 'smooth', block: 'center' });
        }
      }, 100);
    }
  };

  const handleMitreBadgeClick = (techId: string, e: React.MouseEvent) => {
    e.stopPropagation(); // Avoid triggering card toggle
    setHighlightedTechId(techId);

    // Scroll to matrix cell
    setTimeout(() => {
      const cell = matrixCellRefs.current[`cell-${techId}`];
      if (cell) {
        cell.scrollIntoView({ behavior: 'smooth', block: 'center' });
        cell.classList.add('animate-pulse');
        setTimeout(() => cell.classList.remove('animate-pulse'), 2000);
      }
    }, 100);
  };

  // Custom Log Parser
  const handleLogsUpload = (rawText: string) => {
    if (!rawText.trim()) {
      setValidationError("Please input some JSON logs.");
      return;
    }

    try {
      const parsed = JSON.parse(rawText);
      const logArray: any[] = Array.isArray(parsed) ? parsed : [parsed];

      if (logArray.length === 0) {
        setValidationError("JSON list must contain at least one event log object.");
        return;
      }

      // Format custom log objects to match schema
      const enrichedLogs: LogEntry[] = logArray.map(log => {
        const enriched = { ...log };
        if (!enriched['@timestamp'] && enriched.timestamp) {
          enriched['@timestamp'] = enriched.timestamp;
        } else if (!enriched['@timestamp']) {
          enriched['@timestamp'] = new Date().toISOString();
        }

        if (!enriched.event) enriched.event = { action: 'custom-parsed-event' };
        if (!enriched.host) enriched.host = { name: 'external-sensor' };

        // Auto map a simulation if they didn't include mitre structures
        if (!enriched.mitre_attack) {
          enriched.mitre_attack = {
            tactic: { id: "TA0002", name: "Execution" },
            technique: { id: "T1059.001", name: "Command and Scripting Interpreter: PowerShell" }
          };
          enriched.coverage_details = {
            status: "partial_coverage",
            gap_id: "GAP-CUST-01",
            summary: "Custom Ingestion Telemetry Auditing Missing",
            gap_reason: "Custom log payload parsed successfully, but lacks code integrity validations or command audits inside the environment.",
            remediation: {
              title: "Enable Local Script Execution Auditing",
              impact: "Bridges detection gaps for unverified scripts running in high-security contexts.",
              steps: [
                "Configure host EDR sensors to forward telemetry matching process arguments.",
                "Deploy GPO templates to log local script load profiles."
              ],
              cmd: "reg add \"HKLM\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging\" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f"
            }
          };
          enriched.detection_status = 'Monitored';
        }

        return enriched as LogEntry;
      });

      const total = enrichedLogs.length;
      const covered = enrichedLogs.filter(l => l.coverage_details.status === 'full_coverage').length;
      const gaps = enrichedLogs.filter(l => l.coverage_details.status === 'partial_coverage').length;
      const blindspots = enrichedLogs.filter(l => l.coverage_details.status === 'no_coverage').length;

      const newCampaign: Campaign = {
        name: "🛡️ Custom Uploaded Logs",
        description: "Logs uploaded manually by the user, dynamically parsed and mapped in real-time.",
        metrics: { total, covered, gaps, blindspots },
        logs: enrichedLogs
      };

      setCustomCampaign(newCampaign);
      setActiveCampaignId('custom');
      setModalOpen(false);
      setValidationError(null);
      setExpandedLogIndexes(new Set());
    } catch (err: any) {
      setValidationError(`Invalid JSON Structure: ${err.message}`);
    }
  };

  const handleCopyCommand = (cmd: string, btnId: string) => {
    navigator.clipboard.writeText(cmd).then(() => {
      const btn = document.getElementById(btnId);
      if (btn) {
        const originalText = btn.textContent;
        btn.textContent = "Copied!";
        btn.style.color = "#10b981"; // Emerald
        setTimeout(() => {
          btn.textContent = originalText;
          btn.style.color = "";
        }, 1500);
      }
    });
  };

  // Drag and Drop files
  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    const file = e.dataTransfer.files[0];
    if (file && file.type === "application/json") {
      const reader = new FileReader();
      reader.onload = (event) => {
        if (event.target?.result) {
          setPastedLogsText(event.target.result as string);
        }
      };
      reader.readAsText(file);
    }
  };

  // Compile coverage dictionary for matrix heatmap rendering
  const matrixCoverageMap: Record<string, 'full_coverage' | 'partial_coverage' | 'no_coverage'> = {};
  campaign.logs.forEach(log => {
    if (log.mitre_attack?.technique?.id) {
      matrixCoverageMap[log.mitre_attack.technique.id] = log.coverage_details.status;
    }
  });

  return (
    <main className="min-h-screen bg-[#07090e] text-slate-100 flex flex-col md:flex-row font-sans">
      {/* Sidebar Navigation */}
      <aside className="w-full md:w-[280px] bg-[#0d111c]/70 md:border-r border-slate-800/60 p-6 flex flex-col gap-8 backdrop-blur-xl shrink-0">
        <div className="flex items-center gap-3">
          <div className="bg-gradient-to-br from-indigo-500 to-purple-600 w-9 h-9 rounded-lg flex items-center justify-center font-bold text-lg text-white shadow-lg shadow-indigo-500/30">
            ⚔️
          </div>
          <div>
            <h1 className="text-[1.05rem] font-bold tracking-tight bg-gradient-to-r from-white to-purple-400 bg-clip-text text-transparent">
              ATT&CK Coverage
            </h1>
            <span className="text-[0.65rem] text-slate-500 font-semibold uppercase tracking-wider block">
              Gap Mapping & Analytics
            </span>
          </div>
        </div>

        {/* View Mode Tabs */}
        <div className="flex flex-col gap-1">
          <span className="text-[0.7rem] uppercase text-slate-500 tracking-wider font-semibold mb-2">View Modes</span>
          <button 
            onClick={() => setActiveTab('sandbox')}
            className={`w-full text-left px-3 py-2 rounded-lg text-sm font-medium transition-all ${activeTab === 'sandbox' ? 'bg-indigo-500/10 border border-indigo-500/30 text-indigo-300' : 'text-slate-400 hover:bg-slate-800/40'}`}
          >
            🛡️ Coverage Sandbox
          </button>
          <button 
            onClick={() => setActiveTab('detections')}
            className={`w-full text-left px-3 py-2 rounded-lg text-sm font-medium transition-all ${activeTab === 'detections' ? 'bg-indigo-500/10 border border-indigo-500/30 text-indigo-300' : 'text-slate-400 hover:bg-slate-800/40'}`}
          >
            🔍 Rules Database
          </button>
          <button 
            onClick={() => setActiveTab('telemetry')}
            className={`w-full text-left px-3 py-2 rounded-lg text-sm font-medium transition-all ${activeTab === 'telemetry' ? 'bg-indigo-500/10 border border-indigo-500/30 text-indigo-300' : 'text-slate-400 hover:bg-slate-800/40'}`}
          >
            📊 Telemetry Inventory
          </button>
        </div>

        {/* Active Campaigns Selectors (Only shown in Sandbox tab) */}
        {activeTab === 'sandbox' && (
          <div className="flex flex-col gap-1">
            <span className="text-[0.7rem] uppercase text-slate-500 tracking-wider font-semibold mb-2">Simulated Scenarios</span>
            
            <button 
              onClick={() => setActiveCampaignId('apt29')}
              className={`w-full text-left px-3 py-2.5 rounded-lg transition-all flex flex-col gap-0.5 border ${activeCampaignId === 'apt29' ? 'bg-indigo-950/20 border-indigo-500/30 text-slate-100 shadow-lg shadow-indigo-500/5' : 'border-transparent text-slate-400 hover:bg-slate-800/30'}`}
            >
              <span className="text-[0.85rem] font-semibold">APT29 Intrusion</span>
              <span className="text-[0.68rem] text-slate-500">6 events • Email & Lateral</span>
            </button>

            <button 
              onClick={() => setActiveCampaignId('ransomware')}
              className={`w-full text-left px-3 py-2.5 rounded-lg transition-all flex flex-col gap-0.5 border ${activeCampaignId === 'ransomware' ? 'bg-indigo-950/20 border-indigo-500/30 text-slate-100 shadow-lg shadow-indigo-500/5' : 'border-transparent text-slate-400 hover:bg-slate-800/30'}`}
            >
              <span className="text-[0.85rem] font-semibold">LockBit Ransomware</span>
              <span className="text-[0.68rem] text-slate-500">5 events • Shadow Deletion</span>
            </button>

            <button 
              onClick={() => setActiveCampaignId('cloud')}
              className={`w-full text-left px-3 py-2.5 rounded-lg transition-all flex flex-col gap-0.5 border ${activeCampaignId === 'cloud' ? 'bg-indigo-950/20 border-indigo-500/30 text-slate-100 shadow-lg shadow-indigo-500/5' : 'border-transparent text-slate-400 hover:bg-slate-800/30'}`}
            >
              <span className="text-[0.85rem] font-semibold">Cloud Privilege Abuse</span>
              <span className="text-[0.68rem] text-slate-500">5 events • Entra MFA Bypass</span>
            </button>

            {customCampaign && (
              <button 
                onClick={() => setActiveCampaignId('custom')}
                className={`w-full text-left px-3 py-2.5 rounded-lg transition-all flex flex-col gap-0.5 border ${activeCampaignId === 'custom' ? 'bg-indigo-950/20 border-indigo-500/30 text-slate-100 shadow-lg shadow-indigo-500/5' : 'border-transparent text-slate-400 hover:bg-slate-800/30'}`}
              >
                <span className="text-[0.85rem] font-semibold">🛡️ Custom Uploaded Logs</span>
                <span className="text-[0.68rem] text-slate-500">{customCampaign.logs.length} logs ingested</span>
              </button>
            )}

            <button 
              onClick={() => setModalOpen(true)}
              className="mt-4 w-full bg-slate-900 border border-slate-800 hover:border-indigo-500/50 hover:bg-indigo-500/10 text-slate-200 text-xs py-2 rounded-lg font-semibold flex items-center justify-center gap-1.5 transition-all"
            >
              📥 Upload Custom Logs
            </button>
          </div>
        )}

        <div className="mt-auto border-t border-slate-800/60 pt-4 text-center">
          <p className="text-[0.7rem] text-slate-500 font-medium">Designed for Cybersecurity Portfolios</p>
          <span className="text-[0.62rem] text-slate-600 block mt-1">v1.2.0 • ATT&CK Framework v14</span>
        </div>
      </aside>

      {/* Main Panel Content */}
      <section className="flex-1 p-6 md:p-10 overflow-y-auto flex flex-col gap-8 max-w-7xl">
        
        {/* Active Tab: COVERAGE SANDBOX */}
        {activeTab === 'sandbox' && (
          <>
            {/* Header info */}
            <header className="border-b border-slate-800/60 pb-5">
              <h2 className="text-2xl font-bold tracking-tight text-white mb-1">
                {campaign.name}
              </h2>
              <p className="text-slate-400 text-sm max-w-4xl">
                {campaign.description}
              </p>
            </header>

            {/* Metrics Counters Row */}
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4" aria-label="Campaign Metrics">
              <div className="bg-[#0f1322]/80 border border-slate-800/60 p-5 rounded-xl relative overflow-hidden">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider block">Telemetry Events</span>
                <span className="text-3xl font-bold mt-1 block font-mono">{totalLogs}</span>
                <div className="absolute bottom-0 left-0 w-full h-[3px] bg-indigo-500"></div>
              </div>
              <div className="bg-[#0f1322]/80 border border-slate-800/60 p-5 rounded-xl relative overflow-hidden">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider block">Alerted / Covered</span>
                <span className="text-3xl font-bold mt-1 block font-mono text-emerald-400">{coveredLogs}</span>
                <div className="absolute bottom-0 left-0 w-full h-[3px] bg-emerald-500"></div>
              </div>
              <div className="bg-[#0f1322]/80 border border-slate-800/60 p-5 rounded-xl relative overflow-hidden">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider block">Telemetry Gaps</span>
                <span className="text-3xl font-bold mt-1 block font-mono text-amber-500">{gapLogs}</span>
                <div className="absolute bottom-0 left-0 w-full h-[3px] bg-amber-500"></div>
              </div>
              <div className="bg-[#0f1322]/80 border border-slate-800/60 p-5 rounded-xl relative overflow-hidden">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wider block">Blind Spots</span>
                <span className="text-3xl font-bold mt-1 block font-mono text-rose-500">{blindspotLogs}</span>
                <div className="absolute bottom-0 left-0 w-full h-[3px] bg-rose-500"></div>
              </div>
            </div>

            {/* MITRE MATRIX HEATMAP */}
            <div className="bg-[#0d111c]/70 border border-slate-800/60 rounded-2xl p-6">
              <div className="flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4 mb-5">
                <h3 className="text-lg font-bold text-white flex items-center gap-2">
                  🛡️ MITRE ATT&CK Coverage Heatmap
                </h3>
                <div className="flex flex-wrap gap-4 text-xs">
                  <div className="flex items-center gap-1.5 text-slate-400">
                    <div className="w-3 h-3 rounded bg-emerald-500/10 border border-emerald-500"></div>
                    <span>Fully Alerted</span>
                  </div>
                  <div className="flex items-center gap-1.5 text-slate-400">
                    <div className="w-3 h-3 rounded bg-amber-500/10 border border-amber-500"></div>
                    <span>Telemetry Gap</span>
                  </div>
                  <div className="flex items-center gap-1.5 text-slate-400">
                    <div className="w-3 h-3 rounded bg-rose-500/10 border border-rose-500"></div>
                    <span>Blind Spot</span>
                  </div>
                  <div className="flex items-center gap-1.5 text-slate-400">
                    <div className="w-3 h-3 rounded bg-slate-900 border border-slate-800"></div>
                    <span>Unmonitored</span>
                  </div>
                </div>
              </div>

              {/* Scrolls matrix horizontally */}
              <div className="overflow-x-auto pb-2">
                <div className="grid grid-cols-12 gap-2.5 min-w-[1900px]">
                  {MITRE_SCHEMA.map((tactic) => (
                    <div key={tactic.tacticId} className="flex flex-col gap-2.5">
                      <div className="bg-[#121829] border-b-2 border-indigo-500 p-3 rounded text-center min-h-[50px] flex flex-col justify-center shrink-0">
                        <span className="text-[0.78rem] font-bold text-white leading-tight">{tactic.tacticName}</span>
                        <span className="text-[0.62rem] text-slate-500 font-semibold">{tactic.tacticId}</span>
                      </div>

                      {tactic.techniques.map((tech) => {
                        const status = matrixCoverageMap[tech.id];
                        let statusClasses = "bg-slate-950/20 border-slate-800/80 text-slate-400";
                        if (status === 'full_coverage') {
                          statusClasses = "bg-emerald-950/15 border-emerald-500/60 text-emerald-100 shadow-sm shadow-emerald-500/5";
                        } else if (status === 'partial_coverage') {
                          statusClasses = "bg-amber-950/15 border-amber-500/60 text-amber-100 shadow-sm shadow-amber-500/5";
                        } else if (status === 'no_coverage') {
                          statusClasses = "bg-rose-950/15 border-rose-500/60 text-rose-100 shadow-sm shadow-rose-500/5";
                        }

                        const isHighlighted = highlightedTechId === tech.id;
                        const highlightBorder = isHighlighted ? "ring-2 ring-indigo-500 scale-[1.01]" : "";

                        return (
                          <div 
                            key={tech.id}
                            ref={el => { matrixCellRefs.current[`cell-${tech.id}`] = el; }}
                            onClick={() => handleMatrixCellClick(tech.id)}
                            className={`p-3 rounded-lg border text-left cursor-pointer transition-all duration-200 min-h-[82px] flex flex-col justify-between hover:bg-slate-800/30 hover:translate-y-[-1px] ${statusClasses} ${highlightBorder}`}
                          >
                            <span className={`text-[0.68rem] font-mono font-semibold ${status === 'full_coverage' ? 'text-emerald-400' : status === 'partial_coverage' ? 'text-amber-400' : status === 'no_coverage' ? 'text-rose-400' : 'text-slate-500'}`}>
                              {tech.id}
                            </span>
                            <span className="text-[0.76rem] font-medium leading-tight line-clamp-2 mt-1">
                              {tech.name}
                            </span>
                          </div>
                        );
                      })}
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* TWO-COLUMN LOWER SECTION: LOG TIMELINE & REMEDIATION */}
            <div className="grid grid-cols-1 xl:grid-cols-12 gap-8">
              
              {/* Timeline (Left Column: Span 7) */}
              <div className="xl:col-span-7 bg-[#0d111c]/70 border border-slate-800/60 rounded-2xl p-6 flex flex-col">
                <div className="flex justify-between items-center mb-5">
                  <h3 className="text-lg font-bold text-white flex items-center gap-2">
                    📜 Chronological Log Timeline
                  </h3>
                  <span className="text-[0.7rem] text-slate-500">Click a row to inspect JSON payload</span>
                </div>

                <div className="flex flex-col gap-3 max-h-[800px] overflow-y-auto pr-2">
                  {campaign.logs.map((log, index) => {
                    const status = log.coverage_details.status;
                    const statusColor = status === 'full_coverage' ? 'bg-emerald-500' : (status === 'partial_coverage' ? 'bg-amber-500' : 'bg-rose-500');
                    
                    const badgeText = status === 'full_coverage' ? 'Alerted / Covered' : (status === 'partial_coverage' ? 'Telemetry Gap' : 'Blind Spot');
                    const badgeClass = status === 'full_coverage' ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20' : (status === 'partial_coverage' ? 'bg-amber-500/10 text-amber-400 border border-amber-500/20' : 'bg-rose-500/10 text-rose-400 border border-rose-500/20');
                    
                    const techId = log.mitre_attack?.technique?.id;
                    const isExpanded = expandedLogIndexes.has(index);

                    const isFilterActive = highlightedTechId === techId;
                    const activeFilterStyle = isFilterActive ? "border-indigo-500 shadow-md shadow-indigo-500/5 ring-1 ring-indigo-500/30" : "border-slate-800/60";

                    return (
                      <div 
                        key={index}
                        ref={el => { timelineItemRefs.current[`log-${index}`] = el; }}
                        className={`border rounded-xl bg-[#131929]/40 overflow-hidden transition-all duration-200 ${activeFilterStyle}`}
                      >
                        {/* Summary Header */}
                        <div 
                          onClick={() => toggleLogExpand(index)}
                          className="p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 cursor-pointer hover:bg-slate-800/20 select-none"
                        >
                          <div className="flex items-center gap-3 min-w-0">
                            <div className={`w-2.5 h-2.5 rounded-full shrink-0 ${statusColor}`}></div>
                            <div className="flex flex-col min-w-0">
                              <span className="text-[0.8rem] font-medium text-slate-100 truncate">
                                Host: {log.host?.name} | Action: {log.event?.action} | Proc: {log.process?.name || 'Network'}
                              </span>
                              <span className="text-[0.68rem] text-slate-500 font-mono mt-0.5">{log['@timestamp']}</span>
                            </div>
                          </div>

                          <div className="flex items-center gap-2 shrink-0 self-end sm:self-auto">
                            {techId && (
                              <button 
                                onClick={(e) => handleMitreBadgeClick(techId, e)}
                                className="bg-indigo-500/10 hover:bg-indigo-500 hover:text-white border border-indigo-500/20 text-indigo-300 text-[0.66rem] font-mono font-semibold px-2 py-0.5 rounded transition-all"
                              >
                                {techId}
                              </button>
                            )}
                            <span className={`text-[0.66rem] font-bold px-2 py-0.5 rounded ${badgeClass}`}>
                              {badgeText}
                            </span>
                            <span className={`text-slate-500 text-xs transition-transform duration-200 ${isExpanded ? 'rotate-180' : ''}`}>
                              ▼
                            </span>
                          </div>
                        </div>

                        {/* Collapsed Details View */}
                        {isExpanded && (
                          <div className="border-t border-slate-800/60 bg-black/30 p-4">
                            <pre 
                              className="text-[0.74rem] leading-relaxed font-mono overflow-x-auto whitespace-pre-wrap select-all"
                              dangerouslySetInnerHTML={{ __html: syntaxHighlight(JSON.stringify(log, null, 2)) }}
                            />
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </div>

              {/* Remediation Panel (Right Column: Span 5) */}
              <div className="xl:col-span-5 bg-[#0d111c]/70 border border-slate-800/60 rounded-2xl p-6 flex flex-col">
                <div className="flex justify-between items-center mb-5">
                  <h3 className="text-lg font-bold text-white flex items-center gap-2">
                    🛠️ Remediation & Gap Diagnostics
                  </h3>
                  <span className="text-[0.7rem] text-slate-500">Actionable detection fixes</span>
                </div>

                <div className="flex flex-col gap-4 max-h-[800px] overflow-y-auto pr-1">
                  {campaign.logs.filter(l => l.coverage_details.status !== 'full_coverage').map((log, index) => {
                    const details = log.coverage_details;
                    const isBlindspot = details.status === 'no_coverage';
                    const borderLeft = isBlindspot ? "border-l-4 border-l-rose-500" : "border-l-4 border-l-amber-500";
                    
                    return (
                      <div 
                        key={index}
                        className={`bg-[#131929]/40 border border-slate-800/60 rounded-xl p-4 flex flex-col gap-3 hover:border-slate-700/60 transition-all ${borderLeft}`}
                      >
                        <div className="flex justify-between items-start">
                          <h4 className="font-bold text-sm text-slate-200">
                            {details.summary || "Visibility Diagnostic"}
                          </h4>
                          <span className={`text-[0.6rem] font-bold uppercase tracking-wider px-2 py-0.5 rounded border ${isBlindspot ? 'bg-rose-500/10 text-rose-400 border-rose-500/20' : 'bg-amber-500/10 text-amber-400 border-amber-500/20'}`}>
                            {isBlindspot ? 'Blind Spot' : 'Telemetry Gap'}
                          </span>
                        </div>

                        <div className="text-xs text-slate-400 leading-normal">
                          <strong className="text-slate-300">Tactic:</strong> {log.mitre_attack?.tactic?.name} | <strong className="text-slate-300">Technique:</strong> <span className="text-indigo-400 font-mono">{log.mitre_attack?.technique?.id}</span>
                          <p className="mt-2 bg-slate-950/20 border border-slate-800/50 p-2.5 rounded-lg text-slate-300 text-[0.75rem]">
                            <strong>Issue:</strong> {details.gap_reason}
                          </p>
                        </div>

                        {details.remediation && (
                          <div className="border-t border-slate-800/60 pt-3 mt-1 flex flex-col gap-2">
                            <span className="text-[0.72rem] font-bold text-indigo-300 flex items-center gap-1.5">
                              🛡️ Fix: {details.remediation.title}
                            </span>
                            <ul className="list-disc list-inside text-[0.7rem] text-slate-400 flex flex-col gap-1 pl-1 leading-normal">
                              {details.remediation.steps.map((step, idx) => (
                                <li key={idx}>{step}</li>
                              ))}
                            </ul>
                            
                            {details.remediation.cmd && (
                              <div className="mt-2 flex flex-col gap-1.5">
                                <div className="flex justify-between items-center text-[0.62rem] text-slate-500 font-semibold uppercase tracking-wide">
                                  <span>Audit Config Script</span>
                                  <button 
                                    id={`copy-btn-${index}`}
                                    onClick={() => handleCopyCommand(details.remediation!.cmd!, `copy-btn-${index}`)}
                                    className="hover:text-white transition-colors cursor-pointer"
                                  >
                                    Copy Script
                                  </button>
                                </div>
                                <pre className="bg-[#05070c] border border-slate-800/80 p-2.5 rounded text-[0.72rem] font-mono text-cyan-400 overflow-x-auto whitespace-pre">
                                  {details.remediation.cmd}
                                </pre>
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    );
                  })}
                  
                  {campaign.logs.filter(l => l.coverage_details.status !== 'full_coverage').length === 0 && (
                    <div className="bg-emerald-950/10 border border-emerald-500/20 text-emerald-400 p-5 rounded-xl text-center text-xs">
                      🏆 <strong>Security Coverage Perfect!</strong> No telemetry gaps or blind spots identified in this campaign.
                    </div>
                  )}
                </div>
              </div>

            </div>
          </>
        )}

        {/* Active Tab: RULES DATABASE (Tab 2) */}
        {activeTab === 'detections' && (
          <div className="bg-[#0d111c]/70 border border-slate-800/60 rounded-2xl p-6">
            <header className="border-b border-slate-800/60 pb-5 mb-6">
              <h2 className="text-xl font-bold text-white mb-1">
                🔍 Security Detections Database
              </h2>
              <p className="text-slate-400 text-xs">
                Browse our registry of active detection rules ingested into the SIEM and their required telemetry components.
              </p>
            </header>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs border-collapse">
                <thead>
                  <tr className="text-slate-400 border-b border-slate-800 text-[0.7rem] uppercase tracking-wider font-semibold">
                    <th className="py-3 px-4">Rule Name</th>
                    <th className="py-3 px-4">Platform</th>
                    <th className="py-3 px-4">Language</th>
                    <th className="py-3 px-4">ATT&CK Mapping</th>
                    <th className="py-3 px-4">Required Telemetry</th>
                  </tr>
                </thead>
                <tbody>
                  {elasticDetections.map((rule) => (
                    <tr key={rule.rule_name} className="border-b border-slate-800/60 hover:bg-slate-800/10 transition-colors">
                      <td className="py-4 px-4 font-semibold text-slate-100">{rule.rule_name}</td>
                      <td className="py-4 px-4 text-slate-300">{rule.platform}</td>
                      <td className="py-4 px-4 text-slate-400 font-mono">{rule.query_language}</td>
                      <td className="py-4 px-4">
                        <span className="bg-indigo-500/10 text-indigo-300 border border-indigo-500/20 px-2 py-0.5 rounded font-mono text-[0.68rem] font-semibold">
                          {rule.mapped_technique}
                        </span>
                      </td>
                      <td className="py-4 px-4">
                        <div className="flex flex-wrap gap-1.5">
                          {rule.required_telemetry.map((telemetry) => (
                            <span key={telemetry} className="bg-slate-800 text-slate-300 px-2 py-0.5 rounded text-[0.66rem] border border-slate-700/50">
                              {telemetry}
                            </span>
                          ))}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Active Tab: TELEMETRY INVENTORY (Tab 3) */}
        {activeTab === 'telemetry' && (
          <div className="bg-[#0d111c]/70 border border-slate-800/60 rounded-2xl p-6">
            <header className="border-b border-slate-800/60 pb-5 mb-6">
              <h2 className="text-xl font-bold text-white mb-1">
                📊 Telemetry Ingestion Inventory
              </h2>
              <p className="text-slate-400 text-xs">
                Inspect which telemetry feeds are actively forwarding data to the SIEM, and identify missing logging profiles.
              </p>
            </header>

            <div className="grid md:grid-cols-2 gap-6">
              {/* Enabled Feed Column */}
              <div className="bg-[#05070c]/50 border border-slate-800/60 rounded-xl p-5">
                <h3 className="text-emerald-400 font-bold text-sm mb-4 flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-full bg-emerald-500"></span>
                  Active Telemetry Sources
                </h3>
                <div className="flex flex-col gap-3">
                  {telemetryInventory.filter(t => t.status === 'enabled').map(item => (
                    <div key={item.name} className="flex justify-between items-center border-b border-slate-800/60 pb-3">
                      <div>
                        <p className="font-semibold text-xs text-slate-100">{item.name}</p>
                        <p className="text-[0.68rem] text-slate-500">{item.source}</p>
                      </div>
                      <span className="bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 text-[0.62rem] font-bold uppercase tracking-wider px-2 py-0.5 rounded">
                        Active
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Missing Feed Column */}
              <div className="bg-[#05070c]/50 border border-slate-800/60 rounded-xl p-5">
                <h3 className="text-rose-400 font-bold text-sm mb-4 flex items-center gap-1.5">
                  <span className="w-2.5 h-2.5 rounded-full bg-rose-500"></span>
                  Disabled / Missing Sources
                </h3>
                <div className="flex flex-col gap-3">
                  {telemetryInventory.filter(t => t.status === 'missing').map(item => (
                    <div key={item.name} className="flex justify-between items-center border-b border-slate-800/60 pb-3">
                      <div>
                        <p className="font-semibold text-xs text-slate-100">{item.name}</p>
                        <p className="text-[0.68rem] text-slate-500">{item.source}</p>
                      </div>
                      <span className="bg-rose-500/10 text-rose-400 border border-rose-500/20 text-[0.62rem] font-bold uppercase tracking-wider px-2 py-0.5 rounded">
                        Missing
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </div>
        )}

      </section>

      {/* UPLOAD CUSTOM LOGS MODAL OVERLAY */}
      {modalOpen && (
        <div className="fixed inset-0 bg-black/85 backdrop-blur-sm z-50 flex items-center justify-center p-4">
          <div className="bg-[#0f1322] border border-indigo-500/30 rounded-2xl max-w-xl w-full p-6 flex flex-col gap-4 shadow-2xl shadow-black/80">
            <div className="flex justify-between items-center border-b border-slate-800 pb-3">
              <h3 className="text-base font-bold text-white">Ingest Custom Logs</h3>
              <button 
                onClick={() => setModalOpen(false)}
                className="text-slate-500 hover:text-white text-xl font-bold cursor-pointer"
              >
                &times;
              </button>
            </div>

            <p className="text-xs text-slate-400 leading-relaxed">
              Upload custom JSON logs (an individual log object or a JSON array). The analyzer maps fields dynamically, links logs to the MITRE heatmap, and calculates gaps.
            </p>

            {/* Drag & Drop File Container */}
            <div 
              onDragOver={handleDragOver}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              className="border-2 border-dashed border-slate-800 hover:border-indigo-500/50 hover:bg-indigo-500/5 transition-all rounded-xl p-6 text-center cursor-pointer flex flex-col items-center gap-2"
            >
              <input 
                type="file" 
                ref={fileInputRef} 
                onChange={(e) => {
                  const file = e.target.files?.[0];
                  if (file) {
                    const reader = new FileReader();
                    reader.onload = (event) => {
                      if (event.target?.result) setPastedLogsText(event.target.result as string);
                    };
                    reader.readAsText(file);
                  }
                }}
                accept=".json" 
                className="hidden" 
              />
              <span className="text-2xl">📂</span>
              <span className="text-xs text-slate-300">Click to choose a JSON file or drag it here</span>
              <span className="text-[0.62rem] text-slate-500">Supports standard JSON formats</span>
            </div>

            {/* Manual Text Paste Area */}
            <div className="flex flex-col gap-1.5">
              <label htmlFor="modal-paste-area" className="text-xs font-semibold text-slate-400">Or Paste Raw JSON logs:</label>
              <textarea 
                id="modal-paste-area"
                className="w-full h-32 bg-[#05070c] border border-slate-800 rounded-lg p-3 text-cyan-400 font-mono text-xs focus:outline-none focus:border-indigo-500 resize-none"
                placeholder='[
  {
    "@timestamp": "2026-05-24T12:00:00Z",
    "event": { "action": "custom-execution" },
    "process": { "name": "whoami.exe" }
  }
]'
                value={pastedLogsText}
                onChange={(e) => setPastedLogsText(e.target.value)}
              />
              {validationError && (
                <div className="text-rose-400 font-mono text-[0.68rem] mt-1">
                  {validationError}
                </div>
              )}
            </div>

            <button 
              onClick={() => handleLogsUpload(pastedLogsText)}
              className="w-full bg-gradient-to-r from-indigo-500 to-purple-600 hover:brightness-110 text-white font-bold text-xs py-2.5 rounded-lg transition-all shadow-md shadow-indigo-500/20 cursor-pointer"
            >
              ⚡ Ingest & Map Logs
            </button>
          </div>
        </div>
      )}

    </main>
  );
}
