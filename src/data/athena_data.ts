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
