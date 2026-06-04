class TelemetryGapAnalyzer:
    # Telemetry requirements schema by log source types
    TELEMETRY_REQUIREMENTS = {
        'sysmon': {
            'name': 'Microsoft Windows Sysmon Telemetry',
            'required_fields': {
                'EventID': 'Enables parsing and routing of log types.',
                'SourceImage': 'Identifies the initiating process. Critical for identifying compromised binaries.',
                'TargetImage': 'Identifies the target process or DLL being accessed.',
                'GrantedAccess': 'Specific permissions requested. Critical to differentiate memory dumps from normal API calls.',
                'CallTrace': 'The stack trace of the thread. Vital for detecting shellcode injections and memory injection.'
            },
            'gpo_remediation': 'Configure Group Policy: Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> System Audit Policies -> Detailed Tracking -> Audit Process Creation (Success & Failure).',
            'sysmon_remediation': 'Install and update Sysmon with a configuration template like SwiftOnSecurity or Olaf Hartong\'s modular config to ensure Event ID 10 (ProcessAccess) is enabled and targeting lsass.exe.'
        },
        'active_directory': {
            'name': 'Windows Security Event Log (Active Directory)',
            'required_fields': {
                'EventID': 'Enables identifying AD security event types.',
                'TargetUserName': 'Identifies the user account requesting tickets or modification.',
                'ServiceName': 'Identifies the targeted service principal name (SPN).',
                'TicketEncryptionType': 'Identifies encryption cipher (e.g. 0x17 for RC4 vs 0x12 for AES256). Crucial for Kerberoasting detection.',
                'IpAddress': 'The source client IP address. Required to trace physical host location.'
            },
            'gpo_remediation': 'Enable Kerberos Service Ticket Operations auditing. Group Policy: Computer Configuration -> Policies -> Windows Settings -> Security Settings -> Advanced Audit Policy Configuration -> Account Logons -> Audit Kerberos Service Ticket Operations (Success & Failure).'
        },
        'azure_entra': {
            'name': 'Microsoft Entra ID (Azure AD) Audit Logs',
            'required_fields': {
                'OperationName': 'Specifies the action performed (e.g. Consent to application).',
                'Result': 'Specifies success or failure of the operations.',
                'InitiatedBy': 'Identity of the actor (user, admin, or service principal) who performed the action.',
                'TargetResources': 'Details of the application, user, or object that was modified.',
                'Permissions': 'Permissions granted in the OAuth token. Vital for identifying malicious OAuth consent phishing.'
            },
            'gpo_remediation': 'Ensure Microsoft Entra ID Diagnostic Settings are configured to stream AuditLogs and SignInLogs to your Log Analytics Workspace (Azure Sentinel).'
        },
        'aws': {
            'name': 'AWS CloudTrail Audit Logs',
            'required_fields': {
                'eventSource': 'Identifies the AWS service receiving the API call (e.g., iam.amazonaws.com).',
                'eventName': 'Identifies the API action (e.g., CreateAccessKey).',
                'userIdentity': 'Full details of the caller (IAM User, Role, SAML session, root).',
                'requestParameters': 'The parameters of the API call. Crucial to verify which username or policy was affected.',
                'userAgent': 'The client software used to make the call (reveals automated scripts, console, CLI).'
            },
            'gpo_remediation': 'Configure a multi-region AWS CloudTrail Trail, configure integration with CloudWatch Logs, and stream trail JSON logs to a centralized S3 bucket for SIEM ingestion.'
        },
        'dns': {
            'name': 'DNS Query Telemetry',
            'required_fields': {
                'query': 'The requested domain name (e.g., dynamic.malicious-site.com).',
                'query_type': 'DNS record type (A, AAAA, TXT, CNAME, MX). TXT and CNAME are critical for tunneling.',
                'src_ip': 'The source IP of the client resolving the domain.',
                'query_length': 'Length of the query string. Vital metadata for automated exfiltration detection.',
                'reply_code': 'DNS response status (NOERROR, NXDOMAIN). High NXDOMAIN counts indicate DGA activity.'
            },
            'gpo_remediation': 'Enable query logging on local DNS servers (Bind9, Windows DNS Server, or Infoblox) and ingest logs. In cloud environments, enable Route 53 Query Logging or Azure DNS Private Resolver Query Logs.'
        }
    }

    @classmethod
    def analyze_log_quality(cls, service_type, log_record):
        """Analyzes a single log record of a given service type for field completeness.
        Returns a dictionary report of results.
        """
        requirements = cls.TELEMETRY_REQUIREMENTS.get(service_type)
        if not requirements:
            return {
                'error': f"Unknown service type: {service_type}. Available: {list(cls.TELEMETRY_REQUIREMENTS.keys())}"
            }

        checked_fields = []
        missing_fields = []
        total_fields = len(requirements['required_fields'])
        present_count = 0

        for field, desc in requirements['required_fields'].items():
            # Check direct or flat representation (e.g. dots replaced with underscores)
            val = None
            if field in log_record:
                val = log_record[field]
            elif field.replace('.', '_') in log_record:
                val = log_record[field.replace('.', '_')]
            else:
                # Handle nested dict check
                parts = field.split('.')
                temp = log_record
                for part in parts:
                    if isinstance(temp, dict) and part in temp:
                        temp = temp[part]
                    else:
                        temp = None
                        break
                val = temp

            # Field is present if not None and not empty string
            is_present = val is not None and str(val).strip() != ""
            
            if is_present:
                present_count += 1
                checked_fields.append({
                    'field': field,
                    'description': desc,
                    'status': 'Present',
                    'value': str(val)[:50] + ("..." if len(str(val)) > 50 else "")
                })
            else:
                missing_fields.append({
                    'field': field,
                    'description': desc,
                    'status': 'Missing'
                })
                checked_fields.append({
                    'field': field,
                    'description': desc,
                    'status': 'Missing',
                    'value': 'N/A'
                })

        health_score = int((present_count / total_fields) * 100)

        report = {
            'log_source_name': requirements['name'],
            'health_score': health_score,
            'status': 'HEALTHY' if health_score >= 80 else ('WARNING' if health_score >= 50 else 'CRITICAL'),
            'checked_fields': checked_fields,
            'missing_fields': missing_fields,
            'gpo_remediation': requirements.get('gpo_remediation', ''),
            'sysmon_remediation': requirements.get('sysmon_remediation', '')
        }

        return report
