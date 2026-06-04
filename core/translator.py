import re

class QueryTranslator:
    # Log source mappings to SPL and KQL base filters
    LOGSOURCE_MAPPINGS = {
        ('endpoint', 'windows', 'sysmon'): {
            'splunk': 'index=ep_sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"',
            'kql': 'SysmonEventLogs'
        },
        ('identity', 'active_directory', 'security'): {
            'splunk': 'index=ad_security sourcetype="WinEventLog:Security"',
            'kql': 'SecurityEvent'
        },
        ('cloud', 'azure_entra', 'auditlogs'): {
            'splunk': 'index=cloud_entra sourcetype="azure:aad:audit"',
            'kql': 'AuditLogs'
        },
        ('cloud', 'aws', 'cloudtrail'): {
            'splunk': 'index=aws_cloudtrail sourcetype="aws:cloudtrail"',
            'kql': 'AWSCloudTrail'
        },
        ('network', 'dns', 'queries'): {
            'splunk': 'index=net_dns sourcetype="infoblox:dns"',
            'kql': 'DnsEvents'
        }
    }

    @classmethod
    def get_base_filter(cls, logsource, target_siem):
        """Resolves log source category/product/service to SIEM-specific prefix."""
        category = logsource.get('category')
        product = logsource.get('product')
        service = logsource.get('service')
        
        key = (category, product, service)
        mapping = cls.LOGSOURCE_MAPPINGS.get(key)
        if mapping:
            return mapping.get(target_siem, "")
        
        # Fallback
        if target_siem == 'splunk':
            return f"index=security sourcetype=\"{product}:{service}\""
        else:
            return f"{product.capitalize()}Logs"

    @classmethod
    def compile_value(cls, field, value, target_siem):
        """Compiles a single field-value pair into Splunk or KQL syntax."""
        # Handle string numbers with operators like '> 80'
        if isinstance(value, str) and (value.startswith('>') or value.startswith('<') or value.startswith('=')):
            # numeric comparisons
            match = re.match(r'^([><=]+)\s*(.*)$', value)
            if match:
                op, val_num = match.groups()
                if target_siem == 'splunk':
                    # In Splunk search, we can use search filters directly if it's indexed, e.g. field > value
                    return f"{field}{op}{val_num}"
                else: # KQL
                    op_kql = "==" if op == "=" else op
                    return f"{field} {op_kql} {val_num}"

        # Handle lists
        if isinstance(value, list):
            escaped_values = [f'"{v}"' for v in value]
            if target_siem == 'splunk':
                return f"{field} IN ({', '.join(escaped_values)})"
            else: # KQL
                return f"{field} in ({', '.join(escaped_values)})"

        # Handle string wildcards
        val_str = str(value)
        if '*' in val_str:
            if target_siem == 'splunk':
                # Splunk supports wildcards natively in search
                return f'{field}="{val_str}"'
            else: # KQL
                # Translate wildcards to KQL string operators
                if val_str.startswith('*') and val_str.endswith('*'):
                    clean_val = val_str[1:-1]
                    return f'{field} contains "{clean_val}"'
                elif val_str.startswith('*'):
                    clean_val = val_str[1:]
                    return f'{field} endswith "{clean_val}"'
                elif val_str.endswith('*'):
                    clean_val = val_str[:-1]
                    return f'{field} startswith "{clean_val}"'
                else:
                    # In-between wildcards, KQL matches via matches regex
                    regex_val = val_str.replace('*', '.*')
                    return f'{field} matches regex "(?i)^{regex_val}$"'
        
        # Standard equality
        if target_siem == 'splunk':
            return f'{field}="{val_str}"'
        else: # KQL
            # Check if value looks like a number, boolean, or hex
            if val_str.lower() in ['true', 'false']:
                return f'{field} == {val_str.lower()}'
            try:
                # If it's a pure integer, write as number
                int(val_str)
                return f'{field} == {val_str}'
            except ValueError:
                # If it's a hex value (e.g. 0x17), write as string or hex depending on need.
                # In KQL, hex numbers can be written as 0x17, but sometimes logged as strings.
                # We write as string for safety unless it's numeric.
                return f'{field} == "{val_str}"'

    @classmethod
    def compile_selector(cls, selector_data, target_siem):
        """Compiles a selection block (dict of fields and values) into queries."""
        clauses = []
        for field, value in selector_data.items():
            # In KQL, dots in field names are not allowed in variables/operators unless escaped or replaced
            # We replace dots with underscores for KQL to match standard schema flattening
            field_name = field
            if target_siem == 'kql':
                field_name = field.replace('.', '_')
                
            clause = cls.compile_value(field_name, value, target_siem)
            clauses.append(clause)
        
        op = " AND " if target_siem == 'splunk' else " and "
        result = op.join(clauses)
        if len(clauses) > 1:
            return f"({result})"
        return result

    @classmethod
    def translate_to_splunk(cls, rule_data):
        """Compiles rule into Splunk SPL."""
        base_filter = cls.get_base_filter(rule_data['logsource'], 'splunk')
        detection = rule_data['detection']
        condition = detection['condition']
        
        # Compile selectors
        selectors_compiled = {}
        for key, value in detection.items():
            if key != 'condition':
                selectors_compiled[key] = cls.compile_selector(value, 'splunk')

        # Translate condition
        # Standardize operators to uppercase for SPL
        translated_condition = condition
        # We need to replace identifier names with their compiled forms
        # Sort keys by length descending to avoid partial replacements (e.g. filter1 vs filter11)
        for key in sorted(selectors_compiled.keys(), key=len, reverse=True):
            # Using boundary match to replace exact identifiers
            # Use lambda to prevent re.sub from treating backslashes in paths as escape characters
            # Do not wrap in parentheses here; compile_selector already groups multi-clause blocks.
            translated_condition = re.sub(rf'\b{key}\b', lambda m, v=selectors_compiled[key]: v, translated_condition)

        # Map logic operators
        translated_condition = re.sub(r'\band\b', 'AND', translated_condition)
        translated_condition = re.sub(r'\bor\b', 'OR', translated_condition)
        translated_condition = re.sub(r'\bnot\b', 'NOT', translated_condition)

        # Combine
        spl = f"{base_filter} {translated_condition}"
        
        # Clean extra spaces
        spl = re.sub(r'\s+', ' ', spl).strip()
        
        return spl

    @classmethod
    def translate_to_kql(cls, rule_data):
        """Compiles rule into Microsoft Sentinel KQL."""
        base_filter = cls.get_base_filter(rule_data['logsource'], 'kql')
        detection = rule_data['detection']
        condition = detection['condition']
        
        # Compile selectors
        selectors_compiled = {}
        for key, value in detection.items():
            if key != 'condition':
                selectors_compiled[key] = cls.compile_selector(value, 'kql')

        # Translate condition
        translated_condition = condition
        for key in sorted(selectors_compiled.keys(), key=len, reverse=True):
            # Using boundary match
            # Use lambda to prevent re.sub from treating backslashes in paths as escape characters
            # Do not wrap in parentheses here; compile_selector already groups multi-clause blocks.
            translated_condition = re.sub(rf'\b{key}\b', lambda m, v=selectors_compiled[key]: v, translated_condition)

        # Map logic operators (KQL is case sensitive or uses lower case for operators)
        translated_condition = re.sub(r'\bAND\b', 'and', translated_condition, flags=re.IGNORECASE)
        translated_condition = re.sub(r'\bOR\b', 'or', translated_condition, flags=re.IGNORECASE)
        translated_condition = re.sub(r'\bNOT\b', 'not', translated_condition, flags=re.IGNORECASE)

        # Format KQL query
        # Usually written as Table | where Filter
        kql = f"{base_filter}\n| where {translated_condition}"
        
        return kql

# Simple CLI test run when executing module directly
if __name__ == '__main__':
    from rule_parser import RuleParser
    import os
    rules_dir = r"c:\Users\user\Documents\AntiGravity\detection engineering\rules"
    for r_file in os.listdir(rules_dir):
        if r_file.endswith('.yaml'):
            path = os.path.join(rules_dir, r_file)
            data = RuleParser.load_rule(path)
            print(f"=== {r_file} ===")
            print("SPL:")
            print(QueryTranslator.translate_to_splunk(data))
            print("KQL:")
            print(QueryTranslator.translate_to_kql(data))
            print()
