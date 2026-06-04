import os
import yaml
import uuid
import re

class RuleParser:
    REQUIRED_FIELDS = ['id', 'title', 'description', 'status', 'severity', 'author', 'date', 'tags', 'logsource', 'detection']
    VALID_SEVERITIES = ['low', 'medium', 'high', 'critical']
    VALID_STATUSES = ['experimental', 'test', 'production', 'deprecated']

    @staticmethod
    def load_rule(file_path):
        """Loads a YAML file and returns the parsed dict."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Rule file not found: {file_path}")
        
        with open(file_path, 'r', encoding='utf-8') as f:
            try:
                rule_data = yaml.safe_load(f)
                return rule_data
            except yaml.YAMLError as e:
                raise ValueError(f"Invalid YAML syntax in {file_path}: {e}")

    @classmethod
    def validate_rule(cls, rule_data, file_name="rule"):
        """Validates a rule dictionary against standard rules schema.
        Returns a list of validation errors. If empty, the rule is valid.
        """
        errors = []
        
        # Check required top-level fields
        for field in cls.REQUIRED_FIELDS:
            if field not in rule_data or rule_data[field] is None:
                errors.append(f"Missing required field: '{field}'")

        if errors:
            return errors  # Stop here if basic fields are missing

        # Validate UUID format
        try:
            uuid.UUID(str(rule_data['id']))
        except ValueError:
            errors.append(f"Field 'id' must be a valid UUID. Got: {rule_data['id']}")

        # Validate Severity
        if str(rule_data['severity']).lower() not in cls.VALID_SEVERITIES:
            errors.append(f"Field 'severity' must be one of {cls.VALID_SEVERITIES}. Got: {rule_data['severity']}")

        # Validate Status
        if str(rule_data['status']).lower() not in cls.VALID_STATUSES:
            errors.append(f"Field 'status' must be one of {cls.VALID_STATUSES}. Got: {rule_data['status']}")

        # Validate Logsource
        logsource = rule_data.get('logsource', {})
        if not isinstance(logsource, dict):
            errors.append("Field 'logsource' must be a key-value mapping.")
        else:
            if 'category' not in logsource:
                errors.append("Field 'logsource' is missing required subfield 'category'.")
            if 'product' not in logsource:
                errors.append("Field 'logsource' is missing required subfield 'product'.")

        # Validate Detection logic
        detection = rule_data.get('detection', {})
        if not isinstance(detection, dict):
            errors.append("Field 'detection' must be a key-value mapping.")
        else:
            if 'condition' not in detection:
                errors.append("Field 'detection' is missing required subfield 'condition'.")
            
            # Check that referenced identifiers in condition exist in detection
            condition = str(detection.get('condition', ''))
            # Find words that are identifiers (exclude keywords like 'and', 'or', 'not', 'in', spaces, parentheses)
            identifiers = re.findall(r'\b(?!and\b|or\b|not\b|in\b)([a-zA-Z0-9_]+)\b', condition)
            for ident in identifiers:
                if ident not in detection:
                    errors.append(f"Condition references identifier '{ident}' which is not defined in detection.")

        # Ensure MITRE ATT&CK tags are specified
        tags = rule_data.get('tags', [])
        if not isinstance(tags, list):
            errors.append("Field 'tags' must be a list of strings.")
        else:
            has_mitre_tag = any(str(tag).startswith('attack.') for tag in tags)
            if not has_mitre_tag:
                errors.append("Rule should contain at least one MITRE ATT&CK tag matching 'attack.tXXXX' or 'attack.tXXXX.XXX'.")

        return errors

# Simple CLI test run when executing module directly
if __name__ == '__main__':
    # Test directory
    rules_dir = r"c:\Users\user\Documents\AntiGravity\detection engineering\rules"
    for r_file in os.listdir(rules_dir):
        if r_file.endswith('.yaml') or r_file.endswith('.yml'):
            path = os.path.join(rules_dir, r_file)
            print(f"Parsing: {r_file}")
            try:
                data = RuleParser.load_rule(path)
                errs = RuleParser.validate_rule(data, r_file)
                if errs:
                    print(f"  [!] Validation errors in {r_file}: {errs}")
                else:
                    print(f"  [+] {r_file} is VALID!")
            except Exception as e:
                print(f"  [!] Failed to load {r_file}: {e}")
