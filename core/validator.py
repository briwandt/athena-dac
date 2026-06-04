import re

class DetectionValidator:
    @staticmethod
    def match_value(record_val, rule_val):
        """Matches a field value from a log record against the rule definition."""
        if record_val is None:
            return False

        # Convert both to string for general comparison, preserving case for lists but matching insensitively
        rec_str = str(record_val).lower()

        # Handle numeric / comparison operators (e.g. '> 80')
        if isinstance(rule_val, str) and any(rule_val.startswith(op) for op in ['>', '<', '=']):
            match = re.match(r'^([><=]+)\s*(.*)$', rule_val)
            if match:
                op, val_num = match.groups()
                try:
                    num_rec = float(record_val)
                    num_rule = float(val_num)
                    if op == '>': return num_rec > num_rule
                    elif op == '<': return num_rec < num_rule
                    elif op == '>=': return num_rec >= num_rule
                    elif op == '<=': return num_rec <= num_rule
                    elif op == '=' or op == '==': return num_rec == num_rule
                except ValueError:
                    pass

        # Handle lists
        if isinstance(rule_val, list):
            # Check if any value in the list matches
            return any(DetectionValidator.match_value(record_val, v) for v in rule_val)

        # Handle wildcards
        rule_str = str(rule_val).lower()
        if '*' in rule_str:
            if rule_str.startswith('*') and rule_str.endswith('*'):
                clean_val = rule_str[1:-1]
                return clean_val in rec_str
            elif rule_str.startswith('*'):
                clean_val = rule_str[1:]
                return rec_str.endswith(clean_val)
            elif rule_str.endswith('*'):
                clean_val = rule_str[:-1]
                return rec_str.startswith(clean_val)
            else:
                # Middleware wildcard: convert to regex
                regex_pattern = '^' + re.escape(rule_str).replace(r'\*', '.*') + '$'
                return bool(re.match(regex_pattern, rec_str))

        # Direct string matching (case-insensitive)
        return rec_str == rule_str

    @classmethod
    def evaluate_selector(cls, selector_data, record):
        """Evaluates a single selector mapping on a log record.
        All fields in the selector must match (AND behavior).
        """
        for field, rule_value in selector_data.items():
            # Support nested fields flat or nested (e.g. useridentity.arn or useridentity_arn)
            # Try to get direct field first, then check case-insensitive or replaced dots
            record_value = None
            if field in record:
                record_value = record[field]
            elif field.replace('.', '_') in record:
                record_value = record[field.replace('.', '_')]
            else:
                # Handle nested dicts (e.g., {"userIdentity": {"arn": "..."}})
                parts = field.split('.')
                temp = record
                for part in parts:
                    if isinstance(temp, dict) and part in temp:
                        temp = temp[part]
                    else:
                        temp = None
                        break
                record_value = temp

            if not cls.match_value(record_value, rule_value):
                return False
        return True

    @classmethod
    def evaluate_rule_against_record(cls, rule_data, record):
        """Evaluates the entire rule detection block against a single record."""
        detection = rule_data['detection']
        condition = detection['condition']
        
        # Evaluate each sub-selection
        selector_results = {}
        for key, value in detection.items():
            if key != 'condition':
                selector_results[key] = cls.evaluate_selector(value, record)

        # Clean condition string to make it safe for python eval
        # condition is like: selection and not (filter_defender or filter_system)
        clean_condition = condition.lower()
        
        # Replace logical operators with standard python forms
        clean_condition = re.sub(r'\band\b', ' and ', clean_condition)
        clean_condition = re.sub(r'\bor\b', ' or ', clean_condition)
        clean_condition = re.sub(r'\bnot\b', ' not ', clean_condition)
        
        try:
            # Safely evaluate using the selector results as local context
            result = eval(clean_condition, {"__builtins__": None}, selector_results)
            return bool(result)
        except Exception as e:
            # Fallback or error logging
            print(f"Error evaluating condition '{condition}': {e}")
            return False

    @classmethod
    def run_validation(cls, rule_data, dataset):
        """Runs the rule against a list of events.
        Each event in dataset must contain a 'label' field: 'malicious' or 'benign'.
        Calculates: TP, FP, TN, FN, Precision, Recall, F1
        """
        tp = 0 # Malicious log and triggered
        fp = 0 # Benign log and triggered
        tn = 0 # Benign log and NOT triggered
        fn = 0 # Malicious log and NOT triggered
        
        triggered_events = []

        for record in dataset:
            triggered = cls.evaluate_rule_against_record(rule_data, record)
            label = record.get('label', 'benign')
            
            if triggered:
                triggered_events.append(record)
                if label == 'malicious':
                    tp += 1
                else:
                    fp += 1
            else:
                if label == 'malicious':
                    fn += 1
                else:
                    tn += 1

        total = len(dataset)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        return {
            'total_logs': total,
            'true_positives': tp,
            'false_positives': fp,
            'true_negatives': tn,
            'false_negatives': fn,
            'precision': round(precision, 4),
            'recall': round(recall, 4),
            'f1_score': round(f1, 4),
            'triggered_logs': triggered_events
        }
