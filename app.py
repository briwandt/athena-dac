import streamlit as st
import os
import yaml
import json
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime

# Import custom core modules
from core.rule_parser import RuleParser
from core.translator import QueryTranslator
from core.validator import DetectionValidator
from core.gap_analyzer import TelemetryGapAnalyzer

# Set page config with premium aesthetics
st.set_page_config(
    page_title="Athena | Modern Detection-as-Code & Validation Lab",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom premium styling via CSS injection
st.markdown("""
<style>
    /* Main Layout Styling */
    .main {
        background-color: #0d1117;
        color: #c9d1d9;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    }
    
    /* Premium Title and Header Styling */
    .title-text {
        font-family: 'Outfit', sans-serif;
        font-weight: 800;
        background: linear-gradient(135deg, #58a6ff 0%, #1f6feb 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        margin-bottom: 5px;
    }
    .subtitle-text {
        color: #8b949e;
        font-size: 1.1rem;
        margin-bottom: 25px;
    }
    
    /* Glassmorphism Cards */
    .glass-card {
        background: rgba(22, 27, 34, 0.8);
        border: 1px solid #30363d;
        border-radius: 12px;
        padding: 20px;
        margin-bottom: 15px;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.2);
    }
    
    /* Metrics Indicators */
    .metric-value {
        font-size: 2.2rem;
        font-weight: 700;
        color: #58a6ff;
        line-height: 1.2;
    }
    .metric-label {
        font-size: 0.85rem;
        color: #8b949e;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    
    /* Custom Alert Boxes */
    .alert-banner {
        padding: 15px;
        border-radius: 8px;
        margin-bottom: 15px;
    }
    .alert-critical {
        background-color: rgba(248, 81, 73, 0.15);
        border: 1px solid #f85149;
        color: #ff7b72;
    }
    .alert-warning {
        background-color: rgba(210, 153, 34, 0.15);
        border: 1px solid #d29922;
        color: #d29922;
    }
    .alert-healthy {
        background-color: rgba(46, 160, 67, 0.15);
        border: 1px solid #2ea043;
        color: #56d364;
    }
    
    /* Table Styling */
    div[data-testid="stTable"] table {
        background-color: #161b22;
        color: #c9d1d9;
        border-collapse: collapse;
        border: 1px solid #30363d;
        width: 100%;
    }
    div[data-testid="stTable"] th {
        background-color: #21262d;
        color: #58a6ff;
        text-align: left;
        padding: 10px;
        border: 1px solid #30363d;
    }
    div[data-testid="stTable"] td {
        padding: 10px;
        border: 1px solid #30363d;
    }
</style>
""", unsafe_allow_html=True)

# Helper functions to load workspace directories
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RULES_DIR = os.path.join(BASE_DIR, "rules")
TELEMETRY_DIR = os.path.join(BASE_DIR, "telemetry")

def load_all_rules():
    rules = []
    if not os.path.exists(RULES_DIR):
        return rules
    for f in os.listdir(RULES_DIR):
        if f.endswith('.yaml') or f.endswith('.yml'):
            path = os.path.join(RULES_DIR, f)
            try:
                rule_dict = RuleParser.load_rule(path)
                rule_dict['_filename'] = f
                rule_dict['_path'] = path
                rules.append(rule_dict)
            except Exception as e:
                st.error(f"Error loading rule {f}: {e}")
    return rules

def load_telemetry_for_rule(rule):
    category = rule['logsource'].get('category')
    product = rule['logsource'].get('product')
    service = rule['logsource'].get('service')
    
    # Map rule to corresponding file
    filename_map = {
        ('endpoint', 'windows', 'sysmon'): 'sysmon_lsass_dump.json',
        ('identity', 'active_directory', 'security'): 'security_kerberoasting.json',
        ('cloud', 'azure_entra', 'auditlogs'): 'entra_consent_grant.json',
        ('cloud', 'aws', 'cloudtrail'): 'aws_cloudtrail_privesc.json',
        ('network', 'dns', 'queries'): 'dns_query_logs.json'
    }
    
    filename = filename_map.get((category, product, service))
    if not filename:
        return []
    
    file_path = os.path.join(TELEMETRY_DIR, filename)
    if not os.path.exists(file_path):
        return []
        
    with open(file_path, 'r', encoding='utf-8') as f:
        return json.load(f)

# Initialize data
rules = load_all_rules()

# Sidebar Navigation
with st.sidebar:
    st.image("https://raw.githubusercontent.com/google/material-design-icons/master/png/action/shield/xxhdpi.png", width=70)
    st.markdown("<h2 style='margin-top:0px;'>Project Athena</h2>", unsafe_allow_html=True)
    st.markdown("<p style='color:#8b949e; font-size:0.85rem;'>Detection-as-Code & Validation Lab</p>", unsafe_allow_html=True)
    st.divider()
    
    menu = st.radio(
        "Navigation",
        [
            "🏠 Executive Dashboard",
            "🛠️ Rule Registry & DaC Pipeline",
            "🧪 Simulation & Validation Lab",
            "📊 Log Quality & Telemetry Audit",
            "🚨 IR Fast Scoper"
        ]
    )
    
    st.divider()
    st.markdown("""
    **Prudential Specialist Interview**
    - Technical Demo
    - Focus: SPL, KQL, DaC, Simulation
    - Candidate: Cyber Detection Engineer
    """)

# ----------------- 🏠 EXECUTIVE DASHBOARD -----------------
if menu == "🏠 Executive Dashboard":
    st.markdown("<h1 class='title-text'>Shielding the Enterprise: Project Athena</h1>", unsafe_allow_html=True)
    st.markdown("<p class='subtitle-text'>An interactive Detection-as-Code engineering showcase mapping telemetry validation and target query translations for Splunk and Sentinel.</p>", unsafe_allow_html=True)
    
    # Top-level indicators
    cols = st.columns(4)
    with cols[0]:
        st.markdown(f"""
        <div class='glass-card'>
            <div class='metric-label'>Total Rules Managed</div>
            <div class='metric-value'>{len(rules)}</div>
        </div>
        """, unsafe_allow_html=True)
    with cols[1]:
        st.markdown("""
        <div class='glass-card'>
            <div class='metric-label'>Deploy Targets</div>
            <div class='metric-value'>2 <span style='font-size:1.1rem; color:#8b949e;'>(Splunk / KQL)</span></div>
        </div>
        """, unsafe_allow_html=True)
    with cols[2]:
        st.markdown("""
        <div class='glass-card'>
            <div class='metric-label'>Avg Telemetry Health</div>
            <div class='metric-value'>96%</div>
        </div>
        """, unsafe_allow_html=True)
    with cols[3]:
        st.markdown("""
        <div class='glass-card'>
            <div class='metric-label'>Pipeline Status</div>
            <div class='metric-value' style='color:#2ea043;'>Passing</div>
        </div>
        """, unsafe_allow_html=True)
        
    st.markdown("### Detection Framework Strategy")
    st.markdown("""
    Modern enterprise environments require security operations to run at scale with high confidence, minimal latency, and zero tolerance for manually deployed, untested logic.
    
    This platform demonstrates a **Detection-as-Code (DaC)** methodology designed to secure hybrid enterprise ecosystems. By drafting platform-agnostic detection rules in structured configurations, we achieve:
    1. **Portability**: Auto-compile detections directly to **Splunk SPL** and **Microsoft Sentinel KQL**.
    2. **Continuous Validation**: Run adversarial emulation against mock log sources to verify detection efficacy before production deployment.
    3. **Telemetry Accountability**: Quantify and audit log stream formats to identify gaps and enforce data engineering standards.
    """)
    
    # Visualizing MITRE ATT&CK Tactic coverage
    st.markdown("### MITRE ATT&CK Tactic Coverage Map")
    
    tactic_counts = {}
    for r in rules:
        for tag in r.get('tags', []):
            if tag.startswith('attack.'):
                tactic = tag.split('.')[1]
                tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
                
    if tactic_counts:
        df_tactics = pd.DataFrame({
            'Tactic': [t.replace('_', ' ').capitalize() for t in tactic_counts.keys()],
            'Rules Count': list(tactic_counts.values())
        })
        fig = px.bar(
            df_tactics, 
            x='Rules Count', 
            y='Tactic', 
            orientation='h', 
            title="Active Detections by ATT&CK Stage",
            color='Rules Count',
            color_continuous_scale='Blues',
            template='plotly_dark'
        )
        fig.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            height=300,
            margin=dict(l=20, r=20, t=40, b=20)
        )
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No active MITRE ATT&CK tactic tags detected in registry.")

# ----------------- 🛠️ RULE REGISTRY & DAC PIPELINE -----------------
elif menu == "🛠️ Rule Registry & DaC Pipeline":
    st.markdown("<h1 class='title-text'>Rule Registry & DaC Compilation Pipeline</h1>", unsafe_allow_html=True)
    st.markdown("<p class='subtitle-text'>Select a registry detection to view metadata validation, inspect YAML source, and compile to target SIEM queries.</p>", unsafe_allow_html=True)
    
    if not rules:
        st.warning("No rules found in rules directory.")
    else:
        # Rules dropdown selector
        rule_options = {r['title']: r for r in rules}
        selected_title = st.selectbox("Select Rule for Inspection & Compilation", list(rule_options.keys()))
        selected_rule = rule_options[selected_title]
        
        # Validate selected rule on the fly
        validation_errors = RuleParser.validate_rule(selected_rule, selected_rule['_filename'])
        
        col1, col2 = st.columns([1, 1])
        
        with col1:
            st.markdown("### Rule Metadata & Schema Validation")
            
            # Display Validation State
            if not validation_errors:
                st.markdown("""
                <div class='alert-banner alert-healthy'>
                    <strong>✓ Schema Validation Passed</strong>: This rule conforms to enterprise metadata guidelines and contains all mandatory routing keys.
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div class='alert-banner alert-critical'>
                    <strong>✗ Schema Validation Failed</strong>: The following errors must be resolved:
                    <ul>
                        {"".join(f"<li>{err}</li>" for err in validation_errors)}
                    </ul>
                </div>
                """, unsafe_allow_html=True)
            
            # Key Details Card
            st.markdown(f"""
            <div class='glass-card'>
                <h4>{selected_rule['title']}</h4>
                <p style='color:#8b949e; font-size:0.9rem;'>{selected_rule['description']}</p>
                <hr style='border-color:#30363d;'>
                <strong>ID</strong>: <code>{selected_rule['id']}</code><br>
                <strong>Severity</strong>: <span style="color: {'#ff7b72' if selected_rule['severity'] == 'critical' or selected_rule['severity'] == 'high' else '#d29922'}; font-weight:bold;">{selected_rule['severity'].upper()}</span><br>
                <strong>Status</strong>: <code>{selected_rule['status']}</code><br>
                <strong>Author</strong>: {selected_rule['author']}<br>
                <strong>Tags</strong>: {", ".join([f"<code>{t}</code>" for t in selected_rule['tags']])}<br>
                <strong>Domain</strong>: <code>{selected_rule['logsource']['category']}</code> / <code>{selected_rule['logsource']['product']}</code> / <code>{selected_rule['logsource']['service']}</code>
            </div>
            """, unsafe_allow_html=True)
            
            # YAML Viewer
            with st.expander("📄 View Raw YAML Rule Definition"):
                with open(selected_rule['_path'], 'r', encoding='utf-8') as f:
                    st.code(f.read(), language='yaml')

        with col2:
            st.markdown("### Compiling Targets")
            
            # Run compiler translations
            splunk_query = QueryTranslator.translate_to_splunk(selected_rule)
            kql_query = QueryTranslator.translate_to_kql(selected_rule)
            
            # Splunk View
            st.markdown("#### 🟥 Splunk SPL Output")
            st.code(splunk_query, language='sql')
            
            # KQL View
            st.markdown("#### 🟦 Microsoft Sentinel KQL Output")
            st.code(kql_query, language='sql')
            
            # Configuration generation exports
            with st.expander("📦 View Enterprise Infrastructure Deployment Configs"):
                tabs = st.tabs(["Splunk savedsearches.conf", "Microsoft Sentinel ARM Alert Template"])
                with tabs[0]:
                    conf_name = selected_rule['title'].lower().replace(" ", "_")
                    splunk_conf = f"""[{selected_rule['title']}]
search = {splunk_query}
dispatch.earliest_time = -30m
dispatch.latest_time = now
cron_schedule = */5 * * * *
enableSched = 1
action.email = 1
action.email.to = soc-tier1-alerts@prudential-mock.com
severity = {selected_rule['severity']}
description = {selected_rule['description']}"""
                    st.code(splunk_conf, language='ini')
                    
                with tabs[1]:
                    sentinel_arm = {
                        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#",
                        "contentVersion": "1.0.0.0",
                        "resources": [
                            {
                                "type": "Microsoft.OperationalInsights/workspaces/providers/alertRules",
                                "apiVersion": "2020-01-01-preview",
                                "name": f"[concat('myWorkspace/', '{selected_rule['id']}')]",
                                "properties": {
                                    "displayName": selected_rule['title'],
                                    "description": selected_rule['description'],
                                    "severity": selected_rule['severity'].capitalize(),
                                    "enabled": True,
                                    "query": kql_query,
                                    "queryFrequency": "PT5M",
                                    "queryPeriod": "PT30M",
                                    "triggerOperator": "GreaterThan",
                                    "triggerThreshold": 0
                                }
                            }
                        ]
                    }
                    st.code(json.dumps(sentinel_arm, indent=2), language='json')

# ----------------- 🧪 SIMULATION & VALIDATION LAB -----------------
elif menu == "🧪 Simulation & Validation Lab":
    st.markdown("<h1 class='title-text'>Simulation & Rule Validation Lab</h1>", unsafe_allow_html=True)
    st.markdown("<p class='subtitle-text'>Evaluate detection rule accuracy by simulating malicious adversarial actions against a baseline noise dataset.</p>", unsafe_allow_html=True)
    
    rule_options = {r['title']: r for r in rules}
    selected_title = st.selectbox("Select Rule to Validate", list(rule_options.keys()))
    selected_rule = rule_options[selected_title]
    
    # Load corresponding mock logs
    dataset = load_telemetry_for_rule(selected_rule)
    
    if not dataset:
        st.warning("No simulated telemetry logs found for the selected rule.")
    else:
        st.markdown(f"**Loaded Log Dataset**: `{selected_rule['logsource']['service']}` telemetry stream ({len(dataset)} records)")
        
        # Option to run evaluation
        if st.button("🚀 Run Active Ad-Hoc Attack Simulation & Validation"):
            with st.spinner("Executing simulation pipeline and checking detection logic..."):
                results = DetectionValidator.run_validation(selected_rule, dataset)
                
                # Metrics displays
                c1, c2, c3, c4 = st.columns(4)
                with c1:
                    st.metric("Total Log Count", results['total_logs'])
                with c2:
                    st.metric("Precision", f"{int(results['precision'] * 100)}%", help="True Positives / (True Positives + False Positives)")
                with c3:
                    st.metric("Recall", f"{int(results['recall'] * 100)}%", help="True Positives / (True Positives + False Negatives)")
                with c4:
                    st.metric("F1-Score", results['f1_score'])
                
                col1, col2 = st.columns([1, 1.5])
                
                with col1:
                    st.markdown("#### Confusion Matrix")
                    
                    tp = results['true_positives']
                    fp = results['false_positives']
                    tn = results['true_negatives']
                    fn = results['false_negatives']
                    
                    # Custom styled HTML Confusion Matrix
                    st.markdown(f"""
                    <table style='width:100%; border:1px solid #30363d; font-family: monospace; text-align:center;'>
                        <tr>
                            <td style='border:1px solid #30363d; background-color:#21262d;'></td>
                            <th style='border:1px solid #30363d; background-color:#21262d; color:#58a6ff; text-align:center;'>Actual Malicious</th>
                            <th style='border:1px solid #30363d; background-color:#21262d; color:#58a6ff; text-align:center;'>Actual Benign</th>
                        </tr>
                        <tr>
                            <th style='border:1px solid #30363d; background-color:#21262d; color:#58a6ff;'>Triggered Alert</th>
                            <td style='border:1px solid #30363d; background-color: rgba(46, 160, 67, 0.2); color:#56d364; padding:15px;'>
                                <strong>True Positive (TP)</strong><br><span style='font-size:1.5rem;'>{tp}</span>
                            </td>
                            <td style='border:1px solid #30363d; background-color: rgba(248, 81, 73, 0.2); color:#ff7b72; padding:15px;'>
                                <strong>False Positive (FP)</strong><br><span style='font-size:1.5rem;'>{fp}</span>
                            </td>
                        </tr>
                        <tr>
                            <th style='border:1px solid #30363d; background-color:#21262d; color:#58a6ff;'>No Alert</th>
                            <td style='border:1px solid #30363d; background-color: rgba(248, 81, 73, 0.2); color:#ff7b72; padding:15px;'>
                                <strong>False Negative (FN)</strong><br><span style='font-size:1.5rem;'>{fn}</span>
                            </td>
                            <td style='border:1px solid #30363d; background-color: rgba(46, 160, 67, 0.2); color:#56d364; padding:15px;'>
                                <strong>True Negative (TN)</strong><br><span style='font-size:1.5rem;'>{tn}</span>
                            </td>
                        </tr>
                    </table>
                    """, unsafe_allow_html=True)
                    
                    # Highlight operational logic trade-offs
                    st.markdown("#### Operational Impact & Tuning Recommendations")
                    if fp > 0:
                        st.markdown(f"""
                        > [!WARNING]
                        > **Tuning Required**: We detected `{fp}` False Positive alert(s). If deployed to production, this rule will cause unnecessary SOC alert fatigue.
                        > 
                        > **Recommendation**: Inspect the benign logs triggering the rule. Add exclusion filters in the YAML detection logic targeting the specific benign process or service account.
                        """)
                    elif fn > 0:
                        st.markdown(f"""
                        > [!CAUTION]
                        > **Critical Blindspot**: We detected `{fn}` False Negative(s). The rule failed to flag actual adversary activity.
                        > 
                        > **Recommendation**: Loosen field filters or review wildcards. Ensure the logic targets broader attacker behavior rather than overly specific commands.
                        """)
                    else:
                        st.markdown("""
                        > [!TIP]
                        > **Ready for Production**: 100% Precision and 100% Recall achieved on this dataset.
                        > The rule successfully isolated all adversarial events while ignoring all baseline noise. Ensure baseline contains a representative sample of enterprise noise before final release.
                        """)
                        
                with col2:
                    st.markdown("#### Log Evaluation Explorer")
                    
                    df_rows = []
                    for idx, record in enumerate(dataset):
                        triggered = DetectionValidator.evaluate_rule_against_record(selected_rule, record)
                        label = record.get('label', 'benign')
                        
                        status_msg = ""
                        color = "#c9d1d9"
                        if triggered and label == 'malicious':
                            status_msg = "True Positive (TP)"
                            color = "#56d364"
                        elif triggered and label == 'benign':
                            status_msg = "False Positive (FP)"
                            color = "#ff7b72"
                        elif not triggered and label == 'benign':
                            status_msg = "True Negative (TN)"
                            color = "#8b949e"
                        elif not triggered and label == 'malicious':
                            status_msg = "False Negative (FN)"
                            color = "#ff7b72"

                        # Extract some display field
                        display_text = ""
                        if 'SourceImage' in record:
                            display_text = f"Src: {record['SourceImage']} -> Target: {record.get('TargetImage','')}"
                        elif 'ServiceName' in record:
                            display_text = f"Service: {record['ServiceName']} | Enc: {record.get('TicketEncryptionType','')}"
                        elif 'OperationName' in record:
                            display_text = f"Op: {record['OperationName']} | Perms: {record.get('Permissions','')}"
                        elif 'eventName' in record:
                            display_text = f"AWS Op: {record['eventName']} | Caller: {record.get('userIdentity', {}).get('arn','')}"
                        elif 'query' in record:
                            display_text = f"DNS Query: {record['query']} (Len: {record.get('query_length','')})"
                            
                        df_rows.append({
                            'Log Index': idx + 1,
                            'Simulated Label': label.upper(),
                            'Detection Alerted?': "YES" if triggered else "NO",
                            'Status': status_msg,
                            'Telemetry Context': display_text
                        })
                        
                    df_eval = pd.DataFrame(df_rows)
                    st.dataframe(df_eval, use_container_width=True, hide_index=True)

# ----------------- 📊 LOG QUALITY & TELEMETRY AUDIT -----------------
elif menu == "📊 Log Quality & Telemetry Audit":
    st.markdown("<h1 class='title-text'>Telemetry Audit & Log Quality Analyzer</h1>", unsafe_allow_html=True)
    st.markdown("<p class='subtitle-text'>Evaluate log schema health and verify that required field auditing is enabled at the source layer.</p>", unsafe_allow_html=True)
    
    log_sources = {
        "Windows Sysmon (Event ID 10)": "sysmon",
        "Active Directory Security (Event ID 4769)": "active_directory",
        "Entra ID Audit Logs": "azure_entra",
        "AWS CloudTrail": "aws",
        "DNS Resolver Queries": "dns"
    }
    
    selected_source = st.selectbox("Select Log Stream to Audit", list(log_sources.keys()))
    source_key = log_sources[selected_source]
    
    # Load first record from corresponding dataset as a test record
    # Or let the user modify it in a JSON text area
    default_records = {
        'sysmon': {
            "EventID": 10,
            "SourceImage": "C:\\Windows\\System32\\cmd.exe",
            "TargetImage": "C:\\Windows\\System32\\lsass.exe",
            "GrantedAccess": "0x1410",
            "CallTrace": "C:\\Windows\\System32\\ntdll.dll+0x2150"
        },
        'active_directory': {
            "EventID": 4769,
            "ServiceName": "sql_prod_service",
            "TicketEncryptionType": "0x17",
            "TargetUserName": "svc_sql",
            "IpAddress": "192.168.12.80"
        },
        'azure_entra': {
            "OperationName": "Consent to application",
            "ConsentType": "AllPrincipals",
            "Result": "success",
            "InitiatedBy": "admin.smith@company.com",
            "TargetResources": "Malicious App ID",
            "Permissions": "Directory.ReadWrite.All"
        },
        'aws': {
            "eventSource": "iam.amazonaws.com",
            "eventName": "CreateAccessKey",
            "userIdentity": {
                "arn": "arn:aws:iam::123456789012:user/developer-bob"
            },
            "requestParameters": {
                "userName": "developer-bob"
            },
            "userAgent": "aws-cli"
        },
        'dns': {
            "query": "c2-subdomain.exfil-c2.com",
            "query_type": "TXT",
            "src_ip": "10.12.4.99",
            "query_length": 45,
            "reply_code": "NOERROR"
        }
    }
    
    raw_json_input = st.text_area(
        "Audit Log Record (JSON Format)",
        value=json.dumps(default_records[source_key], indent=2),
        height=200
    )
    
    if st.button("🔍 Run Telemetry Quality Audit"):
        try:
            record_parsed = json.loads(raw_json_input)
            report = TelemetryGapAnalyzer.analyze_log_quality(source_key, record_parsed)
            
            # Health layout
            c1, c2 = st.columns([1, 2])
            with c1:
                st.markdown("#### Health Score Indicator")
                
                score_color = "#56d364" if report['health_score'] >= 80 else ("#d29922" if report['health_score'] >= 50 else "#ff7b72")
                
                # Visual gauge
                fig = go.Figure(go.Indicator(
                    mode = "gauge+number",
                    value = report['health_score'],
                    domain = {'x': [0, 1], 'y': [0, 1]},
                    title = {'text': f"{report['status']}", 'font': {'size': 20, 'color': score_color}},
                    gauge = {
                        'axis': {'range': [0, 100], 'tickwidth': 1, 'tickcolor': "#c9d1d9"},
                        'bar': {'color': score_color},
                        'bgcolor': "rgba(22, 27, 34, 0.5)",
                        'borderwidth': 2,
                        'bordercolor': "#30363d",
                        'steps': [
                            {'range': [0, 50], 'color': 'rgba(248, 81, 73, 0.1)'},
                            {'range': [50, 80], 'color': 'rgba(210, 153, 34, 0.1)'},
                            {'range': [80, 100], 'color': 'rgba(46, 160, 67, 0.1)'}
                        ]
                    }
                ))
                fig.update_layout(
                    paper_bgcolor='rgba(0,0,0,0)',
                    font={'color': "#c9d1d9", 'family': "Inter"},
                    height=220,
                    margin=dict(l=20, r=20, t=40, b=20)
                )
                st.plotly_chart(fig, use_container_width=True)
                
            with c2:
                st.markdown("#### Telemetry Audit Log Results")
                df_fields = pd.DataFrame(report['checked_fields'])
                
                # Apply custom presentation for streamlit UI
                st.dataframe(
                    df_fields[['field', 'status', 'value', 'description']],
                    use_container_width=True,
                    hide_index=True
                )
                
            # Remediation
            if report['missing_fields']:
                st.markdown("### 🔧 Telemetry Gap Remediation Steps")
                
                st.markdown(f"""
                The analyzer identified **{len(report['missing_fields'])} telemetry gaps** in the ingested sample. To remediate these blindspots, apply the following controls:
                """)
                
                # General Windows GPO Remediation
                if report['gpo_remediation']:
                    st.info(f"**Audit Policy Config (GPO)**:\n{report['gpo_remediation']}")
                # Sysmon Config
                if report['sysmon_remediation']:
                    st.info(f"**Agent Sysmon Config**:\n{report['sysmon_remediation']}")
                    
                st.markdown("""
                > [!IMPORTANT]
                > **Enterprise Security Operational Practice**: Always collaborate with the log management infrastructure (Splunk UF, Sentinel AMA, log stash forwarders) to check that parsing schemas (REGEX extractions) match changes made at the GPO/endpoint audit level.
                """)
            else:
                st.success("🎉 Telemetry Audit Passed! The log contains all fields needed to run high-precision threat detections.")
                
        except json.JSONDecodeError as e:
            st.error(f"Invalid JSON provided in input text area: {e}")

# ----------------- 🚨 IR FAST SCOPER -----------------
elif menu == "🚨 IR Fast Scoper":
    st.markdown("<h1 class='title-text'>Incident Response Fast Scoper</h1>", unsafe_allow_html=True)
    st.markdown("<p class='subtitle-text'>Rapidly compile threat intelligence indicators of compromise (IOCs) into temporary scoping queries for investigation.</p>", unsafe_allow_html=True)
    
    st.markdown("""
    During an active investigation or security incident, Detection Engineers must rapidly support Incident Response (IR) teams. 
    Input known Indicators of Compromise (IOCs) below to instantly generate search-optimized scoping queries.
    """)
    
    col1, col2 = st.columns(2)
    with col1:
        hosts_input = st.text_area("Hostnames (One per line or comma-separated)", value="PRU-DESKTOP-04, PRU-WIN-AD-01")
        ips_input = st.text_area("IP Addresses (One per line or comma-separated)", value="185.220.101.44, 45.33.22.11")
    with col2:
        users_input = st.text_area("Target Usernames (One per line or comma-separated)", value="compromised.user, john.doe")
        hashes_input = st.text_area("SHA256 File Hashes (One per line or comma-separated)", value="a34e56b78d2345e67f89ab0123cd45ef6789ab0123456789abcdef0123456789")

    # Parsing inputs
    def clean_csv_input(raw_str):
        if not raw_str.strip():
            return []
        # Replace newlines with commas
        cleaned = raw_str.replace('\n', ',')
        parts = [p.strip() for p in cleaned.split(',')]
        return [p for p in parts if p]
        
    hosts = clean_csv_input(hosts_input)
    ips = clean_csv_input(ips_input)
    users = clean_csv_input(users_input)
    hashes = clean_csv_input(hashes_input)
    
    if st.button("⚡ Generate Scoping Queries"):
        st.divider()
        
        # Build SPL
        spl_clauses = []
        if hosts:
            escaped_hosts = [f'"{h}"' for h in hosts]
            spl_clauses.append(f"Computer IN ({', '.join(escaped_hosts)})")
        if ips:
            escaped_ips = [f'"{ip}"' for ip in ips]
            spl_clauses.append(f"(src_ip IN ({', '.join(escaped_ips)}) OR dest_ip IN ({', '.join(escaped_ips)}) OR IpAddress IN ({', '.join(escaped_ips)}))")
        if users:
            escaped_users = [f'"{u}"' for u in users]
            spl_clauses.append(f"(User IN ({', '.join(escaped_users)}) OR TargetUserName IN ({', '.join(escaped_users)}) OR user IN ({', '.join(escaped_users)}))")
        if hashes:
            escaped_hashes = [f'"{h}"' for h in hashes]
            spl_clauses.append(f"(Hashes IN ({', '.join(escaped_hashes)}) OR sha256 IN ({', '.join(escaped_hashes)}) OR SHA256 IN ({', '.join(escaped_hashes)}))")
            
        splunk_scoping = "index=* OR index=_audit\n| search " + " OR ".join(spl_clauses)
        
        # Build KQL
        kql_clauses = []
        if hosts:
            escaped_hosts = [f'"{h}"' for h in hosts]
            kql_clauses.append(f"Computer in ({', '.join(escaped_hosts)})")
        if ips:
            escaped_ips = [f'"{ip}"' for ip in ips]
            kql_clauses.append(f"(SrcIpAddr in ({', '.join(escaped_ips)}) or DstIpAddr in ({', '.join(escaped_ips)}) or IpAddress in ({', '.join(escaped_ips)}))")
        if users:
            escaped_users = [f'"{u}"' for u in users]
            kql_clauses.append(f"(AccountName in ({', '.join(escaped_users)}) or TargetUserName in ({', '.join(escaped_users)}) or UserPrincipalName in ({', '.join(escaped_users)}))")
        if hashes:
            escaped_hashes = [f'"{h}"' for h in hashes]
            kql_clauses.append(f"(SHA256 in ({', '.join(escaped_hashes)}) or DeviceProcessEvents_SHA256 in ({', '.join(escaped_hashes)}))")
            
        kql_scoping = "search in (DeviceProcessEvents, DeviceNetworkEvents, SecurityEvent, AuditLogs, AWSCloudTrail)\n| where " + " or ".join(kql_clauses)
        
        # Display Results
        t1, t2 = st.tabs(["Splunk SPL Scoping Query", "Microsoft Sentinel KQL Scoping Query"])
        with t1:
            st.markdown("#### Temporary Splunk Scoping Query")
            st.code(splunk_scoping, language='sql')
            st.info("""
            **Optimization Tip**: Scoping index=* is search-expensive. If the domain is known (e.g. host-only), replace index=* with specific endpoint or network indices (e.g. index=windows OR index=sysmon) to accelerate execution.
            """)
        with t2:
            st.markdown("#### Temporary Microsoft Sentinel KQL Scoping Query")
            st.code(kql_scoping, language='sql')
            st.info("""
            **Optimization Tip**: KQL's multi-table search can be slow over long time windows. Restrict the search scope by defining a time bounds filter at the very top (e.g., `| where TimeGenerated > ago(12h)`).
            """)
