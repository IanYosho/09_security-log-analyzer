import streamlit as st
import pandas as pd
import re
import plotly.express as px
import os

# Page configuration
st.set_page_config(
    page_title="Security Log Analyzer & SIEM Engine",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️️ Security Log Analyzer & SIEM Detection Engine")
st.markdown(
    "Automated parsing and heuristic detection pipeline for SOC incident triage. "
    "Ingests raw log streams (**Nginx / Apache Web Access** and **Linux Auth / SSH**), "
    "flags malicious behavioral patterns, and aggregates defensive telemetry."
)

# Sidebar: Ingestion controls
with st.sidebar:
    st.header("📂 Log Ingestion")
    source_choice = st.radio(
        "Select Log Source:",
        ["Sample Web Access (Nginx)", "Sample Linux Auth (SSH/Sudo)", "Upload Custom Log File"]
    )
    
    uploaded_file = None
    if source_choice == "Upload Custom Log File":
        uploaded_file = st.file_uploader("Upload raw .log or .txt file", type=["log", "txt"])
    
    st.markdown("---")
    st.caption("SOC Telemetry & Detection Engineering | Project 09")

# --- Log Parsers ---

def parse_nginx_logs(raw_lines):
    # Standard Combined/Common Log Format Regex
    pattern = r'^(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<uri>\S+) \S+" (?P<status>\d{3}) (?P<bytes>\S+) "(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"'
    records = []
    
    # Attack Signatures
    sqli_pattern = re.compile(r"(union.*select|order.*by|--|'|%27|\bOR\b.*=)", re.IGNORECASE)
    xss_pattern = re.compile(r"(<script|%3Cscript|alert\(|onerror=|onload=)", re.IGNORECASE)
    traversal_pattern = re.compile(r"(\.\./|\.\.\\|/etc/passwd|win\.ini|%2e%2e)", re.IGNORECASE)
    scanner_probe_pattern = re.compile(r"(\.env|wp-login\.php|phpmyadmin|\.git|config\.php)", re.IGNORECASE)

    for line in raw_lines:
        match = re.match(pattern, line.strip())
        if match:
            data = match.groupdict()
            uri = data['uri']
            ua = data['user_agent']
            status = int(data['status'])
            
            # Severity / Threat Evaluation
            threat_type = "Normal Activity"
            severity = "Low"
            
            if sqli_pattern.search(uri):
                threat_type = "SQL Injection (SQLi)"
                severity = "Critical"
            elif traversal_pattern.search(uri):
                threat_type = "Path Traversal / LFI"
                severity = "High"
            elif xss_pattern.search(uri):
                threat_type = "Cross-Site Scripting (XSS)"
                severity = "High"
            elif scanner_probe_pattern.search(uri):
                threat_type = "Reconnaissance / Probe"
                severity = "Medium"
            elif status >= 500:
                threat_type = "Server Error (Potential Anomaly)"
                severity = "Medium"
            elif status in [401, 403]:
                threat_type = "Access Denied / Forbidden"
                severity = "Low"
                
            data['threat_type'] = threat_type
            data['severity'] = severity
            records.append(data)
            
    return pd.DataFrame(records)

def parse_auth_logs(raw_lines):
    # Regex for standard Linux syslog auth.log
    records = []
    
    for line in raw_lines:
        line_clean = line.strip()
        if not line_clean:
            continue
            
        threat_type = "Normal Activity"
        severity = "Low"
        user = "N/A"
        src_ip = "N/A"
        timestamp = line_clean[:15]
        
        # Check for SSH Failed password
        if "Failed password" in line_clean:
            threat_type = "SSH Failed Authentication"
            severity = "High"
            # Extract user & IP
            user_match = re.search(r"for (invalid user )?(\S+) from", line_clean)
            ip_match = re.search(r"from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line_clean)
            if user_match:
                user = user_match.group(2)
            if ip_match:
                src_ip = ip_match.group(1)
        
        # Check for SSH Accepted password
        elif "Accepted password" in line_clean:
            threat_type = "SSH Successful Logon"
            severity = "Info"
            user_match = re.search(r"for (\S+) from", line_clean)
            ip_match = re.search(r"from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line_clean)
            if user_match:
                user = user_match.group(1)
            if ip_match:
                src_ip = ip_match.group(1)
                
        # Check for sudo execution
        elif "sudo:" in line_clean:
            threat_type = "Privileged Command Execution (Sudo)"
            severity = "Medium"
            user_match = re.search(r"sudo:\s+(\S+)\s+:", line_clean)
            cmd_match = re.search(r"COMMAND=(.*)", line_clean)
            if user_match:
                user = user_match.group(1)
            if cmd_match and ("/etc/shadow" in cmd_match.group(1) or "chmod" in cmd_match.group(1)):
                threat_type = "Suspicious Sudo Command"
                severity = "Critical"

        records.append({
            "timestamp": timestamp,
            "threat_type": threat_type,
            "severity": severity,
            "user": user,
            "src_ip": src_ip,
            "raw_log": line_clean
        })
        
    return pd.DataFrame(records)

# --- Ingestion Execution ---
raw_lines = []
detected_mode = None

if source_choice == "Sample Web Access (Nginx)":
    sample_path = os.path.join("sample_logs", "nginx_access.log")
    if os.path.exists(sample_path):
        with open(sample_path, "r", encoding="utf-8") as f:
            raw_lines = f.readlines()
        detected_mode = "web"
    else:
        st.error(f"Sample log not found at `{sample_path}`. Please verify your folder setup.")

elif source_choice == "Sample Linux Auth (SSH/Sudo)":
    sample_path = os.path.join("sample_logs", "auth.log")
    if os.path.exists(sample_path):
        with open(sample_path, "r", encoding="utf-8") as f:
            raw_lines = f.readlines()
        detected_mode = "auth"
    else:
        st.error(f"Sample log not found at `{sample_path}`. Please verify your folder setup.")

elif source_choice == "Upload Custom Log File":
    if uploaded_file is not None:
        content = uploaded_file.read().decode("utf-8", errors="ignore")
        raw_lines = content.splitlines()
        # Heuristic detection for log type
        sample_snippet = " ".join(raw_lines[:5])
        if "HTTP/" in sample_snippet or "GET " in sample_snippet or "POST " in sample_snippet:
            detected_mode = "web"
        else:
            detected_mode = "auth"

# --- Main Dashboard Pipeline ---
if raw_lines and detected_mode:
    with st.spinner("Processing security event stream..."):
        if detected_mode == "web":
            df = parse_nginx_logs(raw_lines)
        else:
            df = parse_auth_logs(raw_lines)

    if df.empty:
        st.warning("No records could be parsed with the current regex engine.")
    else:
        # Metrics Row
        total_events = len(df)
        malicious_events = len(df[df['severity'].isin(["Critical", "High"])])
        suspicious_events = len(df[df['severity'] == "Medium"])
        unique_ips = df['ip'].nunique() if 'ip' in df.columns else df[df['src_ip'] != 'N/A']['src_ip'].nunique()

        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Total Events Parsed", total_events)
        c2.metric("Critical / High Threats", malicious_events, delta_color="inverse")
        c3.metric("Medium Suspicious Events", suspicious_events, delta_color="inverse")
        c4.metric("Unique External IPs", unique_ips)

        st.markdown("---")

        # Visual Telemetry Grid
        col_chart1, col_chart2 = st.columns(2)

        with col_chart1:
            st.subheader("📊 Threat Classification Breakdown")
            threat_counts = df['threat_type'].value_counts().reset_index()
            threat_counts.columns = ['Threat Category', 'Count']
            fig_bar = px.bar(
                threat_counts,
                x='Count',
                y='Threat Category',
                orientation='h',
                color='Count',
                color_continuous_scale='Reds',
                title="Event Count by Security Rule"
            )
            fig_bar.update_layout(yaxis={'categoryorder': 'total ascending'})
            st.plotly_chart(fig_bar, use_container_width=True)

        with col_chart2:
            st.subheader("🎯 Severity Distribution")
            fig_pie = px.pie(
                df,
                names='severity',
                title="Events Grouped by Risk Severity",
                color='severity',
                color_discrete_map={
                    "Critical": "#d90429",
                    "High": "#f77f00",
                    "Medium": "#fcbf49",
                    "Low": "#2a9d8f",
                    "Info": "#4a4e69"
                }
            )
            st.plotly_chart(fig_pie, use_container_width=True)

        # SIEM Alert Triage Table
        st.subheader("🚨 Incident Detection & Triage Console")
        
        # Interactive Severity Filter
        selected_severities = st.multiselect(
            "Filter by Severity Level:",
            options=["Critical", "High", "Medium", "Low", "Info"],
            default=["Critical", "High", "Medium"]
        )

        filtered_df = df[df['severity'].isin(selected_severities)]

        if detected_mode == "web":
            display_cols = ["timestamp", "ip", "method", "uri", "status", "threat_type", "severity", "user_agent"]
        else:
            display_cols = ["timestamp", "src_ip", "user", "threat_type", "severity", "raw_log"]

        st.dataframe(filtered_df[display_cols], use_container_width=True)

        # Export Alert Evidence
        csv_data = filtered_df.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="📥 Export Triage Incidents to CSV",
            data=csv_data,
            file_name="security_incident_triage.csv",
            mime="text/csv",
            type="primary"
        )
else:
    st.info("Please select a sample log feed or upload your own file from the left sidebar to initialize telemetry.")