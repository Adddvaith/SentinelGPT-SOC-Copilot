import streamlit as st
import pandas as pd
import requests
from datetime import datetime

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3.1:8b"

MITRE_MAP = {
    "Brute Force": {
        "technique": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access"
    },
    "Suspicious PowerShell": {
        "technique": "T1059.001",
        "name": "PowerShell",
        "tactic": "Execution"
    },
    "Account Creation": {
        "technique": "T1136",
        "name": "Create Account",
        "tactic": "Persistence"
    },
    "Privilege Escalation": {
        "technique": "T1068",
        "name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation"
    }
}

def call_llm(prompt):
    payload = {
        "model": MODEL,
        "prompt": prompt,
        "stream": False
    }

    try:
        response = requests.post(OLLAMA_URL, json=payload, timeout=120)
        response.raise_for_status()
        return response.json().get("response", "No response generated.")
    except Exception as e:
        return f"LLM error: {e}"

def read_uploaded_file(uploaded_file):
    content = uploaded_file.read().decode("utf-8", errors="ignore")
    lines = [line.strip() for line in content.splitlines() if line.strip()]
    return lines

def detect_events(lines):
    detections = []

    failed_login_count = 0

    for line in lines:
        lower = line.lower()

        if "failed password" in lower or "failed login" in lower or "authentication failed" in lower:
            failed_login_count += 1

        if "powershell" in lower and ("encodedcommand" in lower or "-enc" in lower or "iex" in lower):
            detections.append({
                "type": "Suspicious PowerShell",
                "severity": "High",
                "evidence": line
            })

        if "new user" in lower or "useradd" in lower or "account created" in lower:
            detections.append({
                "type": "Account Creation",
                "severity": "Medium",
                "evidence": line
            })

        if "sudo" in lower or "privilege" in lower or "administrator" in lower:
            detections.append({
                "type": "Privilege Escalation",
                "severity": "Medium",
                "evidence": line
            })

    if failed_login_count >= 5:
        detections.append({
            "type": "Brute Force",
            "severity": "High",
            "evidence": f"{failed_login_count} failed login attempts detected."
        })

    for detection in detections:
        detection["mitre"] = MITRE_MAP.get(detection["type"], {})

    return detections

def generate_report(detections):
    detection_text = ""

    for d in detections:
        mitre = d.get("mitre", {})
        detection_text += f"""
Detection Type: {d['type']}
Severity: {d['severity']}
Evidence: {d['evidence']}
MITRE Technique: {mitre.get('technique', 'N/A')} - {mitre.get('name', 'N/A')}
Tactic: {mitre.get('tactic', 'N/A')}
"""

    prompt = f"""
You are a SOC analyst assistant.

Generate an analyst-ready incident report using the detections below.

Include:
1. Executive Summary
2. Technical Findings
3. MITRE ATT&CK Mapping
4. Timeline or Evidence Summary
5. Severity Assessment
6. Recommended Containment Actions
7. Remediation Steps

Detections:
{detection_text}
"""

    return call_llm(prompt)

st.set_page_config(page_title="GPT-Powered SOC Analyst Copilot", layout="wide")

st.title("GPT-Powered SOC Analyst Copilot")
st.write("Upload security logs, detect suspicious activity, map to MITRE ATT&CK, and generate an incident report.")

uploaded_file = st.file_uploader(
    "Upload a log file",
    type=["txt", "log", "csv", "json"]
)

if uploaded_file:
    lines = read_uploaded_file(uploaded_file)

    st.subheader("Raw Log Preview")
    st.code("\n".join(lines[:20]))

    detections = detect_events(lines)

    st.subheader("Detections")

    if detections:
        df = pd.DataFrame([
            {
                "Type": d["type"],
                "Severity": d["severity"],
                "MITRE Technique": d["mitre"].get("technique", "N/A"),
                "MITRE Name": d["mitre"].get("name", "N/A"),
                "Tactic": d["mitre"].get("tactic", "N/A"),
                "Evidence": d["evidence"]
            }
            for d in detections
        ])

        st.dataframe(df, use_container_width=True)

        if st.button("Generate Incident Report"):
            with st.spinner("Generating report..."):
                report = generate_report(detections)

            st.subheader("Incident Report")
            st.markdown(report)

            st.download_button(
                label="Download Report",
                data=report,
                file_name=f"incident_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md",
                mime="text/markdown"
            )
    else:
        st.success("No suspicious activity detected.")
