import json
import requests
from datetime import datetime
import sys
import os
from collections import Counter

# --- CONFIGURATION ---
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY") or input("Enter AbuseIPDB API key: ").strip()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY") or input("Enter Gemini API key: ").strip()
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY") or input("Enter VirusTotal API key: ").strip()

ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2/check"
VIRUSTOTAL_IP_URL = "https://www.virustotal.com/api/v3/ip_addresses/"
GEMINI_URL = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-05-20:generateContent?key={GEMINI_API_KEY}"

SUSPICIOUS_URIS = ["/wp-admin.php", "/admin/login.php", "/phpmyadmin/"]
SUSPICIOUS_USER_AGENTS = ["sqlmap", "nmap", "masscan", "curl"]

# --- Input / Output paths ---
LOG_FILE = sys.argv[1] if len(sys.argv) > 1 else "access_log.txt"
REPORTS_DIR = "reports"
os.makedirs(REPORTS_DIR, exist_ok=True)
REPORT_FILE = os.path.join(REPORTS_DIR, "threat_report.md")

# --- FUNCTIONS ---
def parse_log_file(file_path):
    parsed_logs = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    parts = line.split("\t", 2)
                    if len(parts) == 3 and parts[2].strip().startswith("{"):
                        log_entry = json.loads(parts[2])
                        parsed_logs.append(log_entry)
                except (json.JSONDecodeError, IndexError):
                    continue
        return parsed_logs
    except FileNotFoundError:
        print(f"[!] Error: The log file '{file_path}' was not found.")
        return []

def check_ip_abuseipdb(ip_address):
    headers = {"Accept": "application/json", "Key": ABUSEIPDB_API_KEY}
    params = {"ipAddress": ip_address, "maxAgeInDays": "90"}
    try:
        response = requests.get(ABUSEIPDB_URL, headers=headers, params=params)
        response.raise_for_status()
        return response.json().get("data") or {}
    except:
        return {}

def check_ip_virustotal(ip_address):
    if not VIRUSTOTAL_API_KEY:
        return {}
    url = f"{VIRUSTOTAL_IP_URL}{ip_address}"
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 404:
            return {}
        response.raise_for_status()
        return response.json().get("data", {}).get("attributes", {}) or {}
    except:
        return {}

def get_ai_summary(log_stats, threats):
    if not GEMINI_API_KEY:
        return "Gemini API key not configured."
    prompt = f"""
You are a cybersecurity analyst. Analyze the following web server log statistics
and threat detections. Identify anomalous patterns (e.g., coordinated scans,
low-and-slow attacks, spikes in errors).

Log Summary:
- Total Requests: {log_stats['total_requests']}
- Unique IPs: {log_stats['unique_ips']}
- Status Code Counts: {log_stats['status_counts']}
- 404/200 Ratio: {log_stats['ratio_404_200']}

Threat Detections: {len(threats)} total
Examples: {[t['indicator_type'] for t in threats[:5]]}

Write 2-3 sentences highlighting suspicious trends.
"""
    headers = {"Content-Type": "application/json"}
    payload = {"contents": [{"parts": [{"text": prompt}]}]}
    try:
        response = requests.post(GEMINI_URL, headers=headers, json=payload, timeout=20)
        response.raise_for_status()
        result = response.json()
        return result["candidates"][0]["content"]["parts"][0]["text"].strip()
    except:
        return "Could not generate anomaly summary due to API error."

def analyze_logs(parsed_logs):
    threats = []
    checked_ips = {}
    seen_ips = set()
    for log in parsed_logs:
        if not all(k in log for k in ["remote_addr", "uri", "user_agent"]):
            continue
        ip, uri, ua = log["remote_addr"], log["uri"], log["user_agent"]
        is_suspicious_ua = any(s in ua.lower() for s in SUSPICIOUS_USER_AGENTS)
        is_suspicious_uri = any(pattern in uri.lower() for pattern in SUSPICIOUS_URIS)

        if ip not in checked_ips:
            abuse_report = check_ip_abuseipdb(ip)
            vt_report = check_ip_virustotal(ip)
            checked_ips[ip] = {"abuseipdb": abuse_report, "virustotal": vt_report}
        else:
            abuse_report = checked_ips[ip]["abuseipdb"]
            vt_report = checked_ips[ip]["virustotal"]

        is_malicious_ip_abuse = abuse_report.get("abuseConfidenceScore", 0) > 25
        vt_stats = vt_report.get("last_analysis_stats", {})
        is_malicious_ip_vt = vt_stats.get("malicious", 0) > 2
        is_malicious_ip = is_malicious_ip_abuse or is_malicious_ip_vt

        if ip in seen_ips:
            continue
        seen_ips.add(ip)

        if is_malicious_ip and is_suspicious_ua:
            severity = "High"
            ind_type = "Correlated Threat: Malicious IP + Suspicious User-Agent"
        elif is_malicious_ip:
            severity = "Medium"
            ind_type = "Malicious IP Detected"
        elif is_suspicious_ua:
            severity = "Low"
            ind_type = "Suspicious User-Agent Detected"
        elif is_suspicious_uri:
            severity = "Low"
            ind_type = "Suspicious URI Access Attempt"
        else:
            continue

        threats.append({
            "log": log,
            "indicator_type": ind_type,
            "indicator_value": ip,
            "severity": severity,
            "cti_details": abuse_report or {},
            "vt_details": vt_report or {}
        })
    return threats

def compute_log_stats(parsed_logs):
    total = len(parsed_logs)
    ips = [log["remote_addr"] for log in parsed_logs if "remote_addr" in log]
    status_codes = [log.get("status", "UNK") for log in parsed_logs]
    counts = Counter(status_codes)
    ratio = round(counts.get("404", 0) / counts.get("200", 1), 2) if total > 0 else 0
    ua_counts = Counter([log.get("user_agent", "UNK") for log in parsed_logs])
    return {
        "total_requests": total,
        "unique_ips": len(set(ips)),
        "status_counts": dict(counts),
        "ratio_404_200": ratio,
        "top_ips": Counter(ips).most_common(10),
        "ua_counts": ua_counts.most_common(10)
    }

def generate_report(threats, log_stats):
    filtered_threats = [t for t in threats if t]

    threats_sorted = sorted(
        filtered_threats,
        key=lambda t: (
            {"High": 3, "Medium": 2, "Low": 1}.get(t.get("severity", "Low"), 0),
            (t.get("cti_details") or {}).get("abuseConfidenceScore", 0),
            (t.get("vt_details") or {}).get("last_analysis_stats", {}).get("malicious", 0)
        ),
        reverse=True
    )

    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        f.write("# 🚨 Cyber Threat Intelligence Report\n\n")
        f.write(f"**Generated on:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")

        f.write("## 📊 Executive Summary\n")
        f.write(f"- Total Requests: {log_stats['total_requests']}\n")
        f.write(f"- Unique IPs: {log_stats['unique_ips']}\n")
        f.write(f"- Threats Detected: {len(filtered_threats)}\n")
        f.write(f"- 404/200 Ratio: {log_stats['ratio_404_200']}\n\n")

        f.write("### 🤖 AI Anomaly Detection\n")
        f.write(f"{get_ai_summary(log_stats, filtered_threats)}\n\n")

        f.write("## 🌍 Top Attacker IPs\n")
        for ip, count in log_stats["top_ips"]:
            f.write(f"- {ip}: {count} requests\n")
        f.write("\n")

        f.write("## 🕵️ User-Agent Analysis\n")
        for ua, count in log_stats["ua_counts"]:
            marker = "⚠️" if any(s in ua.lower() for s in SUSPICIOUS_USER_AGENTS) else ""
            f.write(f"- {ua} ({count}) {marker}\n")
        f.write("\n")

        if not threats_sorted:
            f.write("✅ No significant threats identified.\n")
            return

        f.write("## 🔎 Detailed Threats\n")
        for i, t in enumerate(threats_sorted, 1):
            ip = t["indicator_value"]
            f.write(f"### Threat #{i} - {ip}\n")
            f.write(f"- Indicator: {t['indicator_type']}\n")
            f.write(f"- Severity: **{t['severity']}**\n")
            f.write(f"- Source IP: {t['log'].get('remote_addr')}\n")
            f.write(f"- Request: {t['log'].get('method','N/A')} {t['log'].get('uri')}\n")
            f.write(f"- User-Agent: {t['log'].get('user_agent')}\n")

            cti = t.get("cti_details") or {}
            if cti:
                f.write(f"- AbuseIPDB Confidence: {cti.get('abuseConfidenceScore','N/A')}%\n")
                f.write(f"- Total Reports: {cti.get('totalReports','N/A')}\n")
                f.write(f"- Last Reported: {cti.get('lastReportedAt','N/A')}\n")

            vt = t.get("vt_details") or {}
            if vt:
                stats = vt.get("last_analysis_stats", {})
                f.write(f"- VirusTotal Stats: {stats}\n")
                f.write(f"- ASN: {vt.get('asn','N/A')}\n")
                f.write(f"- Organization: {vt.get('as_owner','N/A')}\n")
                f.write(f"- Network: {vt.get('network','N/A')}\n")
                f.write(f"- Country: {vt.get('country','N/A')}\n")
                f.write(f"- RIR: {vt.get('regional_internet_registry','N/A')}\n")

            f.write(f"- Summary: IP {ip} was flagged for {t['indicator_type']} with severity {t['severity']}.\n\n")

    print(f"[+] Report written to {REPORT_FILE}")

# --- MAIN EXECUTION ---
if __name__ == "__main__":
    logs = parse_log_file(LOG_FILE)
    stats = compute_log_stats(logs)
    threats = analyze_logs(logs)
    generate_report(threats, stats)
