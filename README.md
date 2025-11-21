n Cyber Threat Intelligence Log Analyzer
This Python script parses web server access logs, detects suspicious behavior (e.g., malicious IPs,
suspicious URIs, abnormal user-agents), queries AbuseIPDB and VirusTotal threat intelligence APIs,
and generates a markdown report with insights. It can also use Google Gemini AI to provide anomaly
summaries.



---
n Features
- Parse JSON-formatted log entries from a web server log file.
- Detect suspicious activity based on:
- Known malicious URIs (`/wp-admin.php`, `/admin/login.php`, `/phpmyadmin/`, etc.)
- Suspicious User-Agents (`sqlmap`, `nmap`, `masscan`, `curl`, etc.)
- CTI enrichment from AbuseIPDB and VirusTotal.
- Automatically de-duplicate repeated IPs.
- Compute statistics:
- Total requests, unique IPs
- Status code counts (200, 404, etc.)
- Top attacker IPs
- Common User-Agents
- AI anomaly detection summary with Gemini API.
- Generate a detailed Markdown report in `reports/threat_report.md`.
---
n Requirements
- Python 3.8+
- Dependencies:
```bash
pip install requests



```
---
n API Keys
This script requires API keys for:
- AbuseIPDB
- VirusTotal
- Google Gemini
Set them as environment variables before running:
```bash
export ABUSEIPDB_API_KEY="your_abuseipdb_key"
export VIRUSTOTAL_API_KEY="your_virustotal_key"
export GEMINI_API_KEY="your_gemini_key"
```
If keys are missing, the script will ask you to input them at runtime.
---
n Usage
1. Put your log file in the project folder. The log file should be in JSON format per line.
2. Run the script:
```bash
python python_project.py access_log.txt
```
If no file is given, it defaults to `access_log.txt`.


---
n Output
The script generates a report in:
- `reports/threat_report.md`
Report sections include:
- Executive Summary
- AI anomaly detection (if Gemini API key is provided)
- Top attacker IPs
- User-Agent analysis
- Detailed per-threat breakdown.
---
nn Notes
- If API keys are invalid or quotas exceeded, CTI fields may be empty (`{}`).
- Logs without suspicious indicators will still contribute to summary stats.
- To expand detection, edit the lists in the script.
---


---
nnn Author
Developed by a cybersecurity enthusiast to automate log analysis and CTI reporting. Pull requests and
improvements welcome!

