# SentinelAI — AI-Powered SOC Copilot

A portfolio-ready SOC investigation dashboard demonstrating security event ingestion, explainable rule-based detections, alert triage, MITRE ATT&CK context, optional LLM-assisted explanations and incident reporting.

> **Important:** This is a training/demo application. Included data is synthetic. Detection logic is illustrative and must be tuned and validated before use in a real environment. It does not perform endpoint isolation, account disabling or network blocking.

## Features

- Import normalized Windows/Linux/cloud-style events from CSV or JSONL.
- Run transparent detections for repeated authentication failures, successful login after failures, suspicious PowerShell indicators, IAM policy changes, new access key creation and privilege changes.
- Prioritize alerts by severity.
- Add MITRE ATT&CK technique context.
- Correlate failed and successful authentication events from the same source IP.
- Use a local deterministic analyst playbook without an API key.
- Optionally call an OpenAI-compatible Chat Completions endpoint for alert explanations.
- Export alerts and investigation reports as CSV, JSON and Markdown.

## Quick start

### 1. Requirements
- Python 3.10 or newer
- pip

### 2. Create and activate a virtual environment

Windows PowerShell:
```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

macOS/Linux:
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the application
```bash
streamlit run app.py
```
Open the local URL printed by Streamlit (normally http://localhost:8501).

The dashboard loads synthetic demo events automatically. Use the sidebar button to reset the dataset or upload your own CSV/JSONL file.

## Optional AI API

The app works without an API key. To enable API-generated explanations, set environment variables before launching.

Windows PowerShell:
```powershell
$env:OPENAI_API_KEY="your-api-key"
$env:OPENAI_MODEL="gpt-4.1-mini"
streamlit run app.py
```

macOS/Linux:
```bash
export OPENAI_API_KEY="your-api-key"
export OPENAI_MODEL="gpt-4.1-mini"
streamlit run app.py
```

Never commit API keys to GitHub. Do not upload confidential production logs or personal data to an external AI provider without organizational approval. The optional integration sends the selected alert's fields to the configured API.

## Input schema

CSV and JSONL records should contain these fields (optional fields may be blank):

| Field | Purpose |
|---|---|
| timestamp | ISO-8601 event timestamp |
| host | Hostname or cloud resource |
| event_type | authentication, process, iam_policy_change, access_key_created, privilege_change |
| username | Account involved |
| source_ip | Source address |
| status | failed or success for authentication |
| process | Process name |
| command_line | Command line |
| event_name | Cloud event name |
| message | Analyst-readable event details |

Example:
```json
{"timestamp":"2026-11-12T09:00:00","host":"WIN-WS01","event_type":"authentication","username":"analyst","source_ip":"198.51.100.25","status":"failed","message":"Logon failure"}
```

## Detection logic

| Detection | Trigger in this demo | ATT&CK |
|---|---|---|
| Repeated authentication failures | 5+ failed authentication events from one source IP | T1110 |
| Successful login after failures | 3+ failures and a later successful login from same source | T1110 |
| Suspicious PowerShell | Encoded command, download string, hidden window or bypass indicator | T1059.001 |
| IAM policy modification | IAM policy change event | T1098 |
| New access key | Access key creation event | T1098.001 |
| Privilege change | Privileged group or role change event | T1098 |

These simple thresholds are for demonstration, not universal security baselines. The correlation is source-IP based and should be enhanced with time windows, identity context and environment-specific allowlists for production-grade use.

## Testing

Run:
```bash
python -m unittest discover -s tests -v
```

## Project structure

```text
AI-SOC-Copilot/
├── app.py
├── detection_engine.py
├── alert_triage.py
├── log_analyzer.py
├── mitre_mapping.py
├── ai_copilot.py
├── database.py
├── reporting.py
├── sample_logs/
├── tests/
├── reports/
├── requirements.txt
└── README.md
```

## Architecture

1. **Ingestion:** CSV/JSONL or bundled synthetic dataset.
2. **Normalization:** Map records to a common event schema.
3. **Detection:** Transparent Python rules inspect authentication, process and IAM events.
4. **Triage:** Assign severity, stable alert identifier and priority score.
5. **Context:** Add MITRE ATT&CK technique references.
6. **Copilot:** Generate a local playbook explanation or optional LLM explanation.
7. **Reporting:** Export incident reports and alert data.

## Limitations and next improvements

- Add proper time-window correlation and event deduplication.
- Add Sigma rule parsing rather than illustrative Python rules only.
- Add Windows Event ID and Sysmon field mappings.
- Add authentication identity and geolocation context.
- Add analyst workflow states, audit history and role-based access.
- Add a real SIEM connector after defining an approved environment.
- Add precision/recall evaluation on a labeled dataset before making accuracy claims.

## Resume description

**AI-Powered SOC Copilot & Intelligent Threat Detection Platform**  
Developed a Python-based SOC investigation dashboard to ingest and normalize security events, detect suspicious authentication and endpoint/cloud activity, and prioritize alerts. Implemented explainable detection rules, event correlation, MITRE ATT&CK context, optional LLM-assisted investigation summaries and exportable incident reports.

Only describe features as completed after running the application and validating them with the included tests and your own evidence.

<img width="1920" height="1020" alt="Screenshot 2026-11-13 122444" src="https://github.com/user-attachments/assets/3fda44ee-9ea7-4584-9275-76a9e4bddf43" />
<img width="1920" height="1080" alt="Screenshot 2026-11-13 122455" src="https://github.com/user-attachments/assets/48dcc140-e285-40a1-8ffa-52c762247da0" />

