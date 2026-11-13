import json
import os
import urllib.request
import urllib.error

def local_explanation(alert):
    return f"""
### Analyst summary
{alert.get('description','No description available')}

### Why this matters
This behavior may indicate malicious activity, but it can also result from authorized administration or user error. Treat the alert as an investigation lead rather than proof of compromise.

### Evidence to validate
- **Host:** {alert.get('host','unknown')}
- **Source IP:** {alert.get('source_ip','unknown')}
- **Account:** {alert.get('username','unknown')}
- **Observed evidence:** {alert.get('evidence','not supplied')}
- **MITRE ATT&CK:** {alert.get('mitre_technique','not mapped')}

### Recommended investigation
1. Review surrounding authentication and process events for the same host and account.
2. Compare the timestamp and source IP with known user activity and approved change windows.
3. Check endpoint telemetry, identity provider records and threat intelligence sources.
4. Preserve relevant logs and record the analyst's findings.

### Suggested response
{alert.get('recommended_action','Follow the approved incident response procedure.')}

**Confidence note:** This is a rule-based triage explanation. Confirm findings using additional telemetry before containment or account changes.
"""

def explain_alert(alert):
    api_key = os.getenv("OPENAI_API_KEY")
    model = os.getenv("OPENAI_MODEL", "gpt-4.1-mini")
    if not api_key:
        return local_explanation(alert)
    prompt = (
        "You are assisting a SOC analyst. Explain this alert using only supplied evidence. "
        "Separate observed facts from hypotheses. Give validation steps and safe response recommendations. "
        "Do not claim compromise is confirmed.\n\n" + json.dumps(alert, indent=2)
    )
    payload = json.dumps({
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a cautious cybersecurity SOC copilot."},
            {"role": "user", "content": prompt}
        ],
        "temperature": 0.2
    }).encode()
    request = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=payload,
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            data = json.loads(response.read().decode())
        return data["choices"][0]["message"]["content"]
    except (urllib.error.URLError, KeyError, ValueError, TimeoutError) as exc:
        return local_explanation(alert) + f"\n\n> AI API unavailable; local explanation used. Detail: {exc}"
