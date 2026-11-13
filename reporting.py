import csv, io
from datetime import datetime, timezone

def build_incident_report(alert):
    return f"""# Security Alert Investigation Report

**Report generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}  
**Alert ID:** {alert.get('alert_id')}  
**Severity:** {alert.get('severity')}  
**Status:** {alert.get('status')}

## Executive summary
{alert.get('description')}

## Observed evidence
- Timestamp: {alert.get('timestamp')}
- Host: {alert.get('host')}
- Source IP: {alert.get('source_ip')}
- Username: {alert.get('username')}
- Evidence: {alert.get('evidence')}

## MITRE ATT&CK context
{alert.get('mitre_technique')}

## Recommended investigation and response
{alert.get('recommended_action')}

## Analyst conclusion
Pending validation. This alert is generated from illustrative detection logic and does not independently confirm malicious activity.

## Evidence handling
Preserve original event records, note collection timestamps and document all investigation actions.
"""

def alerts_to_csv(alerts):
    if not alerts:
        return b""
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=list(alerts[0].keys()))
    writer.writeheader()
    writer.writerows(alerts)
    return output.getvalue().encode()
