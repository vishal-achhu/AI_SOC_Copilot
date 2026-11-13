from collections import defaultdict
from datetime import datetime, timedelta
from mitre_mapping import MITRE_MAP

def _parse_time(value):
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).replace(tzinfo=None)
    except Exception:
        return datetime(2025, 1, 1)

def run_detections(events):
    """Run transparent, explainable detections over normalized event dictionaries."""
    alerts = []
    failures = defaultdict(list)

    for event in events:
        etype = str(event.get("event_type", "")).lower()
        status = str(event.get("status", "")).lower()
        src = event.get("source_ip") or "unknown"
        if etype in ("authentication", "login", "auth") and status in ("failed", "failure", "denied"):
            failures[src].append(event)

        cmd = str(event.get("command_line", "")).lower()
        process = str(event.get("process", "")).lower()
        if ("powershell" in process or "powershell" in cmd) and any(x in cmd for x in ("-enc", "encodedcommand", "downloadstring", " -w hidden", "bypass")):
            alerts.append(_make_alert(
                event, "Suspicious PowerShell Execution", "High",
                "PowerShell command contains commonly abused execution or obfuscation indicators.",
                f"process={process}; command_line={event.get('command_line','')}",
                "Review process tree and script contents; isolate host if malicious activity is confirmed.",
                "T1059.001"
            ))

        if etype in ("iam_policy_change", "policy_change") or "attachuserpolicy" in str(event.get("event_name","")).lower():
            alerts.append(_make_alert(
                event, "Cloud IAM Policy Modification", "High",
                "An IAM policy modification event was observed and should be validated against change records.",
                f"event_name={event.get('event_name','')}; user={event.get('username','unknown')}",
                "Verify the change request, review policy scope and revert unauthorized privilege changes.",
                "T1098"
            ))

        if etype in ("access_key_created", "create_access_key"):
            alerts.append(_make_alert(
                event, "New Cloud Access Key Created", "Medium",
                "A new access key was created. Confirm that the action was authorized and securely managed.",
                f"user={event.get('username','unknown')}; source_ip={src}",
                "Validate ownership, rotate or disable unapproved keys, and review subsequent API activity.",
                "T1098.001"
            ))

        if etype in ("privilege_change", "user_added_to_admin_group"):
            alerts.append(_make_alert(
                event, "Potential Privilege Escalation", "High",
                "A privileged group or role change was observed.",
                f"user={event.get('username','unknown')}; message={event.get('message','')}",
                "Confirm administrative approval and inspect related account activity.",
                "T1098"
            ))

    for src, failed_events in failures.items():
        if len(failed_events) >= 5:
            first = failed_events[0]
            alerts.append(_make_alert(
                first, "Repeated Authentication Failures", "High",
                f"{len(failed_events)} failed authentication events were observed from the same source IP.",
                f"source_ip={src}; failed_attempts={len(failed_events)}; usernames={sorted(set(str(e.get('username','unknown')) for e in failed_events))}",
                "Check source reputation, identify targeted accounts and apply approved rate-limiting or account-protection controls.",
                "T1110"
            ))

    # Correlate failed logins followed by a successful login from the same source.
    successful_sources = {
        e.get("source_ip") for e in events
        if str(e.get("event_type","")).lower() in ("authentication","login","auth")
        and str(e.get("status","")).lower() in ("success","successful","accepted")
    }
    for src in successful_sources:
        related = failures.get(src, [])
        if len(related) >= 3:
            success_event = next(e for e in events if e.get("source_ip") == src and str(e.get("status","")).lower() in ("success","successful","accepted"))
            alerts.append(_make_alert(
                success_event, "Successful Login After Multiple Failures", "Critical",
                "A successful authentication followed multiple failed attempts from the same source IP.",
                f"source_ip={src}; preceding_failures={len(related)}; account={success_event.get('username','unknown')}",
                "Validate the login with the account owner, review MFA and session activity, and revoke sessions if compromise is confirmed.",
                "T1110"
            ))

    # De-duplicate identical rule + host + source combinations.
    unique = {}
    for alert in alerts:
        key = (alert["rule_name"], alert["host"], alert["source_ip"])
        if key not in unique:
            unique[key] = alert
    return list(unique.values())

def _make_alert(event, title, severity, description, evidence, action, technique):
    mitre = MITRE_MAP.get(technique, {})
    timestamp = str(event.get("timestamp", ""))
    return {
        "timestamp": timestamp,
        "rule_name": title,
        "title": title,
        "severity": severity,
        "description": description,
        "evidence": evidence,
        "source_ip": event.get("source_ip", "unknown"),
        "host": event.get("host", "unknown"),
        "username": event.get("username", "unknown"),
        "mitre_technique": f"{technique} — {mitre.get('name','Technique mapping')}",
        "recommended_action": action,
        "status": "New"
    }
