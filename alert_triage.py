import hashlib

SEVERITY_ORDER = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}

def triage_alerts(alerts):
    """Assign stable IDs and analyst priority metadata."""
    output = []
    for alert in alerts:
        item = dict(alert)
        fingerprint = "|".join([
            item.get("rule_name",""), item.get("timestamp",""),
            item.get("host",""), item.get("source_ip","")
        ])
        item["alert_id"] = "SOC-" + hashlib.sha1(fingerprint.encode()).hexdigest()[:8].upper()
        item["priority_score"] = SEVERITY_ORDER.get(item.get("severity"), 1) * 25
        output.append(item)
    return sorted(output, key=lambda a: (SEVERITY_ORDER.get(a["severity"], 0), a["timestamp"]), reverse=True)
