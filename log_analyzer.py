import csv, io, json
from pathlib import Path

REQUIRED_FIELDS = ["timestamp", "host", "event_type"]

def normalize_events(events):
    normalized = []
    for raw in events:
        item = {str(k).strip().lower(): v for k, v in raw.items()}
        for field in REQUIRED_FIELDS:
            if not item.get(field):
                item[field] = "unknown"
        for field in ["username","source_ip","process","command_line","status","message","event_name"]:
            item.setdefault(field, "")
        normalized.append(item)
    return normalized

def load_sample_logs():
    path = Path(__file__).parent / "sample_logs" / "demo_events.jsonl"
    with path.open(encoding="utf-8") as handle:
        return normalize_events([json.loads(line) for line in handle if line.strip()])

def parse_uploaded_file(uploaded_file):
    name = uploaded_file.name.lower()
    raw = uploaded_file.getvalue().decode("utf-8-sig")
    if name.endswith((".jsonl", ".ndjson")):
        events = [json.loads(line) for line in raw.splitlines() if line.strip()]
    elif name.endswith(".csv"):
        events = list(csv.DictReader(io.StringIO(raw)))
    else:
        raise ValueError("Only CSV and JSONL files are supported.")
    if not events:
        raise ValueError("The uploaded file contains no events.")
    return normalize_events(events)

def summarize_events(events):
    return {
        "total_events": len(events),
        "event_types": dict(__import__("collections").Counter(e.get("event_type","unknown") for e in events)),
        "hosts": sorted(set(e.get("host","unknown") for e in events)),
        "source_ips": sorted(set(e.get("source_ip","unknown") for e in events))
    }
