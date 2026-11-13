import json, sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "soc_copilot.db"

def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with _connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                alert_id TEXT PRIMARY KEY,
                timestamp TEXT,
                severity TEXT,
                rule_name TEXT,
                title TEXT,
                description TEXT,
                evidence TEXT,
                source_ip TEXT,
                host TEXT,
                username TEXT,
                mitre_technique TEXT,
                recommended_action TEXT,
                status TEXT,
                priority_score INTEGER
            )
        """)

def clear_alerts():
    with _connect() as conn:
        conn.execute("DELETE FROM alerts")

def save_alerts(alerts):
    with _connect() as conn:
        for a in alerts:
            conn.execute("""
                INSERT OR REPLACE INTO alerts VALUES (
                    :alert_id,:timestamp,:severity,:rule_name,:title,:description,
                    :evidence,:source_ip,:host,:username,:mitre_technique,
                    :recommended_action,:status,:priority_score
                )
            """, a)

def fetch_alerts():
    with _connect() as conn:
        rows = conn.execute("SELECT * FROM alerts ORDER BY priority_score DESC, timestamp DESC").fetchall()
        return [dict(row) for row in rows]
