import unittest
from detection_engine import run_detections
from alert_triage import triage_alerts
from ai_copilot import local_explanation
from reporting import build_incident_report

class DetectionTests(unittest.TestCase):
    def setUp(self):
        self.events = [
            {"timestamp":"2026-11-12T09:00:00","host":"WIN-01","event_type":"authentication","username":"admin","source_ip":"203.0.113.10","status":"failed"},
            {"timestamp":"2026-11-12T09:01:00","host":"WIN-01","event_type":"authentication","username":"admin","source_ip":"203.0.113.10","status":"failed"},
            {"timestamp":"2026-11-12T09:02:00","host":"WIN-01","event_type":"authentication","username":"admin","source_ip":"203.0.113.10","status":"failed"},
            {"timestamp":"2026-11-12T09:03:00","host":"WIN-01","event_type":"authentication","username":"admin","source_ip":"203.0.113.10","status":"failed"},
            {"timestamp":"2026-11-12T09:04:00","host":"WIN-01","event_type":"authentication","username":"admin","source_ip":"203.0.113.10","status":"failed"},
            {"timestamp":"2026-11-12T09:05:00","host":"WIN-01","event_type":"authentication","username":"admin","source_ip":"203.0.113.10","status":"success"},
            {"timestamp":"2026-11-12T09:06:00","host":"WIN-01","event_type":"process","username":"admin","source_ip":"203.0.113.10","process":"powershell.exe","command_line":"powershell.exe -enc AAAA"},
        ]

    def test_auth_failure_and_success_correlation(self):
        names = [a["rule_name"] for a in run_detections(self.events)]
        self.assertIn("Repeated Authentication Failures", names)
        self.assertIn("Successful Login After Multiple Failures", names)

    def test_suspicious_powershell(self):
        names = [a["rule_name"] for a in run_detections(self.events)]
        self.assertIn("Suspicious PowerShell Execution", names)

    def test_triage_adds_id_and_priority(self):
        alerts = triage_alerts(run_detections(self.events))
        self.assertTrue(all(a["alert_id"].startswith("SOC-") for a in alerts))
        self.assertTrue(all("priority_score" in a for a in alerts))

    def test_local_copilot_and_report(self):
        alert = triage_alerts(run_detections(self.events))[0]
        self.assertIn("Analyst summary", local_explanation(alert))
        self.assertIn("Investigation Report", build_incident_report(alert))

if __name__ == "__main__":
    unittest.main()
