# Architecture notes

```text
CSV / JSONL / Synthetic events
            |
            v
      Event normalizer
            |
            v
      Python detection rules
            |
            v
       Alert triage
            |
       +----+----+
       |         |
       v         v
  SQLite store  MITRE context
       |         |
       +----+----+
            |
            v
       Streamlit UI
       /     |      \
      v      v       v
  Explorer Copilot Reports
           |
           +-- local playbook (default)
           +-- optional LLM API
```

The application is designed around explainable deterministic detection. The optional language model does not decide whether an event is malicious; it explains an already generated alert.
