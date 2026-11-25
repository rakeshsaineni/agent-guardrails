# Control mapping (HIPAA, SOC 2, GDPR)

This shows which **technical controls** in this repo support common requirements. It is a mapping for discussion with a compliance team, **not** a claim that using this code makes a system compliant.

| Requirement | What it asks for | Supporting control here |
|---|---|---|
| HIPAA §164.312(b) Audit controls | Record and examine activity in systems containing ePHI | Hash-chained audit log of every scan and tool call (`audit.py`), with tamper detection |
| HIPAA §164.312(a)(1) Access control | Allow access only to authorized persons or software | Role → tool allowlist, argument constraints (`policy.py`) |
| HIPAA §164.514(b) De-identification (safe harbor identifiers) | Remove identifiers such as SSN, MRN, phone, email, dates | Validated detectors for SSN, MRN, NPI, phone, email, DOB; redaction and reversible tokenization (`pii.py`) |
| SOC 2 CC6.1 / CC6.3 Logical access | Least privilege, role-based access | Per-role tool permissions, domain and host allowlists |
| SOC 2 CC7.2 System monitoring | Detect anomalies and security events | Scan verdicts and blocked calls written to the audit log; `/audit/verify` |
| SOC 2 CC8.1 Change management | Controlled, reviewed changes | Policy as a YAML file in version control; CI gate fails if any red-team attack succeeds |
| GDPR Art. 25 Data protection by design | Minimize personal data processing | Tokenize PII before external model calls; re-identify only in the response |
| GDPR Art. 32 Security of processing | Appropriate technical measures | Layered injection defense, allowlists, audit integrity |
