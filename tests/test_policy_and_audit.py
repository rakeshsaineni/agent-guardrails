import json

from agentguard.audit import AuditLog
from agentguard.policy import ToolPolicy


def test_role_domain_host_and_provenance_rules():
    p = ToolPolicy()
    assert p.check("analyst", "send_email", {"to": "finance@company.example"}).allowed
    assert not p.check("intern", "send_email", {"to": "finance@company.example"}).allowed
    assert "not allowed" in p.check("analyst", "send_email", {"to": "x@evil.example"}).reasons[0]
    assert p.check("analyst", "http_get", {"url": "https://en.wikipedia.org/wiki/Detroit"}).allowed
    assert not p.check("analyst", "http_get", {"url": "https://evil.example/?d=1"}).allowed
    d = p.check("analyst", "send_email", {"to": "finance@company.example"}, provenance="untrusted")
    assert not d.allowed and d.needs_approval


def test_rate_limit():
    p = ToolPolicy()
    results = [p.check("analyst", "send_email", {"to": "a@company.example"}).allowed for _ in range(7)]
    assert results == [True] * 5 + [False] * 2


def test_audit_chain_detects_tampering(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    for i in range(5):
        log.append({"event": "tool_call", "n": i})
    assert log.verify() == (True, None)
    lines = (tmp_path / "a.jsonl").read_text().splitlines()
    entry = json.loads(lines[2])
    entry["n"] = 99  # someone edits history
    lines[2] = json.dumps(entry, sort_keys=True)
    (tmp_path / "a.jsonl").write_text("\n".join(lines) + "\n")
    assert log.verify() == (False, 2)
