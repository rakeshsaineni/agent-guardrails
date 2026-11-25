"""Tool-call authorization enforced outside the model.

The model can be talked into anything, so its tool calls are checked by plain code: who
is asking (role), what for (tool and argument constraints), and where the request came
from (provenance). A call whose arguments came from untrusted content, such as an email
or a web page, can't run without a person approving it, however convincing the content was."""

from __future__ import annotations

import fnmatch
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

import yaml

DEFAULT_POLICY = """
roles:
  analyst:  [read_inbox, search_docs, send_email, http_get]
  intern:   [read_inbox, search_docs]
tools:
  send_email:
    allow_recipient_domains: ["company.example"]
    max_per_minute: 5
  http_get:
    allow_hosts: ["api.company.example", "*.wikipedia.org"]
  read_inbox: {}
  search_docs: {}
untrusted_provenance: require_approval   # deny | require_approval
"""


@dataclass
class Decision:
    allowed: bool
    needs_approval: bool = False
    reasons: list[str] = field(default_factory=list)


@dataclass
class ToolPolicy:
    rules: dict = field(default_factory=lambda: yaml.safe_load(DEFAULT_POLICY))
    _calls: dict = field(default_factory=dict)

    @classmethod
    def from_yaml(cls, text: str) -> ToolPolicy:
        return cls(yaml.safe_load(text))

    def check(self, role: str, tool: str, args: dict, provenance: str = "user") -> Decision:
        """provenance: 'user' (the person asked for this) or 'untrusted' (it came from content)."""
        reasons = []
        if tool not in self.rules["roles"].get(role, []):
            return Decision(False, reasons=[f"role '{role}' may not use {tool}"])
        cfg = self.rules["tools"].get(tool, {})
        if tool == "send_email":
            domain = str(args.get("to", "")).rsplit("@", 1)[-1].lower()
            if domain not in cfg.get("allow_recipient_domains", []):
                reasons.append(f"recipient domain '{domain}' is not allowed")
        if tool == "http_get":
            host = urlparse(str(args.get("url", ""))).hostname or ""
            if not any(fnmatch.fnmatch(host, p) for p in cfg.get("allow_hosts", [])):
                reasons.append(f"host '{host}' is not on the allowlist")
        limit = cfg.get("max_per_minute")
        if limit:
            now = time.monotonic()
            recent = [t for t in self._calls.get((role, tool), []) if now - t < 60]
            if len(recent) >= limit:
                reasons.append(f"rate limit: {limit}/min for {tool}")
            self._calls[(role, tool)] = recent + [now]
        if reasons:
            return Decision(False, reasons=reasons)
        if provenance == "untrusted":
            mode = self.rules.get("untrusted_provenance", "require_approval")
            return Decision(False, needs_approval=(mode == "require_approval"),
                            reasons=["arguments came from untrusted content"])
        return Decision(True)
