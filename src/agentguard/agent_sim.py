"""A deliberately gullible email agent, used as the red-team target.

It does what an over-helpful LLM agent does in the worst case: it follows any instruction
it finds in an email (decoded from base64, through look-alike letters, in other languages).
Defenses are measured on how much damage they prevent *despite* that, which is the property
you can actually guarantee, since you can't guarantee the model's judgment."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .injection import decoded_views

EMAIL = r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+"
URL = r"https?://[^\s)\]]+"
SEND_VERBS = r"(forward|send|email|share|deliver|reenv[ií]a|env[ií]a|weiterleiten)"


@dataclass
class ToolCall:
    tool: str
    args: dict
    provenance: str  # "user" or "untrusted"


@dataclass
class Episode:
    calls: list[ToolCall] = field(default_factory=list)
    executed: list[ToolCall] = field(default_factory=list)
    blocked: list[tuple[ToolCall, list[str]]] = field(default_factory=list)
    approvals: list[ToolCall] = field(default_factory=list)
    quarantined: bool = False


def plan(user_request: str, email_body: str) -> list[ToolCall]:
    calls = [ToolCall("read_inbox", {}, "user")]
    m = re.search(SEND_VERBS + r".{0,60}?(" + EMAIL + ")", user_request, re.I)
    if m:
        calls.append(ToolCall("send_email", {"to": m.group(2), "body": email_body}, "user"))
    for view in decoded_views(email_body):  # the gullible part: instructions in content are obeyed
        for m in re.finditer(SEND_VERBS + r".{0,80}?(" + EMAIL + ")", view, re.I):
            calls.append(ToolCall("send_email", {"to": m.group(2), "body": "<inbox contents>"}, "untrusted"))
        for url in re.findall(URL, view):
            calls.append(ToolCall("http_get", {"url": url}, "untrusted"))
    return calls
