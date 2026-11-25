"""Guardrail sidecar: any agent framework can call it over HTTP before and after model and tool calls."""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI
from pydantic import BaseModel

from .audit import AuditLog
from .datasets import corpus
from .injection import InjectionClassifier, heuristic_flags, spotlight
from .pii import find_pii, redact
from .policy import ToolPolicy


class Text(BaseModel):
    text: str


class ToolRequest(BaseModel):
    user: str
    role: str
    tool: str
    args: dict
    provenance: str = "user"


def create_app(audit_path: Path | None = None, policy: ToolPolicy | None = None) -> FastAPI:
    app = FastAPI(title="agent-guardrails", version="0.1.0")
    data = corpus()
    clf = InjectionClassifier().fit([t for t, _, _ in data], [y for _, y, _ in data])
    pol = policy or ToolPolicy()
    audit = AuditLog(audit_path or Path(os.environ.get("AUDIT_LOG", "audit/guardrails.jsonl")))

    @app.post("/scan")
    def scan(t: Text) -> dict:
        flags, score = heuristic_flags(t.text), clf.score(t.text)
        pii = [{"kind": f.kind, "start": f.start, "end": f.end} for f in find_pii(t.text)]
        verdict = "block" if flags or score >= 0.5 else "allow"
        audit.append({"event": "scan", "verdict": verdict, "flags": flags, "score": round(score, 3),
                      "pii_kinds": sorted({p["kind"] for p in pii})})
        return {"verdict": verdict, "heuristic_flags": flags, "classifier_score": round(score, 3), "pii": pii}

    @app.post("/redact")
    def redact_text(t: Text) -> dict:
        return {"text": redact(t.text)}

    @app.post("/spotlight")
    def spotlight_text(t: Text) -> dict:
        marked, note = spotlight(t.text)
        return {"text": marked, "system_note": note}

    @app.post("/authorize")
    def authorize(r: ToolRequest) -> dict:
        d = pol.check(r.role, r.tool, r.args, r.provenance)
        audit.append({"event": "tool_call", "user": r.user, "role": r.role, "tool": r.tool,
                      "args": {k: redact(str(v)) for k, v in r.args.items()}, "provenance": r.provenance,
                      "allowed": d.allowed, "needs_approval": d.needs_approval, "reasons": d.reasons})
        return {"allowed": d.allowed, "needs_approval": d.needs_approval, "reasons": d.reasons}

    @app.get("/audit/verify")
    def verify() -> dict:
        ok, bad_line = audit.verify()
        return {"intact": ok, "first_bad_line": bad_line}

    return app
