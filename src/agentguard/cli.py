"""agentguard eval | scan TEXT | serve"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="agentguard")
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("eval")
    e.add_argument("--out", default="reports")
    s = sub.add_parser("scan")
    s.add_argument("text")
    v = sub.add_parser("serve")
    v.add_argument("--port", type=int, default=8000)
    a = ap.parse_args(argv)
    if a.cmd == "eval":
        from .evaluate import run

        _, fails = run(Path(a.out))
        print(Path(a.out, "eval_report.md").read_text())
        if fails:
            print("EVAL GATE FAILED: " + "; ".join(fails), file=sys.stderr)
            return 1
    elif a.cmd == "scan":
        from .injection import heuristic_flags
        from .pii import find_pii, redact

        print(json.dumps({"injection_flags": heuristic_flags(a.text), "redacted": redact(a.text),
                          "pii": [f.kind for f in find_pii(a.text)]}, indent=2))
    elif a.cmd == "serve":
        import uvicorn

        uvicorn.run("agentguard.api:create_app", factory=True, host="0.0.0.0", port=a.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
