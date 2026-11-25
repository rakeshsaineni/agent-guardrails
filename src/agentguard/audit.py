"""Tamper-evident audit log: each JSONL entry includes the hash of the previous one,
so editing or deleting any past entry breaks the chain (and verify() says where)."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

GENESIS = "0" * 64


class AuditLog:
    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._last = self._tail_hash()

    def _tail_hash(self) -> str:
        if not self.path.exists() or not self.path.stat().st_size:
            return GENESIS
        return json.loads(self.path.read_text().splitlines()[-1])["hash"]

    def append(self, event: dict) -> dict:
        body = {"ts": round(time.time(), 3), "prev": self._last, **event}
        digest = hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()
        entry = {**body, "hash": digest}
        with self.path.open("a") as f:
            f.write(json.dumps(entry, sort_keys=True) + "\n")
        self._last = digest
        return entry

    def verify(self) -> tuple[bool, int | None]:
        prev = GENESIS
        for i, line in enumerate(self.path.read_text().splitlines()):
            entry = json.loads(line)
            claimed = entry.pop("hash")
            actual = hashlib.sha256(json.dumps(entry, sort_keys=True).encode()).hexdigest()
            if entry["prev"] != prev or actual != claimed:
                return False, i
            prev = claimed
        return True, None
