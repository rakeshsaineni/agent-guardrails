"""PII and secret detection with validators (not just regexes), plus reversible tokenization.

Validators cut false positives: a 16-digit number is a card only if it passes Luhn, a
9-digit number is an SSN only if its area/group/serial are possible, an NPI must pass
Luhn with the 80840 prefix, and an IBAN must pass mod-97."""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass


def luhn_ok(digits: str) -> bool:
    total, parity = 0, len(digits) % 2
    for i, ch in enumerate(digits):
        d = int(ch)
        if i % 2 == parity:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def ssn_ok(s: str) -> bool:
    a, g, n = s[:3], s[3:5], s[5:]
    return a not in ("000", "666") and not a.startswith("9") and g != "00" and n != "0000"


def iban_ok(s: str) -> bool:
    s = s.replace(" ", "").upper()
    if not 15 <= len(s) <= 34:
        return False
    num = "".join(str(int(c, 36)) for c in s[4:] + s[:4])
    return int(num) % 97 == 1


def npi_ok(s: str) -> bool:
    return len(s) == 10 and luhn_ok("80840" + s)


@dataclass
class Finding:
    kind: str
    start: int
    end: int
    text: str


PATTERNS = [
    ("EMAIL", re.compile(r"\b[\w.+-]+@[\w-]+(?:\.[\w-]+)+\b"), None),
    ("SSN", re.compile(r"\b(\d{3})-(\d{2})-(\d{4})\b"), lambda m: ssn_ok("".join(m.groups()))),
    ("CARD", re.compile(r"\b(?:\d[ -]?){12,18}\d\b"), lambda m: luhn_ok(re.sub(r"\D", "", m.group()))),
    ("IBAN", re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b"), lambda m: iban_ok(m.group())),
    ("NPI", re.compile(r"\bNPI[:# ]*(\d{10})\b", re.I), lambda m: npi_ok(m.group(1))),
    ("MRN", re.compile(r"\bMRN[:# ]*\d{6,10}\b", re.I), None),
    ("DOB", re.compile(r"\b(?:DOB|date of birth|born)[:\s]+\d{1,2}/\d{1,2}/\d{2,4}\b", re.I), None),
    ("PHONE", re.compile(r"(?<!\d)(?:\+1[ .-]?)?\(?\d{3}\)?[ .-]?\d{3}[ .-]?\d{4}(?!\d)"), None),
    ("AWS_KEY", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), None),
    ("API_KEY", re.compile(r"\b(?:sk|pk|ghp|xox[bp])[-_][A-Za-z0-9-_]{16,}\b"), None),
]


def find_pii(text: str) -> list[Finding]:
    found: list[Finding] = []
    taken: list[tuple[int, int]] = []
    for kind, pat, check in PATTERNS:
        for m in pat.finditer(text):
            if check and not check(m):
                continue
            if any(m.start() < e and s < m.end() for s, e in taken):
                continue  # earlier, more specific detectors win (e.g. card number before phone)
            found.append(Finding(kind, m.start(), m.end(), m.group()))
            taken.append((m.start(), m.end()))
    return sorted(found, key=lambda f: f.start)


def redact(text: str) -> str:
    out, last = [], 0
    for f in find_pii(text):
        out += [text[last:f.start], f"[{f.kind}]"]
        last = f.end
    return "".join(out + [text[last:]])


class Tokenizer:
    """Reversible pseudonymization: PII becomes stable tokens before text goes to an external
    model, and is restored in the model's answer. Same value -> same token (HMAC), so the
    model can still reason about "the same patient" across a conversation."""

    def __init__(self, key: bytes):
        self.key, self.vault = key, {}

    def tokenize(self, text: str) -> str:
        out, last = [], 0
        for f in find_pii(text):
            tok = f"<{f.kind}_{hmac.new(self.key, f.text.encode(), hashlib.sha256).hexdigest()[:8]}>"
            self.vault[tok] = f.text
            out += [text[last:f.start], tok]
            last = f.end
        return "".join(out + [text[last:]])

    def detokenize(self, text: str) -> str:
        return re.sub(r"<[A-Z_]+_[0-9a-f]{8}>", lambda m: self.vault.get(m.group(), m.group()), text)
