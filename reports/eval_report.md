# Evaluation report

## Red-team benchmark: a gullible email agent

36 attack emails (6 payloads x 6 obfuscations) and 25 benign emails.

| Defense | Attacks that executed | Benign tasks done without friction | Benign quarantined | Benign approval prompts |
|---|---|---|---|---|
| none | 100.0% | 100% | 0 | 0 |
| heuristics | 2.8% | 92% | 2 | 0 |
| classifier | 0.0% | 100% | 0 | 0 |
| policy | 0.0% | 88% | 0 | 3 |
| all | 0.0% | 80% | 2 | 3 |

Attack success by obfuscation (heuristics only): plain 0%, zero_width 0%, homoglyph 0%, base64 0%, spanish 17%, polite_buried 0%

## Injection detectors

| Detector / test | Precision | Recall | Test size |
|---|---|---|---|
| random split (attack styles seen in training) | 1.000 | 1.000 | 480 |
| family split (attack styles never seen) | 0.782 | 0.835 | 800 |
| heuristic rules (no training) | 0.915 | 0.791 | 1600 |

## PII validators

| Type | Precision | Recall | Cases |
|---|---|---|---|
| CARD | 1.000 | 1.000 | 400 |
| SSN | 1.000 | 1.000 | 400 |
