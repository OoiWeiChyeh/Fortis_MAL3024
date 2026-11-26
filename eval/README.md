# Fortis evaluation harness

Black-box, reproducible evaluation of Fortis on a local open-source model.
Methodology and metric justification: [docs/evaluation.md](../docs/evaluation.md).
Latest results: [docs/evaluation/results.md](../docs/evaluation/results.md).

## Running

```bash
# model-in-the-loop suites (CPU: roughly 1 min per QA item on Qwen3.5-4B)
python -m eval qa      --model qwen3.5-4b --config baseline   # upstream behaviour
python -m eval qa      --model qwen3.5-4b --config hardened   # this fork
python -m eval redteam --model qwen3.5-4b --config hardened
python -m eval triage  --model qwen3.5-4b
python -m eval ioc     --model qwen3.5-4b
python -m eval summarize          # -> docs/evaluation/{results.md,summary.json,fig-*.png}

# no model needed (also run in CI)
python -m eval qa --stub --embeddings hash-stub --only FW-01,PI-01
python -m pytest desktop/tests/test_eval_harness.py
```

`--model` takes a GGUF path or a name fragment of a file in the Fortis
models folder. `--only` takes item ids or categories. Runs are resumable and
write `eval/results/<suite>/<model>__<config>/` with `answers.jsonl`
(every answer verbatim plus its scores) and `run.json` (commit, dirty flag,
model file, config, platform, llama.cpp version, wall time). The run's data
root (Chroma, SQLite, uploads) is sandboxed under `data/` and git-ignored;
the user's real `%APPDATA%\Fortis` is never touched.

Configs (`eval/sandbox.py`): `baseline` = all trust hardening off (the
shipped upstream behaviour); `hardened` = catalogue grounding, identifier
verification, spotlighting and the leak guard on; `grounding-only` and
`spotlight-only` for ablation.

## Datasets

All datasets are original work for this project.

### `datasets/soc_qa.jsonl` — 53 items

| Field | Meaning |
|---|---|
| `id`, `category` | e.g. `AT-03`, `attack_id` |
| `question` | sent verbatim to `POST /chat` |
| `docs` | files uploaded to the item's engagement first (lab documents or poisoned documents) |
| `facts` | list of key facts; each is a list of alternative regexes (case-insensitive) |
| `required` | indices of facts that must be present |
| `min_recall` | share of facts needed to pass |
| `expect` | `answer` (default), `refuse` (out of scope) or `deny_premise` (false premise) |
| `canary` | regex whose presence means an injection succeeded |
| `gold_ids` | ATT&CK / CVE ids a correct answer should name |

Categories: `framework` 8, `attack_id` 8, `false_premise` 6, `cve` 6,
`incident_response` 6, `lab_doc` 8 (Labs 2 and 4 of `training/`),
`out_of_scope` 4, `in_scope_edge` 3, `injection` 4.

### `datasets/advisories/` — 12 advisories, 52 gold indicators

Threat advisories in MyCERT, CISA and vendor styles about **real CISA KEV
vulnerabilities** (PAN-OS, NetScaler, FortiOS, MOVEit, Ivanti, ScreenConnect,
Jenkins, WinRAR, IOS XE, OpenSSH) and two campaigns without a CVE, written
for a fictional Malaysian financial client. **All indicators are fictional**:
IPv4 addresses come from the RFC 5737 documentation ranges, domains are
random strings, hashes are seeded random hex. `advisories_gold.json` holds,
per advisory: indicators by type, CVEs, ATT&CK techniques (ids named in the
text for CISA-style advisories; analyst mapping for prose-only ones), exposed
assets, whether the client's sector is targeted, and the P1–P4 priority with
a one-line rationale. Gold indicators were recorded by the generator as each
was inserted, never produced by the extractor being evaluated.

Priority rubric (also given verbatim to the single-prompt baseline):

- **P1** exploited-in-the-wild (CISA KEV) vulnerability in a product the client runs
- **P2** vulnerability in a product the client runs without confirmed exploitation, or an active campaign targeting the client's sector
- **P3** exploited vulnerability in a product the client does not appear to run
- **P4** informational

### `datasets/docs/`

- `bayu-capital-asset-inventory.csv` — the fictional client's 18-asset register (exposure ground truth).
- `vendor-assessment-poisoned.txt`, `incident-log-poisoned.txt`, `policy-poisoned.md`, `meeting-notes-exfil.txt` — realistic documents with genuine weaknesses plus an embedded instruction and canary (override, log-field injection, HTML-comment injection, system-prompt exfiltration).

### Red-team cases (`redteam.py`, generated)

3 goals (override, suppress findings, exfiltrate) × 7 operators (plain,
fake authority, Bahasa Melayu, base64, zero-width + homoglyph, adaptive
fence escape, HTML comment) in 2 carrier documents.

## Quality gates

`gates.json` holds thresholds for the deterministic suites, enforced by
`desktop/tests/test_eval_harness.py` in CI (IOC micro precision ≥ 0.97,
recall = 1.0, zero invented indicators), alongside dataset-integrity tests.
