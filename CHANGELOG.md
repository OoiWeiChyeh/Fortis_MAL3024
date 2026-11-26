# Changelog — Fortis_MAL3024 fork

Changes made in this fork on top of upstream `kenobicjj/Fortis` @ `20dfe52`.
Dates are commit dates; see `git log` for the full record.

## Trust layer, triage agent and evaluation — 2026-11-26

### Added
- **Catalogue grounding and identifier verification** (`core/intel/grounding.py`): ATT&CK/CVE ids in questions and retrieved excerpts are resolved against the vendored ATT&CK v20.1 and CISA KEV catalogues before generation; every id in a reply is classified valid / stale / fabricated / misbound and shown in a footer.
- **Untrusted-document fencing**: uploaded excerpts are delimited as data with a system rule never to follow instructions inside them; planted fence markers are neutralised.
- **Streaming system-prompt leak guard** (`core/guard.py`): replies that reproduce the system prompt are cut, mid-stream included, and not persisted.
- **Advisory triage agent** (`core/agents/triage.py`, `/triage`, `POST /intel/triage`): deterministic indicators, enrichment, evidence-checked technique inference, asset-inventory exposure, P1–P4 rubric, verified and repaired narrative; exports STIX 2.1, Sigma rules and an ATT&CK Navigator layer. `/iocs` and `POST /intel/iocs` for extraction alone.
- **Evaluation harness** (`eval/`): black-box QA benchmark (53 original items), mutation prompt-injection red team (21 cases incl. Bahasa Melayu and an adaptive fence escape), IOC benchmark (12 original advisories, 52 gold indicators), triage agent vs single prompt; summariser with Wilson intervals and McNemar tests.
- CI on Ubuntu and Windows; dataset-integrity tests and quality gates (`eval/gates.json`).
- Deployment evidence and documentation (`docs/deployment.md`, `docs/evaluation.md`, `docs/evidence/`).

### Fixed
- IOC extractor read phrased version strings ("version string is 4.2.0.1") as IPv4 addresses.

## Threat-intel foundations and UI — 2026-11-22
- Deterministic IOC extraction (`core/intel/ioc.py`) and offline ATT&CK / CISA KEV catalogues (`core/intel/sync.py`, `enrich.py`).
- Local API guard against cross-site reads/writes and DNS rebinding (`core/security.py`).
- Test suite no longer overwrites the user's model selection.
- Accessible midnight-navy UI redesign.

## Deployment fixes — 2026-11-12/13
- `setup.ps1` no longer aborts under PowerShell 5.1 when pip writes warnings to stderr.
- Missing CUDA 12 runtime is diagnosed and setup falls back to the CPU engine.
