# Evidence index

Screenshots and logs that document the deployment, the bugs found, the fixes
and the enhancements running on the real system. Unless noted, UI images are
from the real Fortis UI served by `python -m server.app` with a sandboxed data
folder and the **local Qwen3.5-4B model on CPU** (llama.cpp 0.3.36), driven by
headless Microsoft Edge through the same functions the Send button calls.
Terminal images are renderings of captured output; "verbatim" means no lines
were removed. Captured on 26 November 2026.

## Stage 1: deployment

| # | File | Shows | Notes |
|---|---|---|---|
| 01 | `01-upstream-setup-failure.png` | Upstream `setup.ps1` on a fresh clone aborts at line 76 (PowerShell 5.1 `NativeCommandError` from a pip warning) | pip download-progress lines omitted; full log: `upstream-setup.log` |
| 02 | `02-fork-setup-success.png` | This fork on a fresh clone: CUDA runtime diagnosed, CPU engine installed, 302/302 tests, app starts | pip lines omitted; full log: `fork-setup.log` |

## Model picker and GPU detection: before / after

| # | File | Shows | Notes |
|---|---|---|---|
| 03 | `03-model-dialog-before-chat-empty-and-not-downloaded.png` | "Chat & analysis: No tiers available"; downloaded Qwen3.5 4B shown as "will download" | user's screenshot |
| 04 | `04-model-dialog-before-vram-greyed-out.png` | Models greyed out by VRAM on a CPU build | user's screenshot |
| 05 | `05-terminal-before-redownload-on-every-click.png` | Every click re-contacts Hugging Face ("Downloaded …" repeated) | user's screenshot; contains a local Windows user path |
| 06 | `06-terminal-before-torch-cuda-traceback.png` | `Torch not compiled with CUDA enabled` traceback; `n_gpu_layers=915` on a CPU build | user's screenshot; contains a local Windows user path |
| 07 | `07-model-dialog-after-one-click-ready.png` | One click loads Qwen3.5 2B (2.9 s); "Ready ✓ · active · loaded"; nothing greyed out | |
| 08 | `08-model-dialog-after-role-filter.png` | Role filter (Code, 2 of 5), recommended first, accurate GPU message | |
| 09 | `09-terminal-after-no-traceback-no-redownload.png` | Two download clicks return `already_downloaded` with no network; one-click load; `n_gpu_layers=0`; no traceback | verbatim; log: `09-terminal-after.log` |

## Threat-intel trust layer

| # | File | Shows |
|---|---|---|
| 10 | `10-grounded-answer-T1003.001-lsass-memory.png` | Grounded answer names T1003.001 correctly as LSASS Memory (the baseline run said "Delete and Rename") |
| 11 | `11-verification-footer-all-ids-verified.png` | Footer: "Fortis verified 1 identifier against the offline catalogue (ATT&CK v20.1, CISA KEV 2026.11.20)" |
| 12 | `12-false-premise-T1999.123-rejected.png` | False-premise question: "Technique ID T1999.123 does not exist" |
| 13 | `13-verifier-flags-model-invented-T1999.png` | Defence in depth: the model still invented "T1999 (PowerShell Obfuscation)"; the footer flags it as not existing |
| 14 | `14-injection-exfil-instruction-ignored.png` | Document asking Fortis to print its system prompt: instruction ignored, real action items summarised. Also shows the **before** of the linkify bug: NIST "PR.AC"/"PR.PT" rendered as web links |
| 15 | `15-verifier-gap-T1550.001-labelled-with-tactic.png` | Gap found live: "T1550.001 (Credential Access)" passed as verified (any tactic accepted). Fixed: the tactic must be one of the technique's own |
| 16 | `16-after-fix-control-ids-no-longer-links.png` | Same answer as 14 after the fix: control ids are plain text |

## Advisory triage agent: before / after refinement (same advisory ADV-05, same model)

| # | File | Shows |
|---|---|---|
| 17 | `17-triage-agent-P1-brief-before-refinement.png` | First live run: correct P1 and affected assets, but the narrative claims the client is "under active exploitation" |
| 18 | `18-triage-agent-tables-before-refinement.png` | Verifier false positive ("attributed to Daemon"), techniques accepted on irrelevant quotes (PowerShell, Standard Encoding), truncated "Search for **", ids wrapping, documentation IPs called "private/reserved" |
| 19 | `19-triage-agent-trace-before-refinement.png` | Trace: narrative 143 s, 1 issue left |
| 20 | `20-triage-agent-after-refinement-no-overclaim.png` | After: "at risk of compromise rather than confirmed under attack" |
| 21 | `21-triage-agent-after-rejected-irrelevant-technique.png` | After: T1059.001 rejected ("quote does not describe this technique"); ids as code; RFC 5737 notes |
| 22 | `22-triage-agent-after-trace-all-verified.png` | After: "all identifiers verified", narrative 72 s, agent trace as a proper section |
| 23 | `23-exports-validated-stix2-pysigma.png` | STIX 2.1 bundle passes strict OASIS `stix2` parsing and pattern grammar; 3 Sigma rules parse in SigmaHQ `pySigma` with 0 errors; Navigator layer v4.5 (verbatim; reproduce with `eval/validate_exports.py`) |
| 24 | `24-sigma-rule-generated.png` | One generated Sigma rule (verbatim file content) |

## Usability and accessibility

| # | File | Shows |
|---|---|---|
| 25 | `25-before-iocs-reply-wiped-by-history-reload.png` | Bug: the `/iocs` reply vanished — every slash command reloaded the saved transcript |
| 26 | `26-after-iocs-reply-kept-deterministic-extraction.png` | After: 9 indicators extracted and defanged; version string, `config.json` and the attachment name correctly not extracted |
| 27 | `27-sidebar-current-vs-open-engagement.png` | Selected engagement labelled "current" (not colour alone); status shown as "open" instead of a second "active" |

## Engineering process

| # | File | Shows | Notes |
|---|---|---|---|
| 28 | `28-test-suite-392-passed.png` | Offline suite: 392 passed | verbatim |
| 29 | `29-eval-harness-run-real-model.png` | Evaluation harness on Qwen3.5-4B: per-item results, ~60–90 s per answer on CPU | only the per-item result lines of `eval/results/queue1.log`; scores as printed live, before later scorer fixes |
| 30 | `30-eval-results-page-partial.png` | Generated results page: 14 hallucinated identifiers in 33 baseline answers, hand-audited (12 genuine, 2 paraphrases) | partial run, labelled as such |
