# Round 2 handoff — TrustGate-MCP

## What changed

- Added standalone MCP stdio entrypoint `round2_mcp_proxy.py` with one mode selector (`TG_MODE=none|auth_only|auth_guard`; unset uses existing Step63 full configuration).
- Added baseline-only protocol adapter (`round2_baseline.py`); **no change** to Step45 / Step50 / Step63 security implementation.
- Reused the Step67 authorization-only no-content-inspection behavior using `round2_mode.AuthorizationOnlyGuard`.
- Added optional JSON external payload corpus loading in `step58_poisoned_backend.py` via `round2_payloads.py` (`TG_PAYLOAD_FILE`, IDs/classes/text).
- Added trusted host grant helper (`round2_host.py`), smoke demonstration (`round2_benign_demo.py`) and cross-mode authored fixture runner (`round2_ablation.py`).
- Added `RUNNING.md`, new README configuration/commands, `.env.example` comments, `round2_payloads_example.json`.
- Changed `pywin32` to a Windows-only requirement in both dependency lists. Converted the UTF-16 `requirements-lock.txt` into UTF-8 for portability.
- **No LICENSE added** pending team approval. No git commit or `round2-freeze` tag created/pushed because final MCP regression and source commit must run in the canonical repo.

## Validation performed in this handoff

| Command | Result |
|---|---|
| `python -m compileall -q round2_*.py step58_poisoned_backend.py test_round2_offline.py` | PASS |
| `python -m unittest -v test_round2_offline.py` | 18/18 PASS |
| `python step45_authorized_gateway.py` | 9/9 PASS |
| `python step50_all_tools_gateway.py` | 14/14 PASS |
| `python step63_guard_unit_test.py` | 5/5 PASS using the pure-Python SDK bundled in the uploaded environment |
| `python step63_gateway_test.py` | **NOT RUN TO COMPLETION** — local `mcp` SDK unavailable |
| `python round2_benign_demo.py --mode auth_only --attack clean` | PASS: forged grant blocked, legitimate store executed, replay blocked |
| `python round2_benign_demo.py --mode none --attack clean` | PASS: baseline simulated store executed without grant |
| `python round2_benign_demo.py --mode auth_only --attack r2_authority_01 --payload-file round2_payloads_example.json` | PASS: external payload delivered; trusted grant enforced |
| `python round2_ablation.py --payload-file round2_payloads_example.json --modes none auth_only --max-cases 2 --trials 1` | PASS: 4 fresh gateway sessions; 0 errors |

MCP and OpenAI package sources were temporarily loaded from the uploaded virtual environment *for local testing only*; they are **not** included in this handoff. `step63_gateway_test.py` requires a real configured LLM guard and remains untested here because live model access is unavailable. **Run the full Step 63 gateway regression on your machine before freezing the tag.** `auth_guard` can incur API charges.

## Apply to your existing repository

This handoff contains only changed/new files (no `.git`, `.venv`, `.env`, credentials or `results`). Unzip directly into your current **project root** while preserving other files. Review `git diff` and `git status` before committing. Do **not** upload the original raw project ZIP to GitHub: it contained a `.env` file and local Git/virtual-environment data. The `.env` was not tracked by the Git index contained in the uploaded snapshot.

Windows PowerShell (change ZIP location as needed):

```powershell
cd C:\Users\Saksh\Desktop\trustgate-mcp
Expand-Archive -Path "$HOME\Downloads\TrustGate_Round2_Update.zip" -DestinationPath . -Force
git status
git diff --check
python -m unittest -v test_round2_offline.py
python step45_authorized_gateway.py
python step50_all_tools_gateway.py
python step63_guard_unit_test.py
python step63_gateway_test.py
python round2_benign_demo.py --mode auth_only --attack clean
```

With API access, also test `auth_guard` on a benign case and at least one synthetic malicious case. Run `python round2_ablation.py --payload-file round2_payloads_example.json --trials 1` for the complete comparison; this invokes the LLM in `auth_guard`.

When all agreed tests pass, commit and freeze:

```powershell
git add .
git diff --cached --name-only
git commit -m "Round 2: gateway modes, payload corpus and host runner"
git tag round2-freeze
git rev-parse 'round2-freeze^{commit}'
git push origin main
git push origin round2-freeze
```

Record the returned commit hash in the Round 2 report and reference the `round2-freeze` tag in the README. Don't force-push or retag after results are collected.

## Scope/interpretation

`none` deliberately drops authorization; use only with the simulated local backend. `auth_only` and `auth_guard` retain the existing host grant/provenance/policy decisions. The `round2_ablation.py` runner issues **authorized** store requests in every mode to study content screening, false positives, and latency, **not** to demonstrate prevention of actual unauthorized exploits. Use live agent execution experiments for the latter research question.
