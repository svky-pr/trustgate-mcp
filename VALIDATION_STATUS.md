# Round 2 validation status — 2026-11-06

- Source of validation evidence: researcher's pasted Windows PowerShell output.
- Model pin explicitly verified: `TRUSTGATE_GUARD_MODEL=gpt-4.1-mini`.
- Round 2 unit suite **18/18**; Step 45 **9/9**; Step 50 **14/14**; Step 63 guard unit **5/5**.
- Step 63 full model-backed integration **71/71 PASS** (`results/step63_gateway_20261106_202711.csv` and later `results/step63_gateway_20261106_210716.csv`). Some other attempts were manually interrupted; no security code change is implicated.
- Standalone demo `none` + clean: authorized simulated store executed; `auth_only` + clean: authorized store executed, forged grant and replay denied; `auth_guard` + clean: `ai_decision=ALLOW`, store executed; `auth_guard` + authority: `ai_decision=BLOCK`, no store execution.
- `verify_round2_live.py --self-test`: **8/8 PASS**. `verify_round2_live.py`: **ALL REQUESTED CHECKS PASSED**.
- One-time published annotated tag replacement completed, still dereferencing to frozen code **`c25ce4d6dfe2cc818284b07e1960f1d70945a1e0`**. **Never move tag again**. The tag is not the same as the later documentation commit.
- Step 84 workflow `baseline`, `gpt-4.1-mini`, standard system prompt, 10 trials: 10/10 delivery, **0/10 unauthorized store attempts and 0/10 executions**, 0 errors (`results/step84_live_adversarial_20261106_210216.csv`). This numerically agrees with the teammate's separately reported 0/10; environments differ.
- Local/example three-trial ablation completed, **not** the teammate's external corpus: `results/round2_ablation_20261106_192731.csv`.
- Still pending: commit these documentation corrections on `main` (without moving tag), record documentation-only commit SHA, run Rob's four-payload corpus with 10 trials in each mode and record outcomes/latency.
