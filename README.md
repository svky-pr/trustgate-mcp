# TrustGate-MCP

### An Intent-Aware, Provenance-Aware Security Gateway for MCP-Based AI Agents

**TrustGate-MCP** is a research prototype designed to protect Large Language Model (LLM) agents from prompt-injection attacks, unauthorized tool operations, and suspicious cross-tool workflows in environments using the **Model Context Protocol (MCP)**.

The project explores a layered security architecture combining deterministic authorization, tool-output inspection, document provenance tracking, session-level activity monitoring, and Generative AI-assisted workflow-risk assessment.

Rather than relying exclusively on an LLM to recognize malicious instructions, TrustGate-MCP enforces security decisions at the MCP gateway and uses GenAI as an additional advisory monitoring component.

## Overview

LLM agents increasingly interact with external tools to retrieve documents, summarize information, and perform operations on behalf of users. MCP provides a standardized interface for these interactions.

However, MCP-connected agents can encounter security risks when information returned by external tools contains attacker-controlled instructions.

For example, a user might ask an AI agent to summarize a document. An attacker could embed instructions in the tool response directing the agent to export the document to an unauthorized destination.

TrustGate-MCP addresses this problem by separating trusted user authorization from untrusted tool-provided content.

### Research Objectives

- Detect and mitigate prompt-injection attacks delivered through MCP tool responses.
- Enforce trusted user intent before executing sensitive tool operations.
- Prevent unauthorized document access and simulated data exports.
- Track provenance and authorization across tool interactions.
- Monitor multi-tool activity for suspicious workflow patterns.
- Evaluate whether GenAI-assisted monitoring provides additional detection capability beyond deterministic security controls.
- Measure security effectiveness and performance overhead using controlled adversarial experiments.

## System Architecture

TrustGate-MCP operates as a security intermediary between an LLM agent and MCP-connected tools.

```text
                  +-----------------------+
                  |       User / Host     |
                  |  Trusted Instructions |
                  +-----------+-----------+
                              |
                              v
                  +-----------------------+
                  |       LLM Agent       |
                  |   MCP Tool Requests   |
                  +-----------+-----------+
                              |
                              v
        +-------------------------------------------+
        |              TrustGate-MCP                |
        |                                           |
        |  +-------------------------------------+  |
        |  | Trusted Intent Enforcement          |  |
        |  +-------------------------------------+  |
        |  | Host Authorization & Scoped Grants  |  |
        |  +-------------------------------------+  |
        |  | Provenance & Reference Validation   |  |
        |  +-------------------------------------+  |
        |  | Tool-Output Injection Inspection    |  |
        |  +-------------------------------------+  |
        |  | Session Activity Monitoring         |  |
        |  +-------------------------------------+  |
        |  | GenAI Workflow-Risk Review          |  |
        |  +-------------------------------------+  |
        |  | Security Audit & Alert Generation   |  |
        |  +-------------------------------------+  |
        +---------------------+---------------------+
                              |
                              v
                  +-----------------------+
                  |     MCP Tool Server   |
                  | Documents / Operations|
                  +-----------------------+
```

The architecture combines preventive controls with session-level monitoring. GenAI-generated workflow alerts are advisory and do not replace deterministic authorization decisions.

## Key Features

### 1. MCP Tool-Output Prompt-Injection Protection

TrustGate-MCP inspects tool responses for suspicious instructions that attempt to manipulate an agent's behavior.

The controlled attack scenarios include:

- Direct prompt injection
- Authority spoofing
- Workflow hijacking
- Metadata-based injection
- Encoded payloads

The content protection layer can prevent malicious tool-output instructions from reaching the LLM agent.

### 2. Trusted Intent Enforcement

TrustGate-MCP evaluates proposed tool operations against trusted host instructions.

The gateway considers factors such as:

- Permitted tools and operations
- Authorized document references
- Requested task scope
- Export permissions
- Tool-call parameters

Unauthorized operations can be rejected before execution.

### 3. Host-Controlled Authorization

Sensitive operations are protected using host-issued authorization grants.

The prototype supports scoped, single-use authorization tokens and validates whether requested operations comply with the granted permissions.

Untrusted tool responses cannot independently grant authorization.

### 4. Document Provenance and Reference Validation

TrustGate-MCP tracks document references and their origins.

The gateway can reject operations involving unknown or unauthorized document references and enforce restrictions on document handling.

### 5. Cross-Tool Activity Monitoring

The project records tool operations and their outcomes across a session.

This enables the monitoring system to identify suspicious patterns, including blocked confidential-document access and unauthorized export attempts.

### 6. GenAI-Assisted Workflow-Risk Assessment

TrustGate-MCP includes an optional GenAI-based reviewer that evaluates session activity using redacted tool metadata and operation outcomes.

The reviewer produces advisory risk assessments to supplement deterministic monitoring.

Current evaluations have not established a consistent incremental detection benefit from GenAI over the deterministic monitoring layer.

### 7. Security Evaluation and Audit Logging

The prototype includes experimental scripts for evaluating:

- Gateway security controls
- Prompt-injection resistance
- Intent enforcement
- Authorization checks
- Workflow-risk detection
- Live LLM-agent behavior
- Ablation performance
- End-to-end session latency

## Technology Stack

| Component | Technology |
|---|---|
| Programming language | Python |
| Agent integration | Model Context Protocol (MCP) |
| MCP communication | Python MCP SDK, stdio transport |
| LLM integration | OpenAI API |
| Security enforcement | Python-based gateway and guards |
| Workflow monitoring | Deterministic rules and GenAI review |
| Evaluation | Python test harnesses and CSV analysis |
| Development environment | VS Code, Windows, PowerShell |

## Experimental Evaluation

TrustGate-MCP was evaluated using controlled MCP security tests, scripted workflow scenarios, and LLM-driven adversarial experiments.

### Live Adversarial Agent Evaluation — Step 84

The final live-agent evaluation consisted of 54 sessions across three configurations.

| Metric | Baseline | Deterministic | Hybrid |
|---|---:|---:|---:|
| Total agent sessions | 18 | 18 | 18 |
| Malicious payloads delivered | 15/15 | 0/15 | 0/15 |
| Unauthorized agent attempts | 3 | 0 | 0 |
| Unauthorized simulated executions | 3 | 0 | 0 |
| Deterministic workflow alerts | 0 | 0 | 0 |
| GenAI workflow alerts | 0 | 0 | 0 |

**Key finding:** Both protected configurations prevented delivery of all tested malicious payloads, and neither produced an unauthorized simulated execution.

The unprotected baseline produced three unauthorized simulated storage executions.

Because no unauthorized agent attempts occurred in the protected configurations, this experiment demonstrates content-level prevention rather than successful interception of malicious live-agent tool calls.

### Performance Evaluation — Step 85

Median end-to-end agent session latency:

| Configuration | Median latency |
|---|---:|
| Baseline | 2,571 ms |
| Deterministic | 4,767 ms |
| Hybrid | 4,778 ms |

The protected configurations exhibited higher session latency than the unprotected baseline.

The difference between deterministic and hybrid median latency was 11 ms. This is an observed difference between session medians, not a measurement of isolated GenAI-review overhead.

### Workflow-Risk Evaluation — Steps 82–83

In the controlled contextual-risk evaluation, the deterministic monitoring layer correctly identified all five suspicious sessions without false positives.

The integrated live hybrid gateway evaluation produced:

| Metric | Result |
|---|---:|
| MCP sessions | 8 |
| MCP tool calls | 25 |
| True positives | 4 |
| False negatives | 0 |
| False positives | 0 |
| True negatives | 4 |
| Additional GenAI detections | 0 |

These results demonstrate workflow-monitoring functionality in the tested scenarios. They do not establish generalization to arbitrary autonomous attack chains.

### Ablation Evaluation — Step 67

A controlled 40-case evaluation compared authorization-only, semantic-only, and full gateway configurations.

| Configuration | TP | FN | FP | TN |
|---|---:|---:|---:|---:|
| Authorization only | 0 | 24 | 0 | 16 |
| Semantic only | 23 | 1 | 3 | 13 |
| Full protection | 23 | 1 | 3 | 13 |

These figures reflect the experiment's attack-detection classification, not a universal measure of authorization effectiveness. Authorization controls were retained across the tested configurations.

## Installation

### Prerequisites

- Python and pip
- Git
- OpenAI API credentials for LLM-based experiments
- Dependencies required by the Python MCP SDK

### 1. Clone the Repository

```bash
git clone https://github.com/svky-pr/trustgate-mcp.git
cd trustgate-mcp
```

### 2. Create a Virtual Environment

On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3. Install Dependencies

```powershell
pip install -r requirements.txt
```

### 4. Configure Environment Variables

Create a `.env` file in the project root:

```dotenv
OPENAI_API_KEY=your_api_key_here
```

If your model provider requires a custom API base URL, configure the corresponding environment variable used by your scripts.

**Never commit `.env`, API credentials, or other secrets to version control.**

## Round 2: Standalone Gateway / Attack-Side Client Integration

**Launch `round2_mcp_proxy.py` as the MCP stdio server** for the new cross-repo
Round 2 comparisons. See **[RUNNING.md](RUNNING.md)** for Windows/macOS/Linux
installation, the trusted-host grant helper, example payload corpus and
reproducibility instructions. The earlier numbered `step*.py` entrypoints
remain available and their defaults are unchanged.

### Round 2 defense switch

| Variable | Values | Default / effect |
|---|---|---|
| `TG_MODE` | `none`, `auth_only`, `auth_guard` | Unset = `auth_guard` (original full Step 63 hybrid). Used by `round2_mcp_proxy.py` only. |
| `TG_PAYLOAD_FILE` | JSON file path | Unset = original built-in `ATTACKS` dictionary only; set for the external attack corpus. |
| `TG58_ATTACK` | Built-in name or external payload `id` | `clean`; chooses the *same* fixture across modes. |
| `TG58_BACKEND_FILE` | Local backend Python filename | `step58_poisoned_backend.py`. |
| `TG52_HOST_SECRET` | Private random string, >=40 characters | Required in protected modes; host-only authentication. |
| `TG52_HOST_PORT` | Available localhost port 1024–65535 | Required in protected modes; host-control endpoint. |
| `TG52_TRUSTED_REQUEST` | Trusted original user request | Required in protected modes; used by existing grant restrictions. |
| `TG52_ALLOWED_DEST` | `local` or `external` | Required in protected modes; host-approved destination. |
| `OPENAI_API_KEY` | Provider API key | Needed for `auth_guard` only; never commit or pass to the agent. |
| `TRUSTGATE_GUARD_MODEL` | **`gpt-4.1-mini` for Round 2** | **Required experiment setting** for `auth_guard`; passed to both Step 62 detector and Step 33 v3 guard. Historical unset Step 63 defaults are mixed (nano/mini) and must not be used for reported Round 2 comparisons. |

- `none`: baseline simulated backend pass-through (no grant, policy or LLM
  guard; mapping document refs remains necessary for the backend's API).
- `auth_only`: existing host-issued single-use grants, reference/provenance and
  deterministic policy checks; bypasses **only** LLM content inspection.
- `auth_guard`: existing Step 63 hybrid semantic guard **plus** the same
  host authorization/provenance/policy checks. This is the default.

Minimal cross-platform smoke commands:

```bash
python -m unittest -v test_round2_offline.py
python round2_benign_demo.py --mode none --attack clean
python round2_benign_demo.py --mode auth_only --attack clean
# The following also requires a configured OpenAI API key:
python round2_benign_demo.py --mode auth_guard --attack clean
# Runs each payload class against all three configurations (API calls in auth_guard):
python round2_ablation.py --payload-file round2_payloads_example.json --trials 3
```

The external payload schema is `{ "payloads": [{ "id": "...", "class": "...", "text": "..." }] }`.
No external payload can replace a built-in attack ID. The `class` labels the
fixture for research analysis but does not influence gateway decisions.

### Guard model provenance and reproducibility

**Final Step 90–93 authored replay (November 5, 2026):** The command
`python step93_final_evaluation.py --trials 3 --stop-on-error` was run **without**
`--guard-model`. Step 93's CLI default is **`gpt-4.1-mini`**; it explicitly
forwards this value to Steps 90, 91, and 92, overriding their guard's fallback
model settings. The recorded 15/15, 12/15, and 12/18 semantic detections therefore
correspond to **`gpt-4.1-mini`**, not to a confirmed `gpt-4.1-nano` experiment.
The Step 89 live pilot's script also defaults to `gpt-4.1-mini`, but its actual
runtime flags should be checked against the original run log before claiming
any model-specific live-agent results.

**Historical Step 63 gateway:** `step62_hybrid_detector.py` defaults to
`gpt-4.1-nano`, whereas `step33_v3_ai_guard.py` defaults to `gpt-4.1-mini`.
Both read the same `TRUSTGATE_GUARD_MODEL` environment setting. Thus, **unset is
not a single-model configuration**: the hybrid can invoke both models.
For new Round 2 comparisons with the final authored replay, set
`TRUSTGATE_GUARD_MODEL=gpt-4.1-mini` explicitly in your private environment
or copy it from `.env.example`. Record the model, prompt/guard code revision,
fixture hashes, and frozen commit SHA with each run. The midterm's stated
`gpt-4.1-nano` model describes a different configuration; do **not** silently
relabel the mini evaluation as nano or pool results across configurations.
If reproducing the midterm instead, explicitly set `gpt-4.1-nano` for **both**
components and report those results separately.

### Round 2 guard-model configuration (pin this for all measured runs)

| Experiment | Guard model and confidence | Important caveat |
|---|---|---|
| Midterm / historical Step 63 description | `gpt-4.1-nano` was **reported** in the midterm | Historical Step 63 code actually had **two** unset defaults: Step 62 = `gpt-4.1-nano`, Step 33 v3 = `gpt-4.1-mini`. Without the original environment/log, a single historical model is **not verified**. |
| Step 89 live-agent pilot | Script default: `gpt-4.1-mini` | Actual recorded CLI override/environment should be checked before assigning its measured runs to a model. |
| Step 90 controlled replay | `gpt-4.1-mini` | Explicitly selected by Step 93, which forwarded the CLI default. |
| Step 91 integrity replay | `gpt-4.1-mini` | Explicitly selected by Step 93. |
| Step 92 approved-unsafe replay | `gpt-4.1-mini` | Explicitly selected by Step 93. |
| Step 93 combined three-trial evaluation | `gpt-4.1-mini` | `--guard-model` was omitted; its actual default is mini and it forwarded mini to the child scripts. |
| Round 2 (`auth_guard`) | **Set `TRUSTGATE_GUARD_MODEL=gpt-4.1-mini` explicitly** | Both Step 62 and Step 33 v3 will use mini. 2026-11-06 owner workstation live verification passed: Step 63 71/71; clean ALLOW and authority BLOCK. |

Proposed correction to the midterm model statement: **"The midterm described `gpt-4.1-nano`, but the Step 63 hybrid implementation used distinct unset defaults for its two model-based components. The later Step 90–93 evaluation explicitly used `gpt-4.1-mini`. Round 2 pins both hybrid components to `gpt-4.1-mini`; cross-configuration results are reported separately."**

For PowerShell:

```powershell
$env:TRUSTGATE_GUARD_MODEL = 'gpt-4.1-mini'
python verify_round2_live.py --self-test
python verify_round2_live.py
```

### Version freeze (validated; immutable)

- **Round 2 code tag:** `round2-freeze`, dereferenced commit `c25ce4d6dfe2cc818284b07e1960f1d70945a1e0`.
- **Validation:** On **November 6, 2026**, with `TRUSTGATE_GUARD_MODEL=gpt-4.1-mini`, the owner completed Step 63 **71/71**, Round 2 offline **18/18**, Step 45 **9/9**, Step 50 **14/14**, Step 63 guard units **5/5**, and clean/authority `auth_guard` checks. See [ROUND2_HANDOFF.md](ROUND2_HANDOFF.md) for exact evidence and interrupted-run details.
- **One-time tag replacement already performed:** An initially lightweight tag created before regression was deleted and replaced with an annotated tag **after** the verifier passed. Its **code commit remained `c25ce4d6dfe2cc818284b07e1960f1d70945a1e0`**. The different SHA for the tag object itself does not change the code commit.
- **Freeze is final:** **Do not move, delete, recreate, or force-update `round2-freeze` again.** Future documentation-only commits on `main` are *outside* the frozen version. Cite both the frozen code commit and any later documentation commit separately.
- **Attack-side repository:** [TrustGate-MCP Red Team](https://github.com/waradorn-sir/trustgate-mcp-redteam). The four-payload JSON corpus stays in that separate repo; pass its local absolute path to `--payload-file`.
- No open-source license was added; team approval is pending.

#### Additional experiment/model attribution

| Experiment | Model actually established by evidence | Notes |
|---|---|---|
| Midterm Experiment A | **Unknown** | Midterm reported `gpt-4.1-nano` globally, but per-experiment model override/log not verified. |
| Midterm Experiment B | **Unknown** | Same limitation; do not treat the midterm sentence as proof of every guard call. |
| Historical Step 63, override unset | **Mixed defaults** | Step 62 = `gpt-4.1-nano`; Step 33 v3 = `gpt-4.1-mini`. Actual historical override unknown. |
| Step 84 workflow baseline, Nov 6, 2026 | **Agent: `gpt-4.1-mini`; no guard** | Standard system prompt, ten trials, payload delivered 10/10, unauthorized execution 0/10. |
| Steps 90–93 three-trial authored replays | **Guard: `gpt-4.1-mini`** | Step 93 forwarded its CLI model default to the individual replay programs. |
| Step 63 / Round 2 live validation, Nov 6, 2026 | **Both guard components: `gpt-4.1-mini`** | `TRUSTGATE_GUARD_MODEL` explicitly set in the user's terminal. |
| Future Round 2 ablation (Rob's corpus) | **Set `gpt-4.1-mini`** | Must record completed output separately; not yet run. |

**Step 84 cross-check:** `results/step84_live_adversarial_20261106_210216.csv` found **0/10 unauthorized workflow stores** in `baseline`, matching the teammate's reported 0/10 numerically. A baseline success/failure is not evidence of gateway protection.

## Running the Experiments

The repository preserves the original numbered development scripts. Later experiments may depend on earlier modules, so the original filenames should remain unchanged.

### Gateway Security Evaluation

```powershell
python step63_gateway_test.py
```

### Intent Enforcement

```powershell
python step71_mcp_eval.py
```

### Controlled Ablation Evaluation

```powershell
python step67_ablation_eval.py
```

### Contextual Workflow Monitoring

```powershell
python step82_real_mcp_eval.py
```

### Integrated Hybrid Gateway

```powershell
python step83_live_hybrid_eval.py
```

### Live Adversarial Agent Evaluation

```powershell
python step84_live_adversarial_eval.py --trials 3
```

This experiment makes LLM API calls and may incur usage charges.

### Final Results Analysis

```powershell
python step85_final_analysis.py
```

The analysis script summarizes existing evaluation outputs. It does not perform a new autonomous-agent attack experiment.

## Security and Research Limitations

TrustGate-MCP is a research prototype, not a production-ready enterprise security gateway.

Current limitations include:

- Testing is limited to selected MCP tools and controlled attack scenarios.
- Document storage and unauthorized export operations are simulated.
- Some evaluations use scripted workflows rather than autonomous LLM-generated tool calls.
- The protected live-agent configurations prevented malicious payload delivery, so downstream live-agent interception was not directly exercised in those trials.
- GenAI monitoring has not demonstrated consistent incremental detection benefits over deterministic rules.
- Performance results reflect end-to-end sessions and do not isolate the overhead of every individual security component.
- Generalization to arbitrary third-party MCP servers, new attack families, and production workloads remains unverified.

## Future Work

Potential extensions include:

1. Evaluating additional MCP servers and more diverse tool schemas.
2. Testing autonomous multi-tool attack chains that reach authorization enforcement.
3. Expanding unseen adversarial datasets.
4. Improving GenAI workflow reasoning for ambiguous attack patterns.
5. Measuring per-component latency and resource overhead.
6. Adding stronger session isolation and persistent audit storage.
7. Evaluating false positives on larger legitimate workloads.
8. Developing a deployable MCP gateway configuration for external applications.

## Responsible Use

This repository is intended for defensive security research, experimentation, and educational use.

Attack payloads and simulated unauthorized operations are used to evaluate security controls in controlled environments. The prototype does not perform real-world data exfiltration in the reported experiments.

## Project Status

**Research prototype — implemented and experimentally evaluated.**

The project demonstrates layered MCP security enforcement and monitoring, with evidence of prompt-injection prevention in the tested live-agent scenarios.

The incremental security value of GenAI-assisted workflow monitoring remains an open research question.

## License

No license has been selected yet. Unless a license is added, standard copyright restrictions apply.

---

**TrustGate-MCP — Securing the boundary between trusted user intent and untrusted AI tool interactions.**
