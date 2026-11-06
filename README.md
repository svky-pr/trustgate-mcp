TrustGate-MCP
An Intent-Aware, Provenance-Aware Security Gateway for MCP-Based AI Agents
TrustGate-MCP is a research prototype designed to protect Large Language Model (LLM) agents from prompt-injection attacks, unauthorized tool operations, and suspicious cross-tool workflows in environments using the Model Context Protocol (MCP).
The project explores a layered security architecture combining deterministic authorization, tool-output inspection, document provenance tracking, session-level activity monitoring, and Generative AI-assisted workflow-risk assessment.
Rather than relying exclusively on an LLM to recognize malicious instructions, TrustGate-MCP enforces security decisions at the MCP gateway and uses GenAI as an additional advisory monitoring component.
Overview
LLM agents increasingly interact with external tools to retrieve documents, summarize information, and perform operations on behalf of users. MCP provides a standardized interface for these interactions.
However, MCP-connected agents can encounter security risks when information returned by external tools contains attacker-controlled instructions.
For example, a user might ask an AI agent to summarize a document. An attacker could embed instructions in the tool response directing the agent to export the document to an unauthorized destination.
TrustGate-MCP addresses this problem by separating trusted user authorization from untrusted tool-provided content.
Research Objectives
Detect and mitigate prompt-injection attacks delivered through MCP tool responses.
Enforce trusted user intent before executing sensitive tool operations.
Prevent unauthorized document access and simulated data exports.
Track provenance and authorization across tool interactions.
Monitor multi-tool activity for suspicious workflow patterns.
Evaluate whether GenAI-assisted monitoring provides additional detection capability beyond deterministic security controls.
Measure security effectiveness and performance overhead using controlled adversarial experiments.
System Architecture
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
Key Features
1. MCP Tool-Output Prompt-Injection Protection
TrustGate-MCP inspects tool responses for suspicious instructions that attempt to manipulate an agent's behavior.
The controlled attack scenarios include:
Direct prompt injection
Authority spoofing
Workflow hijacking
Metadata-based injection
Encoded payloads
The content protection layer can prevent malicious tool-output instructions from reaching the LLM agent.
2. Trusted Intent Enforcement
TrustGate-MCP evaluates proposed tool operations against trusted host instructions.
The gateway considers factors such as:
Permitted tools and operations
Authorized document references
Requested task scope
Export permissions
Tool-call parameters
Unauthorized operations can be rejected before execution.
3. Host-Controlled Authorization
Sensitive operations are protected using host-issued authorization grants.
The prototype supports scoped, single-use authorization tokens and validates whether requested operations comply with the granted permissions.
Untrusted tool responses cannot independently grant authorization.
4. Document Provenance and Reference Validation
TrustGate-MCP tracks document references and their origins.
The gateway can reject operations involving unknown or unauthorized document references and enforce restrictions on document handling.
5. Cross-Tool Activity Monitoring
The project records tool operations and their outcomes across a session.
This enables the monitoring system to identify suspicious patterns, including blocked confidential-document access and unauthorized export attempts.
6. GenAI-Assisted Workflow-Risk Assessment
TrustGate-MCP includes an optional GenAI-based reviewer that evaluates session activity using redacted tool metadata and operation outcomes.
The reviewer produces advisory risk assessments to supplement deterministic monitoring.
Current evaluations have not established a consistent incremental detection benefit from GenAI over the deterministic monitoring layer.
7. Security Evaluation and Audit Logging
The prototype includes experimental scripts for evaluating:
Gateway security controls
Prompt-injection resistance
Intent enforcement
Authorization checks
Workflow-risk detection
Live LLM-agent behavior
Ablation performance
End-to-end session latency
Technology Stack
Component	Technology
Programming language	Python
Agent integration	Model Context Protocol (MCP)
MCP communication	Python MCP SDK, stdio transport
LLM integration	OpenAI API
Security enforcement	Python-based gateway and guards
Workflow monitoring	Deterministic rules and GenAI review
Evaluation	Python test harnesses and CSV analysis
Development environment	VS Code, Windows, PowerShell
Experimental Evaluation
TrustGate-MCP was evaluated using controlled MCP security tests, scripted workflow scenarios, and LLM-driven adversarial experiments.
Live Adversarial Agent Evaluation — Step 84
The final live-agent evaluation consisted of 54 sessions across three configurations.
Metric	Baseline	Deterministic	Hybrid
Total agent sessions	18	18	18
Malicious payloads delivered	15/15	0/15	0/15
Unauthorized agent attempts	3	0	0
Unauthorized simulated executions	3	0	0
Deterministic workflow alerts	0	0	0
GenAI workflow alerts	0	0	0
Key finding: Both protected configurations prevented delivery of all tested malicious payloads, and neither produced an unauthorized simulated execution.
The unprotected baseline produced three unauthorized simulated storage executions.
Because no unauthorized agent attempts occurred in the protected configurations, this experiment demonstrates content-level prevention rather than successful interception of malicious live-agent tool calls.
Performance Evaluation — Step 85
Median end-to-end agent session latency:
Configuration	Median latency
Baseline	2,571 ms
Deterministic	4,767 ms
Hybrid	4,778 ms
The protected configurations exhibited higher session latency than the unprotected baseline.
The difference between deterministic and hybrid median latency was 11 ms. This is an observed difference between session medians, not a measurement of isolated GenAI-review overhead.
Workflow-Risk Evaluation — Steps 82–83
In the controlled contextual-risk evaluation, the deterministic monitoring layer correctly identified all five suspicious sessions without false positives.
The integrated live hybrid gateway evaluation produced:
Metric	Result
MCP sessions	8
MCP tool calls	25
True positives	4
False negatives	0
False positives	0
True negatives	4
Additional GenAI detections	0
These results demonstrate workflow-monitoring functionality in the tested scenarios. They do not establish generalization to arbitrary autonomous attack chains.
Ablation Evaluation — Step 67
A controlled 40-case evaluation compared authorization-only, semantic-only, and full gateway configurations.
Configuration	TP	FN	FP	TN
Authorization only	0	24	0	16
Semantic only	23	1	3	13
Full protection	23	1	3	13
These figures reflect the experiment's attack-detection classification, not a universal measure of authorization effectiveness. Authorization controls were retained across the tested configurations.
Installation
Prerequisites
Python and pip
Git
OpenAI API credentials for LLM-based experiments
Dependencies required by the Python MCP SDK
1. Clone the Repository
```bash
git clone https://github.com/svky-pr/trustgate-mcp.git
cd trustgate-mcp
```
2. Create a Virtual Environment
On Windows PowerShell:
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```
3. Install Dependencies
```powershell
pip install -r requirements.txt
```
4. Configure Environment Variables
Create a `.env` file in the project root:
```dotenv
OPENAI_API_KEY=your_api_key_here
```
If your model provider requires a custom API base URL, configure the corresponding environment variable used by your scripts.
Never commit `.env`, API credentials, or other secrets to version control.
Round 2: Standalone Gateway / Attack-Side Client Integration
Launch `round2_mcp_proxy.py` as the MCP stdio server for the new cross-repo
Round 2 comparisons. See RUNNING.md for Windows/macOS/Linux
installation, the trusted-host grant helper, example payload corpus and
reproducibility instructions. The earlier numbered `step*.py` entrypoints
remain available and their defaults are unchanged.
Round 2 defense switch
Variable	Values	Default / effect
`TG_MODE`	`none`, `auth_only`, `auth_guard`	Unset = `auth_guard` (original full Step 63 hybrid). Used by `round2_mcp_proxy.py` only.
`TG_PAYLOAD_FILE`	JSON file path	Unset = original built-in `ATTACKS` dictionary only; set for the external attack corpus.
`TG58_ATTACK`	Built-in name or external payload `id`	`clean`; chooses the same fixture across modes.
`TG58_BACKEND_FILE`	Local backend Python filename	`step58_poisoned_backend.py`.
`TG52_HOST_SECRET`	Private random string, >=40 characters	Required in protected modes; host-only authentication.
`TG52_HOST_PORT`	Available localhost port 1024–65535	Required in protected modes; host-control endpoint.
`TG52_TRUSTED_REQUEST`	Trusted original user request	Required in protected modes; used by existing grant restrictions.
`TG52_ALLOWED_DEST`	`local` or `external`	Required in protected modes; host-approved destination.
`OPENAI_API_KEY`	Provider API key	Needed for `auth_guard` only; never commit or pass to the agent.
`none`: baseline simulated backend pass-through (no grant, policy or LLM
guard; mapping document refs remains necessary for the backend's API).
`auth_only`: existing host-issued single-use grants, reference/provenance and
deterministic policy checks; bypasses only LLM content inspection.
`auth_guard`: existing Step 63 hybrid semantic guard plus the same
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
Version freeze and license
Source snapshot supplied for Round 2 adaptation: `6ab4d7e49e6f94953a5c8bf58859333ec77943d4`.
Round 2 frozen commit hash: pending local integration, complete MCP tests,
commit and tag. Retrieve the authoritative SHA after tagging with
`git rev-parse 'round2-freeze^{commit}'` (works in PowerShell and bash).
After review and green tests, use:
```bash
git add README.md RUNNING.md .env.example requirements.txt requirements-lock.txt \
  step58_poisoned_backend.py round2_*.py round2_payloads_example.json test_round2_offline.py
git commit -m "Round 2: selectable MCP gateway modes and external attack corpus"
git tag round2-freeze
git push origin main
git push origin round2-freeze
```
For Windows PowerShell, use `git add .` after checking `git status` and the
staged diff; the multiline bash command above is not PowerShell syntax.
The tag identifies the exact frozen commit without embedding a
self-referential commit SHA in that same commit. Verify with
`git rev-parse 'round2-freeze^{commit}'` and record that hash in the Round 2
report. Do not create/push the tag until local MCP tests have passed.
No new `LICENSE` file has been added: the team has not approved an open-source
license. The existing copyright notice remains applicable.
Running the Experiments
The repository preserves the original numbered development scripts. Later experiments may depend on earlier modules, so the original filenames should remain unchanged.
Gateway Security Evaluation
```powershell
python step63_gateway_test.py
```
Intent Enforcement
```powershell
python step71_mcp_eval.py
```
Controlled Ablation Evaluation
```powershell
python step67_ablation_eval.py
```
Contextual Workflow Monitoring
```powershell
python step82_real_mcp_eval.py
```
Integrated Hybrid Gateway
```powershell
python step83_live_hybrid_eval.py
```
Live Adversarial Agent Evaluation
```powershell
python step84_live_adversarial_eval.py --trials 3
```
This experiment makes LLM API calls and may incur usage charges.
Final Results Analysis
```powershell
python step85_final_analysis.py
```
The analysis script summarizes existing evaluation outputs. It does not perform a new autonomous-agent attack experiment.
Security and Research Limitations
TrustGate-MCP is a research prototype, not a production-ready enterprise security gateway.
Current limitations include:
Testing is limited to selected MCP tools and controlled attack scenarios.
Document storage and unauthorized export operations are simulated.
Some evaluations use scripted workflows rather than autonomous LLM-generated tool calls.
The protected live-agent configurations prevented malicious payload delivery, so downstream live-agent interception was not directly exercised in those trials.
GenAI monitoring has not demonstrated consistent incremental detection benefits over deterministic rules.
Performance results reflect end-to-end sessions and do not isolate the overhead of every individual security component.
Generalization to arbitrary third-party MCP servers, new attack families, and production workloads remains unverified.
Future Work
Potential extensions include:
Evaluating additional MCP servers and more diverse tool schemas.
Testing autonomous multi-tool attack chains that reach authorization enforcement.
Expanding unseen adversarial datasets.
Improving GenAI workflow reasoning for ambiguous attack patterns.
Measuring per-component latency and resource overhead.
Adding stronger session isolation and persistent audit storage.
Evaluating false positives on larger legitimate workloads.
Developing a deployable MCP gateway configuration for external applications.
Responsible Use
This repository is intended for defensive security research, experimentation, and educational use.
Attack payloads and simulated unauthorized operations are used to evaluate security controls in controlled environments. The prototype does not perform real-world data exfiltration in the reported experiments.
Project Status
Research prototype — implemented and experimentally evaluated.
The project demonstrates layered MCP security enforcement and monitoring, with evidence of prompt-injection prevention in the tested live-agent scenarios.
The incremental security value of GenAI-assisted workflow monitoring remains an open research question.
License
No license has been selected yet. Unless a license is added, standard copyright restrictions apply.
---
TrustGate-MCP — Securing the boundary between trusted user intent and untrusted AI tool interactions.
