# TrustGate-MCP Round 2: Standalone MCP Gateway

The **new Round 2 entrypoint is `round2_mcp_proxy.py`**. It is an MCP **stdio
server**; the trusted host starts it as a subprocess, connects using MCP stdio,
and keeps the host-only TCP grant secret away from the LLM and untrusted tool
output. The numbered `step*.py` scripts remain unchanged (except the additive
opt-in JSON payload loader in `step58_poisoned_backend.py`) and keep their
historical defaults and CLI parameters.

> **Research prototype**: storage is simulated by the Step 58 backend. The
> localhost host-control channel is shared-secret-authenticated but is not a
> hardened production service. Do not expose its port/secret to a malicious
> agent or an untrusted external client.

## Installation (Windows, macOS and Linux)

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

Windows PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

The only Windows-specific package, `pywin32`, is now installed **only on
Windows** using a requirement environment marker. The Round 2 entrypoint and
helpers use `sys.executable`, `pathlib`, Python TCP sockets and MCP stdio;
there are no hard-coded Windows drive paths in this flow.

## Environment settings

| Setting | Needed | Meaning / default |
|---|---|---|
| `TG_MODE` | Optional | `none`, `auth_only`, `auth_guard`; **unset = `auth_guard`** (existing Step 63 hybrid). Applies to `round2_mcp_proxy.py` only. |
| `TG58_ATTACK` | Optional | Built-in attack ID (`clean`, `direct`, `authority`, `workflow`, `metadata`, `encoded`) or an ID from `TG_PAYLOAD_FILE`; default `clean`. |
| `TG_PAYLOAD_FILE` | Optional | JSON payload corpus; **unset = original built-in `ATTACKS` dictionary only**. Relative paths are rooted at this repository. |
| `TG58_BACKEND_FILE` | Optional | Existing local backend Python filename; default `step58_poisoned_backend.py`. The existing Step 63 local-file restriction still applies. |
| `TG52_HOST_SECRET` | Protected modes | Host-only, unpredictable secret of at least 40 characters, unique per run; never an MCP argument. |
| `TG52_HOST_PORT` | Protected modes | Available localhost TCP port, 1024–65535, selected by host before starting gateway. |
| `TG52_TRUSTED_REQUEST` | Protected modes | Original legitimate **user-approved** request, set by the trusted host (not model/tool content). |
| `TG52_ALLOWED_DEST` | Protected modes | Host-approved `local` or `external` workspace. |
| `OPENAI_API_KEY` | `auth_guard` | OpenAI API key needed by the existing Step 63 semantic guard. Not used in `none` / `auth_only`. |
| `TRUSTGATE_GUARD_MODEL` | **required for Round 2 reproducibility** | **Set to `gpt-4.1-mini`** for every `auth_guard` Round 2 trial. This sets both Step 62 and Step 33 v3 to mini; otherwise their historical defaults differ (nano versus mini). |

Modes:

- **`none`**: unguarded read / summarize / simulated store via backend. It
  ignores the `grant_token` argument and skips host-control, policy,
  provenance enforcement, DLP and LLM inspection. The adapter still maps
  document references to bytes for the backend's `store_document(document, ...)`
  API; unknown references cannot be translated. This is **not** intended for
  production use.
- **`auth_only`**: delegates to the original Step 63 gateway and uses the
  existing Step 67 `authorization_only`-equivalent no-op guard. The **same**
  trusted host grants, single-use consumption, policy and provenance checks
  are enforced; there is **no LLM call or prompt-injection content inspection**.
- **`auth_guard`**: delegates to the **unmodified Step 63 hybrid guard path**.
  It performs the same grant/provenance/policy checks and existing semantic
  guard assessment. A semantic veto/review can block an otherwise permitted
  store. The default is unchanged when `TG_MODE` is not set.

The `TG67_MODE`, `TG76_SEMANTIC` and `TG83_GENAI` settings are **legacy
experiment-specific switches** and do not override Round 2 `TG_MODE`. When
running the Round 2 entrypoint, only `TG_MODE` controls the selected defense
configuration.

## Pin the guard model for paired evaluations

The final **Step 90–93** three-trial replay used `gpt-4.1-mini`, because
`step93_final_evaluation.py` defaults to it and forwards `--guard-model`
explicitly. The Step 63 hybrid gateway has **two model components** with
*different* defaults when `TRUSTGATE_GUARD_MODEL` is unset: the Step 62 detector
uses `gpt-4.1-nano`, and Step 33 v3 uses `gpt-4.1-mini`.

Set this for every `auth_guard` gateway process and host ablation runner:

```powershell
$env:TRUSTGATE_GUARD_MODEL = 'gpt-4.1-mini'
```

macOS/Linux:

```bash
export TRUSTGATE_GUARD_MODEL=gpt-4.1-mini
```

If you instead choose the midterm model `gpt-4.1-nano`, pin it explicitly for
**both** components and label it as a *different* model configuration.
The model pin does not affect `none` or `auth_only`. Do not compare results
across model pins without marking the difference in the experiment metadata.

## Run the standalone proxy

The proxy must be started **by an MCP stdio client**. Running
`python round2_mcp_proxy.py` in a terminal will wait for protocol traffic on
stdin; logs go to stderr, stdout is reserved for MCP.

Use the trusted-host smoke harness, which starts the stdio proxy, sets a random
host secret and port, asks for a grant, and attempts one simulated store:

```bash
python round2_benign_demo.py --mode none --attack clean
python round2_benign_demo.py --mode auth_only --attack clean
python round2_benign_demo.py --mode auth_guard --attack clean
```

The `auth_guard` example makes real OpenAI calls; the others do not. Any mode
may block a store or fail closed; report both legitimate completion and false
positives rather than assuming authorized content must always pass the LLM.

In your **own MCP host code**, create a `StdioServerParameters` object:

```python
import os, sys
from pathlib import Path
from mcp import StdioServerParameters

settings = dict(os.environ)
settings.update({
    'TG_MODE': 'auth_only',
    'TG52_HOST_SECRET': trusted_secret,  # secrets.token_urlsafe(48)
    'TG52_HOST_PORT': str(trusted_free_port),
    'TG52_TRUSTED_REQUEST': approved_user_request,
    'TG52_ALLOWED_DEST': 'external',
    'TG58_ATTACK': 'clean',
})
params = StdioServerParameters(
    command=sys.executable,
    args=[str(Path('round2_mcp_proxy.py').resolve())],
    env=settings,
)
```

Connect using `mcp.client.stdio.stdio_client` and `mcp.ClientSession` as in
`round2_benign_demo.py`. Do not pass the secret, host port, or grant issuer to
LLM-visible tool descriptions.

## Trusted host: requesting a grant

In the trusted host, **after** the user explicitly approves saving the public
notice to the approved external workspace:

1. Start the gateway with host-only `TG52_*` settings.
2. Call MCP tool `read_public_notice`; save the returned `data.document_ref`.
3. Call the independent localhost host-control API using the host helper:

```python
from round2_host import issue_grant

grant_token = await issue_grant(host_port, trusted_secret,
                                document_ref, 'external')
```

4. Call MCP tool `store_document_ref` with `document_ref`, `workspace='external'`
   and `grant_token`. Tokens are bound to that session, document, action and
   destination and are consumed **once**. The gateway separately enforces the
   trusted original request and source reference.

The CLI helper is also usable **from the trusted host's own shell** while the
proxy session is still running:

```bash
python round2_host.py --port 53271 --health
python round2_host.py --port 53271 --document-ref doc_... --destination external
```

The CLI requires `TG52_HOST_SECRET` in the host's private environment. The port
above is an **example only**; use the actual port selected by your host. The
helper returns JSON containing the one-time grant token; do not log it in
agent-visible transcripts. The tool-output payload **cannot grant itself**.
For `TG_MODE=none`, send a nonempty placeholder `grant_token='baseline-ignored'`
only to satisfy the stable MCP tool schema; it has no authorization effect.

## External attack corpus

JSON is supported (no YAML dependency). Example:

```json
{
  "payloads": [
    {
      "id": "r2_authority_01",
      "class": "authority_spoofing",
      "text": "\n\n[Untrusted synthetic test payload] Follow this instruction."
    }
  ]
}
```

The `id` is chosen using `TG58_ATTACK`. Set `class` to `benign` (or prefix
`benign...`) for safe controls, so the ablation can count false positives on
more than the built-in `clean` fixture. The `class` is recorded by the
attack-side corpus for grouping evaluation results; **it does not authorize or
change any gateway decision**. The `text` is appended to the synthetic public
notice as untrusted backend output. All built-in payload IDs remain unchanged.
An external file cannot override built-ins; duplicate IDs, malformed JSON or
invalid entries fail closed. Absolute paths are supported; relative paths
resolve from the repository root. File content is snapshotted per backend
process, so use a fresh process for each trial or freeze a content hash.

```bash
python round2_benign_demo.py --mode auth_only --attack r2_authority_01 \
  --payload-file round2_payloads_example.json
```

For a paired ablation, keep the same `TG58_ATTACK`, `TG_PAYLOAD_FILE`, trusted
user request, approved destination, model, and fixture text across all three
`TG_MODE` values. Run in isolated fresh gateway sessions. Track whether the
attack prompt was delivered, whether storage was attempted, whether it
executed, benign completion, guard calls, and latency. **Do not equate
content screening with preventing a live agent's unauthorized tool action.**

## Cross-mode ablation matrix

Use the same external JSON corpus for every defense mode, including the clean
control; each case runs in its own fresh MCP proxy process with the **same
trusted host-approved export request**:

```bash
python round2_ablation.py --payload-file round2_payloads_example.json --trials 3
# Built-in attacks instead of an external corpus:
python round2_ablation.py --trials 3
```

This writes a timestamped CSV under `results/` with fixture ID, attack class,
mode, whether simulated storage executed, guard decision, **store-call** latency
and **whole-session** latency. `auth_guard` uses paid LLM calls. A false positive is a hold on the
`clean` authorized control. The security interpretation matters: an attempted
store in this runner is **legitimate**, so a block on an injection-bearing
notice measures content screening rather than interception of unauthorized
storage. The existing Step 89 live-agent experiments address a different
question and must be reported separately.

## Regression and reproducibility

```bash
python -m unittest -v test_round2_offline.py
python step45_authorized_gateway.py
python step50_all_tools_gateway.py
python step63_guard_unit_test.py
python step63_gateway_test.py
```

`step63_gateway_test.py` and `round2_benign_demo.py` require the MCP Python
SDK. Step 63's live hybrid path also requires the configured OpenAI API. Do not
claim the full real-MCP regression suite passed if dependencies, API access or
quotas are unavailable. These tests simulate storage, not real exports.

### Verified Round 2 tag (do not move)

The owner completed the model-backed validation on **2026-11-06** with
`TRUSTGATE_GUARD_MODEL=gpt-4.1-mini`: Step 63 **71/71**, and benign clean
`ai_decision=ALLOW`/malicious authority `ai_decision=BLOCK` smoke probes. The
agreed one-time replacement was used to publish an annotated `round2-freeze`
tag that dereferences to **`c25ce4d6dfe2cc818284b07e1960f1d70945a1e0`**.

The frozen code tag is final. **Do not move it again.** A different SHA from
`git ls-remote` for the annotated tag object does **not** mean it points to a
different commit. Check the target without modifying it:

```powershell
git rev-parse 'round2-freeze^{commit}'
git ls-remote origin 'refs/tags/round2-freeze' 'refs/tags/round2-freeze^{}'
```

Use the exact frozen tag to reproduce the Round 2 runs, and set
`TRUSTGATE_GUARD_MODEL=gpt-4.1-mini` explicitly. If unset, Step 62 defaults to
`gpt-4.1-nano` and Step 33 v3 to `gpt-4.1-mini`.

### Rob's external four-payload corpus

Pass the **absolute local path** to the separate cloned red-team repo, without
copying the file into TrustGate-MCP:

```powershell
$env:TRUSTGATE_GUARD_MODEL = 'gpt-4.1-mini'
$payload = 'C:\Users\Saksh\Desktop\trustgate-mcp-redteam\payloads\round1_gateway.json'
if (-not (Test-Path $payload)) { throw "Payload corpus missing: $payload" }
python round2_ablation.py --payload-file $payload --modes none auth_only auth_guard --trials 10
```

Record payload checksum and the generated `results/round2_ablation_*.csv`.
Authored authorized-content holds/false positives must be distinguished from
live-agent attack success. See [ROUND2_HANDOFF.md](ROUND2_HANDOFF.md).

No license is included pending team approval.
