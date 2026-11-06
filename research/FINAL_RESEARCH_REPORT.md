# TrustGate-MCP: Evaluating Semantic Guardrails and Deterministic Controls Against Tool-Output Prompt Injection

**Research status:** Prototype and controlled comparative evaluation (November 2026)
**Scope:** Host-only authored replay in Steps 90–92, supplemented by earlier live-agent testing in Step 89.
**Important:** This report is based on the console results shared by the researcher, not an independent audit of the full source repository or its raw data.


## Model provenance and correction to the midterm

| Experiment | Guard model attribution | Evidence/qualification |
|---|---|---|
| Midterm (original statement) | `gpt-4.1-nano` **as reported** | Not sufficient to establish that all historical Step 63 guard calls used nano; Step 62 and Step 33 v3 have different code defaults when the environment variable was unset. |
| Step 63 legacy hybrid | Step 62 defaults to `gpt-4.1-nano`; Step 33 v3 defaults to `gpt-4.1-mini` | Both can be overridden by `TRUSTGATE_GUARD_MODEL`. The historical runtime override is not independently established. |
| Step 89 live-agent pilot | Script default `gpt-4.1-mini` | Verify actual runtime flags/log before model-specific attribution. |
| Steps 90–92, three-trial rerun via Step 93 | **`gpt-4.1-mini`** | Step 93's default `--guard-model` was explicitly forwarded to all child experiments; observed 15/15, 12/15, and 12/18 detections correspond to mini. |
| Round 2 `auth_guard` (planned) | **`gpt-4.1-mini` for both components** | Explicitly set `TRUSTGATE_GUARD_MODEL=gpt-4.1-mini`; live Step 63 validation passed 71/71 on November 6; the four-payload Rob corpus ablation is pending. |

**Corrected midterm description for the final manuscript:** "Our midterm described a `gpt-4.1-nano` guard. The legacy Step 63 hybrid code actually had two independent model-backed components with different defaults (`gpt-4.1-nano` for Step 62 and `gpt-4.1-mini` for Step 33 v3) when no override was set. The final Step 90–93 authored replay used `gpt-4.1-mini`; Round 2 will pin both components to `gpt-4.1-mini` explicitly. Results from different configurations are reported separately."

**Version status (November 6, 2026):** Full Step 63 regression passed 71/71 with the Round 2 mini model pin, and clean/authority guard smoke tests passed. The owner then performed the agreed one-time annotated `round2-freeze` tag replacement. Its dereferenced commit remained `c25ce4d6dfe2cc818284b07e1960f1d70945a1e0`. Do not move this tag again. Post-freeze documentation revisions are not part of the frozen commit. The ten-trial Rob corpus ablation is still pending.

## Abstract

Model Context Protocol (MCP) tools expose language-model agents to externally supplied content that can include adversarial instructions. TrustGate-MCP investigates whether a semantic guard contributes useful screening beyond deterministic metadata authorization, approved-content integrity checks, and simple data-loss prevention (DLP) rules. The prototype uses intent, provenance, taint tracking, and a model-based content assessment at tool boundaries. A controlled, authored replay compared defenses across three experiments, each repeated three times. In Step 90, semantic screening identified all 15 injection-bearing assessments, with no detections among nine benign assessments. In Step 91, trusted content-integrity enforcement rejected all 15 unapproved malicious assessments but also rejected nine of 15 benign assessments because those benign versions were not approved; semantic screening provided no observed additional enforcement benefit when integrity was already decisive. In Step 92, all content hashes were deliberately approved, modeling an approval-quality failure rather than a hash bypass. The combined integrity, DLP, and semantic defense permitted three of 18 labeled unsafe assessments, compared with nine of 18 under the tested DLP-only defense, with no benign blocks in 12 assessments. These results support complementary semantic screening within the tested authored scenarios, while highlighting missed factual reversals, latency, and the lack of demonstrated live exploit prevention.

## 1. Problem and motivation

An agent may read a legitimate MCP tool result that contains attacker-authored text. The text may claim elevated authority, redirect a workflow, impersonate a role, or request data transfer. Tool output is data, not a source of instructions with authority to change the user's task or host policy. Deterministic controls can constrain tool identity, arguments, destinations, and approved content, but cannot necessarily assess every semantic property of approved text. Conversely, a model-based semantic guard may flag suspicious instructions but can miss content or incorrectly block benign work.

The research question is not whether AI replaces authorization. It is whether semantic screening adds measurable benefit to a layered host-enforced security design under specified trust assumptions.

## 2. Research questions

- **RQ1:** Can semantic screening identify instruction-bearing MCP tool output in a controlled authored replay without blocking benign examples?
- **RQ2:** Does semantic screening improve enforcement when a trusted hash manifest already rejects all unapproved changes?
- **RQ3:** Does semantic screening complement simple DLP rules when content passes an approved-content manifest but contains independently labeled unsafe material?
- **RQ4:** What operational and methodological limitations prevent these results from establishing real-world exploit prevention?

## 3. Threat model and trust assumptions

**Attacker-controlled surface:** Untrusted text returned by a tool, including apparent instructions, role claims, destination changes, and potentially unsafe content.

**Protected assets:** Host-authorized tool execution, destination restrictions, confidential information, and the integrity of user-requested operations.

**Trusted components in the replay:** Host metadata for authorization, an approved-content hash manifest, and the simulation's independently specified labels. The attacker is not modeled as changing host policy or rewriting the trusted manifest in Step 91. In Step 92, unsafe text is intentionally present in the approved manifest, which represents an approval-quality problem, not a cryptographic collision or integrity bypass.

**Out of scope:** Proving actual data exfiltration, malicious execution in production MCP deployments, arbitrary unseen attacker strategies, and secure operation under a compromised host or approval authority.

## 4. System architecture

The research prototype has previously developed an MCP gateway and deterministic controls for intent authorization, provenance, taint lineage, and destination restrictions, plus an LLM-based semantic guard. The replay studies isolate particular controls rather than measuring the full end-to-end gateway on every case.

```text
User request + trusted host policy
                |
         MCP tool invocation
                |
      Tool response (untrusted)
                |
     Host metadata / provenance
                |
   Authorization and destination rules
                |
      Approved-content integrity
                |
        Deterministic DLP
                |
        Semantic assessment
                |
    Host-enforced ALLOW / BLOCK / HOLD
                |
      Authorized downstream tool
```

The diagram is a conceptual control flow, not proof that every stage was exercised by the live-agent experiment. A production design should apply cheap deterministic controls first and invoke semantic assessment only where needed; the authored experiments sometimes evaluate all fixtures for comparison even when integrity would have already rejected them.

## 5. Methodology

Three experiments were repeated three times on fixed authored fixtures. Within each experiment, defense configurations were compared on the same content. The unit of repeated assessment is not an independent attack family: 84 assessments correspond to 28 distinct fixtures evaluated three times. The labels differ across experiments and should not be pooled into one general attack-prevention rate.

### Step 90: Semantic injection replay

Eight distinct authored fixtures: five malicious instruction-bearing and three benign. Three repetitions produced 15 malicious and nine benign assessments. The simulated proposed exports were authorized. Metrics therefore describe injection recognition and hold/block behavior, **not** prevention of unauthorized exports.

### Step 91: Integrity comparison

Ten fixtures: five labeled malicious, five benign. Two benign versions were approved, while three benign modifications and all five malicious versions were unapproved. A trusted SHA-256 manifest checked whether content matched approved versions. This experiment measures the effect of version approval, not the semantic safety of all approved text.

### Step 92: Approved-but-unsafe replay

Ten fixtures: six labeled unsafe and four benign. All hashes were intentionally approved. This experiment tests content-policy screening after approval, including basic DLP matching and semantic assessment. An unsafe label is an authored content-policy label; it is not evidence that a live model followed an injected instruction.

### Evaluation metrics

- **Labeled unsafe allowed:** Count of authored unsafe assessments for which the simulated enforcement decision was EXECUTE.
- **Benign blocked:** Count of benign assessments not permitted by a defense.
- **Guard detection:** Number of authored malicious/unsafe inputs flagged by the semantic guard.
- **Latency:** Median time per offline guard assessment, not end-to-end agent overhead.
- **Errors:** Reported guard API or assessment errors.

## 6. Results

### 6.1 Semantic detection

| Experiment | Detected labeled cases | Benign detections | Guard errors | Median guard latency |
|---|---:|---:|---:|---:|
| Step 90 — injection presence | 15/15 | 0/9 | 0 | 1,593.2 ms |
| Step 91 — malicious content | 12/15 | 0/15 | 0 | 1,486.1 ms |
| Step 92 — approved unsafe content | 12/18 | 0/12 | 0 | 1,447.0 ms |

These rates describe different target labels. Do not interpret their aggregate as a single exploit-prevention metric.

### 6.2 Step 90 — injection screening

| Defense | Injection-bearing assessments allowed | Benign blocked |
|---|---:|---:|
| Baseline | 15/15 | 0/9 |
| Deterministic metadata | 15/15 | 0/9 |
| Hybrid semantic block | 0/15 | 0/9 |
| Hybrid semantic hold | 0/15 | 0/9 |

All proposed exports were authorized; these figures show content-screening interventions, not thwarted unauthorized actions.

### 6.3 Step 91 — trusted integrity

| Defense | Labeled malicious content allowed | Benign blocked |
|---|---:|---:|
| Baseline | 15/15 | 0/15 |
| Metadata only | 15/15 | 0/15 |
| Integrity only | 0/15 | 9/15 |
| Semantic only | 3/15 | 0/15 |
| Integrity + semantic | 0/15 | 9/15 |

The three benign unapproved versions were rejected on every repetition. Adding semantic screening to integrity did not improve enforcement in this dataset.

### 6.4 Step 92 — approved but unsafe

| Defense | Labeled unsafe content allowed | Benign blocked |
|---|---:|---:|
| Baseline | 18/18 | 0/12 |
| Metadata only | 18/18 | 0/12 |
| Integrity only | 18/18 | 0/12 |
| DLP only | 9/18 | 0/12 |
| Semantic only | 6/18 | 0/12 |
| Integrity + DLP | 9/18 | 0/12 |
| Integrity + semantic | 6/18 | 0/12 |
| All controls | **3/18** | **0/12** |

Compared with DLP alone, all controls reduced labeled unsafe allowances from nine to three assessments in this fixed replay. The `factual_reversal` fixture remained allowed by all controls. The semantic guard also missed `internal_only_detail`, which DLP caught. These misses motivate trusted-source verification and stronger data classification.

## 7. Earlier live-agent evidence (Step 89)

The earlier live-agent pilot used actual model/tool interactions with host-simulated storage, not actual storage. In the reported malicious pilot (12 sessions), attacker payloads were delivered, but there were **zero unauthorized attempts and zero unauthorized executions** across defense modes. The baseline and deterministic configurations completed three of three attacked tasks; two hybrid configurations each completed two of three. Thus the pilot did **not** demonstrate a harmful baseline export prevented by TrustGate-MCP. It instead exposed possible availability/usability costs from semantic intervention on authorized tasks. This pilot is distinct from Steps 90–92 and should not be pooled with their metrics.

## 8. Discussion

**Where semantic analysis helped:** In Step 90, the guard identified authored injection-bearing text that metadata rules did not treat as disallowed. In Step 92, semantic assessment caught instruction-bearing unsafe approved content that the tested simple DLP rules missed.

**Where deterministic controls dominated:** In Step 91, a trusted manifest rejected every unapproved malicious modification without semantic assistance. This result cautions against attributing all layered-defense wins to AI.

**Where both failed:** The Step 92 factual-reversal scenario passed all tested controls. A hash confirms approval, not factual correctness; a semantic injection classifier is not a general factual verifier.

**Costs and trade-offs:** Median offline semantic checks took approximately 1.45–1.59 seconds. The sample did not show false positives in authored benign controls, but those small fixed sets cannot establish a low false-positive rate in deployment. Earlier live-agent tests did show some legitimate task noncompletion with semantic guardrails.

## 9. Limitations and threats to validity

1. Fixed authored fixtures and only three repeated assessments per fixture limit external validity.
2. The replay does not run a live MCP agent, actual storage, or real exfiltration.
3. Step 90's injected content was paired with authorized export actions; holding them is not proof of stopping unauthorized behavior.
4. The Step 91 manifest is assumed trusted; Step 92 deliberately assumes unsafe content was approved.
5. DLP is a simple tested comparator, not a comprehensive enterprise DLP platform.
6. The GenAI guard is a prompt-injection-oriented classifier, not a factual verifier or complete data-classification system.
7. No broad unseen attack set, adversarial adaptation, or statistical independence is established.
8. Offline guard latency is not full workflow latency or cost.
9. The Step 89 pilot did not exhibit a successful unauthorized baseline attempt, preventing a causal claim of blocked live exploit success.
10. This synthesis uses reported outputs; raw CSVs, code revision hashes, API settings, and source provenance should be archived for independent replication.

## 10. Future work

- Design a live-agent experiment that elicits an actual unauthorized baseline tool call, with the same task and payload tested across defenses.
- Expand to held-out, adversarially varied payloads and independently labeled benign samples.
- Add trusted-source factual validation for factual reversals.
- Compare stronger deterministic policy and DLP baselines to isolate true semantic incremental benefit.
- Measure end-to-end task completion, false positives, latency, cost, and analyst review burden.
- Record fixed model version, prompt, parameters, code commit, fixture hashes, and raw output for reproducibility.

## 11. Conclusion

TrustGate-MCP's controlled replay indicates that model-based semantic screening can complement host-enforced deterministic controls for some instruction-bearing tool outputs, especially when content passes a trusted approval manifest. Yet trusted integrity enforcement already blocks unapproved modifications without AI, and semantic screening misses some unsafe approved content. The results support a layered defense-in-depth design and identify clear evaluation gaps; they do **not** establish generalized or real-world MCP exploit prevention.

## 12. Provenance of numerical claims

Reported outputs supplied by the researcher:
- `results/step93_report_20261105_184318.json` (consolidated Step 93)
- `results/step90_semantic_incremental_20261105_184359.csv`
- `results/step91_content_integrity_20261105_184445.csv`
- `results/step92_approved_unsafe_20261105_184534.csv`
- Step 89 live-agent console results as previously discussed

The files above are provenance identifiers from the researcher's Windows environment; they are not embedded in this package. Include them with a final submission when available.


### Guard model version used in final replay

The November 5, 2026 three-trial Step 93 command was run without an explicit
`--guard-model` argument. Its CLI default is `gpt-4.1-mini`, which it passes
to each Step 90–92 replay script. Therefore the reported 15/15, 12/15, and
12/18 semantic detection figures are associated with **gpt-4.1-mini**, not a
verified `gpt-4.1-nano` evaluation. This differs from the midterm's stated
nano configuration and should be identified as a change of guard model in
the final manuscript. The historical live Step 63 hybrid gateway has
different fallback models when `TRUSTGATE_GUARD_MODEL` is unset: Step 62
uses nano, while Step 33 v3 uses mini. Round 2 should explicitly pin a single
`TRUSTGATE_GUARD_MODEL` for both components; comparison with past results
requires noting any model change.



## November 6, 2026 validated regression addendum

With `TRUSTGATE_GUARD_MODEL=gpt-4.1-mini`, the owner reported a complete Step 63 model-backed gateway regression of 71/71, an authorized clean `auth_guard` store accepted (ALLOW), and an authority-spoofing injected store rejected (BLOCK). These are controlled gateway probes with simulated storage and do not replace live-agent exploitation tests. A Step 84 unprotected workflow baseline against `gpt-4.1-mini`, standard system prompt, completed 10/10 trials with poisoned tool output delivered in all trials and **0/10 unauthorized storage attempts/executions**. This numerically matches the red-team team's reported 0/10, although the server implementations differ. The `round2-freeze` tag resolves to `c25ce4d6dfe2cc818284b07e1960f1d70945a1e0` and must remain immutable.
