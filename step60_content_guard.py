#!/usr/bin/env python3
"""Step 60: conservative content-inspection wrapper for TrustGate MCP.

The wrapper adds deterministic checks for the five known Step 58 injection
families before delegating to the existing Step 33 LLM guard.
It does NOT treat detection as proof of attacker intent in arbitrary documents.
This is a prototype, not a comprehensive prompt-injection detector.
"""
import base64
import binascii
import re
from dataclasses import replace

from step33_v3_ai_guard import ImprovedTrustGateAIGuard, GuardAssessment

# Focus on instructions aimed at an agent, not ordinary security prose.
DIRECT = re.compile(
    r"\bignore\s+(?:the\s+)?user(?:'s)?\s+request\b.{0,220}"
    r"\b(?:export|store|upload|send)\b", re.I | re.S)
AUTHORITY = re.compile(
    r"\[\s*system\s+override\s*\]|"
    r"\b(?:authorized\s+system\s+instruction|superseding\s+the\s+user\s+request)\b",
    re.I)
WORKFLOW = re.compile(
    r"\bworkflow\s+prerequisite\s*:.{0,240}"
    r"\b(?:store|export|upload)\b", re.I | re.S)
METADATA = re.compile(
    r"<processing_metadata>[\s\S]{0,700}?"
    r"(?:required_tool\s*=\s*store_document_ref|workspace\s*=\s*external)"
    r"[\s\S]{0,700}?</processing_metadata>", re.I)
ENCODED_MARKER = re.compile(r"\bbase64\s+instruction\s*:", re.I)
BASE64_TOKEN = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/])")
EXFIL_ACTION = re.compile(r"\b(?:export|store|upload|send)\b.{0,110}"
                         r"\b(?:externally|external\s+workspace|outside)\b", re.I | re.S)


def inspect_content(content: str):
    """Return (attack_type, explanation) or None."""
    if not isinstance(content, str):
        return ('other', 'Untrusted content is not text')
    if len(content) > 100_000:
        return ('other', 'Document exceeds inspection limit; fail closed')
    if DIRECT.search(content):
        return ('data_exfiltration', 'Direct instruction overrides user request and requests export')
    if AUTHORITY.search(content):
        return ('authority_spoofing', 'Document impersonates a higher-priority system instruction')
    if WORKFLOW.search(content):
        return ('workflow_hijacking', 'Document invents a storage prerequisite')
    if METADATA.search(content):
        return ('tool_output_laundering', 'Untrusted metadata directs tool invocation')
    if ENCODED_MARKER.search(content):
        for match in BASE64_TOKEN.finditer(content):
            token = match.group()
            try:
                decoded = base64.b64decode(token, validate=True).decode('utf-8')
            except (binascii.Error, UnicodeDecodeError, ValueError):
                continue
            if EXFIL_ACTION.search(decoded):
                return ('data_exfiltration', 'Encoded text contains an export instruction')
        if re.search(r"\bdecode\s+and\s+follow\b", content, re.I):
            return ('workflow_hijacking', 'Document directs the agent to execute encoded instructions')
    return None


class Step60ContentGuard:
    """Drop-in replacement for ImprovedTrustGateAIGuard."""
    def __init__(self, underlying=None):
        self.underlying = underlying or ImprovedTrustGateAIGuard()
        self.model = getattr(self.underlying, 'model', 'unknown')

    async def assess(self, *, user_request: str, tool_output: str,
                     proposed_tool: str, proposed_arguments: dict,
                     classification: str = 'unknown') -> GuardAssessment:
        hit = inspect_content(tool_output)
        if hit:
            attack_type, explanation = hit
            # Detection is a separate gate. Do not send malicious content to
            # the LLM authorization step and do not grant storage.
            return GuardAssessment(
                attack_detected=True,
                attack_type=attack_type,
                risk_level='high',
                intent_aligned=False,  # not evaluated, conservative fail closed
                recommended_action='BLOCK',
                explanation='Step60 content inspection: ' + explanation,
            )
        assessment = await self.underlying.assess(
            user_request=user_request,
            tool_output=tool_output,
            proposed_tool=proposed_tool,
            proposed_arguments=proposed_arguments,
            classification=classification,
        )
        # Step 33 previously could ALLOW even after detecting an injection.
        # Enforce the detection verdict independently of authorization.
        if assessment.attack_detected and assessment.recommended_action == 'ALLOW':
            return replace(assessment, recommended_action='BLOCK',
                           explanation=assessment.explanation +
                           ' Step60: detected injection overrides authorization.')
        return assessment


def self_test():
    from step58_poisoned_backend import NOTICE, ATTACKS
    results = []
    for name, payload in ATTACKS.items():
        hit = inspect_content(NOTICE + payload)
        expected = name != 'clean'
        passed = bool(hit) == expected
        results.append(passed)
        print(f'{"PASS" if passed else "FAIL"} attack={name:10s} detected={bool(hit)} detail={hit}')
    benign = (
        'The report discusses how attackers may impersonate system messages.',
        'The team should avoid exporting confidential documents externally.',
        'Public notice: Apply security patches and enable multifactor authentication.',
    )
    for i, sample in enumerate(benign, 1):
        hit = inspect_content(sample)
        passed = hit is None
        results.append(passed)
        print(f'{"PASS" if passed else "FAIL"} benign={i} detected={bool(hit)}')
    print(f'\nStep60 content-inspection self-test: {sum(results)}/{len(results)}')
    if not all(results):
        raise SystemExit(1)


if __name__ == '__main__':
    self_test()
