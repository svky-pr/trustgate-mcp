
#!/usr/bin/env python3
"""Offline Step63 fail-closed checks using fake detectors; no API calls."""
import asyncio
from dataclasses import dataclass
from step63_hybrid_guard import Step63HybridGuard
from step33_v3_ai_guard import GuardAssessment

@dataclass
class FakeDetection:
    decision: str
    reason: str = 'simulated result'
    attack_type: str = 'other'

class Detector:
    model = 'fake-offline'
    def __init__(self, verdict): self.verdict = verdict
    async def classify(self, content):
        if isinstance(self.verdict, Exception): raise self.verdict
        return FakeDetection(self.verdict)

class Auth:
    def __init__(self, detected=False): self.calls=0; self.detected=detected
    async def assess(self, **kwargs):
        self.calls+=1
        return GuardAssessment(self.detected, 'other' if self.detected else 'none',
                               'high' if self.detected else 'low', True, 'ALLOW', 'fake authorization')

async def main():
    cases=[('semantic detected','DETECTED',False,'BLOCK',0),
           ('semantic review','REVIEW',False,'REVIEW',0),
           ('semantic error',RuntimeError('offline failure'),False,'REVIEW',0),
           ('benign authorized','NOT_DETECTED',False,'ALLOW',1),
           ('secondary injection flag','NOT_DETECTED',True,'BLOCK',1)]
    passed=0
    for name, verdict, detected, expected, expected_calls in cases:
        auth=Auth(detected)
        guard=Step63HybridGuard(detector=Detector(verdict), authorization_guard=auth)
        result=await guard.assess(user_request='Export this notice externally',
            tool_output='sample', proposed_tool='store_document_ref',
            proposed_arguments={'document_ref':'x','workspace':'external'})
        ok=result.recommended_action==expected and auth.calls==expected_calls
        passed+=ok
        print(f'{"PASS" if ok else "FAIL"} {name}: {result.recommended_action} auth_calls={auth.calls}')
    print(f'\nStep63 offline unit checks: {passed}/{len(cases)}')
    if passed!=len(cases): raise SystemExit(1)

if __name__=='__main__': asyncio.run(main())
