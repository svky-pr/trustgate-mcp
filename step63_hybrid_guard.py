#!/usr/bin/env python3
"""Step 63: semantic injection detection + independent authorization guard.

The untrusted document is evaluated by Step 62; only content judged benign
is sent to Step 33's independent authorization guard. Errors fail closed.
"""
from step33_v3_ai_guard import GuardAssessment, ImprovedTrustGateAIGuard
from step62_hybrid_detector import HybridDetector


class Step63HybridGuard:
    def __init__(self, detector=None, authorization_guard=None):
        self.detector = detector if detector is not None else HybridDetector()
        self.authorization_guard = (authorization_guard if authorization_guard is not None
                                    else ImprovedTrustGateAIGuard())
        self.model = self.detector.model
        self.last_detection = None

    async def assess(self, *, user_request: str, tool_output: str,
                     proposed_tool: str, proposed_arguments: dict,
                     classification: str = 'unknown') -> GuardAssessment:
        try:
            detection = await self.detector.classify(tool_output)
            self.last_detection = detection
            if detection.decision != 'NOT_DETECTED':
                # REVIEW and DETECTED both prevent storage; REVIEW is not counted
                # as a positive detection in research metrics.
                return GuardAssessment(
                    attack_detected=detection.decision == 'DETECTED',
                    attack_type=detection.attack_type if detection.decision == 'DETECTED' else 'other',
                    risk_level='high', intent_aligned=False,
                    recommended_action=('BLOCK' if detection.decision == 'DETECTED' else 'REVIEW'),
                    explanation=f'Step63 semantic gate ({detection.decision}): {detection.reason}',
                )
            # Step 33 has a separate authorization call and injection detector.
            assessment = await self.authorization_guard.assess(
                user_request=user_request, tool_output=tool_output,
                proposed_tool=proposed_tool, proposed_arguments=proposed_arguments,
                classification=classification,
            )
            # Step 33 may ALLOW despite its own injection flag. Enforce that flag.
            if assessment.attack_detected and assessment.recommended_action == 'ALLOW':
                return GuardAssessment(True, assessment.attack_type,
                                       assessment.risk_level, assessment.intent_aligned,
                                       'BLOCK', 'Step63: Step33 detected injection. ' +
                                       assessment.explanation)
            return assessment
        except Exception as exc:
            return GuardAssessment(False, 'other', 'high', False, 'REVIEW',
                                   f'Step63 guard unavailable: {type(exc).__name__}')
