#!/usr/bin/env python3
"""Step67 ablation proxy. Keeps the Step63 MCP server and grant enforcement intact.

TG67_MODE:
  authorization_only - bypasses content AI guard, retains trusted grants/policy
  semantic_only      - uses Step62 semantic detector, retains common grant/policy substrate
  full               - unchanged Step63 hybrid guard and grant/policy substrate

NOTE: semantic_only is NOT a grant-free deployment. Grant enforcement is kept
constant so content-guard effects can be compared without weakening host security.
"""
import os
from types import SimpleNamespace

import step63_mcp_proxy as proxy

MODE = os.environ.get("TG67_MODE", "full")
if MODE not in ("authorization_only", "semantic_only", "full"):
    raise SystemExit("Invalid TG67_MODE")

if MODE == "authorization_only":
    class AuthorizationOnlyGuard:
        async def assess(self, **kwargs):
            return SimpleNamespace(recommended_action="ALLOW")
    proxy.Step63HybridGuard = AuthorizationOnlyGuard

elif MODE == "semantic_only":
    from step62_hybrid_detector import HybridDetector

    class SemanticOnlyGuard:
        def __init__(self):
            self.detector = HybridDetector()

        async def assess(self, *, tool_output, **kwargs):
            try:
                result = await self.detector.classify(tool_output)
                decision = str(result.decision).upper()
                if decision == "DETECTED":
                    action = "BLOCK"
                elif decision == "NOT_DETECTED":
                    action = "ALLOW"
                else:
                    action = "REVIEW"
                return SimpleNamespace(recommended_action=action)
            except Exception:
                return SimpleNamespace(recommended_action="REVIEW")
    proxy.Step63HybridGuard = SemanticOnlyGuard

if __name__ == "__main__":
    proxy._backend_path()
    proxy.mcp.run(transport="stdio")
