#!/usr/bin/env python3
"""Step 70: deterministic pre-execution tool-call guard (simulated tools).

Run: python step70_tool_call_guard.py
This prototype does not connect to real MCP servers or call an LLM.
"""
from __future__ import annotations
from dataclasses import dataclass, asdict
import json
from typing import Any

@dataclass(frozen=True)
class UserIntent:
    allowed_tools: frozenset[str]
    allowed_documents: frozenset[str]
    allowed_destinations: frozenset[str]
    export_authorized: bool = False
    delete_authorized: bool = False

@dataclass(frozen=True)
class ToolCall:
    name: str
    arguments: dict[str, Any]
    origin: str = "agent"  # origin is informational; not trusted as an authorization claim

@dataclass(frozen=True)
class Decision:
    action: str
    reason: str

class ToolCallGuard:
    """Fail-closed allowlist with per-operation scope and explicit intent checks.

    UserIntent MUST come from a trusted host, not the LLM or tool output.
    """
    def evaluate(self, intent: UserIntent, call: ToolCall) -> Decision:
        if call.name not in intent.allowed_tools:
            return Decision("BLOCK", "Tool not in host-approved allowlist")
        if not isinstance(call.arguments, dict):
            return Decision("BLOCK", "Invalid arguments")
        specs = {
            "read_report": {"document_id"},
            "summarize_report": {"document_id"},
            "store_document_ref": {"document_id", "destination"},
            "delete_document": {"document_id"},
        }
        expected = specs.get(call.name)
        if expected is None:
            return Decision("BLOCK", "Unknown tool; no policy defined")
        if set(call.arguments) != expected:
            return Decision("BLOCK", "Unexpected or missing tool arguments")
        if not all(isinstance(v, str) and v.strip() for v in call.arguments.values()):
            return Decision("BLOCK", "Arguments must be nonempty strings")
        doc = call.arguments["document_id"]
        if doc not in intent.allowed_documents:
            return Decision("BLOCK", "Document outside trusted request scope")
        if call.name == "store_document_ref":
            if not intent.export_authorized:
                return Decision("BLOCK", "User did not authorize export")
            if call.arguments["destination"] not in intent.allowed_destinations:
                return Decision("BLOCK", "Destination not authorized")
            # In the existing gateway, a separate scoped, single-use host grant
            # must ALSO be checked before executing storage.
        if call.name == "delete_document" and not intent.delete_authorized:
            return Decision("BLOCK", "User did not authorize deletion")
        return Decision("ALLOW", "Within host-approved tool and argument scope")

class SimulatedGateway:
    def __init__(self, intent: UserIntent):
        self.intent = intent
        self.guard = ToolCallGuard()
        self.executed: list[ToolCall] = []

    def invoke(self, call: ToolCall) -> dict[str, Any]:
        decision = self.guard.evaluate(self.intent, call)
        if decision.action != "ALLOW":
            return {"decision": decision.action, "reason": decision.reason, "executed": False}
        # SIMULATION ONLY. Production must enforce host grants and provenance
        # and dispatch to the real MCP tool only after all checks pass.
        self.executed.append(call)
        return {"decision": "ALLOW", "reason": decision.reason, "executed": True}


def run_tests() -> None:
    intent = UserIntent(
        allowed_tools=frozenset({"read_report", "summarize_report", "store_document_ref", "delete_document"}),
        allowed_documents=frozenset({"report-001"}),
        allowed_destinations=frozenset(),
        export_authorized=False,
        delete_authorized=False,
    )
    gateway = SimulatedGateway(intent)
    cases = [
        ("legitimate read", ToolCall("read_report", {"document_id": "report-001"}), "ALLOW"),
        ("legitimate summary", ToolCall("summarize_report", {"document_id": "report-001"}), "ALLOW"),
        ("unrequested export", ToolCall("store_document_ref", {"document_id": "report-001", "destination": "external"}), "BLOCK"),
        ("unrequested delete", ToolCall("delete_document", {"document_id": "report-001"}), "BLOCK"),
        ("out-of-scope document", ToolCall("read_report", {"document_id": "secret-002"}), "BLOCK"),
        ("unknown tool", ToolCall("execute_shell", {"command": "whoami"}), "BLOCK"),
        ("unexpected argument", ToolCall("read_report", {"document_id": "report-001", "force": "true"}), "BLOCK"),
    ]
    failures = 0
    for label, call, expected in cases:
        result = gateway.invoke(call)
        passed = result["decision"] == expected
        failures += not passed
        print(f'{"PASS" if passed else "FAIL"} | {label:22} | {result["decision"]:5} | {result["reason"]}')
    print(f"\nStep70: {len(cases)-failures}/{len(cases)} passed; simulated executions={len(gateway.executed)}")
    if failures:
        raise SystemExit(1)

if __name__ == "__main__":
    run_tests()
