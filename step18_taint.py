
"""Step 18: Data-flow taint tracking for TrustGate-MCP.

No LLM calls or MCP server required.
Python 3.10+

Run:
    python step18_taint.py
"""

from dataclasses import dataclass, field
from typing import Optional
import secrets


LEVELS = {
    "public": 0,
    "confidential": 1,
}

SENSITIVE = "confidential"


@dataclass(frozen=True)
class TaintRecord:
    value_id: str
    classification: str
    source: str
    parents: tuple[str, ...] = ()
    content: Optional[str] = None


@dataclass
class TaintState:
    """Middleware-owned registry of data-flow dependencies."""

    records: dict[str, TaintRecord] = field(
        default_factory=dict
    )

    def register_source(
        self,
        content: str,
        classification: str,
        source: str,
    ) -> str:

        if classification not in LEVELS:
            raise ValueError(
                f"Unsupported classification: {classification}"
            )

        value_id = secrets.token_hex(16)

        self.records[value_id] = TaintRecord(
            value_id=value_id,
            classification=classification,
            source=source,
            content=content,
        )

        return value_id

    def derive(
        self,
        content: str,
        parents: list[str],
        source: str,
    ) -> str:
        """Register a trusted, explicitly declared transformation."""

        if not parents:
            raise ValueError(
                "Derived values must have at least one parent"
            )

        for parent in parents:
            if parent not in self.records:
                raise ValueError(
                    f"Unknown parent: {parent}"
                )

        classification = max(
            (
                self.records[parent].classification
                for parent in parents
            ),
            key=lambda label: LEVELS[label],
        )

        value_id = secrets.token_hex(16)

        self.records[value_id] = TaintRecord(
            value_id=value_id,
            classification=classification,
            source=source,
            parents=tuple(parents),
            content=content,
        )

        return value_id

    def resolve(
        self,
        value_id: str,
    ) -> Optional[TaintRecord]:

        return self.records.get(value_id)

    def classification(
        self,
        value_id: str,
    ) -> str:

        record = self.resolve(value_id)

        if record is None:
            return "unknown"

        return record.classification

    def ancestors(
        self,
        value_id: str,
    ) -> set[str]:
        """Return transitive dependencies."""

        if value_id not in self.records:
            return set()

        visited = set()
        pending = [value_id]

        while pending:
            current = pending.pop()

            if current in visited:
                continue

            visited.add(current)

            pending.extend(
                self.records[current].parents
            )

        visited.discard(value_id)

        return visited

    def explain(
        self,
        value_id: str,
    ) -> dict:

        record = self.resolve(value_id)

        if record is None:
            return {
                "status": "unknown",
                "classification": "unknown",
            }

        return {
            "status": "tracked",
            "value_id": value_id,
            "classification": record.classification,
            "source": record.source,
            "parents": list(record.parents),
            "ancestor_count": len(
                self.ancestors(value_id)
            ),
        }


def check_transfer(
    taint: TaintState,
    value_id: str,
    workspace: str,
    allowed_workspaces: set[str],
    allow_confidential_external: bool = False,
) -> tuple[str, str]:
    """Enforce destination and data-flow restrictions.

    BLOCK = known unauthorized operation
    CONFIRM = insufficient trusted information
    ALLOW = authorized operation
    """

    # User intent is checked independently of taint.
    if workspace not in allowed_workspaces:
        return (
            "BLOCK",
            "Destination not authorized by user",
        )

    record = taint.resolve(value_id)

    if record is None:
        return (
            "CONFIRM",
            "Unknown data identity or missing lineage",
        )

    if workspace == "local":
        return (
            "ALLOW",
            "Authorized local storage",
        )

    if workspace == "external":

        if record.classification == "public":
            return (
                "ALLOW",
                "Tracked public data",
            )

        if record.classification == "confidential":

            if allow_confidential_external:
                return (
                    "ALLOW",
                    "Explicit confidential export authorization",
                )

            return (
                "BLOCK",
                "Confidential data dependency detected",
            )

    return (
        "CONFIRM",
        "Unsupported destination or classification",
    )


def run_tests():
    state = TaintState()

    # -------------------------------------------------------
    # Register source values
    # -------------------------------------------------------

    confidential = state.register_source(
        "CONFIDENTIAL: Internal assessment findings",
        "confidential",
        "read_report",
    )

    public = state.register_source(
        "Public maintenance announcement",
        "public",
        "read_public_notice",
    )

    # -------------------------------------------------------
    # Trusted transformations
    # -------------------------------------------------------

    summary = state.derive(
        "A summary of internal security findings",
        [confidential],
        "summarize_report",
    )

    mixed = state.derive(
        "Public notice with internal findings",
        [public, confidential],
        "merge_documents",
    )

    public_rewrite = state.derive(
        "Rewritten public maintenance notice",
        [public],
        "rewrite_document",
    )

    # Simulates a tracked intermediate tool result that
    # was NOT registered in the provenance document store.
    intermediate = state.derive(
        "Security findings reformatted as a table",
        [summary],
        "format_table",
    )

    # -------------------------------------------------------
    # Fixed scenarios
    # -------------------------------------------------------

    cases = [
        {
            "name": "authorized_public_export",
            "value_id": public,
            "workspace": "external",
            "allowed": {"external"},
            "confidential_export": False,
            "expected": "ALLOW",
        },
        {
            "name": "unauthorized_confidential_export",
            "value_id": confidential,
            "workspace": "external",
            "allowed": {"external"},
            "confidential_export": False,
            "expected": "BLOCK",
        },
        {
            "name": "authorized_confidential_export",
            "value_id": confidential,
            "workspace": "external",
            "allowed": {"external"},
            "confidential_export": True,
            "expected": "ALLOW",
        },
        {
            "name": "confidential_summary_laundering",
            "value_id": summary,
            "workspace": "external",
            "allowed": {"external"},
            "confidential_export": False,
            "expected": "BLOCK",
        },
        {
            "name": "mixed_source_laundering",
            "value_id": mixed,
            "workspace": "external",
            "allowed": {"external"},
            "confidential_export": False,
            "expected": "BLOCK",
        },
        {
            "name": "unregistered_intermediate",
            "value_id": intermediate,
            "workspace": "external",
            "allowed": {"external"},
            "confidential_export": False,
            "expected": "BLOCK",
        },
        {
            "name": "public_after_confidential_read",
            "value_id": public_rewrite,
            "workspace": "external",
            "allowed": {"external"},
            "confidential_export": False,
            "expected": "ALLOW",
        },
        {
            "name": "authorized_local_confidential",
            "value_id": confidential,
            "workspace": "local",
            "allowed": {"local"},
            "confidential_export": False,
            "expected": "ALLOW",
        },
        {
            "name": "unauthorized_destination",
            "value_id": public,
            "workspace": "external",
            "allowed": {"local"},
            "confidential_export": False,
            "expected": "BLOCK",
        },
        {
            "name": "unknown_value",
            "value_id": "nonexistent-value",
            "workspace": "external",
            "allowed": {"external"},
            "confidential_export": False,
            "expected": "CONFIRM",
        },
    ]

    print("\n=== STEP 18 TAINT PROPAGATION TESTS ===")

    passed = 0

    for case in cases:

        decision, reason = check_transfer(
            taint=state,
            value_id=case["value_id"],
            workspace=case["workspace"],
            allowed_workspaces=case["allowed"],
            allow_confidential_external=(
                case["confidential_export"]
            ),
        )

        ok = decision == case["expected"]

        if ok:
            passed += 1

        print(
            f"{'PASS' if ok else 'FAIL'} "
            f"{case['name']:35s} "
            f"expected={case['expected']:7s} "
            f"actual={decision:7s}"
        )

        if not ok:
            print(f"  Reason: {reason}")

    print("\n=== LINEAGE VERIFICATION ===")

    assert state.classification(summary) == "confidential"
    assert state.classification(mixed) == "confidential"
    assert state.classification(intermediate) == "confidential"
    assert state.classification(public_rewrite) == "public"

    assert confidential in state.ancestors(intermediate)
    assert public in state.ancestors(mixed)
    assert confidential in state.ancestors(mixed)

    print("Confidential summary lineage: PASS")
    print("Multi-source contamination: PASS")
    print("Transitive dependency tracking: PASS")
    print("Independent public document: PASS")

    print("\n=== STEP 18 SUMMARY ===")
    print(f"Passed: {passed}/{len(cases)}")

    if passed != len(cases):
        raise AssertionError(
            "One or more taint tests failed"
        )


if __name__ == "__main__":
    run_tests()
