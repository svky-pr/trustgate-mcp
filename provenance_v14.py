
"""Step 14: Trusted provenance and transformation lineage."""

import hashlib
import secrets
from dataclasses import dataclass, field


@dataclass
class DocumentRecord:
    document_id: str
    content: str
    classification: str
    source: str
    parents: list = field(default_factory=list)


class TrustedProvenance:
    LEVELS = {
        "public": 0,
        "confidential": 1,
    }

    def __init__(self):
        self.records = {}
        self.fingerprints = {}

    @staticmethod
    def fingerprint(content):
        return hashlib.sha256(
            content.encode("utf-8")
        ).hexdigest()

    def register_source(
        self,
        content,
        classification,
        source,
    ):
        """Register data from a trusted MCP source.

        Classification must be assigned by the middleware,
        not accepted from an LLM response.
        """

        if classification not in self.LEVELS:
            raise ValueError("Invalid classification")

        if not isinstance(content, str):
            raise TypeError("Content must be a string")

        document_id = secrets.token_hex(16)

        record = DocumentRecord(
            document_id=document_id,
            content=content,
            classification=classification,
            source=source,
        )

        self.records[document_id] = record

        digest = self.fingerprint(content)

        self.fingerprints.setdefault(
            digest, set()
        ).add(document_id)

        return document_id

    def register_transformation(
        self,
        content,
        parent_ids,
        source,
    ):
        """Register a transformation performed by a trusted tool.

        Parent IDs must come from verified middleware state.
        An LLM-provided parent ID is not trusted evidence.
        """

        if not parent_ids:
            raise ValueError(
                "Trusted transformations require parent IDs"
            )

        parents = []

        for parent_id in parent_ids:
            if parent_id not in self.records:
                raise ValueError(
                    f"Unknown parent: {parent_id}"
                )

            parents.append(
                self.records[parent_id]
            )

        classification = max(
            (
                parent.classification
                for parent in parents
            ),
            key=lambda item: self.LEVELS[item],
        )

        document_id = secrets.token_hex(16)

        record = DocumentRecord(
            document_id=document_id,
            content=content,
            classification=classification,
            source=source,
            parents=list(parent_ids),
        )

        self.records[document_id] = record

        digest = self.fingerprint(content)

        self.fingerprints.setdefault(
            digest, set()
        ).add(document_id)

        return document_id

    def resolve_exact(self, content):
        """Return trusted matches for exactly identical content."""

        digest = self.fingerprint(content)

        candidates = self.fingerprints.get(
            digest, set()
        )

        return [
            self.records[document_id]
            for document_id in candidates
            if self.records[document_id].content == content
        ]

    def resolve_handle(self, document_id):
        """Resolve a handle from trusted middleware state only."""

        return self.records.get(document_id)

    def classify_exact(self, content):
        matches = self.resolve_exact(content)

        if not matches:
            return "unknown", False

        # Conservative classification if the same content
        # was registered through multiple sources.
        classification = max(
            (
                record.classification
                for record in matches
            ),
            key=lambda item: self.LEVELS[item],
        )

        return classification, True

    def lineage(self, document_id):
        record = self.resolve_handle(document_id)

        if record is None:
            return []

        return list(record.parents)
