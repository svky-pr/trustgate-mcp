
"""
TrustGate-MCP — Step 21 Reference Gateway

Provides short, gateway-owned document references for
LLM tool calls while preserving trusted handles,
provenance, taint tracking, and storage authorization.

Security:
- Unpredictable references per gateway instance
- No cross-instance reference resolution
- Unknown references cannot execute storage
- Storage authorization remains in TrustGateGateway
"""

import secrets
from dataclasses import dataclass
from typing import Optional

from step19_gateway import TrustGateGateway


@dataclass
class ReferenceResult:
    decision: str
    reason: str
    executed: bool


class ReferenceGateway(TrustGateGateway):

    def __init__(self, session, user_policy):
        super().__init__(session, user_policy)

        # A fresh random namespace for every gateway instance.
        # This prevents doc_1 in one gateway from colliding
        # with doc_1 in another gateway.
        self._session_namespace = secrets.token_hex(16)

        # Model-visible reference -> trusted internal handle.
        # This mapping belongs only to this gateway instance.
        self._references = {}

        self._reference_counter = 0

    def _new_reference(self, handle):
        """
        Register an internal handle and return an
        unpredictable, gateway-owned reference.
        """
        self._reference_counter += 1

        document_ref = (
            f"doc_{self._session_namespace}_"
            f"{self._reference_counter}"
        )

        self._references[document_ref] = handle

        return document_ref

    def _resolve_reference(self, document_ref):
        """
        Resolve only references issued by this gateway.

        A foreign or unknown reference returns None.
        """
        if not isinstance(document_ref, str):
            return None

        prefix = f"doc_{self._session_namespace}_"

        if not document_ref.startswith(prefix):
            return None

        return self._references.get(document_ref)

    async def read_ref(self, tool_name):
        """
        Read a document through the trusted gateway and
        return an LLM-visible reference plus content.
        """
        handle, content = await self.read_document(
            tool_name
        )

        document_ref = self._new_reference(handle)

        return {
            "document_ref": document_ref,
            "content": content,
        }

    def derive_ref(self, parent_ref):
        """
        Create a deterministic derived document from
        a trusted parent reference.

        The derived document inherits its parent's taint.
        It intentionally does not register exact provenance,
        preserving the Step 21 ablation behavior.
        """
        parent_handle = self._resolve_reference(
            parent_ref
        )

        if parent_handle is None:
            raise ValueError(
                "Unknown or foreign document reference"
            )

        parent_content = self.documents[parent_handle]

        # Deterministic table transformation.
        # The derived value remains linked to its parent.
        derived_content = (
            "Field,Value\n"
            f"document,{str(parent_content).replace(chr(10), ' ')}"
        )

        derived_handle = self.derive_value(
            derived_content,
            [parent_handle],
            source="trusted_table_transform",
            register_provenance=False,
        )

        document_ref = self._new_reference(
            derived_handle
        )

        return {
            "document_ref": document_ref,
            "content": derived_content,
        }

    async def store_ref(
        self,
        document_ref,
        workspace,
    ):
        """
        Attempt storage using a model-visible reference.

        The reference must belong to this gateway instance.
        The underlying TrustGate policy determines whether
        the document may be stored.
        """
        handle = self._resolve_reference(
            document_ref
        )

        if handle is None:
            return ReferenceResult(
                decision="CONFIRM",
                reason="Unknown or foreign document reference",
                executed=False,
            )

        result = await self.store_handle(
            handle,
            workspace,
        )

        return ReferenceResult(
            decision=result.decision,
            reason=result.reason,
            executed=result.executed,
        )
