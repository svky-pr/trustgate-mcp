
from dataclasses import dataclass, field


@dataclass
class TaintState:
    """
    Tracks whether confidential information has been
    accessed during the current agent session.

    This is session-level risk context, not proof
    of document-level information flow.
    """

    confidential_context_active: bool = False
    confidential_sources: set = field(
        default_factory=set
    )

    def observe_access(
        self,
        tool_name,
        classification,
        success=True
    ):
        """
        Mark the session as sensitive only after a
        successful confidential-data access.
        """

        if (
            success
            and classification == "confidential"
        ):
            self.confidential_context_active = True
            self.confidential_sources.add(tool_name)

    def assess_transfer(
        self,
        classification,
        workspace
    ):
        """
        Return a contextual risk assessment.

        Exact confidential classification takes
        precedence over session-level taint.
        """

        if workspace == "local":
            return {
                "risk": "low",
                "reason": "Local workspace."
            }

        if classification == "confidential":
            return {
                "risk": "verified_confidential",
                "reason": (
                    "Document is verified confidential."
                )
            }

        if classification == "public":
            return {
                "risk": "verified_public",
                "reason": (
                    "Document is registered as public."
                )
            }

        if self.confidential_context_active:
            return {
                "risk": "context_tainted",
                "reason": (
                    "Confidential information was accessed "
                    "earlier in this session, but the "
                    "proposed document's origin is unverified."
                )
            }

        return {
            "risk": "unknown",
            "reason": (
                "Document provenance is unverified."
            )
        }
