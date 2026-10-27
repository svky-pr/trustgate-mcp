
import hashlib

from tracker import ActivityTracker


class ProvenanceMiddleware:
    """
    Trusted provenance middleware for MCP tool executions.

    Features:
    - SHA-256 content fingerprinting
    - Exact document matching
    - Data classification tracking
    - Parent-child lineage tracking
    - Confidentiality inheritance
    - Safe provenance diagnostics

    Important:
    Provenance is registered by trusted application code,
    not by the LLM.
    """

    def __init__(self, tracker: ActivityTracker):
        self.tracker = tracker

        # Maps content fingerprints to registered data IDs.
        self.fingerprints = {}

        # Generates unique data IDs within this session.
        self.counter = 0

    # ========================================================
    # CONTENT FINGERPRINTING
    # ========================================================

    @staticmethod
    def fingerprint(content):
        """
        Generate a SHA-256 fingerprint of document content.

        Returns None if content is not a string.
        """

        if not isinstance(content, str):
            return None

        return hashlib.sha256(
            content.encode("utf-8")
        ).hexdigest()

    # ========================================================
    # PROVENANCE RESOLUTION
    # ========================================================

    def resolve(self, content):
        """
        Find the registered data ID for exact document content.

        This does not perform semantic or fuzzy matching.
        """

        digest = self.fingerprint(content)

        if digest is None:
            return None

        return self.fingerprints.get(digest)

    # ========================================================
    # STEP 9D: PROVENANCE DIAGNOSTICS
    # ========================================================

    def diagnose(self, content):
        """
        Return provenance diagnostics without exposing
        the document contents.

        Used by test_llm_provenance.py and attack_suite.py.
        """

        if not isinstance(content, str):
            return {
                "length": None,
                "exact_match": False,
                "data_id": None,
                "classification": "unknown"
            }

        data_id = self.resolve(content)

        classification = (
            self.tracker.get_classification(data_id)
            if data_id is not None
            else "unknown"
        )

        return {
            "length": len(content),
            "exact_match": data_id is not None,
            "data_id": data_id,
            "classification": classification
        }

    # ========================================================
    # REGISTER DATA AND LINEAGE
    # ========================================================

    def register(
        self,
        content,
        source_tool,
        classification="public",
        parents=None
    ):
        """
        Register content observed by trusted middleware.

        If any parent is confidential, the registered child
        inherits the confidential classification.

        If identical content already exists, reuse its data ID
        and incorporate newly verified parent relationships.
        """

        if not isinstance(content, str):
            raise ValueError(
                "Content must be a string."
            )

        if classification not in (
            "public",
            "confidential"
        ):
            raise ValueError(
                f"Invalid classification: {classification}"
            )

        parents = list(parents or [])

        # Verify that all parent records exist.
        for parent_id in parents:
            if parent_id not in self.tracker.data_registry:
                raise ValueError(
                    f"Unknown parent data ID: {parent_id}"
                )

        digest = self.fingerprint(content)

        # ====================================================
        # EXISTING CONTENT
        # ====================================================

        if digest in self.fingerprints:

            data_id = self.fingerprints[digest]

            record = self.tracker.data_registry[data_id]

            # Add newly verified parent relationships.
            for parent_id in parents:

                # Avoid direct self-references.
                if parent_id == data_id:
                    continue

                # Avoid cycles in the lineage graph.
                if data_id in self.tracker.get_lineage(
                    parent_id
                ):
                    raise ValueError(
                        "Provenance cycle detected."
                    )

                if parent_id not in record["parents"]:
                    record["parents"].append(
                        parent_id
                    )

            # Upgrade classification if necessary.
            if classification == "confidential":
                record["classification"] = (
                    "confidential"
                )

            # Inherit confidentiality from parents.
            for parent_id in record["parents"]:

                parent_classification = (
                    self.tracker.get_classification(
                        parent_id
                    )
                )

                if (
                    parent_classification
                    == "confidential"
                ):
                    record["classification"] = (
                        "confidential"
                    )
                    break

            return data_id

        # ====================================================
        # NEW CONTENT
        # ====================================================

        self.counter += 1

        data_id = f"data_{self.counter:04d}"

        self.tracker.register_data(
            data_id=data_id,
            source_tool=source_tool,
            classification=classification,
            parents=parents
        )

        self.fingerprints[digest] = data_id

        return data_id

    # ========================================================
    # OBSERVE SUCCESSFUL MCP TOOL EXECUTION
    # ========================================================

    def observe_result(
        self,
        tool_name,
        arguments,
        output
    ):
        """
        Register data returned by a successful MCP tool call.

        IMPORTANT:
        The caller must verify that the MCP execution succeeded
        before calling this method.

        The LLM must not directly invoke this method.
        """

        # ====================================================
        # CONFIDENTIAL REPORT
        # ====================================================

        if tool_name == "read_report":

            return self.register(
                content=output,
                source_tool="read_report",
                classification="confidential"
            )

        # ====================================================
        # PUBLIC NOTICE
        # ====================================================

        if tool_name == "read_public_notice":

            return self.register(
                content=output,
                source_tool="read_public_notice",
                classification="public"
            )

        # ====================================================
        # SUMMARY DERIVED FROM A REPORT
        # ====================================================

        if tool_name == "summarize_report":

            input_text = arguments.get(
                "report"
            )

            parent_id = self.resolve(
                input_text
            )

            # Do not claim verified provenance if the input
            # does not match previously registered content.
            if parent_id is None:

                print(
                    "[PROVENANCE] Summary input "
                    "does not exactly match "
                    "registered content."
                )

                return None

            # Register summary as a derivative of its parent.
            # Classification inheritance happens in register().
            return self.register(
                content=output,
                source_tool="summarize_report",
                classification="public",
                parents=[parent_id]
            )

        # Other tools are not automatically registered.
        return None
