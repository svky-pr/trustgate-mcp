
from taint import TaintState


def main():

    # Test 1: Fresh session, unknown document.
    state = TaintState()

    result = state.assess_transfer(
        classification=None,
        workspace="external"
    )

    assert result["risk"] == "unknown"
    print("PASS 1: Unknown document remains unknown.")

    # Test 2: Failed confidential read does not taint.
    state.observe_access(
        "read_report",
        "confidential",
        success=False
    )

    assert not state.confidential_context_active
    print("PASS 2: Failed read does not activate taint.")

    # Test 3: Successful confidential read activates taint.
    state.observe_access(
        "read_report",
        "confidential",
        success=True
    )

    assert state.confidential_context_active
    assert "read_report" in state.confidential_sources

    print("PASS 3: Confidential access activates taint.")

    # Test 4: Unknown external transfer after confidential read.
    result = state.assess_transfer(
        classification=None,
        workspace="external"
    )

    assert result["risk"] == "context_tainted"
    print("PASS 4: Unknown transfer is context-tainted.")

    # Test 5: Verified confidential transfer.
    result = state.assess_transfer(
        classification="confidential",
        workspace="external"
    )

    assert result["risk"] == "verified_confidential"
    print("PASS 5: Verified confidentiality takes priority.")

    # Test 6: Verified public document remains public.
    result = state.assess_transfer(
        classification="public",
        workspace="external"
    )

    assert result["risk"] == "verified_public"
    print("PASS 6: Public document is not automatically tainted.")

    # Test 7: Local destination.
    result = state.assess_transfer(
        classification=None,
        workspace="local"
    )

    assert result["risk"] == "low"
    print("PASS 7: Local destination has low transfer risk.")

    print("\nALL STEP 9E TAINT TESTS PASSED")


if __name__ == "__main__":
    main()
