"""Tests for the pure review-domain model."""

from diaryvault_memory.review import (
    DecisionOutcome,
    ReviewDraft,
    ReviewState,
)


def test_new_draft_is_open() -> None:
    draft = ReviewDraft(
        content="A captured family moment",
        tags=("family",),
    )

    assert draft.state is ReviewState.OPEN
    assert draft.pending_suggestion_ids == ()
    assert draft.resolved_fields() == {
        "content": "A captured family moment",
        "tags": ["family"],
    }


def test_suggestion_is_not_confirmed_automatically() -> None:
    draft = ReviewDraft(content="A moment")

    updated = draft.add_suggestion(
        field_name="location",
        value="Seoul",
        source="echo",
        confidence=0.9,
    )

    assert "location" not in draft.resolved_fields()
    assert "location" not in updated.resolved_fields()
    assert len(updated.pending_suggestion_ids) == 1


def test_accept_uses_suggested_value() -> None:
    draft = ReviewDraft(content="A moment").add_suggestion(
        field_name="location",
        value="Seoul",
        source="echo",
        suggestion_id="suggestion-1",
    )

    reviewed = draft.accept(
        "suggestion-1",
        reviewer="parent",
    )

    assert reviewed.resolved_fields()["location"] == "Seoul"
    assert reviewed.decisions[0].outcome is DecisionOutcome.ACCEPTED


def test_accept_can_use_edited_value() -> None:
    draft = ReviewDraft(content="A moment").add_suggestion(
        field_name="location",
        value="Seoul",
        source="echo",
        suggestion_id="suggestion-1",
    )

    reviewed = draft.accept(
        "suggestion-1",
        reviewer="parent",
        value="Seoul Forest",
    )

    assert reviewed.resolved_fields()["location"] == "Seoul Forest"


def test_rejected_suggestion_is_not_resolved() -> None:
    draft = ReviewDraft(content="A moment").add_suggestion(
        field_name="title",
        value="The first laugh",
        source="echo",
        suggestion_id="suggestion-1",
    )

    reviewed = draft.reject_suggestion(
        "suggestion-1",
        reviewer="parent",
    )

    assert "title" not in reviewed.resolved_fields()
    assert reviewed.decisions[0].outcome is DecisionOutcome.REJECTED


def test_original_draft_is_not_mutated() -> None:
    original = ReviewDraft(content="A moment")

    suggested = original.add_suggestion(
        field_name="title",
        value="A title",
        source="echo",
    )

    assert original.suggestions == ()
    assert len(suggested.suggestions) == 1


def test_suggestion_cannot_be_reviewed_twice() -> None:
    draft = ReviewDraft(content="A moment").add_suggestion(
        field_name="title",
        value="A title",
        source="echo",
        suggestion_id="suggestion-1",
    )

    reviewed = draft.accept(
        "suggestion-1",
        reviewer="parent",
    )

    try:
        reviewed.reject_suggestion(
            "suggestion-1",
            reviewer="parent",
        )
    except ValueError as error:
        assert "already been reviewed" in str(error)
    else:
        raise AssertionError("expected ValueError")


def test_only_one_suggestion_can_be_accepted_per_field() -> None:
    draft = ReviewDraft(content="A moment")

    draft = draft.add_suggestion(
        field_name="title",
        value="Title one",
        source="model-a",
        suggestion_id="suggestion-1",
    )

    draft = draft.add_suggestion(
        field_name="title",
        value="Title two",
        source="model-b",
        suggestion_id="suggestion-2",
    )

    reviewed = draft.accept(
        "suggestion-1",
        reviewer="parent",
    )

    try:
        reviewed.accept(
            "suggestion-2",
            reviewer="parent",
        )
    except ValueError as error:
        assert "already accepted" in str(error)
    else:
        raise AssertionError("expected ValueError")


def test_approval_requires_all_suggestions_reviewed() -> None:
    draft = ReviewDraft(content="A moment").add_suggestion(
        field_name="title",
        value="A title",
        source="echo",
    )

    try:
        draft.approve(reviewer="parent")
    except ValueError as error:
        assert "all suggestions" in str(error)
    else:
        raise AssertionError("expected ValueError")


def test_draft_can_be_approved_after_review() -> None:
    draft = ReviewDraft(content="A moment")

    draft = draft.add_suggestion(
        field_name="title",
        value="A title",
        source="echo",
        suggestion_id="suggestion-1",
    )

    draft = draft.accept(
        "suggestion-1",
        reviewer="parent",
    )

    approved = draft.approve(reviewer="parent")

    assert approved.state is ReviewState.APPROVED
    assert approved.completed_by == "parent"
    assert approved.completed_at is not None


def test_terminal_draft_cannot_change() -> None:
    approved = ReviewDraft(content="A moment").approve(reviewer="parent")

    try:
        approved.add_suggestion(
            field_name="title",
            value="A title",
            source="echo",
        )
    except ValueError as error:
        assert "already approved" in str(error)
    else:
        raise AssertionError("expected ValueError")


def test_rejected_draft_is_terminal() -> None:
    rejected = ReviewDraft(content="A moment").reject(reviewer="parent")

    assert rejected.state is ReviewState.REJECTED

    try:
        rejected.approve(reviewer="parent")
    except ValueError as error:
        assert "already rejected" in str(error)
    else:
        raise AssertionError("expected ValueError")


def test_confidence_is_validated() -> None:
    try:
        ReviewDraft(content="A moment").add_suggestion(
            field_name="title",
            value="A title",
            source="echo",
            confidence=1.1,
        )
    except ValueError as error:
        assert "confidence" in str(error)
    else:
        raise AssertionError("expected ValueError")


def test_json_roundtrip_preserves_review_state() -> None:
    draft = ReviewDraft(
        content="A moment",
        tags=("family",),
    )

    draft = draft.add_suggestion(
        field_name="location",
        value="Seoul",
        source="echo",
        model="example-model",
        process_version="prompt-v1",
        suggestion_id="suggestion-1",
    )

    draft = draft.accept(
        "suggestion-1",
        reviewer="parent",
        value="Seoul Forest",
    )

    draft = draft.approve(reviewer="parent")

    restored = ReviewDraft.from_json(draft.to_json())

    assert restored == draft
    assert restored.resolved_fields()["location"] == "Seoul Forest"
