"""Tests for the pure review-domain model."""

import pytest

from diaryvault_memory.review import (
    DecisionOutcome,
    ReviewDecision,
    ReviewDraft,
    ReviewState,
    Suggestion,
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


def test_suggestion_value_is_deeply_immutable() -> None:
    original = ["family"]

    suggestion = Suggestion(
        field_name="tags",
        value=original,
        source="echo",
    )

    original.append("mutated-input")

    assert suggestion.value == ("family",)

    with pytest.raises(AttributeError):
        suggestion.value = ("other",)  # type: ignore[misc]


def test_nested_suggestion_value_is_deeply_immutable() -> None:
    suggestion = Suggestion(
        field_name="metadata",
        value={"people": ["grandma"]},
        source="echo",
    )

    with pytest.raises(TypeError):
        suggestion.value["people"] = []

    assert suggestion.value["people"] == ("grandma",)


def test_resolved_fields_returns_detached_copies() -> None:
    draft = ReviewDraft(content="hello").add_suggestion(
        "metadata",
        {"people": ["grandma"]},
        "echo",
        suggestion_id="suggestion-1",
    )

    draft = draft.accept("suggestion-1", reviewer="parent")

    resolved = draft.resolved_fields()
    resolved["metadata"]["people"].append("mutated-output")

    assert draft.resolved_fields()["metadata"] == {"people": ["grandma"]}


def test_rejected_decision_cannot_carry_accepted_value() -> None:
    with pytest.raises(ValueError):
        ReviewDecision(
            suggestion_id="suggestion-1",
            outcome=DecisionOutcome.REJECTED,
            reviewer="parent",
            accepted_value="stray",
        )


def test_from_dict_rejects_approved_draft_with_pending_suggestions() -> None:
    draft = ReviewDraft(content="hello").add_suggestion(
        "title",
        "First laugh",
        "echo",
    )

    data = draft.to_dict()
    data["state"] = "approved"
    data["completed_by"] = "parent"
    data["completed_at"] = draft.created_at

    with pytest.raises(ValueError):
        ReviewDraft.from_dict(data)


def test_from_dict_rejects_terminal_draft_without_completion_metadata() -> None:
    draft = ReviewDraft(content="hello")

    data = draft.to_dict()
    data["state"] = "rejected"

    with pytest.raises(ValueError):
        ReviewDraft.from_dict(data)


def test_from_dict_rejects_open_draft_with_completion_metadata() -> None:
    draft = ReviewDraft(content="hello")

    data = draft.to_dict()
    data["completed_by"] = "parent"

    with pytest.raises(ValueError):
        ReviewDraft.from_dict(data)


def test_from_dict_rejects_decision_for_unknown_suggestion() -> None:
    draft = ReviewDraft(content="hello").add_suggestion(
        "title",
        "First laugh",
        "echo",
        suggestion_id="suggestion-1",
    )

    draft = draft.accept("suggestion-1", reviewer="parent")

    data = draft.to_dict()
    data["decisions"][0]["suggestion_id"] = "ghost"

    with pytest.raises(ValueError):
        ReviewDraft.from_dict(data)


def test_from_dict_rejects_duplicate_suggestion_ids() -> None:
    draft = ReviewDraft(content="hello").add_suggestion(
        "title",
        "First laugh",
        "echo",
        suggestion_id="suggestion-1",
    )

    data = draft.to_dict()
    data["suggestions"].append(dict(data["suggestions"][0]))

    with pytest.raises(ValueError):
        ReviewDraft.from_dict(data)


def test_from_dict_rejects_second_decision_for_same_suggestion() -> None:
    draft = ReviewDraft(content="hello").add_suggestion(
        "title",
        "First laugh",
        "echo",
        suggestion_id="suggestion-1",
    )

    draft = draft.accept("suggestion-1", reviewer="parent")

    data = draft.to_dict()
    data["decisions"].append(dict(data["decisions"][0]))

    with pytest.raises(ValueError):
        ReviewDraft.from_dict(data)


def test_from_dict_rejects_two_accepted_values_for_one_field() -> None:
    draft = (
        ReviewDraft(content="hello")
        .add_suggestion(
            "title",
            "First laugh",
            "echo",
            suggestion_id="suggestion-1",
        )
        .add_suggestion(
            "title",
            "The giggle",
            "echo",
            suggestion_id="suggestion-2",
        )
    )

    draft = draft.accept("suggestion-1", reviewer="parent")

    data = draft.to_dict()
    data["decisions"].append(
        {
            "suggestion_id": "suggestion-2",
            "outcome": "accepted",
            "reviewer": "parent",
            "accepted_value": "The giggle",
            "decided_at": draft.created_at,
        }
    )

    with pytest.raises(ValueError):
        ReviewDraft.from_dict(data)


def test_json_roundtrip_preserves_nested_values() -> None:
    draft = ReviewDraft(content="hello").add_suggestion(
        "metadata",
        {"people": ["grandma"], "weather": "sunny"},
        "echo",
        suggestion_id="suggestion-1",
    )

    draft = draft.accept("suggestion-1", reviewer="parent")
    restored = ReviewDraft.from_json(draft.to_json())

    assert restored == draft
    assert restored.resolved_fields()["metadata"] == {
        "people": ["grandma"],
        "weather": "sunny",
    }


def test_tags_must_be_a_sequence_of_strings() -> None:
    with pytest.raises(TypeError):
        ReviewDraft(content="hello", tags="family")  # type: ignore[arg-type]

    with pytest.raises(ValueError):
        ReviewDraft(content="hello", tags=("family", ""))
