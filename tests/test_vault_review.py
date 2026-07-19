"""Tests for review draft persistence and finalization in the vault."""

import json

import pytest

from diaryvault_memory import MemoryVault, ReviewState


@pytest.fixture
def vault(tmp_path):
    return MemoryVault(
        encryption_key="test-secret",
        storage_dir=str(tmp_path / "vault"),
    )


def _reviewed_draft(vault):
    draft = vault.create_draft(
        content="She laughed when the dog sneezed.",
        tags=["family"],
    )

    draft = draft.add_suggestion(
        field_name="location",
        value="Seoul",
        source="echo",
        confidence=0.9,
        suggestion_id="suggestion-location",
    )

    draft = draft.add_suggestion(
        field_name="title",
        value="The first laugh",
        source="echo",
        suggestion_id="suggestion-title",
    )

    draft = draft.accept(
        "suggestion-location",
        reviewer="parent",
        value="Seoul Forest",
    )

    draft = draft.reject_suggestion(
        "suggestion-title",
        reviewer="parent",
    )

    return vault.save_draft(draft)


def test_create_draft_persists_and_reloads(vault, tmp_path):
    draft = vault.create_draft("A moment", tags=["family"])

    assert draft.state is ReviewState.OPEN
    assert vault.get_draft(draft.draft_id) == draft

    reopened = MemoryVault(
        encryption_key="test-secret",
        storage_dir=str(tmp_path / "vault"),
    )

    assert reopened.get_draft(draft.draft_id) == draft


def test_save_draft_replaces_record(vault):
    draft = vault.create_draft("A moment")

    updated = draft.add_suggestion(
        field_name="title",
        value="A title",
        source="echo",
    )

    vault.save_draft(updated)

    assert vault.get_draft(draft.draft_id) == updated


def test_save_draft_rejects_non_draft(vault):
    with pytest.raises(TypeError):
        vault.save_draft("not a draft")


def test_get_draft_returns_none_for_unknown(vault):
    assert vault.get_draft("missing") is None


def test_list_drafts_filters_by_state(vault):
    open_draft = vault.create_draft("Open moment")

    approved = vault.create_draft("Approved moment").approve(
        reviewer="parent",
    )
    vault.save_draft(approved)

    all_drafts = vault.list_drafts()
    assert {d.draft_id for d in all_drafts} == {
        open_draft.draft_id,
        approved.draft_id,
    }

    open_only = vault.list_drafts(state=ReviewState.OPEN)
    assert [d.draft_id for d in open_only] == [open_draft.draft_id]

    approved_only = vault.list_drafts(state=ReviewState.APPROVED)
    assert [d.draft_id for d in approved_only] == [approved.draft_id]


def test_delete_draft(vault):
    draft = vault.create_draft("A moment")

    assert vault.delete_draft(draft.draft_id) is True
    assert vault.get_draft(draft.draft_id) is None
    assert vault.delete_draft(draft.draft_id) is False


def test_finalize_requires_saved_draft(vault):
    with pytest.raises(ValueError):
        vault.finalize_draft("missing")


def test_finalize_requires_approval(vault):
    draft = vault.create_draft("A moment")

    with pytest.raises(ValueError):
        vault.finalize_draft(draft.draft_id)

    rejected = draft.reject(reviewer="parent")
    vault.save_draft(rejected)

    with pytest.raises(ValueError):
        vault.finalize_draft(draft.draft_id)


def test_finalize_creates_verified_memory_with_provenance(vault):
    draft = _reviewed_draft(vault)
    draft = draft.approve(reviewer="parent")

    memory = vault.finalize_draft(draft)

    assert memory.content == "She laughed when the dog sneezed."
    assert memory.metadata.tags == ["family"]
    assert memory.metadata.location == "Seoul Forest"
    assert memory.metadata.source == "review"
    assert memory.metadata.ai_enriched is True

    review = memory.metadata.custom["review"]
    assert review["draft_id"] == draft.draft_id
    assert review["state"] == "approved"
    assert review["completed_by"] == "parent"
    assert len(review["suggestions"]) == 2
    assert len(review["decisions"]) == 2

    assert vault.verify(memory)
    assert vault.get(memory.id) is not None
    assert vault.finalized_memory_id(draft.draft_id) == memory.id


def test_finalize_without_accepted_suggestions_is_not_ai_enriched(vault):
    draft = vault.create_draft("A plain moment", tags=["family"])
    draft = draft.approve(reviewer="parent")

    memory = vault.finalize_draft(draft)

    assert memory.metadata.ai_enriched is False
    assert memory.metadata.location is None
    assert "confirmed_fields" not in memory.metadata.custom


def test_extra_confirmed_fields_are_stored(vault):
    draft = vault.create_draft("A moment")

    draft = draft.add_suggestion(
        field_name="title",
        value="A title",
        source="echo",
        suggestion_id="suggestion-title",
    )

    draft = draft.accept("suggestion-title", reviewer="parent")
    draft = draft.approve(reviewer="parent")

    memory = vault.finalize_draft(draft)

    assert memory.metadata.custom["confirmed_fields"] == {
        "title": "A title",
    }


def test_finalize_twice_is_rejected(vault):
    draft = _reviewed_draft(vault)
    draft = draft.approve(reviewer="parent")

    memory = vault.finalize_draft(draft)

    with pytest.raises(ValueError) as error:
        vault.finalize_draft(draft.draft_id)

    assert memory.id in str(error.value)


def test_finalized_draft_cannot_be_replaced_or_deleted(vault):
    draft = _reviewed_draft(vault)
    draft = draft.approve(reviewer="parent")

    vault.finalize_draft(draft)

    with pytest.raises(ValueError):
        vault.save_draft(draft)

    with pytest.raises(ValueError):
        vault.delete_draft(draft.draft_id)


def test_finalization_survives_reload(vault, tmp_path):
    draft = _reviewed_draft(vault)
    draft = draft.approve(reviewer="parent")

    memory = vault.finalize_draft(draft)

    reopened = MemoryVault(
        encryption_key="test-secret",
        storage_dir=str(tmp_path / "vault"),
    )

    assert reopened.finalized_memory_id(draft.draft_id) == memory.id
    assert reopened.get(memory.id) is not None
    assert reopened.verify(reopened.get(memory.id))

    with pytest.raises(ValueError):
        reopened.finalize_draft(draft.draft_id)


def test_corrupt_draft_files_are_skipped(vault, tmp_path):
    vault.create_draft("A valid moment")

    drafts_dir = tmp_path / "vault" / "drafts"
    (drafts_dir / "broken.json").write_text("{not json", encoding="utf-8")

    invalid = {
        "draft_record_version": "1.0",
        "draft": {"draft_id": "x"},
        "finalized_memory_id": None,
    }
    (drafts_dir / "invalid.json").write_text(
        json.dumps(invalid),
        encoding="utf-8",
    )

    reopened = MemoryVault(
        encryption_key="test-secret",
        storage_dir=str(tmp_path / "vault"),
    )

    assert len(reopened.list_drafts()) == 1


def test_drafts_do_not_leak_into_memories(vault):
    vault.create_draft("A draft moment")

    assert len(vault) == 0
    assert vault.list_drafts()
    assert vault.list() == []
