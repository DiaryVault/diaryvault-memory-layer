"""Tests for approval aware exports."""

import pytest

from diaryvault_memory import MemoryVault, VaultExporter


@pytest.fixture
def vault(tmp_path):
    vault = MemoryVault(
        encryption_key="test-secret",
        storage_dir=str(tmp_path / "vault"),
    )

    vault.create("A plain unreviewed memory.", tags=["daily"])

    draft = vault.create_draft(
        content="She laughed when the dog sneezed.",
        tags=["family"],
    )

    draft = draft.add_suggestion(
        field_name="location",
        value="Seoul",
        source="echo",
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

    draft = draft.approve(reviewer="parent")
    vault.finalize_draft(draft)

    return vault


def _by_reviewed(items, key):
    reviewed = [item for item in items if key(item)["reviewed"]]
    unreviewed = [item for item in items if not key(item)["reviewed"]]
    return reviewed, unreviewed


def test_rag_chunks_carry_review_summary(vault):
    chunks = VaultExporter(vault).to_rag_chunks()

    reviewed, unreviewed = _by_reviewed(
        chunks,
        lambda chunk: chunk.metadata["review"],
    )

    assert len(reviewed) == 1
    assert len(unreviewed) == 1

    info = reviewed[0].metadata["review"]
    assert info["approved_by"] == "parent"
    assert info["approved_at"]
    assert info["suggestion_count"] == 2
    assert info["accepted_count"] == 1
    assert info["confirmed_fields"] == ["location"]

    assert unreviewed[0].metadata["review"] == {"reviewed": False}


def test_generic_jsonl_carries_review_summary(vault):
    examples = VaultExporter(vault).to_jsonl(format="generic")

    reviewed, unreviewed = _by_reviewed(
        examples,
        lambda example: example["review"],
    )

    assert len(reviewed) == 1
    assert len(unreviewed) == 1
    assert reviewed[0]["review"]["confirmed_fields"] == ["location"]


def test_finetune_formats_stay_schema_clean(vault):
    for format in ("openai", "anthropic"):
        examples = VaultExporter(vault).to_jsonl(format=format)

        for example in examples:
            assert "review" not in example


def test_conversation_history_carries_review_summary(vault):
    history = VaultExporter(vault).to_conversation_history()

    reviewed, unreviewed = _by_reviewed(
        history,
        lambda entry: entry["metadata"]["review"],
    )

    assert len(reviewed) == 1
    assert len(unreviewed) == 1


def test_knowledge_graph_memory_nodes_carry_review_summary(vault):
    graph = VaultExporter(vault).to_knowledge_graph(extract_entities=False)

    memory_nodes = [node for node in graph.nodes if node.node_type == "memory"]

    reviewed, unreviewed = _by_reviewed(
        memory_nodes,
        lambda node: node.properties["review"],
    )

    assert len(reviewed) == 1
    assert len(unreviewed) == 1


def test_summary_counts_reviewed_memories(vault):
    summary = VaultExporter(vault).summary()

    assert summary["total_memories"] == 2
    assert summary["reviewed_memories"] == 1
