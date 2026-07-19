"""Tests for review-first memories."""

import tempfile
import unittest

from diaryvault_memory import (
    DraftStatus,
    MemoryDraft,
    MemoryVault,
    SuggestionStatus,
    VaultExporter,
)


class TestMemoryDraft(unittest.TestCase):
    def test_create_draft(self):
        draft = MemoryDraft(
            content=(
                "She laughed when the "
                "dog sneezed."
            ),
            tags=["family"],
        )

        self.assertEqual(
            draft.status,
            DraftStatus.DRAFT,
        )
        self.assertEqual(
            draft.pending_suggestions,
            [],
        )

    def test_suggestion_is_not_confirmed(self):
        draft = MemoryDraft(
            content="A family moment"
        )

        suggestion = draft.add_suggestion(
            field_name="location",
            suggested_value="Seoul",
            source="echo",
            model="example-model",
            process_version="prompt-v1",
            confidence=0.82,
        )

        self.assertEqual(
            suggestion.status,
            SuggestionStatus.PENDING,
        )
        self.assertNotIn(
            "location",
            draft.confirmed_fields,
        )

    def test_accept_suggestion(self):
        draft = MemoryDraft(
            content="A family moment"
        )

        suggestion = draft.add_suggestion(
            "location",
            "Seoul",
            source="echo",
        )

        draft.accept_suggestion(
            suggestion.suggestion_id,
            actor="user-1",
        )

        self.assertEqual(
            suggestion.status,
            SuggestionStatus.ACCEPTED,
        )
        self.assertEqual(
            draft.confirmed_fields[
                "location"
            ],
            "Seoul",
        )

    def test_accept_suggestion_with_edit(self):
        draft = MemoryDraft(
            content="A family moment"
        )

        suggestion = draft.add_suggestion(
            "location",
            "Seoul",
            source="echo",
        )

        draft.accept_suggestion(
            suggestion.suggestion_id,
            actor="user-1",
            value="Seoul Forest",
        )

        self.assertEqual(
            draft.confirmed_fields[
                "location"
            ],
            "Seoul Forest",
        )

    def test_reject_suggestion(self):
        draft = MemoryDraft(
            content="A family moment"
        )

        suggestion = draft.add_suggestion(
            "mood",
            "happy",
            source="echo",
        )

        draft.reject_suggestion(
            suggestion.suggestion_id,
            actor="user-1",
        )

        self.assertEqual(
            suggestion.status,
            SuggestionStatus.REJECTED,
        )
        self.assertNotIn(
            "mood",
            draft.confirmed_fields,
        )

    def test_direct_field_confirmation(self):
        draft = MemoryDraft(
            content="A family moment"
        )

        draft.set_field(
            "content",
            (
                "She laughed when the "
                "dog sneezed."
            ),
            actor="user-1",
        )

        self.assertEqual(
            draft.resolved_fields()[
                "content"
            ],
            (
                "She laughed when the "
                "dog sneezed."
            ),
        )

    def test_approval_requires_review(self):
        draft = MemoryDraft(
            content="A family moment"
        )

        draft.add_suggestion(
            "mood",
            "happy",
            source="echo",
        )

        with self.assertRaises(
            ValueError
        ):
            draft.approve(
                actor="user-1"
            )

    def test_approval_record(self):
        draft = MemoryDraft(
            content="A family moment",
            tags=["family"],
        )

        approval = draft.approve(
            actor="user-1",
            note="Confirmed.",
        )

        self.assertEqual(
            draft.status,
            DraftStatus.APPROVED,
        )
        self.assertEqual(
            approval.actor,
            "user-1",
        )
        self.assertTrue(
            draft.to_review_manifest()[
                "approved"
            ]
        )

    def test_terminal_draft_cannot_change(self):
        draft = MemoryDraft(
            content="A family moment"
        )

        draft.approve(
            actor="user-1"
        )

        with self.assertRaises(
            ValueError
        ):
            draft.set_field(
                "mood",
                "happy",
                actor="user-1",
            )

    def test_confidence_validation(self):
        draft = MemoryDraft(
            content="A family moment"
        )

        with self.assertRaises(
            ValueError
        ):
            draft.add_suggestion(
                "mood",
                "happy",
                source="echo",
                confidence=1.2,
            )

    def test_json_roundtrip(self):
        draft = MemoryDraft(
            content="A family moment",
            tags=["family"],
        )

        suggestion = draft.add_suggestion(
            "mood",
            "happy",
            source="echo",
        )

        draft.accept_suggestion(
            suggestion.suggestion_id,
            actor="user-1",
        )

        draft.approve(
            actor="user-1"
        )

        restored = MemoryDraft.from_json(
            draft.to_json()
        )

        self.assertEqual(
            restored.status,
            DraftStatus.APPROVED,
        )
        self.assertEqual(
            restored.suggestions[0].status,
            SuggestionStatus.ACCEPTED,
        )


class TestVaultReviewWorkflow(
    unittest.TestCase
):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()

        self.vault = MemoryVault(
            encryption_key=(
                "review-workflow-test-key"
            ),
            storage_dir=self.tmpdir,
        )

    def test_create_and_reload_draft(self):
        draft = self.vault.create_draft(
            content="A family moment",
            tags=["family"],
        )

        reloaded = MemoryVault(
            encryption_key=(
                "review-workflow-test-key"
            ),
            storage_dir=self.tmpdir,
        )

        restored = reloaded.get_draft(
            draft.draft_id
        )

        self.assertIsNotNone(restored)
        self.assertEqual(
            restored.content,
            "A family moment",
        )

    def test_full_approval_workflow(self):
        draft = self.vault.create_draft(
            content="A family moment",
            tags=["family"],
            source="quick_capture",
        )

        location = (
            self.vault.add_suggestion(
                draft,
                field_name="location",
                suggested_value="Seoul",
                source="echo",
                model="example-model",
                process_version=(
                    "memory-card-v1"
                ),
                confidence=0.91,
            )
        )

        title = self.vault.add_suggestion(
            draft,
            field_name="title",
            suggested_value=(
                "The first laugh"
            ),
            source="echo",
        )

        self.vault.accept_suggestion(
            draft,
            location.suggestion_id,
            actor="user-1",
            value="Seoul Forest",
        )

        self.vault.reject_suggestion(
            draft,
            title.suggestion_id,
            actor="user-1",
        )

        memory = self.vault.approve_draft(
            draft,
            actor="user-1",
            note="Reviewed.",
        )

        self.assertTrue(
            self.vault.verify(memory)
        )
        self.assertEqual(
            memory.metadata.source,
            "reviewed_draft",
        )
        self.assertTrue(
            memory.metadata.ai_enriched
        )

        review = (
            memory.metadata.custom[
                "review"
            ]
        )

        self.assertTrue(
            review["approved"]
        )
        self.assertEqual(
            review["draft_id"],
            draft.draft_id,
        )
        self.assertEqual(
            review["final_memory_id"],
            memory.id,
        )

    def test_confirmed_content_override(self):
        draft = self.vault.create_draft(
            content="Unfinished text",
            tags=["draft"],
        )

        self.vault.update_draft_field(
            draft,
            "content",
            "Confirmed text",
            actor="user-1",
        )

        self.vault.update_draft_field(
            draft,
            "tags",
            ["family", "confirmed"],
            actor="user-1",
        )

        memory = self.vault.approve_draft(
            draft,
            actor="user-1",
        )

        self.assertEqual(
            memory.content,
            "Confirmed text",
        )
        self.assertEqual(
            memory.metadata.tags,
            ["family", "confirmed"],
        )

    def test_list_drafts_by_status(self):
        first = self.vault.create_draft(
            "First"
        )
        second = self.vault.create_draft(
            "Second"
        )

        self.vault.reject_draft(
            second,
            actor="user-1",
        )

        self.assertIn(
            first,
            self.vault.list_drafts(
                DraftStatus.DRAFT
            ),
        )
        self.assertIn(
            second,
            self.vault.list_drafts(
                "rejected"
            ),
        )

    def test_unknown_draft(self):
        with self.assertRaises(KeyError):
            self.vault.approve_draft(
                "missing",
                actor="user-1",
            )

    def test_approval_aware_exports(self):
        self.vault.create(
            "Legacy memory",
            tags=["family"],
        )

        draft = self.vault.create_draft(
            "Reviewed memory",
            tags=["family"],
        )

        approved = (
            self.vault.approve_draft(
                draft,
                actor="user-1",
            )
        )

        exporter = VaultExporter(
            self.vault
        )

        chunks = exporter.to_rag_chunks(
            approved_only=True
        )

        self.assertEqual(
            len(chunks),
            1,
        )
        self.assertEqual(
            chunks[0].id,
            approved.id,
        )
        self.assertTrue(
            chunks[0].metadata[
                "approved"
            ]
        )

        manifests = (
            exporter.to_approved_manifest()
        )

        self.assertEqual(
            len(manifests),
            1,
        )
        self.assertEqual(
            manifests[0]["memory_id"],
            approved.id,
        )

        summary = exporter.summary(
            approved_only=True
        )

        self.assertEqual(
            summary["total_memories"],
            1,
        )


if __name__ == "__main__":
    unittest.main()
