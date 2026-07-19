"""Reviewable memory workflow example."""

from tempfile import TemporaryDirectory

from diaryvault_memory import (
    MemoryVault,
    VaultExporter,
)


def main() -> None:
    with TemporaryDirectory() as storage:
        vault = MemoryVault(
            encryption_key="example-secret",
            storage_dir=storage,
        )

        draft = vault.create_draft(
            content=(
                "She laughed when the "
                "dog sneezed."
            ),
            tags=["family"],
            source="quick_capture",
        )

        location = vault.add_suggestion(
            draft,
            field_name="location",
            suggested_value="Seoul",
            source="echo",
            model="example-model",
            process_version="memory-card-v1",
            confidence=0.88,
        )

        title = vault.add_suggestion(
            draft,
            field_name="title",
            suggested_value=(
                "The first laugh"
            ),
            source="echo",
        )

        vault.accept_suggestion(
            draft,
            location.suggestion_id,
            actor="user",
            value="Seoul Forest",
        )

        vault.reject_suggestion(
            draft,
            title.suggestion_id,
            actor="user",
        )

        memory = vault.approve_draft(
            draft,
            actor="user",
            note="Reviewed and confirmed.",
        )

        exporter = VaultExporter(vault)

        print(memory.content)
        print(
            memory.metadata.custom[
                "review"
            ]["approved"]
        )
        print(
            exporter.to_approved_manifest()
        )


if __name__ == "__main__":
    main()
