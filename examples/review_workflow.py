"""
DiaryVault review workflow example.

Demonstrates the pure review domain model:

* AI suggestions are unconfirmed by default
* Users accept, edit, or reject each suggestion explicitly
* Approval requires every suggestion to be reviewed
* Drafts serialize to JSON and back without losing review state

This example does not persist anything and does not create final
Memory objects. Persistence and finalization arrive in a later
release.
"""

from diaryvault_memory import ReviewDraft


def main() -> None:
    draft = ReviewDraft(
        content="She laughed when the dog sneezed.",
        tags=("family",),
    )

    draft = draft.add_suggestion(
        field_name="location",
        value="Seoul",
        source="echo",
        model="example-model",
        confidence=0.88,
        suggestion_id="suggestion-location",
    )

    draft = draft.add_suggestion(
        field_name="title",
        value="The first laugh",
        source="echo",
        suggestion_id="suggestion-title",
    )

    print("State:", draft.state.value)
    print("Pending:", draft.pending_suggestion_ids)

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

    print("State:", draft.state.value)
    print("Resolved fields:", draft.resolved_fields())

    restored = ReviewDraft.from_json(draft.to_json())

    print("Round trip equal:", restored == draft)


if __name__ == "__main__":
    main()
