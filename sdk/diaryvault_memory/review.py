"""Review-first memory drafts, suggestions, and approvals."""

from __future__ import annotations

import json
import uuid
from copy import deepcopy
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class DraftStatus(str, Enum):
    """Lifecycle state for a reviewable memory draft."""

    DRAFT = "draft"
    IN_REVIEW = "in_review"
    APPROVED = "approved"
    REJECTED = "rejected"


class SuggestionStatus(str, Enum):
    """Review state for an individual suggestion."""

    PENDING = "pending"
    ACCEPTED = "accepted"
    REJECTED = "rejected"


@dataclass
class MemorySuggestion:
    """A proposed field value that remains unconfirmed until reviewed."""

    field_name: str
    suggested_value: Any
    source: str
    model: Optional[str] = None
    process_version: Optional[str] = None
    confidence: Optional[float] = None
    rationale: Optional[str] = None
    suggestion_id: str = field(
        default_factory=lambda: str(uuid.uuid4())
    )
    status: SuggestionStatus = SuggestionStatus.PENDING
    created_at: str = field(default_factory=_now)
    reviewed_at: Optional[str] = None
    reviewed_by: Optional[str] = None
    accepted_value: Any = None

    def __post_init__(self) -> None:
        if not self.field_name.strip():
            raise ValueError("field_name must not be empty")

        if not self.source.strip():
            raise ValueError("source must not be empty")

        if (
            self.confidence is not None
            and not 0 <= self.confidence <= 1
        ):
            raise ValueError(
                "confidence must be between 0 and 1"
            )

    def accept(
        self,
        actor: str,
        value: Any = None,
    ) -> Any:
        """Accept the suggestion, optionally with an edited value."""
        if self.status is not SuggestionStatus.PENDING:
            raise ValueError(
                "suggestion has already been reviewed"
            )

        if not actor.strip():
            raise ValueError("actor must not be empty")

        self.status = SuggestionStatus.ACCEPTED
        self.reviewed_at = _now()
        self.reviewed_by = actor
        self.accepted_value = (
            deepcopy(self.suggested_value)
            if value is None
            else deepcopy(value)
        )

        return deepcopy(self.accepted_value)

    def reject(self, actor: str) -> None:
        """Reject the suggestion."""
        if self.status is not SuggestionStatus.PENDING:
            raise ValueError(
                "suggestion has already been reviewed"
            )

        if not actor.strip():
            raise ValueError("actor must not be empty")

        self.status = SuggestionStatus.REJECTED
        self.reviewed_at = _now()
        self.reviewed_by = actor
        self.accepted_value = None

    def to_dict(self) -> dict:
        data = asdict(self)
        data["status"] = self.status.value
        return data

    @classmethod
    def from_dict(
        cls,
        data: dict,
    ) -> "MemorySuggestion":
        payload = deepcopy(data)
        status = payload.get(
            "status",
            SuggestionStatus.PENDING,
        )

        if isinstance(status, str):
            payload["status"] = SuggestionStatus(status)

        return cls(**payload)


@dataclass
class DraftRevision:
    """Append-only audit entry for a draft review action."""

    action: str
    actor: str
    field_name: Optional[str] = None
    previous_value: Any = None
    new_value: Any = None
    suggestion_id: Optional[str] = None
    note: Optional[str] = None
    revision_id: str = field(
        default_factory=lambda: str(uuid.uuid4())
    )
    created_at: str = field(default_factory=_now)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "DraftRevision":
        return cls(**deepcopy(data))


@dataclass
class ApprovalRecord:
    """Explicit approval of final confirmed draft fields."""

    actor: str
    confirmed_fields: dict
    note: Optional[str] = None
    approval_id: str = field(
        default_factory=lambda: str(uuid.uuid4())
    )
    approved_at: str = field(default_factory=_now)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "ApprovalRecord":
        return cls(**deepcopy(data))


@dataclass
class MemoryDraft:
    """A reviewable memory with suggestions separated from truth."""

    content: str
    tags: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)
    source: str = "manual"
    draft_id: str = field(
        default_factory=lambda: str(uuid.uuid4())
    )
    status: DraftStatus = DraftStatus.DRAFT
    suggestions: list[MemorySuggestion] = field(
        default_factory=list
    )
    confirmed_fields: dict = field(default_factory=dict)
    revisions: list[DraftRevision] = field(
        default_factory=list
    )
    approval: Optional[ApprovalRecord] = None
    final_memory_id: Optional[str] = None
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)

    def __post_init__(self) -> None:
        if not isinstance(self.content, str):
            raise TypeError("content must be a string")

        if not self.source.strip():
            raise ValueError("source must not be empty")

    @property
    def pending_suggestions(
        self,
    ) -> list[MemorySuggestion]:
        return [
            suggestion
            for suggestion in self.suggestions
            if suggestion.status
            is SuggestionStatus.PENDING
        ]

    @property
    def is_terminal(self) -> bool:
        return self.status in {
            DraftStatus.APPROVED,
            DraftStatus.REJECTED,
        }

    def add_suggestion(
        self,
        field_name: str,
        suggested_value: Any,
        source: str,
        model: Optional[str] = None,
        process_version: Optional[str] = None,
        confidence: Optional[float] = None,
        rationale: Optional[str] = None,
    ) -> MemorySuggestion:
        """Attach an unconfirmed suggestion to the draft."""
        self._require_editable()

        suggestion = MemorySuggestion(
            field_name=field_name,
            suggested_value=deepcopy(
                suggested_value
            ),
            source=source,
            model=model,
            process_version=process_version,
            confidence=confidence,
            rationale=rationale,
        )

        self.suggestions.append(suggestion)
        self.status = DraftStatus.IN_REVIEW

        self._record(
            action="suggestion_added",
            actor=source,
            field_name=field_name,
            new_value=suggested_value,
            suggestion_id=suggestion.suggestion_id,
        )

        return suggestion

    def accept_suggestion(
        self,
        suggestion_id: str,
        actor: str,
        value: Any = None,
        note: Optional[str] = None,
    ) -> MemorySuggestion:
        """Accept a suggestion into confirmed fields."""
        self._require_editable()

        suggestion = self.get_suggestion(
            suggestion_id
        )

        previous = deepcopy(
            self.confirmed_fields.get(
                suggestion.field_name
            )
        )

        accepted = suggestion.accept(
            actor=actor,
            value=value,
        )

        self.confirmed_fields[
            suggestion.field_name
        ] = deepcopy(accepted)

        self._record(
            action="suggestion_accepted",
            actor=actor,
            field_name=suggestion.field_name,
            previous_value=previous,
            new_value=accepted,
            suggestion_id=suggestion.suggestion_id,
            note=note,
        )

        return suggestion

    def reject_suggestion(
        self,
        suggestion_id: str,
        actor: str,
        note: Optional[str] = None,
    ) -> MemorySuggestion:
        """Reject a suggestion without confirming its value."""
        self._require_editable()

        suggestion = self.get_suggestion(
            suggestion_id
        )

        suggestion.reject(actor=actor)

        self._record(
            action="suggestion_rejected",
            actor=actor,
            field_name=suggestion.field_name,
            previous_value=suggestion.suggested_value,
            suggestion_id=suggestion.suggestion_id,
            note=note,
        )

        return suggestion

    def set_field(
        self,
        field_name: str,
        value: Any,
        actor: str,
        note: Optional[str] = None,
    ) -> None:
        """Explicitly confirm or edit a field."""
        self._require_editable()

        if not field_name.strip():
            raise ValueError(
                "field_name must not be empty"
            )

        if not actor.strip():
            raise ValueError(
                "actor must not be empty"
            )

        previous = deepcopy(
            self.confirmed_fields.get(field_name)
        )

        self.confirmed_fields[
            field_name
        ] = deepcopy(value)

        self.status = DraftStatus.IN_REVIEW

        self._record(
            action="field_confirmed",
            actor=actor,
            field_name=field_name,
            previous_value=previous,
            new_value=value,
            note=note,
        )

    def approve(
        self,
        actor: str,
        note: Optional[str] = None,
    ) -> ApprovalRecord:
        """Explicitly approve all resolved draft fields."""
        self._require_editable()

        if not actor.strip():
            raise ValueError(
                "actor must not be empty"
            )

        if self.pending_suggestions:
            raise ValueError(
                "all suggestions must be accepted "
                "or rejected"
            )

        confirmed = self.resolved_fields()

        approval = ApprovalRecord(
            actor=actor,
            confirmed_fields=deepcopy(confirmed),
            note=note,
        )

        self.approval = approval
        self.status = DraftStatus.APPROVED

        self._record(
            action="draft_approved",
            actor=actor,
            new_value=confirmed,
            note=note,
        )

        return approval

    def reject(
        self,
        actor: str,
        note: Optional[str] = None,
    ) -> None:
        """Reject the entire draft."""
        self._require_editable()

        if not actor.strip():
            raise ValueError(
                "actor must not be empty"
            )

        self.status = DraftStatus.REJECTED

        self._record(
            action="draft_rejected",
            actor=actor,
            note=note,
        )

    def resolved_fields(self) -> dict:
        """Return base fields plus confirmed overrides."""
        resolved = {
            "content": self.content,
            "tags": list(self.tags),
            "metadata": deepcopy(self.metadata),
        }

        resolved.update(
            deepcopy(self.confirmed_fields)
        )

        return resolved

    def get_suggestion(
        self,
        suggestion_id: str,
    ) -> MemorySuggestion:
        for suggestion in self.suggestions:
            if (
                suggestion.suggestion_id
                == suggestion_id
            ):
                return suggestion

        raise KeyError(
            f"unknown suggestion: {suggestion_id}"
        )

    def to_review_manifest(self) -> dict:
        """Return provenance for a finalized memory."""
        return {
            "review_version": "1.0",
            "draft_id": self.draft_id,
            "approved": (
                self.status
                is DraftStatus.APPROVED
            ),
            "status": self.status.value,
            "source": self.source,
            "approval": (
                self.approval.to_dict()
                if self.approval
                else None
            ),
            "suggestions": [
                item.to_dict()
                for item in self.suggestions
            ],
            "revisions": [
                item.to_dict()
                for item in self.revisions
            ],
            "confirmed_fields": deepcopy(
                self.confirmed_fields
            ),
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "final_memory_id": (
                self.final_memory_id
            ),
        }

    def to_dict(self) -> dict:
        data = asdict(self)
        data["status"] = self.status.value
        data["suggestions"] = [
            item.to_dict()
            for item in self.suggestions
        ]
        data["revisions"] = [
            item.to_dict()
            for item in self.revisions
        ]
        data["approval"] = (
            self.approval.to_dict()
            if self.approval
            else None
        )
        return data

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            indent=2,
            default=str,
        )

    @classmethod
    def from_dict(
        cls,
        data: dict,
    ) -> "MemoryDraft":
        payload = deepcopy(data)

        status = payload.get(
            "status",
            DraftStatus.DRAFT,
        )

        if isinstance(status, str):
            payload["status"] = DraftStatus(status)

        payload["suggestions"] = [
            MemorySuggestion.from_dict(item)
            if isinstance(item, dict)
            else item
            for item in payload.get(
                "suggestions",
                [],
            )
        ]

        payload["revisions"] = [
            DraftRevision.from_dict(item)
            if isinstance(item, dict)
            else item
            for item in payload.get(
                "revisions",
                [],
            )
        ]

        approval = payload.get("approval")

        if isinstance(approval, dict):
            payload["approval"] = (
                ApprovalRecord.from_dict(
                    approval
                )
            )

        return cls(**payload)

    @classmethod
    def from_json(
        cls,
        json_str: str,
    ) -> "MemoryDraft":
        return cls.from_dict(
            json.loads(json_str)
        )

    def _record(
        self,
        action: str,
        actor: str,
        field_name: Optional[str] = None,
        previous_value: Any = None,
        new_value: Any = None,
        suggestion_id: Optional[str] = None,
        note: Optional[str] = None,
    ) -> None:
        self.updated_at = _now()

        self.revisions.append(
            DraftRevision(
                action=action,
                actor=actor,
                field_name=field_name,
                previous_value=deepcopy(
                    previous_value
                ),
                new_value=deepcopy(
                    new_value
                ),
                suggestion_id=suggestion_id,
                note=note,
            )
        )

    def _require_editable(self) -> None:
        if self.is_terminal:
            raise ValueError(
                f"draft is already "
                f"{self.status.value}"
            )
