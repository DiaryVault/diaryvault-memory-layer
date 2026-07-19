"""Pure review-domain objects for AI-suggested memories.

This module does not persist drafts, create final Memory objects, or
modify MemoryVault. It only models suggestions, decisions, and explicit
approval as immutable value objects.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from types import MappingProxyType
from typing import Any


__all__ = [
    "DecisionOutcome",
    "ReviewDecision",
    "ReviewDraft",
    "ReviewState",
    "Revision",
    "Suggestion",
]


_UNSET = object()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _require_text(value: str, name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must not be empty")


def _freeze(value: Any) -> Any:
    """Recursively convert JSON-style values into immutable containers."""
    if isinstance(value, (dict, MappingProxyType)):
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})

    if isinstance(value, (list, tuple)):
        return tuple(_freeze(item) for item in value)

    return value


def _thaw(value: Any) -> Any:
    """Recursively convert frozen values back into plain JSON-style values."""
    if isinstance(value, (dict, MappingProxyType)):
        return {key: _thaw(item) for key, item in value.items()}

    if isinstance(value, (list, tuple)):
        return [_thaw(item) for item in value]

    return value


class ReviewState(str, Enum):
    """Lifecycle state for a review draft."""

    OPEN = "open"
    APPROVED = "approved"
    REJECTED = "rejected"


class DecisionOutcome(str, Enum):
    """Outcome of reviewing one suggestion."""

    ACCEPTED = "accepted"
    REJECTED = "rejected"


@dataclass(frozen=True)
class Revision:
    """A derived, read-only event in a draft's review history.

    Revisions are not stored. They are computed from the suggestions,
    decisions, and completion metadata a draft already carries, so the
    history cannot drift from the record it describes.
    """

    action: str
    occurred_at: str
    actor: str | None = None
    field_name: str | None = None
    value: Any = None
    suggestion_id: str | None = None

    def __post_init__(self) -> None:
        _require_text(self.action, "action")
        _require_text(self.occurred_at, "occurred_at")

        object.__setattr__(
            self,
            "value",
            _freeze(self.value),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "occurred_at": self.occurred_at,
            "actor": self.actor,
            "field_name": self.field_name,
            "value": _thaw(self.value),
            "suggestion_id": self.suggestion_id,
        }


@dataclass(frozen=True)
class Suggestion:
    """An unconfirmed value proposed for one memory field."""

    field_name: str
    value: Any
    source: str
    suggestion_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    model: str | None = None
    process_version: str | None = None
    confidence: float | None = None
    created_at: str = field(default_factory=_utc_now)

    def __post_init__(self) -> None:
        _require_text(self.field_name, "field_name")
        _require_text(self.source, "source")
        _require_text(self.suggestion_id, "suggestion_id")

        if self.confidence is not None and not 0 <= self.confidence <= 1:
            raise ValueError("confidence must be between 0 and 1")

        object.__setattr__(
            self,
            "value",
            _freeze(self.value),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "suggestion_id": self.suggestion_id,
            "field_name": self.field_name,
            "value": _thaw(self.value),
            "source": self.source,
            "model": self.model,
            "process_version": self.process_version,
            "confidence": self.confidence,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Suggestion":
        return cls(
            suggestion_id=data["suggestion_id"],
            field_name=data["field_name"],
            value=data["value"],
            source=data["source"],
            model=data.get("model"),
            process_version=data.get("process_version"),
            confidence=data.get("confidence"),
            created_at=data["created_at"],
        )


@dataclass(frozen=True)
class ReviewDecision:
    """A user's decision about one suggestion."""

    suggestion_id: str
    outcome: DecisionOutcome
    reviewer: str
    accepted_value: Any = None
    decided_at: str = field(default_factory=_utc_now)

    def __post_init__(self) -> None:
        _require_text(self.suggestion_id, "suggestion_id")
        _require_text(self.reviewer, "reviewer")

        object.__setattr__(
            self,
            "outcome",
            DecisionOutcome(self.outcome),
        )
        object.__setattr__(
            self,
            "accepted_value",
            _freeze(self.accepted_value),
        )

        if self.outcome is DecisionOutcome.REJECTED and self.accepted_value is not None:
            raise ValueError("rejected decisions must not carry an accepted value")

    def to_dict(self) -> dict[str, Any]:
        return {
            "suggestion_id": self.suggestion_id,
            "outcome": self.outcome.value,
            "reviewer": self.reviewer,
            "accepted_value": _thaw(self.accepted_value),
            "decided_at": self.decided_at,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ReviewDecision":
        return cls(
            suggestion_id=data["suggestion_id"],
            outcome=DecisionOutcome(data["outcome"]),
            reviewer=data["reviewer"],
            accepted_value=data.get("accepted_value"),
            decided_at=data["decided_at"],
        )


@dataclass(frozen=True)
class ReviewDraft:
    """Immutable review state for one proposed memory."""

    content: str
    tags: tuple[str, ...] = ()
    draft_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    suggestions: tuple[Suggestion, ...] = ()
    decisions: tuple[ReviewDecision, ...] = ()
    state: ReviewState = ReviewState.OPEN
    completed_by: str | None = None
    completed_at: str | None = None
    created_at: str = field(default_factory=_utc_now)

    def __post_init__(self) -> None:
        if not isinstance(self.content, str):
            raise TypeError("content must be a string")

        _require_text(self.draft_id, "draft_id")

        if isinstance(self.tags, str):
            raise TypeError("tags must be a sequence of strings, not a string")

        object.__setattr__(
            self,
            "state",
            ReviewState(self.state),
        )
        object.__setattr__(
            self,
            "tags",
            tuple(self.tags),
        )

        for tag in self.tags:
            _require_text(tag, "tag")
        object.__setattr__(
            self,
            "suggestions",
            tuple(self.suggestions),
        )
        object.__setattr__(
            self,
            "decisions",
            tuple(self.decisions),
        )

        self._validate_invariants()

    def _validate_invariants(self) -> None:
        suggestions_by_id: dict[str, Suggestion] = {}

        for suggestion in self.suggestions:
            if suggestion.suggestion_id in suggestions_by_id:
                raise ValueError(f"duplicate suggestion_id: {suggestion.suggestion_id}")

            suggestions_by_id[suggestion.suggestion_id] = suggestion

        decided: set[str] = set()
        accepted_fields: set[str] = set()

        for decision in self.decisions:
            suggestion = suggestions_by_id.get(decision.suggestion_id)

            if suggestion is None:
                raise ValueError(
                    f"decision references unknown suggestion: {decision.suggestion_id}"
                )

            if decision.suggestion_id in decided:
                raise ValueError(
                    f"suggestion has more than one decision: {decision.suggestion_id}"
                )

            decided.add(decision.suggestion_id)

            if decision.outcome is DecisionOutcome.ACCEPTED:
                if suggestion.field_name in accepted_fields:
                    raise ValueError(
                        "multiple accepted suggestions for field "
                        f"{suggestion.field_name!r}"
                    )

                accepted_fields.add(suggestion.field_name)

        if self.state is ReviewState.OPEN:
            if self.completed_by is not None or self.completed_at is not None:
                raise ValueError("open drafts must not carry completion metadata")
        else:
            _require_text(self.completed_by, "completed_by")
            _require_text(self.completed_at, "completed_at")

        if self.state is ReviewState.APPROVED and self.pending_suggestion_ids:
            raise ValueError("approved drafts must have every suggestion reviewed")

    @property
    def pending_suggestion_ids(self) -> tuple[str, ...]:
        decided = {decision.suggestion_id for decision in self.decisions}

        return tuple(
            suggestion.suggestion_id
            for suggestion in self.suggestions
            if suggestion.suggestion_id not in decided
        )

    def add_suggestion(
        self,
        field_name: str,
        value: Any,
        source: str,
        *,
        model: str | None = None,
        process_version: str | None = None,
        confidence: float | None = None,
        suggestion_id: str | None = None,
    ) -> "ReviewDraft":
        """Return a new draft containing an unconfirmed suggestion."""
        self._require_open()

        suggestion = Suggestion(
            suggestion_id=(suggestion_id or str(uuid.uuid4())),
            field_name=field_name,
            value=value,
            source=source,
            model=model,
            process_version=process_version,
            confidence=confidence,
        )

        if any(
            item.suggestion_id == suggestion.suggestion_id for item in self.suggestions
        ):
            raise ValueError("duplicate suggestion_id")

        return replace(
            self,
            suggestions=self.suggestions + (suggestion,),
        )

    def accept(
        self,
        suggestion_id: str,
        reviewer: str,
        *,
        value: Any = _UNSET,
    ) -> "ReviewDraft":
        """Return a new draft with one accepted suggestion."""
        self._require_open()
        _require_text(reviewer, "reviewer")

        suggestion = self._suggestion(suggestion_id)
        self._require_undecided(suggestion_id)

        for decision in self.decisions:
            if decision.outcome is not DecisionOutcome.ACCEPTED:
                continue

            accepted_suggestion = self._suggestion(decision.suggestion_id)

            if accepted_suggestion.field_name == suggestion.field_name:
                raise ValueError(
                    "another suggestion is already accepted "
                    f"for field {suggestion.field_name!r}"
                )

        accepted_value = suggestion.value if value is _UNSET else value

        decision = ReviewDecision(
            suggestion_id=suggestion_id,
            outcome=DecisionOutcome.ACCEPTED,
            reviewer=reviewer,
            accepted_value=accepted_value,
        )

        return replace(
            self,
            decisions=self.decisions + (decision,),
        )

    def reject_suggestion(
        self,
        suggestion_id: str,
        reviewer: str,
    ) -> "ReviewDraft":
        """Return a new draft with one rejected suggestion."""
        self._require_open()
        _require_text(reviewer, "reviewer")

        self._suggestion(suggestion_id)
        self._require_undecided(suggestion_id)

        decision = ReviewDecision(
            suggestion_id=suggestion_id,
            outcome=DecisionOutcome.REJECTED,
            reviewer=reviewer,
        )

        return replace(
            self,
            decisions=self.decisions + (decision,),
        )

    def approve(self, reviewer: str) -> "ReviewDraft":
        """Return an approved draft after every suggestion is reviewed."""
        self._require_open()
        _require_text(reviewer, "reviewer")

        if self.pending_suggestion_ids:
            raise ValueError("all suggestions must be accepted or rejected")

        return replace(
            self,
            state=ReviewState.APPROVED,
            completed_by=reviewer,
            completed_at=_utc_now(),
        )

    def reject(self, reviewer: str) -> "ReviewDraft":
        """Return a rejected terminal draft."""
        self._require_open()
        _require_text(reviewer, "reviewer")

        return replace(
            self,
            state=ReviewState.REJECTED,
            completed_by=reviewer,
            completed_at=_utc_now(),
        )

    def revision_history(self) -> tuple[Revision, ...]:
        """Return the derived, chronologically ordered review history.

        The history is computed from the draft's own records: creation,
        each suggestion, each decision, and the terminal action if any.
        """
        suggestions_by_id = {
            suggestion.suggestion_id: suggestion for suggestion in self.suggestions
        }

        events = [
            Revision(
                action="draft_created",
                occurred_at=self.created_at,
            )
        ]

        for suggestion in self.suggestions:
            events.append(
                Revision(
                    action="suggestion_added",
                    occurred_at=suggestion.created_at,
                    actor=suggestion.source,
                    field_name=suggestion.field_name,
                    value=suggestion.value,
                    suggestion_id=suggestion.suggestion_id,
                )
            )

        for decision in self.decisions:
            suggestion = suggestions_by_id[decision.suggestion_id]

            if decision.outcome is DecisionOutcome.ACCEPTED:
                action = "suggestion_accepted"
            else:
                action = "suggestion_rejected"

            events.append(
                Revision(
                    action=action,
                    occurred_at=decision.decided_at,
                    actor=decision.reviewer,
                    field_name=suggestion.field_name,
                    value=decision.accepted_value,
                    suggestion_id=decision.suggestion_id,
                )
            )

        if self.state is not ReviewState.OPEN:
            if self.state is ReviewState.APPROVED:
                action = "draft_approved"
            else:
                action = "draft_rejected"

            events.append(
                Revision(
                    action=action,
                    occurred_at=self.completed_at,
                    actor=self.completed_by,
                )
            )

        events.sort(key=lambda event: event.occurred_at)
        return tuple(events)

    def resolved_fields(self) -> dict[str, Any]:
        """Return original fields plus explicitly accepted values."""
        resolved: dict[str, Any] = {
            "content": self.content,
            "tags": list(self.tags),
        }

        suggestions = {
            suggestion.suggestion_id: suggestion for suggestion in self.suggestions
        }

        for decision in self.decisions:
            if decision.outcome is not DecisionOutcome.ACCEPTED:
                continue

            suggestion = suggestions[decision.suggestion_id]

            resolved[suggestion.field_name] = _thaw(decision.accepted_value)

        return resolved

    def to_dict(self) -> dict[str, Any]:
        return {
            "draft_id": self.draft_id,
            "content": self.content,
            "tags": list(self.tags),
            "suggestions": [suggestion.to_dict() for suggestion in self.suggestions],
            "decisions": [decision.to_dict() for decision in self.decisions],
            "state": self.state.value,
            "completed_by": self.completed_by,
            "completed_at": self.completed_at,
            "created_at": self.created_at,
        }

    def to_json(self) -> str:
        return json.dumps(
            self.to_dict(),
            ensure_ascii=False,
            indent=2,
        )

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ReviewDraft":
        return cls(
            draft_id=data["draft_id"],
            content=data["content"],
            tags=tuple(data.get("tags", [])),
            suggestions=tuple(
                Suggestion.from_dict(item) for item in data.get("suggestions", [])
            ),
            decisions=tuple(
                ReviewDecision.from_dict(item) for item in data.get("decisions", [])
            ),
            state=ReviewState(data["state"]),
            completed_by=data.get("completed_by"),
            completed_at=data.get("completed_at"),
            created_at=data["created_at"],
        )

    @classmethod
    def from_json(cls, value: str) -> "ReviewDraft":
        return cls.from_dict(json.loads(value))

    def _suggestion(self, suggestion_id: str) -> Suggestion:
        for suggestion in self.suggestions:
            if suggestion.suggestion_id == suggestion_id:
                return suggestion

        raise KeyError(f"unknown suggestion: {suggestion_id}")

    def _require_undecided(self, suggestion_id: str) -> None:
        if any(decision.suggestion_id == suggestion_id for decision in self.decisions):
            raise ValueError("suggestion has already been reviewed")

    def _require_open(self) -> None:
        if self.state is not ReviewState.OPEN:
            raise ValueError(f"draft is already {self.state.value}")
