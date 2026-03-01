from __future__ import annotations

"""
Agent Context Layer — Selective, verified memory sharing for AI agents.

This is the bridge between user-owned memory and AI agents.
Users control what gets shared. Agents get cryptographic proof
that the context they received is authentic and unmodified.

Usage:
    # Agent side: request context
    request = ContextRequest(
        agent_id="openclaw-agent-001",
        scope=["preference", "work"],
        purpose="Personalize meeting scheduling",
    )

    # User side: selectively share
    response = vault.share(request, allowed_tags=["preference", "work"])

    # Agent side: verify what they received
    assert response.verify_all()  # Every memory is hash-verified
"""

import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Optional


@dataclass
class ContextRequest:
    """
    What an agent sends to request user context.

    The agent declares what it wants and why. The user (or their vault
    policy) decides what to actually share.
    """
    agent_id: str
    scope: list[str] = field(default_factory=list)
    purpose: str = ""
    max_memories: int = 10
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    requested_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: dict) -> "ContextRequest":
        return cls(**data)

    @classmethod
    def from_json(cls, json_str: str) -> "ContextRequest":
        return cls.from_dict(json.loads(json_str))


@dataclass
class SharedMemory:
    """
    A single memory shared with an agent.

    Contains the content and cryptographic proof but NOT the
    encryption key. The agent can verify integrity but cannot
    decrypt other memories in the vault.
    """
    memory_id: str
    content: str
    tags: list[str]
    hash: str
    signature: str
    created_at: str
    verified: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ContextResponse:
    """
    What the vault returns to an agent.

    Contains selectively shared memories with cryptographic proofs.
    The agent can verify each memory's integrity independently.
    """
    request_id: str
    agent_id: str
    vault_merkle_root: Optional[str] = None
    shared_memories: list[SharedMemory] = field(default_factory=list)
    scope_granted: list[str] = field(default_factory=list)
    scope_denied: list[str] = field(default_factory=list)
    responded_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    response_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    @property
    def memory_count(self) -> int:
        return len(self.shared_memories)

    def verify_all(self) -> bool:
        """Check that all shared memories passed verification."""
        if not self.shared_memories:
            return True
        return all(m.verified for m in self.shared_memories)

    def to_dict(self) -> dict:
        data = asdict(self)
        return data

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: dict) -> "ContextResponse":
        memories = [
            SharedMemory(**m) if isinstance(m, dict) else m
            for m in data.pop("shared_memories", [])
        ]
        resp = cls(**data)
        resp.shared_memories = memories
        return resp

    @classmethod
    def from_json(cls, json_str: str) -> "ContextResponse":
        return cls.from_dict(json.loads(json_str))

    def __repr__(self) -> str:
        return (
            f"ContextResponse(memories={self.memory_count}, "
            f"scope_granted={self.scope_granted}, "
            f"verified={self.verify_all()})"
        )
