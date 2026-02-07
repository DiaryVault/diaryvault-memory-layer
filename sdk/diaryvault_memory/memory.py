from __future__ import annotations

"""
Memory data model — the fundamental unit of the Memory Layer.

A Memory is an immutable, cryptographically verified record of a moment in time.
"""

import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class MemoryStatus(str, Enum):
    """Lifecycle status of a memory record."""
    CREATED = "created"           # Raw content captured
    HASHED = "hashed"             # SHA-256 hash computed
    ENCRYPTED = "encrypted"       # Content encrypted
    SIGNED = "signed"             # Digitally signed
    ANCHORED = "anchored"         # Hash anchored to permanence layer
    VERIFIED = "verified"         # Integrity verified after retrieval


@dataclass
class MemoryMetadata:
    """Extensible metadata attached to a memory."""
    tags: list[str] = field(default_factory=list)
    location: Optional[str] = None
    mood: Optional[str] = None
    source: str = "manual"        # manual, agent, api, import
    agent_id: Optional[str] = None
    ai_enriched: bool = False
    custom: dict = field(default_factory=dict)


@dataclass
class MemoryAnchor:
    """Record of where a memory hash has been anchored."""
    backend: str                  # "local", "arweave", "ethereum", "ipfs"
    transaction_id: Optional[str] = None
    block_number: Optional[int] = None
    anchored_at: Optional[str] = None
    url: Optional[str] = None     # Explorer/gateway URL


@dataclass
class Memory:
    """
    An immutable memory record.

    Once created, the content and hash form a cryptographic bond.
    Any modification to content invalidates the hash, making tampering detectable.
    """
    # Identity
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    version: str = "1.0.0"

    # Content
    content: str = ""
    content_type: str = "text/plain"  # text/plain, text/markdown, application/json

    # Cryptographic fields
    hash: Optional[str] = None              # SHA-256 of content
    encrypted_content: Optional[bytes] = None
    signature: Optional[str] = None
    nonce: Optional[bytes] = None           # AES-GCM nonce

    # Timestamps (RFC 3339)
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    updated_at: Optional[str] = None

    # Status
    status: MemoryStatus = MemoryStatus.CREATED

    # Metadata & anchoring
    metadata: MemoryMetadata = field(default_factory=MemoryMetadata)
    anchors: list[MemoryAnchor] = field(default_factory=list)

    # Merkle tree support
    merkle_root: Optional[str] = None
    merkle_proof: Optional[list[str]] = None

    @property
    def verified(self) -> bool:
        """Quick check if memory has been verified."""
        return self.status == MemoryStatus.VERIFIED

    @property
    def is_anchored(self) -> bool:
        """Check if memory is anchored to any permanence layer."""
        return len(self.anchors) > 0

    def to_dict(self) -> dict:
        """Serialize memory to dictionary (for storage/export)."""
        data = asdict(self)
        data["status"] = self.status.value
        # Convert bytes to hex for JSON serialization
        if self.encrypted_content:
            data["encrypted_content"] = self.encrypted_content.hex()
        if self.nonce:
            data["nonce"] = self.nonce.hex()
        return data

    def to_json(self) -> str:
        """Serialize memory to JSON string."""
        return json.dumps(self.to_dict(), indent=2, default=str)

    def to_dvmem(self) -> str:
        """
        Export as .dvmem format (DiaryVault Memory Format).

        .dvmem is a JSON-based open format with the following structure:
        - Header: format version, encoding info
        - Payload: memory data
        - Verification: hash, signature, anchors
        """
        dvmem = {
            "dvmem_version": "1.0",
            "encoding": "utf-8",
            "payload": self.to_dict(),
            "verification": {
                "hash": self.hash,
                "signature": self.signature,
                "anchors": [asdict(a) for a in self.anchors],
            }
        }
        return json.dumps(dvmem, indent=2, default=str)

    @classmethod
    def from_dict(cls, data: dict) -> "Memory":
        """Deserialize memory from dictionary."""
        # Handle status enum
        if "status" in data and isinstance(data["status"], str):
            data["status"] = MemoryStatus(data["status"])

        # Handle bytes fields
        if "encrypted_content" in data and isinstance(data["encrypted_content"], str):
            data["encrypted_content"] = bytes.fromhex(data["encrypted_content"])
        if "nonce" in data and isinstance(data["nonce"], str):
            data["nonce"] = bytes.fromhex(data["nonce"])

        # Handle nested dataclasses
        if "metadata" in data and isinstance(data["metadata"], dict):
            data["metadata"] = MemoryMetadata(**data["metadata"])
        if "anchors" in data and isinstance(data["anchors"], list):
            data["anchors"] = [
                MemoryAnchor(**a) if isinstance(a, dict) else a
                for a in data["anchors"]
            ]

        return cls(**data)

    @classmethod
    def from_dvmem(cls, dvmem_str: str) -> "Memory":
        """Import from .dvmem format."""
        dvmem = json.loads(dvmem_str)
        assert dvmem.get("dvmem_version", "").startswith("1."), \
            f"Unsupported dvmem version: {dvmem.get('dvmem_version')}"
        return cls.from_dict(dvmem["payload"])

    def __repr__(self) -> str:
        content_preview = self.content[:50] + "..." if len(self.content) > 50 else self.content
        return (
            f"Memory(id={self.id[:8]}..., "
            f"status={self.status.value}, "
            f"hash={self.hash[:12] + '...' if self.hash else 'None'}, "
            f"content='{content_preview}')"
        )
