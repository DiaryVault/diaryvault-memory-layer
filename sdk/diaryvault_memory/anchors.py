from __future__ import annotations

"""
Anchor backends for the permanence layer.

Anchoring stores a cryptographic hash on an immutable medium,
proving that a memory existed at a specific point in time.

Backends:
- LocalAnchor: File-based anchoring (default, no dependencies)
- ArweaveAnchor: Permanent storage on Arweave (coming soon)
- EthereumAnchor: L2 hash anchoring on Base/Arbitrum (coming soon)
- IPFSAnchor: Content-addressed storage on IPFS (coming soon)
"""

import json
import os
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from .memory import MemoryAnchor


class AnchorBackend(ABC):
    """Abstract base class for anchor backends."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable backend name."""
        ...

    @abstractmethod
    def anchor(self, memory_id: str, content_hash: str, signature: str) -> MemoryAnchor:
        """
        Anchor a memory hash to the permanence layer.

        Args:
            memory_id: Unique memory identifier.
            content_hash: SHA-256 hash of the memory content.
            signature: HMAC signature of the hash.

        Returns:
            MemoryAnchor with transaction details.
        """
        ...

    @abstractmethod
    def verify(self, memory_id: str, content_hash: str) -> bool:
        """
        Verify that a memory hash exists in the permanence layer.

        Args:
            memory_id: Unique memory identifier.
            content_hash: Expected SHA-256 hash.

        Returns:
            True if the anchored hash matches.
        """
        ...

    @abstractmethod
    def retrieve(self, memory_id: str) -> Optional[dict]:
        """
        Retrieve anchor data for a memory.

        Args:
            memory_id: Unique memory identifier.

        Returns:
            Anchor data dict or None if not found.
        """
        ...


class LocalAnchor(AnchorBackend):
    """
    File-based local anchoring.

    Stores anchor records as JSON files in a local directory.
    No external dependencies. Good for development and self-hosting.

    Anchor records are append-only — once written, they should not be modified.
    """

    def __init__(self, storage_dir: str = "~/.diaryvault/anchors"):
        self._storage_dir = Path(os.path.expanduser(storage_dir))
        self._storage_dir.mkdir(parents=True, exist_ok=True)
        self._index_path = self._storage_dir / "index.json"
        self._index = self._load_index()

    @property
    def name(self) -> str:
        return "local"

    def _load_index(self) -> dict:
        """Load the anchor index from disk."""
        if self._index_path.exists():
            with open(self._index_path, "r") as f:
                return json.load(f)
        return {"version": "1.0", "anchors": {}}

    def _save_index(self):
        """Persist the anchor index to disk."""
        with open(self._index_path, "w") as f:
            json.dump(self._index, f, indent=2, default=str)

    def anchor(self, memory_id: str, content_hash: str, signature: str) -> MemoryAnchor:
        """Anchor a hash to local storage."""
        now = datetime.now(timezone.utc).isoformat()

        anchor_record = {
            "memory_id": memory_id,
            "content_hash": content_hash,
            "signature": signature,
            "anchored_at": now,
            "backend": "local",
        }

        # Write individual anchor file (append-only)
        anchor_file = self._storage_dir / f"{memory_id}.json"
        with open(anchor_file, "w") as f:
            json.dump(anchor_record, f, indent=2)

        # Update index
        self._index["anchors"][memory_id] = {
            "hash": content_hash,
            "anchored_at": now,
            "file": str(anchor_file),
        }
        self._save_index()

        return MemoryAnchor(
            backend="local",
            transaction_id=memory_id,
            anchored_at=now,
            url=f"file://{anchor_file}",
        )

    def verify(self, memory_id: str, content_hash: str) -> bool:
        """Verify a hash against local anchor."""
        record = self.retrieve(memory_id)
        if record is None:
            return False
        return record.get("content_hash") == content_hash

    def retrieve(self, memory_id: str) -> Optional[dict]:
        """Retrieve anchor data from local storage."""
        anchor_file = self._storage_dir / f"{memory_id}.json"
        if not anchor_file.exists():
            return None
        with open(anchor_file, "r") as f:
            return json.load(f)

    def list_anchors(self) -> list[dict]:
        """List all anchored memories."""
        return [
            {"memory_id": k, **v}
            for k, v in self._index.get("anchors", {}).items()
        ]


class ArweaveAnchor(AnchorBackend):
    """
    Arweave permanent storage backend.

    Stores data permanently on the Arweave blockweave.
    Cost: ~$0.005 per KB (one-time, stored forever).

    Requires: arweave-python-client
    Status: Coming in v0.3
    """

    @property
    def name(self) -> str:
        return "arweave"

    def anchor(self, memory_id: str, content_hash: str, signature: str) -> MemoryAnchor:
        raise NotImplementedError(
            "Arweave anchoring coming in v0.3. "
            "Track progress: https://github.com/diaryvault/memory-layer/issues"
        )

    def verify(self, memory_id: str, content_hash: str) -> bool:
        raise NotImplementedError("Arweave verification coming in v0.3")

    def retrieve(self, memory_id: str) -> Optional[dict]:
        raise NotImplementedError("Arweave retrieval coming in v0.3")


class EthereumAnchor(AnchorBackend):
    """
    Ethereum L2 hash anchoring backend.

    Anchors memory hashes to an Ethereum L2 (Base, Arbitrum, Optimism).
    Only the hash goes on-chain — content stays encrypted off-chain.
    Cost: ~$0.01 per anchor on L2.

    Requires: web3.py
    Status: Coming in v0.3
    """

    @property
    def name(self) -> str:
        return "ethereum"

    def anchor(self, memory_id: str, content_hash: str, signature: str) -> MemoryAnchor:
        raise NotImplementedError(
            "Ethereum L2 anchoring coming in v0.3. "
            "Track progress: https://github.com/diaryvault/memory-layer/issues"
        )

    def verify(self, memory_id: str, content_hash: str) -> bool:
        raise NotImplementedError("Ethereum verification coming in v0.3")

    def retrieve(self, memory_id: str) -> Optional[dict]:
        raise NotImplementedError("Ethereum retrieval coming in v0.3")
