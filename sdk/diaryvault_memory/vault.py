from __future__ import annotations

"""
MemoryVault — The main interface for the DiaryVault Memory Layer.

This is the primary class users interact with. It orchestrates:
- Memory creation
- Encryption & hashing
- Verification
- Storage & anchoring
- Export & import

Usage:
    vault = MemoryVault(encryption_key="your-secret-key")
    memory = vault.create("Today was a good day.", tags=["daily"])
    assert vault.verify(memory) == True
    vault.anchor(memory, backend="local")
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Union

from .memory import Memory, MemoryMetadata, MemoryStatus
from .crypto import MemoryCrypto
from .anchors import AnchorBackend, LocalAnchor


class MemoryVault:
    """
    Your personal memory vault.

    All cryptographic operations happen locally. Your encryption key
    never leaves your device. Not even DiaryVault can read your memories.
    """

    def __init__(
        self,
        encryption_key: str,
        storage_dir: str = "~/.diaryvault/memories",
        anchor_backend: Optional[AnchorBackend] = None,
    ):
        """
        Initialize a MemoryVault.

        Args:
            encryption_key: Your secret key for encryption and signing.
                          KEEP THIS SAFE. Lose it = lose your memories.
            storage_dir: Local directory for encrypted memory storage.
            anchor_backend: Default anchor backend. Defaults to LocalAnchor.
        """
        self._crypto = MemoryCrypto(encryption_key)
        self._storage_dir = Path(os.path.expanduser(storage_dir))
        self._storage_dir.mkdir(parents=True, exist_ok=True)
        self._default_anchor = anchor_backend or LocalAnchor()
        self._memories: dict[str, Memory] = {}

        # Load existing memories from storage
        self._load_memories()

    # ── Core Operations ──────────────────────────────────────────────────

    def create(
        self,
        content: str,
        tags: Optional[list[str]] = None,
        metadata: Optional[dict] = None,
        auto_encrypt: bool = True,
        auto_anchor: bool = False,
    ) -> Memory:
        """
        Create a new immutable memory.

        This is the primary method. It:
        1. Creates a Memory record
        2. Computes SHA-256 hash
        3. Encrypts content (AES-256-GCM)
        4. Signs the hash (HMAC-SHA256)
        5. Optionally anchors to permanence layer

        Args:
            content: The memory content (text, markdown, or JSON).
            tags: Optional tags for organization.
            metadata: Optional additional metadata dict.
            auto_encrypt: Encrypt content automatically (default: True).
            auto_anchor: Anchor to default backend (default: False).

        Returns:
            A fully processed Memory object.
        """
        # Build metadata
        mem_metadata = MemoryMetadata(
            tags=tags or [],
            **({"custom": metadata} if metadata else {})
        )

        # Create memory
        memory = Memory(
            content=content,
            metadata=mem_metadata,
        )

        # Hash
        memory.hash = self._crypto.hash_content(content)
        memory.status = MemoryStatus.HASHED

        # Encrypt
        if auto_encrypt:
            ciphertext, nonce = self._crypto.encrypt(content)
            memory.encrypted_content = ciphertext
            memory.nonce = nonce
            memory.status = MemoryStatus.ENCRYPTED

        # Sign
        memory.signature = self._crypto.sign(memory.hash)
        memory.status = MemoryStatus.SIGNED

        # Store locally
        self._memories[memory.id] = memory
        self._persist_memory(memory)

        # Anchor if requested
        if auto_anchor:
            self.anchor(memory)

        return memory

    def verify(self, memory: Union[Memory, str]) -> bool:
        """
        Verify the integrity of a memory.

        Checks:
        1. Content hash matches stored hash
        2. Signature is valid
        3. If anchored, anchor hash matches

        Args:
            memory: A Memory object or memory ID string.

        Returns:
            True if all verification checks pass.
        """
        if isinstance(memory, str):
            memory = self.get(memory)
            if memory is None:
                return False

        # Verify content hash
        if not self._crypto.verify_hash(memory.content, memory.hash):
            return False

        # Verify signature
        if memory.signature:
            if not self._crypto.verify_signature(memory.hash, memory.signature):
                return False

        # Verify anchors
        for anchor_record in memory.anchors:
            backend = self._get_anchor_backend(anchor_record.backend)
            if backend and not backend.verify(memory.id, memory.hash):
                return False

        memory.status = MemoryStatus.VERIFIED
        return True

    def anchor(
        self,
        memory: Memory,
        backend: Optional[Union[str, AnchorBackend]] = None,
    ) -> Memory:
        """
        Anchor a memory's hash to a permanence layer.

        Args:
            memory: The memory to anchor.
            backend: Backend name ("local", "arweave", "ethereum")
                    or AnchorBackend instance. Defaults to local.

        Returns:
            The memory with anchor information attached.
        """
        if isinstance(backend, str):
            anchor_backend = self._get_anchor_backend(backend)
        elif backend is not None:
            anchor_backend = backend
        else:
            anchor_backend = self._default_anchor

        if anchor_backend is None:
            raise ValueError(f"Unknown anchor backend: {backend}")

        anchor = anchor_backend.anchor(
            memory_id=memory.id,
            content_hash=memory.hash,
            signature=memory.signature or "",
        )

        memory.anchors.append(anchor)
        memory.status = MemoryStatus.ANCHORED
        self._persist_memory(memory)

        return memory

    def decrypt(self, memory: Memory) -> str:
        """
        Decrypt a memory's content.

        Args:
            memory: The memory to decrypt.

        Returns:
            The original plaintext content.
        """
        if memory.encrypted_content is None or memory.nonce is None:
            return memory.content

        return self._crypto.decrypt(memory.encrypted_content, memory.nonce)

    # ── Retrieval ────────────────────────────────────────────────────────

    def get(self, memory_id: str) -> Optional[Memory]:
        """Get a memory by ID."""
        return self._memories.get(memory_id)

    def list(
        self,
        tags: Optional[list[str]] = None,
        after: Optional[str] = None,
        before: Optional[str] = None,
        limit: int = 50,
    ) -> list[Memory]:
        """
        List memories with optional filters.

        Args:
            tags: Filter by tags (any match).
            after: Filter memories created after this ISO timestamp.
            before: Filter memories created before this ISO timestamp.
            limit: Max number of results.

        Returns:
            List of matching Memory objects.
        """
        results = list(self._memories.values())

        if tags:
            tag_set = set(tags)
            results = [
                m for m in results
                if tag_set.intersection(set(m.metadata.tags))
            ]

        if after:
            results = [m for m in results if m.created_at > after]

        if before:
            results = [m for m in results if m.created_at < before]

        # Sort by creation time, newest first
        results.sort(key=lambda m: m.created_at, reverse=True)

        return results[:limit]

    def search(self, query: str) -> list[Memory]:
        """
        Simple text search across memory contents.

        Args:
            query: Search string.

        Returns:
            List of matching memories.
        """
        query_lower = query.lower()
        return [
            m for m in self._memories.values()
            if query_lower in m.content.lower()
        ]

    # ── Batch Operations ─────────────────────────────────────────────────

    def batch_verify(self) -> dict:
        """
        Verify all memories in the vault.

        Returns:
            Dict with 'valid', 'invalid', and 'total' counts.
        """
        valid = 0
        invalid = 0
        invalid_ids = []

        for memory_id, memory in self._memories.items():
            if self.verify(memory):
                valid += 1
            else:
                invalid += 1
                invalid_ids.append(memory_id)

        return {
            "total": len(self._memories),
            "valid": valid,
            "invalid": invalid,
            "invalid_ids": invalid_ids,
        }

    def compute_merkle_root(self) -> Optional[str]:
        """
        Compute a Merkle root for all memories in the vault.

        This single hash can verify the entire vault's integrity.
        Useful for periodic batch anchoring.

        Returns:
            Merkle root hash, or None if vault is empty.
        """
        hashes = [
            m.hash for m in self._memories.values()
            if m.hash is not None
        ]
        if not hashes:
            return None
        return self._crypto.compute_merkle_root(sorted(hashes))

    # ── Export & Import ──────────────────────────────────────────────────

    def export_memory(self, memory: Memory, path: str) -> str:
        """
        Export a single memory to .dvmem format.

        Args:
            memory: The memory to export.
            path: File path for the export.

        Returns:
            The file path written to.
        """
        if not path.endswith(".dvmem"):
            path += ".dvmem"

        with open(path, "w") as f:
            f.write(memory.to_dvmem())

        return path

    def import_memory(self, path: str) -> Memory:
        """
        Import a memory from .dvmem format.

        Args:
            path: Path to the .dvmem file.

        Returns:
            The imported Memory object.
        """
        with open(path, "r") as f:
            memory = Memory.from_dvmem(f.read())

        self._memories[memory.id] = memory
        self._persist_memory(memory)
        return memory

    def export_vault(self, path: str) -> str:
        """
        Export the entire vault to a single JSON file.

        Args:
            path: File path for the export.

        Returns:
            The file path written to.
        """
        export_data = {
            "dvmem_vault_version": "1.0",
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "memory_count": len(self._memories),
            "merkle_root": self.compute_merkle_root(),
            "memories": {
                mid: m.to_dict() for mid, m in self._memories.items()
            },
        }

        with open(path, "w") as f:
            json.dump(export_data, f, indent=2, default=str)

        return path

    # ── Stats ────────────────────────────────────────────────────────────

    @property
    def stats(self) -> dict:
        """Vault statistics."""
        memories = list(self._memories.values())
        return {
            "total_memories": len(memories),
            "encrypted": sum(1 for m in memories if m.encrypted_content),
            "anchored": sum(1 for m in memories if m.is_anchored),
            "verified": sum(1 for m in memories if m.verified),
            "tags": list(set(
                tag for m in memories for tag in m.metadata.tags
            )),
        }

    # ── Private Methods ──────────────────────────────────────────────────

    def _persist_memory(self, memory: Memory):
        """Save a memory to local encrypted storage."""
        memory_file = self._storage_dir / f"{memory.id}.json"
        with open(memory_file, "w") as f:
            json.dump(memory.to_dict(), f, indent=2, default=str)

    def _load_memories(self):
        """Load all memories from local storage."""
        for memory_file in self._storage_dir.glob("*.json"):
            try:
                with open(memory_file, "r") as f:
                    data = json.load(f)
                memory = Memory.from_dict(data)
                self._memories[memory.id] = memory
            except (json.JSONDecodeError, KeyError, TypeError):
                continue  # Skip corrupted files

    def _get_anchor_backend(self, name: str) -> Optional[AnchorBackend]:
        """Get an anchor backend by name."""
        from .anchors import ArweaveAnchor, EthereumAnchor

        backends = {
            "local": LocalAnchor,
            "arweave": ArweaveAnchor,
            "ethereum": EthereumAnchor,
        }
        cls = backends.get(name)
        if cls:
            return cls()
        return None

    def __repr__(self) -> str:
        return (
            f"MemoryVault(memories={len(self._memories)}, "
            f"storage='{self._storage_dir}')"
        )

    def __len__(self) -> int:
        return len(self._memories)
