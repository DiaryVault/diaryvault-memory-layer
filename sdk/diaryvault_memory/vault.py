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
    assert vault.verify(memory)
    vault.anchor(memory, backend="local")
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Union

from .memory import Memory, MemoryMetadata, MemoryStatus
from .crypto import MemoryCrypto
from .anchors import AnchorBackend, LocalAnchor
from .context import ContextRequest, ContextResponse, SharedMemory
from .review import DraftStatus, MemoryDraft, MemorySuggestion


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
        self._drafts: dict[str, MemoryDraft] = {}
        self._draft_dir = self._storage_dir / ".drafts"
        self._draft_dir.mkdir(
            parents=True,
            exist_ok=True,
        )

        self._load_memories()
        self._load_drafts()

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
        Create a new tamper-evident memory.

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

    # ── Reviewable Drafts ─────────────────────────────────────────────

    def create_draft(
        self,
        content: str,
        tags: Optional[list[str]] = None,
        metadata: Optional[dict] = None,
        source: str = "manual",
    ) -> MemoryDraft:
        """Create and persist a reviewable draft."""
        draft = MemoryDraft(
            content=content,
            tags=tags or [],
            metadata=metadata or {},
            source=source,
        )

        self._drafts[draft.draft_id] = draft
        self._persist_draft(draft)

        return draft

    def get_draft(
        self,
        draft_id: str,
    ) -> Optional[MemoryDraft]:
        """Get a reviewable draft by identifier."""
        return self._drafts.get(draft_id)

    def list_drafts(
        self,
        status: Optional[
            Union[DraftStatus, str]
        ] = None,
    ) -> list[MemoryDraft]:
        """List drafts with an optional status filter."""
        drafts = list(
            self._drafts.values()
        )

        if status is not None:
            resolved_status = (
                DraftStatus(status)
                if isinstance(status, str)
                else status
            )

            drafts = [
                draft
                for draft in drafts
                if draft.status
                is resolved_status
            ]

        drafts.sort(
            key=lambda draft: (
                draft.created_at
            ),
            reverse=True,
        )

        return drafts

    def add_suggestion(
        self,
        draft: Union[MemoryDraft, str],
        field_name: str,
        suggested_value: Any,
        source: str,
        model: Optional[str] = None,
        process_version: Optional[str] = None,
        confidence: Optional[float] = None,
        rationale: Optional[str] = None,
    ) -> MemorySuggestion:
        """Add an unconfirmed suggestion."""
        resolved = self._resolve_draft(
            draft
        )

        suggestion = resolved.add_suggestion(
            field_name=field_name,
            suggested_value=(
                suggested_value
            ),
            source=source,
            model=model,
            process_version=(
                process_version
            ),
            confidence=confidence,
            rationale=rationale,
        )

        self._persist_draft(resolved)

        return suggestion

    def accept_suggestion(
        self,
        draft: Union[MemoryDraft, str],
        suggestion_id: str,
        actor: str,
        value: Any = None,
        note: Optional[str] = None,
    ) -> MemorySuggestion:
        """Accept a suggestion after review."""
        resolved = self._resolve_draft(
            draft
        )

        suggestion = (
            resolved.accept_suggestion(
                suggestion_id=(
                    suggestion_id
                ),
                actor=actor,
                value=value,
                note=note,
            )
        )

        self._persist_draft(resolved)

        return suggestion

    def reject_suggestion(
        self,
        draft: Union[MemoryDraft, str],
        suggestion_id: str,
        actor: str,
        note: Optional[str] = None,
    ) -> MemorySuggestion:
        """Reject a suggestion after review."""
        resolved = self._resolve_draft(
            draft
        )

        suggestion = (
            resolved.reject_suggestion(
                suggestion_id=(
                    suggestion_id
                ),
                actor=actor,
                note=note,
            )
        )

        self._persist_draft(resolved)

        return suggestion

    def update_draft_field(
        self,
        draft: Union[MemoryDraft, str],
        field_name: str,
        value: Any,
        actor: str,
        note: Optional[str] = None,
    ) -> MemoryDraft:
        """Explicitly confirm or edit a field."""
        resolved = self._resolve_draft(
            draft
        )

        resolved.set_field(
            field_name=field_name,
            value=value,
            actor=actor,
            note=note,
        )

        self._persist_draft(resolved)

        return resolved

    def approve_draft(
        self,
        draft: Union[MemoryDraft, str],
        actor: str,
        note: Optional[str] = None,
        auto_encrypt: bool = True,
        auto_anchor: bool = False,
    ) -> Memory:
        """Approve a draft and create a Memory."""
        resolved = self._resolve_draft(
            draft
        )

        fields = resolved.resolved_fields()

        content = fields.pop(
            "content",
            resolved.content,
        )
        tags = fields.pop(
            "tags",
            resolved.tags,
        )
        metadata = fields.pop(
            "metadata",
            resolved.metadata,
        )

        if not isinstance(content, str):
            raise TypeError(
                "confirmed content must be "
                "a string"
            )

        if (
            not isinstance(tags, list)
            or not all(
                isinstance(tag, str)
                for tag in tags
            )
        ):
            raise TypeError(
                "confirmed tags must be "
                "a list of strings"
            )

        if not isinstance(metadata, dict):
            raise TypeError(
                "confirmed metadata must be "
                "a dictionary"
            )

        resolved.approve(
            actor=actor,
            note=note,
        )

        custom_metadata = dict(metadata)

        if fields:
            custom_metadata[
                "confirmed_fields"
            ] = fields

        custom_metadata["review"] = (
            resolved.to_review_manifest()
        )

        memory = self.create(
            content=content,
            tags=tags,
            metadata=custom_metadata,
            auto_encrypt=auto_encrypt,
            auto_anchor=auto_anchor,
        )

        memory.metadata.source = (
            "reviewed_draft"
        )
        memory.metadata.ai_enriched = bool(
            resolved.suggestions
        )

        resolved.final_memory_id = memory.id

        custom_metadata["review"] = (
            resolved.to_review_manifest()
        )

        memory.metadata.custom = (
            custom_metadata
        )

        self._persist_memory(memory)
        self._persist_draft(resolved)

        return memory

    def reject_draft(
        self,
        draft: Union[MemoryDraft, str],
        actor: str,
        note: Optional[str] = None,
    ) -> MemoryDraft:
        """Reject and persist an entire draft."""
        resolved = self._resolve_draft(
            draft
        )

        resolved.reject(
            actor=actor,
            note=note,
        )

        self._persist_draft(resolved)

        return resolved

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

    def _resolve_draft(
        self,
        draft: Union[MemoryDraft, str],
    ) -> MemoryDraft:
        if isinstance(draft, MemoryDraft):
            resolved = self._drafts.get(
                draft.draft_id
            )
        else:
            resolved = self.get_draft(
                draft
            )

        if resolved is None:
            raise KeyError(
                f"unknown draft: {draft}"
            )

        return resolved

    def _persist_draft(
        self,
        draft: MemoryDraft,
    ) -> None:
        """Persist a draft and its review history."""
        draft_file = (
            self._draft_dir
            / f"{draft.draft_id}.json"
        )

        with open(draft_file, "w") as file:
            json.dump(
                draft.to_dict(),
                file,
                indent=2,
                default=str,
            )

    def _load_drafts(self) -> None:
        """Load reviewable drafts from storage."""
        for draft_file in (
            self._draft_dir.glob("*.json")
        ):
            try:
                with open(
                    draft_file,
                    "r",
                ) as file:
                    data = json.load(file)

                draft = (
                    MemoryDraft.from_dict(data)
                )

                self._drafts[
                    draft.draft_id
                ] = draft

            except (
                json.JSONDecodeError,
                KeyError,
                TypeError,
                ValueError,
            ):
                continue

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


    # ── Agent Context Sharing ────────────────────────────────────────────

    def share(
        self,
        request: ContextRequest,
        allowed_tags: Optional[list[str]] = None,
        denied_tags: Optional[list[str]] = None,
        max_memories: Optional[int] = None,
    ) -> ContextResponse:
        """
        Selectively share memories with an agent.

        The user controls exactly what gets shared. Each shared memory
        includes stored proof fields and the vault's verification result.

        Args:
            request: The agent's ContextRequest.
            allowed_tags: Tags the user permits sharing. If None, uses
                         request.scope as the allowed set.
            denied_tags: Tags to explicitly block (overrides allowed).
            max_memories: Override max memories to share.

        Returns:
            A ContextResponse with verified, selectively shared memories.
        """
        # Determine what tags are allowed
        permitted = set(allowed_tags or request.scope)
        blocked = set(denied_tags or [])
        effective_scope = permitted - blocked

        # Find matching memories
        matching = []
        for memory in self._memories.values():
            mem_tags = set(memory.metadata.tags)
            if mem_tags.intersection(effective_scope):
                matching.append(memory)

        # Sort by recency
        matching.sort(key=lambda m: m.created_at, reverse=True)

        # Apply limit
        limit = max_memories or request.max_memories
        matching = matching[:limit]

        # Build shared memories with verification
        shared = []
        for memory in matching:
            is_valid = self.verify(memory)
            shared.append(SharedMemory(
                memory_id=memory.id,
                content=memory.content,
                tags=memory.metadata.tags,
                hash=memory.hash,
                signature=memory.signature,
                created_at=memory.created_at,
                verified=is_valid,
            ))

        # Compute what was granted vs denied
        requested_scope = set(request.scope)
        scope_granted = list(requested_scope.intersection(effective_scope))
        scope_denied = list(requested_scope - effective_scope)

        return ContextResponse(
            request_id=request.request_id,
            agent_id=request.agent_id,
            vault_merkle_root=self.compute_merkle_root(),
            shared_memories=shared,
            scope_granted=scope_granted,
            scope_denied=scope_denied,
        )
