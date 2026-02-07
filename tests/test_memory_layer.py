"""
Tests for DiaryVault Memory Layer SDK.

Run: python -m pytest tests/ -v
"""

import json
import os
import sys
import tempfile

# Add SDK to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sdk"))

from diaryvault_memory import MemoryVault, Memory, MemoryStatus, MemoryCrypto
from diaryvault_memory.anchors import LocalAnchor


class TestMemoryCrypto:
    """Test cryptographic operations."""

    def setup_method(self):
        self.crypto = MemoryCrypto("test-secret-key")

    def test_hash_deterministic(self):
        """Same content always produces same hash."""
        content = "Today was a good day."
        hash1 = self.crypto.hash_content(content)
        hash2 = self.crypto.hash_content(content)
        assert hash1 == hash2
        assert len(hash1) == 64  # SHA-256 hex length

    def test_hash_changes_with_content(self):
        """Different content produces different hash."""
        hash1 = self.crypto.hash_content("Hello")
        hash2 = self.crypto.hash_content("Hello!")
        assert hash1 != hash2

    def test_hash_verification(self):
        """Hash verification catches tampering."""
        content = "Original content"
        content_hash = self.crypto.hash_content(content)
        assert self.crypto.verify_hash(content, content_hash) == True
        assert self.crypto.verify_hash("Tampered content", content_hash) == False

    def test_encrypt_decrypt_roundtrip(self):
        """Content survives encryption/decryption."""
        content = "This is a secret memory. 🧠"
        ciphertext, nonce = self.crypto.encrypt(content)
        decrypted = self.crypto.decrypt(ciphertext, nonce)
        assert decrypted == content

    def test_encryption_produces_different_ciphertext(self):
        """Each encryption produces unique ciphertext (unique nonce)."""
        content = "Same content"
        ct1, n1 = self.crypto.encrypt(content)
        ct2, n2 = self.crypto.encrypt(content)
        assert ct1 != ct2  # Different ciphertext
        assert n1 != n2    # Different nonce

    def test_wrong_key_fails_decryption(self):
        """Wrong key cannot decrypt content."""
        content = "Secret stuff"
        ct, nonce = self.crypto.encrypt(content)
        wrong_crypto = MemoryCrypto("wrong-key")
        try:
            wrong_crypto.decrypt(ct, nonce)
            assert False, "Should have raised an exception"
        except Exception:
            pass  # Expected

    def test_signing(self):
        """Signature verification works."""
        content_hash = self.crypto.hash_content("Test content")
        signature = self.crypto.sign(content_hash)
        assert self.crypto.verify_signature(content_hash, signature) == True
        assert self.crypto.verify_signature("fake-hash", signature) == False

    def test_merkle_root_single(self):
        """Merkle root of single hash is the hash itself."""
        hashes = ["abc123"]
        root = self.crypto.compute_merkle_root(hashes)
        assert root == "abc123"

    def test_merkle_root_deterministic(self):
        """Same hashes always produce same Merkle root."""
        hashes = ["hash1", "hash2", "hash3", "hash4"]
        root1 = self.crypto.compute_merkle_root(hashes)
        root2 = self.crypto.compute_merkle_root(hashes)
        assert root1 == root2

    def test_merkle_root_changes(self):
        """Changing any hash changes the Merkle root."""
        hashes1 = ["hash1", "hash2", "hash3"]
        hashes2 = ["hash1", "hash2", "TAMPERED"]
        root1 = self.crypto.compute_merkle_root(hashes1)
        root2 = self.crypto.compute_merkle_root(hashes2)
        assert root1 != root2


class TestMemory:
    """Test Memory data model."""

    def test_memory_creation(self):
        """Memory initializes with defaults."""
        m = Memory(content="Hello world")
        assert m.content == "Hello world"
        assert m.status == MemoryStatus.CREATED
        assert m.id is not None
        assert m.created_at is not None

    def test_memory_serialization(self):
        """Memory round-trips through JSON."""
        m = Memory(content="Test", metadata=m.metadata if False else None)
        m = Memory(content="Test content")
        m.hash = "abc123"
        m.status = MemoryStatus.HASHED

        data = m.to_dict()
        restored = Memory.from_dict(data)
        assert restored.content == m.content
        assert restored.hash == m.hash
        assert restored.status == MemoryStatus.HASHED

    def test_dvmem_format(self):
        """Memory exports/imports via .dvmem format."""
        m = Memory(content="Important memory")
        m.hash = "def456"
        m.signature = "sig789"

        dvmem_str = m.to_dvmem()
        dvmem = json.loads(dvmem_str)
        assert dvmem["dvmem_version"] == "1.0"
        assert dvmem["payload"]["content"] == "Important memory"

        restored = Memory.from_dvmem(dvmem_str)
        assert restored.content == m.content
        assert restored.hash == m.hash


class TestMemoryVault:
    """Test the main MemoryVault interface."""

    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.vault = MemoryVault(
            encryption_key="test-key-12345",
            storage_dir=os.path.join(self.tmpdir, "memories"),
            anchor_backend=LocalAnchor(
                storage_dir=os.path.join(self.tmpdir, "anchors")
            ),
        )

    def test_create_memory(self):
        """Creating a memory produces hash, encryption, and signature."""
        memory = self.vault.create(
            content="I started a company today.",
            tags=["milestone", "career"]
        )

        assert memory.hash is not None
        assert memory.encrypted_content is not None
        assert memory.nonce is not None
        assert memory.signature is not None
        assert memory.status == MemoryStatus.SIGNED
        assert "milestone" in memory.metadata.tags

    def test_verify_memory(self):
        """Verification passes for untampered memory."""
        memory = self.vault.create(content="Untampered content")
        assert self.vault.verify(memory) == True

    def test_verify_detects_tampering(self):
        """Verification fails if content is tampered."""
        memory = self.vault.create(content="Original")
        memory.content = "Tampered!"
        assert self.vault.verify(memory) == False

    def test_decrypt_memory(self):
        """Encrypted memories can be decrypted."""
        original = "This is my deepest secret."
        memory = self.vault.create(content=original)
        decrypted = self.vault.decrypt(memory)
        assert decrypted == original

    def test_anchor_memory(self):
        """Memory can be anchored to local backend."""
        memory = self.vault.create(content="Anchor me")
        self.vault.anchor(memory, backend="local")
        assert memory.is_anchored == True
        assert len(memory.anchors) == 1
        assert memory.anchors[0].backend == "local"

    def test_list_memories(self):
        """Memories can be listed and filtered."""
        self.vault.create(content="Entry 1", tags=["daily"])
        self.vault.create(content="Entry 2", tags=["daily", "work"])
        self.vault.create(content="Entry 3", tags=["personal"])

        all_memories = self.vault.list()
        assert len(all_memories) == 3

        daily = self.vault.list(tags=["daily"])
        assert len(daily) == 2

        work = self.vault.list(tags=["work"])
        assert len(work) == 1

    def test_search_memories(self):
        """Full-text search works."""
        self.vault.create(content="Had coffee with Sarah at Blue Bottle")
        self.vault.create(content="Worked on the Python SDK all day")
        self.vault.create(content="Coffee machine broke at the office")

        results = self.vault.search("coffee")
        assert len(results) == 2

    def test_batch_verify(self):
        """Batch verification checks all memories."""
        for i in range(5):
            self.vault.create(content=f"Memory {i}")

        result = self.vault.batch_verify()
        assert result["total"] == 5
        assert result["valid"] == 5
        assert result["invalid"] == 0

    def test_merkle_root(self):
        """Vault computes Merkle root across all memories."""
        self.vault.create(content="Memory 1")
        self.vault.create(content="Memory 2")
        root = self.vault.compute_merkle_root()
        assert root is not None
        assert len(root) == 64

    def test_export_import_memory(self):
        """Memory survives export/import cycle."""
        memory = self.vault.create(
            content="Export me",
            tags=["test"]
        )

        path = os.path.join(self.tmpdir, "export.dvmem")
        self.vault.export_memory(memory, path)
        assert os.path.exists(path)

        # Create new vault and import
        vault2 = MemoryVault(
            encryption_key="test-key-12345",
            storage_dir=os.path.join(self.tmpdir, "vault2"),
        )
        imported = vault2.import_memory(path)
        assert imported.content == "Export me"
        assert imported.hash == memory.hash

    def test_vault_stats(self):
        """Vault reports accurate stats."""
        self.vault.create(content="Entry 1", tags=["a"])
        self.vault.create(content="Entry 2", tags=["b"])
        stats = self.vault.stats

        assert stats["total_memories"] == 2
        assert stats["encrypted"] == 2
        assert set(stats["tags"]) == {"a", "b"}

    def test_vault_persistence(self):
        """Memories persist across vault instances."""
        storage = os.path.join(self.tmpdir, "persist_test")
        vault1 = MemoryVault(encryption_key="key", storage_dir=storage)
        vault1.create(content="Persistent memory")

        # New vault instance, same storage
        vault2 = MemoryVault(encryption_key="key", storage_dir=storage)
        assert len(vault2) == 1


class TestLocalAnchor:
    """Test local anchor backend."""

    def setup_method(self):
        self.tmpdir = tempfile.mkdtemp()
        self.anchor = LocalAnchor(storage_dir=self.tmpdir)

    def test_anchor_and_verify(self):
        """Anchor and verify a hash."""
        result = self.anchor.anchor("mem-1", "hash123", "sig456")
        assert result.backend == "local"
        assert result.anchored_at is not None
        assert self.anchor.verify("mem-1", "hash123") == True
        assert self.anchor.verify("mem-1", "wrong-hash") == False

    def test_retrieve_anchor(self):
        """Retrieve anchor data."""
        self.anchor.anchor("mem-2", "hash789", "sig012")
        data = self.anchor.retrieve("mem-2")
        assert data is not None
        assert data["content_hash"] == "hash789"

    def test_list_anchors(self):
        """List all anchored memories."""
        self.anchor.anchor("mem-1", "h1", "s1")
        self.anchor.anchor("mem-2", "h2", "s2")
        anchors = self.anchor.list_anchors()
        assert len(anchors) == 2


if __name__ == "__main__":
    import pytest
    pytest.main([__file__, "-v"])
