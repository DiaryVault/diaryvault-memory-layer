"""
Tests for the Agent Context Layer (v0.2).
"""
import json
import unittest
from diaryvault_memory import (
    MemoryVault,
    ContextRequest,
    ContextResponse,
    SharedMemory,
)


class TestContextRequest(unittest.TestCase):
    """Tests for ContextRequest creation and serialization."""

    def test_create_request(self):
        req = ContextRequest(
            agent_id="test-agent-001",
            scope=["preference", "work"],
            purpose="Personalize scheduling",
        )
        self.assertEqual(req.agent_id, "test-agent-001")
        self.assertEqual(req.scope, ["preference", "work"])
        self.assertEqual(req.purpose, "Personalize scheduling")
        self.assertIsNotNone(req.request_id)
        self.assertIsNotNone(req.requested_at)

    def test_request_defaults(self):
        req = ContextRequest(agent_id="agent-1")
        self.assertEqual(req.scope, [])
        self.assertEqual(req.purpose, "")
        self.assertEqual(req.max_memories, 10)

    def test_request_serialization(self):
        req = ContextRequest(
            agent_id="agent-1",
            scope=["health"],
            purpose="Track wellness",
        )
        data = req.to_dict()
        self.assertEqual(data["agent_id"], "agent-1")
        self.assertEqual(data["scope"], ["health"])

    def test_request_json_roundtrip(self):
        req = ContextRequest(
            agent_id="agent-1",
            scope=["work", "preference"],
            purpose="Meeting prep",
        )
        json_str = req.to_json()
        restored = ContextRequest.from_json(json_str)
        self.assertEqual(restored.agent_id, req.agent_id)
        self.assertEqual(restored.scope, req.scope)
        self.assertEqual(restored.request_id, req.request_id)


class TestSharedMemory(unittest.TestCase):
    """Tests for SharedMemory data class."""

    def test_create_shared_memory(self):
        sm = SharedMemory(
            memory_id="mem-1",
            content="Test content",
            tags=["work"],
            hash="abc123",
            signature="sig456",
            created_at="2026-03-09T00:00:00Z",
            verified=True,
        )
        self.assertEqual(sm.memory_id, "mem-1")
        self.assertTrue(sm.verified)

    def test_shared_memory_to_dict(self):
        sm = SharedMemory(
            memory_id="mem-1",
            content="Test",
            tags=["work"],
            hash="abc",
            signature="sig",
            created_at="2026-03-09T00:00:00Z",
        )
        data = sm.to_dict()
        self.assertIn("memory_id", data)
        self.assertIn("hash", data)
        self.assertFalse(data["verified"])


class TestContextResponse(unittest.TestCase):
    """Tests for ContextResponse creation and verification."""

    def test_create_response(self):
        resp = ContextResponse(
            request_id="req-1",
            agent_id="agent-1",
            scope_granted=["work"],
            scope_denied=["health"],
        )
        self.assertEqual(resp.memory_count, 0)
        self.assertTrue(resp.verify_all())

    def test_verify_all_with_verified_memories(self):
        memories = [
            SharedMemory("m1", "content1", ["work"], "h1", "s1", "2026-01-01", verified=True),
            SharedMemory("m2", "content2", ["work"], "h2", "s2", "2026-01-02", verified=True),
        ]
        resp = ContextResponse(
            request_id="req-1",
            agent_id="agent-1",
            shared_memories=memories,
        )
        self.assertTrue(resp.verify_all())
        self.assertEqual(resp.memory_count, 2)

    def test_verify_all_fails_with_unverified(self):
        memories = [
            SharedMemory("m1", "content1", ["work"], "h1", "s1", "2026-01-01", verified=True),
            SharedMemory("m2", "content2", ["work"], "h2", "s2", "2026-01-02", verified=False),
        ]
        resp = ContextResponse(
            request_id="req-1",
            agent_id="agent-1",
            shared_memories=memories,
        )
        self.assertFalse(resp.verify_all())

    def test_response_json_roundtrip(self):
        memories = [
            SharedMemory("m1", "content", ["work"], "h1", "s1", "2026-01-01", verified=True),
        ]
        resp = ContextResponse(
            request_id="req-1",
            agent_id="agent-1",
            shared_memories=memories,
            scope_granted=["work"],
            scope_denied=["health"],
            vault_merkle_root="merkle123",
        )
        json_str = resp.to_json()
        restored = ContextResponse.from_json(json_str)
        self.assertEqual(restored.request_id, resp.request_id)
        self.assertEqual(restored.memory_count, 1)
        self.assertEqual(restored.scope_granted, ["work"])
        self.assertTrue(restored.shared_memories[0].verified)

    def test_response_repr(self):
        resp = ContextResponse(
            request_id="req-1",
            agent_id="agent-1",
            scope_granted=["work"],
        )
        self.assertIn("memories=0", repr(resp))
        self.assertIn("verified=True", repr(resp))


class TestVaultShare(unittest.TestCase):
    """Integration tests for vault.share() with the context layer."""

    def setUp(self):
        self.vault = MemoryVault(encryption_key="test-key-for-context-layer")
        # Create test memories with different tags
        self.vault.create("I prefer dark mode and minimal UI", tags=["preference"])
        self.vault.create("Meeting with client at 3pm about Q2 targets", tags=["work"])
        self.vault.create("Ran 5km this morning, felt great", tags=["health"])
        self.vault.create("Annual salary is $150k", tags=["financial"])
        self.vault.create("Love working from coffee shops", tags=["preference", "work"])

    def test_share_basic(self):
        request = ContextRequest(
            agent_id="scheduler-agent",
            scope=["work"],
            purpose="Schedule meetings",
        )
        response = self.vault.share(request)
        self.assertEqual(response.agent_id, "scheduler-agent")
        self.assertIn("work", response.scope_granted)
        self.assertTrue(response.verify_all())
        # Should get 2 memories (pure work + work+preference)
        self.assertGreaterEqual(response.memory_count, 1)

    def test_share_multiple_scopes(self):
        request = ContextRequest(
            agent_id="personal-assistant",
            scope=["preference", "work"],
            purpose="Personalize experience",
        )
        response = self.vault.share(request)
        self.assertGreaterEqual(response.memory_count, 3)
        self.assertTrue(response.verify_all())

    def test_share_denied_tags(self):
        request = ContextRequest(
            agent_id="wellness-agent",
            scope=["health", "financial"],
            purpose="Health tracking",
        )
        response = self.vault.share(
            request,
            allowed_tags=["health"],
            denied_tags=["financial"],
        )
        self.assertIn("health", response.scope_granted)
        self.assertIn("financial", response.scope_denied)
        # Should only get health memory, not financial
        for mem in response.shared_memories:
            self.assertNotIn("financial", mem.tags)

    def test_share_empty_scope(self):
        request = ContextRequest(
            agent_id="empty-agent",
            scope=["nonexistent_tag"],
            purpose="Test empty results",
        )
        response = self.vault.share(request)
        self.assertEqual(response.memory_count, 0)
        self.assertTrue(response.verify_all())

    def test_share_max_memories(self):
        request = ContextRequest(
            agent_id="limited-agent",
            scope=["preference", "work", "health"],
            max_memories=2,
        )
        response = self.vault.share(request)
        self.assertLessEqual(response.memory_count, 2)

    def test_share_includes_merkle_root(self):
        request = ContextRequest(
            agent_id="verifier-agent",
            scope=["work"],
        )
        response = self.vault.share(request)
        self.assertIsNotNone(response.vault_merkle_root)
        self.assertTrue(len(response.vault_merkle_root) > 0)

    def test_share_memories_have_hashes(self):
        request = ContextRequest(
            agent_id="crypto-agent",
            scope=["preference"],
        )
        response = self.vault.share(request)
        for mem in response.shared_memories:
            self.assertIsNotNone(mem.hash)
            self.assertIsNotNone(mem.signature)
            self.assertTrue(len(mem.hash) > 0)
            self.assertTrue(len(mem.signature) > 0)

    def test_share_all_memories_verified(self):
        request = ContextRequest(
            agent_id="trust-agent",
            scope=["preference", "work", "health"],
        )
        response = self.vault.share(request)
        for mem in response.shared_memories:
            self.assertTrue(mem.verified)

    def test_share_denied_overrides_allowed(self):
        request = ContextRequest(
            agent_id="strict-agent",
            scope=["preference", "work", "health", "financial"],
        )
        response = self.vault.share(
            request,
            denied_tags=["health", "financial"],
        )
        self.assertIn("health", response.scope_denied)
        self.assertIn("financial", response.scope_denied)
        for mem in response.shared_memories:
            self.assertNotIn("health", mem.tags)
            self.assertNotIn("financial", mem.tags)


if __name__ == "__main__":
    unittest.main()
