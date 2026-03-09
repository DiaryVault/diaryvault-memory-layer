"""
Tests for Personal AI Export (v0.3).
"""
import json
import os
import tempfile
import unittest
from diaryvault_memory import (
    MemoryVault,
    VaultExporter,
    RAGChunk,
    KnowledgeGraph,
)


class TestVaultExporter(unittest.TestCase):
    """Tests for the VaultExporter."""

    def setUp(self):
        import tempfile
        self.tmpdir = tempfile.mkdtemp()
        self.vault = MemoryVault(encryption_key="test-export-key", storage_dir=self.tmpdir)
        self.vault.create("I prefer dark mode and minimal UI", tags=["preference"])
        self.vault.create("Meeting with client about Q2 targets", tags=["work"])
        self.vault.create("Ran 5km this morning, felt great", tags=["health"])
        self.vault.create("Annual salary is 150k at TechCorp", tags=["financial"])
        self.vault.create("Love working from coffee shops in Seoul", tags=["preference", "work"])
        self.vault.create("Started learning Korean last month", tags=["personal"])
        self.exporter = VaultExporter(self.vault)

    def test_summary(self):
        summary = self.exporter.summary()
        self.assertEqual(summary["total_memories"], 6)
        self.assertIn("preference", summary["unique_tags"])
        self.assertIn("work", summary["unique_tags"])
        self.assertGreater(summary["total_characters"], 0)
        self.assertEqual(len(summary["export_formats"]), 6)

    def test_summary_filtered_by_tags(self):
        summary = self.exporter.summary(tags=["work"])
        self.assertEqual(summary["total_memories"], 2)

    # ── JSONL Export ──────────────────────────

    def test_to_jsonl_openai(self):
        examples = self.exporter.to_jsonl(format="openai")
        self.assertEqual(len(examples), 6)
        for ex in examples:
            self.assertIn("messages", ex)
            self.assertEqual(len(ex["messages"]), 3)
            self.assertEqual(ex["messages"][0]["role"], "system")
            self.assertEqual(ex["messages"][1]["role"], "user")
            self.assertEqual(ex["messages"][2]["role"], "assistant")

    def test_to_jsonl_anthropic(self):
        examples = self.exporter.to_jsonl(format="anthropic")
        self.assertEqual(len(examples), 6)
        for ex in examples:
            self.assertIn("messages", ex)
            self.assertIn("system", ex)

    def test_to_jsonl_generic(self):
        examples = self.exporter.to_jsonl(format="generic")
        for ex in examples:
            self.assertIn("input", ex)
            self.assertIn("output", ex)
            self.assertIn("tags", ex)
            self.assertIn("hash", ex)

    def test_to_jsonl_with_tags_filter(self):
        examples = self.exporter.to_jsonl(format="openai", tags=["health"])
        self.assertEqual(len(examples), 1)

    def test_to_jsonl_writes_file(self):
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as f:
            path = f.name
        try:
            self.exporter.to_jsonl(path=path, format="openai")
            with open(path, 'r') as f:
                lines = f.readlines()
            self.assertEqual(len(lines), 6)
            for line in lines:
                parsed = json.loads(line)
                self.assertIn("messages", parsed)
        finally:
            os.unlink(path)

    def test_to_jsonl_custom_system_prompt(self):
        examples = self.exporter.to_jsonl(
            format="openai",
            system_prompt="You are Stephen's personal AI."
        )
        self.assertEqual(examples[0]["messages"][0]["content"], "You are Stephen's personal AI.")

    # ── RAG Chunks ────────────────────────────

    def test_to_rag_chunks(self):
        chunks = self.exporter.to_rag_chunks()
        self.assertEqual(len(chunks), 6)
        for chunk in chunks:
            self.assertIsInstance(chunk, RAGChunk)
            self.assertGreater(len(chunk.content), 0)
            self.assertGreater(len(chunk.tags), 0)
            self.assertGreater(len(chunk.hash), 0)
            self.assertEqual(chunk.metadata["source"], "diaryvault")

    def test_to_rag_chunks_filtered(self):
        chunks = self.exporter.to_rag_chunks(tags=["preference"])
        self.assertEqual(len(chunks), 2)

    def test_to_rag_chunks_no_hash(self):
        chunks = self.exporter.to_rag_chunks(include_hash=False)
        for chunk in chunks:
            self.assertEqual(chunk.hash, "")

    # ── Knowledge Graph ───────────────────────

    def test_to_knowledge_graph(self):
        graph = self.exporter.to_knowledge_graph()
        self.assertIsInstance(graph, KnowledgeGraph)
        self.assertGreater(graph.node_count, 6)  # memories + tags + dates
        self.assertGreater(graph.edge_count, 6)  # at least tagged_with + created_on

    def test_knowledge_graph_has_memory_nodes(self):
        graph = self.exporter.to_knowledge_graph()
        memory_nodes = [n for n in graph.nodes if n.node_type == "memory"]
        self.assertEqual(len(memory_nodes), 6)

    def test_knowledge_graph_has_tag_nodes(self):
        graph = self.exporter.to_knowledge_graph()
        tag_nodes = [n for n in graph.nodes if n.node_type == "tag"]
        tag_labels = {n.label for n in tag_nodes}
        self.assertIn("preference", tag_labels)
        self.assertIn("work", tag_labels)
        self.assertIn("health", tag_labels)

    def test_knowledge_graph_has_date_nodes(self):
        graph = self.exporter.to_knowledge_graph()
        date_nodes = [n for n in graph.nodes if n.node_type == "date"]
        self.assertGreater(len(date_nodes), 0)

    def test_knowledge_graph_edges(self):
        graph = self.exporter.to_knowledge_graph()
        relations = {e.relation for e in graph.edges}
        self.assertIn("tagged_with", relations)
        self.assertIn("created_on", relations)

    def test_knowledge_graph_to_json(self):
        graph = self.exporter.to_knowledge_graph()
        json_str = graph.to_json()
        parsed = json.loads(json_str)
        self.assertIn("nodes", parsed)
        self.assertIn("edges", parsed)
        self.assertIn("stats", parsed)

    def test_knowledge_graph_no_entities(self):
        graph = self.exporter.to_knowledge_graph(extract_entities=False)
        entity_nodes = [n for n in graph.nodes if n.node_type == "entity"]
        self.assertEqual(len(entity_nodes), 0)

    # ── Conversation History ──────────────────

    def test_to_conversation_history(self):
        history = self.exporter.to_conversation_history()
        self.assertEqual(len(history), 6)
        for msg in history:
            self.assertEqual(msg["role"], "user")
            self.assertIn("metadata", msg)
            self.assertTrue(msg["metadata"]["verified"])

    def test_to_conversation_history_filtered(self):
        history = self.exporter.to_conversation_history(tags=["work"])
        self.assertEqual(len(history), 2)


if __name__ == "__main__":
    unittest.main()
