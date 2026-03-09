"""
Personal AI Export — Transform your vault into AI-ready formats.

Export your memories as:
- Fine-tuning datasets (JSONL for OpenAI, Anthropic, etc.)
- RAG-ready chunks with metadata
- Conversation-format exports
- Personal knowledge graph (nodes + edges)

Usage:
    from diaryvault_memory import MemoryVault
    from diaryvault_memory.export import VaultExporter

    vault = MemoryVault(encryption_key="my-key")
    exporter = VaultExporter(vault)

    # Export for fine-tuning
    exporter.to_jsonl("my_memories.jsonl", format="openai")

    # Export for RAG
    chunks = exporter.to_rag_chunks()

    # Export as knowledge graph
    graph = exporter.to_knowledge_graph()
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from typing import Optional, Literal


@dataclass
class RAGChunk:
    """A single chunk ready for embedding and retrieval."""
    id: str
    content: str
    tags: list[str]
    created_at: str
    hash: str
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class KnowledgeNode:
    """A node in a personal knowledge graph."""
    id: str
    label: str
    node_type: str  # "memory", "tag", "entity", "date"
    properties: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class KnowledgeEdge:
    """An edge connecting two nodes."""
    source: str
    target: str
    relation: str  # "tagged_with", "created_on", "mentions", "related_to"
    properties: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class KnowledgeGraph:
    """A personal knowledge graph built from vault memories."""
    nodes: list[KnowledgeNode] = field(default_factory=list)
    edges: list[KnowledgeEdge] = field(default_factory=list)

    @property
    def node_count(self) -> int:
        return len(self.nodes)

    @property
    def edge_count(self) -> int:
        return len(self.edges)

    def to_dict(self) -> dict:
        return {
            "nodes": [n.to_dict() for n in self.nodes],
            "edges": [e.to_dict() for e in self.edges],
            "stats": {
                "node_count": self.node_count,
                "edge_count": self.edge_count,
            }
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


class VaultExporter:
    """Export vault memories in AI-ready formats."""

    def __init__(self, vault):
        self._vault = vault

    def to_jsonl(
        self,
        path: Optional[str] = None,
        format: Literal["openai", "anthropic", "generic"] = "openai",
        system_prompt: Optional[str] = None,
        tags: Optional[list[str]] = None,
    ) -> list[dict]:
        """
        Export memories as JSONL for fine-tuning.

        Args:
            path: File path to write JSONL. If None, returns list of dicts.
            format: Target format (openai, anthropic, generic).
            system_prompt: Custom system prompt for conversation format.
            tags: Filter to only memories with these tags.

        Returns:
            List of formatted training examples.
        """
        memories = self._get_memories(tags)
        default_system = system_prompt or (
            "You are a personal AI assistant with deep knowledge of the user. "
            "You understand their preferences, experiences, and context. "
            "Respond naturally, as someone who truly knows them."
        )

        examples = []
        for memory in memories:
            if format == "openai":
                example = {
                    "messages": [
                        {"role": "system", "content": default_system},
                        {"role": "user", "content": self._generate_prompt(memory)},
                        {"role": "assistant", "content": memory.content},
                    ]
                }
            elif format == "anthropic":
                example = {
                    "messages": [
                        {"role": "user", "content": self._generate_prompt(memory)},
                        {"role": "assistant", "content": memory.content},
                    ],
                    "system": default_system,
                }
            else:  # generic
                example = {
                    "input": self._generate_prompt(memory),
                    "output": memory.content,
                    "tags": memory.metadata.tags,
                    "created_at": memory.created_at,
                    "hash": memory.hash,
                }

            examples.append(example)

        if path:
            with open(path, 'w') as f:
                for example in examples:
                    f.write(json.dumps(example) + '\n')

        return examples

    def to_rag_chunks(
        self,
        tags: Optional[list[str]] = None,
        include_hash: bool = True,
    ) -> list[RAGChunk]:
        """
        Export memories as RAG-ready chunks with metadata.

        Each chunk includes content, tags, timestamp, and hash
        for retrieval-augmented generation pipelines.
        """
        memories = self._get_memories(tags)
        chunks = []

        for memory in memories:
            chunk = RAGChunk(
                id=memory.id,
                content=memory.content,
                tags=memory.metadata.tags,
                created_at=memory.created_at,
                hash=memory.hash if include_hash else "",
                metadata={
                    "source": "diaryvault",
                    "verified": True,
                    "encrypted_at_rest": True,
                },
            )
            chunks.append(chunk)

        return chunks

    def to_knowledge_graph(
        self,
        tags: Optional[list[str]] = None,
        extract_entities: bool = True,
    ) -> KnowledgeGraph:
        """
        Build a personal knowledge graph from vault memories.

        Creates nodes for memories, tags, and dates.
        Edges represent relationships (tagged_with, created_on).
        """
        memories = self._get_memories(tags)
        graph = KnowledgeGraph()

        tag_nodes = {}
        date_nodes = {}

        for memory in memories:
            # Memory node
            mem_node = KnowledgeNode(
                id=f"mem_{memory.id[:8]}",
                label=memory.content[:60] + ("..." if len(memory.content) > 60 else ""),
                node_type="memory",
                properties={
                    "full_content": memory.content,
                    "hash": memory.hash,
                    "created_at": memory.created_at,
                },
            )
            graph.nodes.append(mem_node)

            # Tag nodes + edges
            for tag in memory.metadata.tags:
                if tag not in tag_nodes:
                    tag_node = KnowledgeNode(
                        id=f"tag_{tag}",
                        label=tag,
                        node_type="tag",
                    )
                    graph.nodes.append(tag_node)
                    tag_nodes[tag] = tag_node

                graph.edges.append(KnowledgeEdge(
                    source=mem_node.id,
                    target=f"tag_{tag}",
                    relation="tagged_with",
                ))

            # Date node + edge
            date_str = memory.created_at[:10]  # YYYY-MM-DD
            if date_str not in date_nodes:
                date_node = KnowledgeNode(
                    id=f"date_{date_str}",
                    label=date_str,
                    node_type="date",
                )
                graph.nodes.append(date_node)
                date_nodes[date_str] = date_node

            graph.edges.append(KnowledgeEdge(
                source=mem_node.id,
                target=f"date_{date_str}",
                relation="created_on",
            ))

            # Entity extraction (simple keyword-based)
            if extract_entities:
                entities = self._extract_entities(memory.content)
                for entity_name, entity_type in entities:
                    entity_id = f"entity_{entity_name.lower().replace(' ', '_')}"
                    # Check if entity node already exists
                    if not any(n.id == entity_id for n in graph.nodes):
                        graph.nodes.append(KnowledgeNode(
                            id=entity_id,
                            label=entity_name,
                            node_type=entity_type,
                        ))
                    graph.edges.append(KnowledgeEdge(
                        source=mem_node.id,
                        target=entity_id,
                        relation="mentions",
                    ))

        return graph

    def to_conversation_history(
        self,
        tags: Optional[list[str]] = None,
    ) -> list[dict]:
        """
        Export as a conversation history format.
        Useful for injecting into LLM context windows.
        """
        memories = self._get_memories(tags)
        history = []

        for memory in memories:
            history.append({
                "role": "user",
                "content": f"[{memory.created_at[:10]}] [{', '.join(memory.metadata.tags)}] {memory.content}",
                "metadata": {
                    "memory_id": memory.id,
                    "hash": memory.hash,
                    "verified": True,
                }
            })

        return history

    def summary(self, tags: Optional[list[str]] = None) -> dict:
        """Get export summary statistics."""
        memories = self._get_memories(tags)
        all_tags = set()
        total_chars = 0
        dates = set()

        for m in memories:
            all_tags.update(m.metadata.tags)
            total_chars += len(m.content)
            dates.add(m.created_at[:10])

        return {
            "total_memories": len(memories),
            "unique_tags": sorted(list(all_tags)),
            "total_characters": total_chars,
            "date_range": {
                "earliest": min(dates) if dates else None,
                "latest": max(dates) if dates else None,
            },
            "avg_memory_length": total_chars // max(len(memories), 1),
            "export_formats": ["openai_jsonl", "anthropic_jsonl", "generic_jsonl", "rag_chunks", "knowledge_graph", "conversation_history"],
        }

    # ── Internal helpers ──────────────────────────

    def _get_memories(self, tags: Optional[list[str]] = None) -> list:
        """Get memories, optionally filtered by tags."""
        all_memories = list(self._vault._memories.values())
        if tags:
            tag_set = set(tags)
            all_memories = [
                m for m in all_memories
                if set(m.metadata.tags).intersection(tag_set)
            ]
        all_memories.sort(key=lambda m: m.created_at)
        return all_memories

    def _generate_prompt(self, memory) -> str:
        """Generate a natural prompt for a memory (for fine-tuning)."""
        tags = memory.metadata.tags
        if "preference" in tags:
            return "What are some of my preferences?"
        elif "health" in tags:
            return "Tell me about my health and wellness."
        elif "work" in tags:
            return "What's going on with my work?"
        elif "financial" in tags:
            return "What do you know about my finances?"
        elif "personal" in tags:
            return "Tell me something personal about myself."
        else:
            return "What do you remember about me?"

    def _extract_entities(self, content: str) -> list[tuple[str, str]]:
        """
        Simple entity extraction from content.
        Returns list of (entity_name, entity_type) tuples.
        """
        entities = []

        # Simple patterns — in production, use spaCy or an LLM
        words = content.split()
        i = 0
        while i < len(words):
            word = words[i]
            # Capitalized words that aren't at sentence start
            if i > 0 and word[0].isupper() and word.isalpha() and len(word) > 2:
                # Check for multi-word entities
                entity = word
                j = i + 1
                while j < len(words) and words[j][0].isupper() and words[j].isalpha():
                    entity += " " + words[j]
                    j += 1
                entities.append((entity, "entity"))
                i = j
            else:
                i += 1

        # Deduplicate
        seen = set()
        unique = []
        for name, etype in entities:
            if name.lower() not in seen:
                seen.add(name.lower())
                unique.append((name, etype))

        return unique
