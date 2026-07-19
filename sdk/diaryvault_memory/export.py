"""Export memories into portable and AI-ready formats."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Literal, Optional


@dataclass
class RAGChunk:
    """A chunk ready for embedding and retrieval."""

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
    node_type: str
    properties: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class KnowledgeEdge:
    """An edge connecting graph nodes."""

    source: str
    target: str
    relation: str
    properties: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class KnowledgeGraph:
    """A graph built from vault memories."""

    nodes: list[KnowledgeNode] = field(
        default_factory=list
    )
    edges: list[KnowledgeEdge] = field(
        default_factory=list
    )

    @property
    def node_count(self) -> int:
        return len(self.nodes)

    @property
    def edge_count(self) -> int:
        return len(self.edges)

    def to_dict(self) -> dict:
        return {
            "nodes": [
                node.to_dict()
                for node in self.nodes
            ],
            "edges": [
                edge.to_dict()
                for edge in self.edges
            ],
            "stats": {
                "node_count": self.node_count,
                "edge_count": self.edge_count,
            },
        }

    def to_json(
        self,
        indent: int = 2,
    ) -> str:
        return json.dumps(
            self.to_dict(),
            indent=indent,
        )


class VaultExporter:
    """Export memories with optional approval filtering."""

    def __init__(self, vault):
        self._vault = vault

    def to_jsonl(
        self,
        path: Optional[str] = None,
        format: Literal[
            "openai",
            "anthropic",
            "generic",
        ] = "openai",
        system_prompt: Optional[str] = None,
        tags: Optional[list[str]] = None,
        approved_only: bool = False,
    ) -> list[dict]:
        """Export selected memories as JSONL."""
        memories = self._get_memories(
            tags,
            approved_only=approved_only,
        )

        default_system = system_prompt or (
            "You are a personal AI assistant "
            "using memory records selected by "
            "the user. Distinguish confirmed "
            "records from model inference and "
            "do not invent missing details."
        )

        examples = []

        for memory in memories:
            approval = self._approval_metadata(
                memory
            )

            if format == "openai":
                example = {
                    "messages": [
                        {
                            "role": "system",
                            "content": (
                                default_system
                            ),
                        },
                        {
                            "role": "user",
                            "content": (
                                self._generate_prompt(
                                    memory
                                )
                            ),
                        },
                        {
                            "role": "assistant",
                            "content": memory.content,
                        },
                    ]
                }

            elif format == "anthropic":
                example = {
                    "messages": [
                        {
                            "role": "user",
                            "content": (
                                self._generate_prompt(
                                    memory
                                )
                            ),
                        },
                        {
                            "role": "assistant",
                            "content": memory.content,
                        },
                    ],
                    "system": default_system,
                }

            else:
                example = {
                    "input": self._generate_prompt(
                        memory
                    ),
                    "output": memory.content,
                    "tags": (
                        memory.metadata.tags
                    ),
                    "created_at": (
                        memory.created_at
                    ),
                    "hash": memory.hash,
                    "approval": approval,
                }

            examples.append(example)

        if path:
            with open(path, "w") as file:
                for example in examples:
                    file.write(
                        json.dumps(example)
                        + "\n"
                    )

        return examples

    def to_rag_chunks(
        self,
        tags: Optional[list[str]] = None,
        include_hash: bool = True,
        approved_only: bool = False,
    ) -> list[RAGChunk]:
        """Export RAG chunks with trust metadata."""
        memories = self._get_memories(
            tags,
            approved_only=approved_only,
        )

        chunks = []

        for memory in memories:
            approval = self._approval_metadata(
                memory
            )

            chunks.append(
                RAGChunk(
                    id=memory.id,
                    content=memory.content,
                    tags=memory.metadata.tags,
                    created_at=(
                        memory.created_at
                    ),
                    hash=(
                        memory.hash
                        if include_hash
                        else ""
                    ),
                    metadata={
                        "source": "diaryvault",
                        "verified": (
                            self._vault.verify(
                                memory
                            )
                        ),
                        "encrypted_at_rest": (
                            bool(
                                memory
                                .encrypted_content
                            )
                        ),
                        "approved": (
                            approval["approved"]
                        ),
                        "approval_id": (
                            approval.get(
                                "approval_id"
                            )
                        ),
                        "draft_id": (
                            approval.get(
                                "draft_id"
                            )
                        ),
                    },
                )
            )

        return chunks

    def to_knowledge_graph(
        self,
        tags: Optional[list[str]] = None,
        extract_entities: bool = True,
        approved_only: bool = False,
    ) -> KnowledgeGraph:
        """Build a graph from selected memories."""
        memories = self._get_memories(
            tags,
            approved_only=approved_only,
        )

        graph = KnowledgeGraph()
        tag_nodes = {}
        date_nodes = {}

        for memory in memories:
            approval = self._approval_metadata(
                memory
            )

            mem_node = KnowledgeNode(
                id=f"mem_{memory.id[:8]}",
                label=(
                    memory.content[:60]
                    + (
                        "..."
                        if len(memory.content)
                        > 60
                        else ""
                    )
                ),
                node_type="memory",
                properties={
                    "full_content": (
                        memory.content
                    ),
                    "hash": memory.hash,
                    "created_at": (
                        memory.created_at
                    ),
                    "approved": (
                        approval["approved"]
                    ),
                    "approval_id": (
                        approval.get(
                            "approval_id"
                        )
                    ),
                    "draft_id": (
                        approval.get(
                            "draft_id"
                        )
                    ),
                },
            )

            graph.nodes.append(mem_node)

            for tag in memory.metadata.tags:
                if tag not in tag_nodes:
                    tag_node = KnowledgeNode(
                        id=f"tag_{tag}",
                        label=tag,
                        node_type="tag",
                    )
                    graph.nodes.append(
                        tag_node
                    )
                    tag_nodes[tag] = (
                        tag_node
                    )

                graph.edges.append(
                    KnowledgeEdge(
                        source=mem_node.id,
                        target=f"tag_{tag}",
                        relation=(
                            "tagged_with"
                        ),
                    )
                )

            date_str = (
                memory.created_at[:10]
            )

            if date_str not in date_nodes:
                date_node = KnowledgeNode(
                    id=f"date_{date_str}",
                    label=date_str,
                    node_type="date",
                )

                graph.nodes.append(date_node)
                date_nodes[date_str] = (
                    date_node
                )

            graph.edges.append(
                KnowledgeEdge(
                    source=mem_node.id,
                    target=(
                        f"date_{date_str}"
                    ),
                    relation="created_on",
                )
            )

            if extract_entities:
                entities = (
                    self._extract_entities(
                        memory.content
                    )
                )

                for (
                    entity_name,
                    entity_type,
                ) in entities:
                    entity_id = (
                        "entity_"
                        + entity_name.lower()
                        .replace(" ", "_")
                    )

                    if not any(
                        node.id == entity_id
                        for node in graph.nodes
                    ):
                        graph.nodes.append(
                            KnowledgeNode(
                                id=entity_id,
                                label=entity_name,
                                node_type=(
                                    entity_type
                                ),
                            )
                        )

                    graph.edges.append(
                        KnowledgeEdge(
                            source=(
                                mem_node.id
                            ),
                            target=entity_id,
                            relation=(
                                "mentions"
                            ),
                        )
                    )

        return graph

    def to_conversation_history(
        self,
        tags: Optional[list[str]] = None,
        approved_only: bool = False,
    ) -> list[dict]:
        """Export selected memories as context."""
        memories = self._get_memories(
            tags,
            approved_only=approved_only,
        )

        history = []

        for memory in memories:
            approval = self._approval_metadata(
                memory
            )

            history.append(
                {
                    "role": "user",
                    "content": (
                        f"[{memory.created_at[:10]}] "
                        f"[{', '.join(memory.metadata.tags)}] "
                        f"{memory.content}"
                    ),
                    "metadata": {
                        "memory_id": (
                            memory.id
                        ),
                        "hash": memory.hash,
                        "verified": (
                            self._vault.verify(
                                memory
                            )
                        ),
                        "approved": (
                            approval["approved"]
                        ),
                        "approval_id": (
                            approval.get(
                                "approval_id"
                            )
                        ),
                        "draft_id": (
                            approval.get(
                                "draft_id"
                            )
                        ),
                    },
                }
            )

        return history

    def to_approved_manifest(
        self,
        tags: Optional[list[str]] = None,
    ) -> list[dict]:
        """Export manifests for approved memories."""
        memories = self._get_memories(
            tags,
            approved_only=True,
        )

        manifests = []

        for memory in memories:
            review = (
                memory.metadata.custom.get(
                    "review",
                    {},
                )
            )

            manifests.append(
                {
                    "manifest_version": "1.0",
                    "memory_id": memory.id,
                    "hash": memory.hash,
                    "created_at": (
                        memory.created_at
                    ),
                    "tags": list(
                        memory.metadata.tags
                    ),
                    "review": review,
                }
            )

        return manifests

    def summary(
        self,
        tags: Optional[list[str]] = None,
        approved_only: bool = False,
    ) -> dict:
        """Get export summary statistics."""
        memories = self._get_memories(
            tags,
            approved_only=approved_only,
        )

        all_tags = set()
        total_chars = 0
        dates = set()

        for memory in memories:
            all_tags.update(
                memory.metadata.tags
            )
            total_chars += len(
                memory.content
            )
            dates.add(
                memory.created_at[:10]
            )

        return {
            "total_memories": len(memories),
            "approved_only": approved_only,
            "unique_tags": sorted(all_tags),
            "total_characters": total_chars,
            "date_range": {
                "earliest": (
                    min(dates)
                    if dates
                    else None
                ),
                "latest": (
                    max(dates)
                    if dates
                    else None
                ),
            },
            "avg_memory_length": (
                total_chars
                // max(len(memories), 1)
            ),
            "export_formats": [
                "openai_jsonl",
                "anthropic_jsonl",
                "generic_jsonl",
                "rag_chunks",
                "knowledge_graph",
                "conversation_history",
                "approved_manifest",
            ],
        }

    def _get_memories(
        self,
        tags: Optional[list[str]] = None,
        approved_only: bool = False,
    ) -> list:
        all_memories = list(
            self._vault._memories.values()
        )

        if tags:
            tag_set = set(tags)

            all_memories = [
                memory
                for memory in all_memories
                if set(
                    memory.metadata.tags
                ).intersection(tag_set)
            ]

        if approved_only:
            all_memories = [
                memory
                for memory in all_memories
                if self._approval_metadata(
                    memory
                )["approved"]
            ]

        all_memories.sort(
            key=lambda memory: (
                memory.created_at
            )
        )

        return all_memories

    @staticmethod
    def _approval_metadata(
        memory,
    ) -> dict:
        review = (
            memory.metadata.custom.get(
                "review",
                {},
            )
        )

        approval = (
            review.get("approval")
            or {}
        )

        return {
            "approved": bool(
                review.get("approved")
            ),
            "approval_id": approval.get(
                "approval_id"
            ),
            "approved_at": approval.get(
                "approved_at"
            ),
            "approved_by": approval.get(
                "actor"
            ),
            "draft_id": review.get(
                "draft_id"
            ),
        }

    @staticmethod
    def _generate_prompt(memory) -> str:
        tags = memory.metadata.tags

        if "preference" in tags:
            return (
                "What are some of my "
                "preferences?"
            )

        if "health" in tags:
            return (
                "Tell me about my health "
                "and wellness."
            )

        if "work" in tags:
            return (
                "What's going on with "
                "my work?"
            )

        if "financial" in tags:
            return (
                "What do you know about "
                "my finances?"
            )

        if "personal" in tags:
            return (
                "Tell me something personal "
                "about myself."
            )

        return "What do you remember about me?"

    @staticmethod
    def _extract_entities(
        content: str,
    ) -> list[tuple[str, str]]:
        entities = []
        words = content.split()
        index = 0

        while index < len(words):
            word = words[index]

            if (
                index > 0
                and word
                and word[0].isupper()
                and word.isalpha()
                and len(word) > 2
            ):
                entity = word
                next_index = index + 1

                while (
                    next_index < len(words)
                    and words[next_index]
                    and words[
                        next_index
                    ][0].isupper()
                    and words[
                        next_index
                    ].isalpha()
                ):
                    entity += (
                        " "
                        + words[next_index]
                    )
                    next_index += 1

                entities.append(
                    (entity, "entity")
                )
                index = next_index

            else:
                index += 1

        seen = set()
        unique = []

        for name, entity_type in entities:
            if name.lower() not in seen:
                seen.add(name.lower())
                unique.append(
                    (name, entity_type)
                )

        return unique
