"""
DiaryVault Memory Layer.

Portable, tamper-evident memory records with selective context sharing
and AI-ready exports.
"""

from .vault import MemoryVault
from .memory import Memory, MemoryStatus
from .crypto import MemoryCrypto
from .anchors import AnchorBackend, LocalAnchor
from .context import ContextRequest, ContextResponse, SharedMemory
from .export import VaultExporter, RAGChunk, KnowledgeGraph, KnowledgeNode, KnowledgeEdge
from .review import (
    DecisionOutcome,
    ReviewDecision,
    ReviewDraft,
    ReviewState,
    Revision,
    Suggestion,
)


__version__ = "0.3.0"

__all__ = [
    "MemoryVault",
    "Memory",
    "MemoryStatus",
    "MemoryCrypto",
    "AnchorBackend",
    "LocalAnchor",
    "ContextRequest",
    "ContextResponse",
    "SharedMemory",
    "VaultExporter",
    "RAGChunk",
    "KnowledgeGraph",
    "KnowledgeNode",
    "KnowledgeEdge",
    "DecisionOutcome",
    "ReviewDecision",
    "ReviewDraft",
    "ReviewState",
    "Revision",
    "Suggestion",
]
