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
from .review import (
    ApprovalRecord,
    DraftRevision,
    DraftStatus,
    MemoryDraft,
    MemorySuggestion,
    SuggestionStatus,
)
from .export import VaultExporter, RAGChunk, KnowledgeGraph, KnowledgeNode, KnowledgeEdge


__version__ = "0.4.0"

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
    "ApprovalRecord",
    "DraftRevision",
    "DraftStatus",
    "MemoryDraft",
    "MemorySuggestion",
    "SuggestionStatus",
    "VaultExporter",
    "RAGChunk",
    "KnowledgeGraph",
    "KnowledgeNode",
    "KnowledgeEdge",
]
