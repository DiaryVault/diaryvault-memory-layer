"""
DiaryVault Memory Layer — An open-source memory layer for humans.

Cryptographically verified, encrypted, permanent memory records.
https://github.com/diaryvault/memory-layer
"""

__version__ = "0.2.0"

from .vault import MemoryVault
from .memory import Memory, MemoryStatus
from .crypto import MemoryCrypto
from .anchors import AnchorBackend, LocalAnchor
from .context import ContextRequest, ContextResponse, SharedMemory

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
]
