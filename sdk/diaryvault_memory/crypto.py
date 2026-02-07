"""
Cryptographic operations for the Memory Layer.

All encryption happens client-side. Your keys never leave your device.

Supported operations:
- SHA-256 content hashing
- AES-256-GCM symmetric encryption
- HMAC-SHA256 signing
- Merkle tree batch verification
"""

import hashlib
import hmac
import os
import json
from typing import Optional


class MemoryCrypto:
    """
    Cryptographic engine for memory operations.

    Uses standard, auditable algorithms:
    - SHA-256 for hashing
    - AES-256-GCM for encryption (via cryptography library)
    - HMAC-SHA256 for signing
    """

    def __init__(self, encryption_key: str):
        """
        Initialize with an encryption key.

        Args:
            encryption_key: User's secret key. Used to derive encryption
                          and signing keys. Keep this safe — lose it and
                          your memories are unrecoverable.
        """
        self._master_key = encryption_key.encode("utf-8")
        self._enc_key = self._derive_key(b"encryption")
        self._sign_key = self._derive_key(b"signing")

    def _derive_key(self, purpose: bytes) -> bytes:
        """Derive a purpose-specific key from the master key using HKDF-like construction."""
        return hashlib.sha256(self._master_key + purpose).digest()

    # ── Hashing ──────────────────────────────────────────────────────────

    @staticmethod
    def hash_content(content: str) -> str:
        """
        Compute SHA-256 hash of content.

        This is the fingerprint of your memory. If even one character
        changes, the hash changes completely.

        Args:
            content: The raw text content to hash.

        Returns:
            Hex-encoded SHA-256 hash string.
        """
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    @staticmethod
    def verify_hash(content: str, expected_hash: str) -> bool:
        """
        Verify that content matches its expected hash.

        Args:
            content: The content to verify.
            expected_hash: The hash to check against.

        Returns:
            True if content is untampered.
        """
        actual = hashlib.sha256(content.encode("utf-8")).hexdigest()
        return hmac.compare_digest(actual, expected_hash)

    # ── Encryption ───────────────────────────────────────────────────────

    def encrypt(self, plaintext: str) -> tuple[bytes, bytes]:
        """
        Encrypt content using AES-256-GCM.

        AES-GCM provides both confidentiality and authenticity.
        Each encryption uses a unique nonce (number used once).

        Args:
            plaintext: Content to encrypt.

        Returns:
            Tuple of (ciphertext, nonce). Both needed for decryption.
        """
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            raise ImportError(
                "Install cryptography package: pip install cryptography"
            )

        nonce = os.urandom(12)  # 96-bit nonce for AES-GCM
        aesgcm = AESGCM(self._enc_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
        return ciphertext, nonce

    def decrypt(self, ciphertext: bytes, nonce: bytes) -> str:
        """
        Decrypt content using AES-256-GCM.

        Args:
            ciphertext: The encrypted content.
            nonce: The nonce used during encryption.

        Returns:
            The original plaintext content.

        Raises:
            cryptography.exceptions.InvalidTag: If decryption fails
                (wrong key or tampered ciphertext).
        """
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError:
            raise ImportError(
                "Install cryptography package: pip install cryptography"
            )

        aesgcm = AESGCM(self._enc_key)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode("utf-8")

    # ── Signing ──────────────────────────────────────────────────────────

    def sign(self, content_hash: str) -> str:
        """
        Sign a content hash using HMAC-SHA256.

        The signature proves that the holder of the key created this hash.

        Args:
            content_hash: The SHA-256 hash to sign.

        Returns:
            Hex-encoded HMAC signature.
        """
        return hmac.new(
            self._sign_key,
            content_hash.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

    def verify_signature(self, content_hash: str, signature: str) -> bool:
        """
        Verify an HMAC signature.

        Args:
            content_hash: The hash that was signed.
            signature: The signature to verify.

        Returns:
            True if signature is valid.
        """
        expected = self.sign(content_hash)
        return hmac.compare_digest(expected, signature)

    # ── Merkle Tree ──────────────────────────────────────────────────────

    @staticmethod
    def compute_merkle_root(hashes: list[str]) -> str:
        """
        Compute a Merkle root from a list of content hashes.

        Useful for batch verification — anchor one root hash
        that verifies an entire batch of memories.

        Args:
            hashes: List of hex-encoded SHA-256 hashes.

        Returns:
            The Merkle root hash.
        """
        if not hashes:
            raise ValueError("Cannot compute Merkle root of empty list")
        if len(hashes) == 1:
            return hashes[0]

        # Pad to even length
        current_level = list(hashes)
        if len(current_level) % 2 == 1:
            current_level.append(current_level[-1])

        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                combined = current_level[i] + current_level[i + 1]
                parent = hashlib.sha256(combined.encode("utf-8")).hexdigest()
                next_level.append(parent)
            current_level = next_level
            if len(current_level) > 1 and len(current_level) % 2 == 1:
                current_level.append(current_level[-1])

        return current_level[0]

    @staticmethod
    def compute_merkle_proof(hashes: list[str], target_index: int) -> list[dict]:
        """
        Compute a Merkle proof for a specific hash at target_index.

        The proof allows anyone to verify a single memory's inclusion
        in a batch without seeing all other memories.

        Args:
            hashes: List of all hashes in the batch.
            target_index: Index of the hash to prove.

        Returns:
            List of proof nodes with 'hash' and 'position' (left/right).
        """
        if not hashes or target_index >= len(hashes):
            raise ValueError("Invalid hashes or target index")

        proof = []
        current_level = list(hashes)
        if len(current_level) % 2 == 1:
            current_level.append(current_level[-1])

        idx = target_index

        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                combined = current_level[i] + current_level[i + 1]
                parent = hashlib.sha256(combined.encode("utf-8")).hexdigest()
                next_level.append(parent)

                if i == idx or i + 1 == idx:
                    if i == idx:
                        proof.append({
                            "hash": current_level[i + 1],
                            "position": "right"
                        })
                    else:
                        proof.append({
                            "hash": current_level[i],
                            "position": "left"
                        })

            idx = idx // 2
            current_level = next_level
            if len(current_level) > 1 and len(current_level) % 2 == 1:
                current_level.append(current_level[-1])

        return proof
