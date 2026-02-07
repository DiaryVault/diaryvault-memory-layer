"""
DiaryVault Memory Layer — Terminal Demo
Records beautifully for GIF/video capture.

Usage:
    pip install diaryvault-memory rich
    python demo.py
"""

import time
import sys

def slow_print(text, delay=0.02):
    """Print text character by character for recording effect."""
    for char in text:
        sys.stdout.write(char)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def pause(seconds=0.8):
    time.sleep(seconds)

def section(title):
    print()
    print(f"\033[1;33m{'─' * 50}\033[0m")
    slow_print(f"\033[1;33m  {title}\033[0m", 0.03)
    print(f"\033[1;33m{'─' * 50}\033[0m")
    pause(0.5)

def cmd(text):
    """Simulate typing a command."""
    sys.stdout.write("\033[1;32m$ \033[0m")
    slow_print(f"\033[1;37m{text}\033[0m", 0.04)
    pause(0.3)

def success(text):
    print(f"  \033[1;32m✓\033[0m {text}")
    pause(0.2)

def fail(text):
    print(f"  \033[1;31m✗\033[0m {text}")
    pause(0.2)

def info(text):
    print(f"  \033[0;36m{text}\033[0m")
    pause(0.1)

def main():
    print()
    print()
    slow_print("\033[1;36m  🧠 DiaryVault Memory Layer\033[0m", 0.04)
    slow_print("\033[0;90m  An open-source memory layer for humans.\033[0m", 0.03)
    pause(1)

    # Install
    section("Install")
    cmd("pip install diaryvault-memory")
    pause(0.3)
    print("\033[0;90m  Successfully installed diaryvault-memory-0.1.0\033[0m")
    pause(0.8)

    # Create vault
    section("Create a vault")
    cmd("python")
    pause(0.3)
    slow_print("\033[0;37m>>> from diaryvault_memory import MemoryVault\033[0m", 0.03)
    pause(0.3)
    slow_print("\033[0;37m>>> vault = MemoryVault(encryption_key=\"my-secret-key\")\033[0m", 0.03)
    pause(0.5)
    success("Vault initialized with AES-256-GCM encryption")
    pause(0.8)

    # Create memory
    section("Create an immutable memory")
    slow_print("\033[0;37m>>> memory = vault.create(\033[0m", 0.03)
    slow_print("\033[0;37m...     content=\"Today I decided to start a company.\",\033[0m", 0.03)
    slow_print("\033[0;37m...     tags=[\"career\", \"milestone\"]\033[0m", 0.03)
    slow_print("\033[0;37m... )\033[0m", 0.03)
    pause(0.5)
    print()
    success("SHA-256 hashed")
    info("Hash: a7f3b261d0f7548e92c1...")
    success("AES-256-GCM encrypted")
    info("Ciphertext: 94 bytes")
    success("HMAC-SHA256 signed")
    info("Signature: 6ef69912ab91...")
    success("Timestamped (RFC 3339)")
    info("Created: 2025-02-07T14:32:01+00:00")
    pause(1)

    # Verify
    section("Verify integrity")
    slow_print("\033[0;37m>>> vault.verify(memory)\033[0m", 0.03)
    pause(0.5)
    success("Content hash matches    \033[1;32mPASS\033[0m")
    success("Signature valid         \033[1;32mPASS\033[0m")
    success("Memory verified         \033[1;32mTrue\033[0m")
    pause(1)

    # Tamper detection
    section("Tamper detection")
    slow_print("\033[0;37m>>> memory.content = \"I NEVER said this.\"\033[0m", 0.03)
    slow_print("\033[0;37m>>> vault.verify(memory)\033[0m", 0.03)
    pause(0.5)
    fail("Content hash mismatch   \033[1;31mFAIL\033[0m")
    fail("Tampering detected      \033[1;31mFalse\033[0m")
    pause(1)

    # Anchor
    section("Anchor to permanent storage")
    slow_print("\033[0;37m>>> vault.anchor(memory, backend=\"local\")\033[0m", 0.03)
    pause(0.5)
    success("Hash anchored to local storage")
    info("Transaction: memory-550e8400...")
    info("Anchored at: 2025-02-07T14:32:05+00:00")
    pause(1)

    # Merkle root
    section("Batch verification")
    slow_print("\033[0;37m>>> vault.compute_merkle_root()\033[0m", 0.03)
    pause(0.5)
    success("Merkle root: 72af4492390...")
    info("1 root hash verifies all memories in vault")
    pause(1)

    # Finish
    print()
    print()
    print(f"\033[1;33m{'─' * 50}\033[0m")
    slow_print("\033[1;36m  Own your life story forever.\033[0m", 0.04)
    print()
    info("pip install diaryvault-memory")
    info("github.com/DiaryVault/diaryvault-memory-layer")
    info("memory.diaryvault.com")
    print(f"\033[1;33m{'─' * 50}\033[0m")
    print()
    pause(2)

if __name__ == "__main__":
    main()
