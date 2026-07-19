"""
DiaryVault Memory Layer — Quick Example

Run this script to see the Memory Layer in action:

    pip install diaryvault-memory
    python example.py
"""

from diaryvault_memory import MemoryVault

# ── Create a vault ───────────────────────────────────────────────
vault = MemoryVault(encryption_key="my-secret-key-change-this")

print("🧠 DiaryVault Memory Layer — Demo\n")

# ── Create some memories ─────────────────────────────────────────
memories = [
    {
        "content": "Started learning Python today. Wrote my first 'Hello World'. Feels like a superpower.",
        "tags": ["coding", "milestone"],
    },
    {
        "content": "Had the best conversation with Dad about his childhood. He grew up without electricity. I never want to forget these stories.",
        "tags": ["family", "important"],
    },
    {
        "content": "Decided to quit my job and start a company. Terrified but excited. Revenue target: $10k/month by December.",
        "tags": ["career", "milestone", "goals"],
    },
]

print("Creating memories...\n")
created = []
for entry in memories:
    memory = vault.create(content=entry["content"], tags=entry["tags"])
    created.append(memory)
    print(f"  ✓ Memory {memory.id[:8]}...")
    print(f"    Hash:      {memory.hash[:24]}...")
    print(f"    Encrypted: {len(memory.encrypted_content)} bytes")
    print(f"    Signed:    {memory.signature[:24]}...")
    print(f"    Tags:      {', '.join(memory.metadata.tags)}")
    print()

# ── Verify integrity ─────────────────────────────────────────────
print("Verifying all memories...")
result = vault.batch_verify()
print(f"  ✓ {result['valid']}/{result['total']} memories verified\n")

# ── Demonstrate tamper detection ─────────────────────────────────
print("Tampering with a memory...")
tampered = created[0]
original_content = tampered.content
tampered.content = "I NEVER SAID THIS"
is_valid = vault.verify(tampered)
print(f"  ✗ Tampered memory valid? {is_valid}")
tampered.content = original_content  # restore
print(f"  ✓ Original memory valid? {vault.verify(tampered)}\n")

# ── Search memories ──────────────────────────────────────────────
print("Searching for 'company'...")
results = vault.search("company")
print(f"  Found {len(results)} result(s):")
for r in results:
    print(f"    → {r.content[:60]}...\n")

# ── Decrypt a memory ─────────────────────────────────────────────
print("Decrypting memory...")
decrypted = vault.decrypt(created[1])
print(f"  ✓ {decrypted[:60]}...\n")

# ── Anchor to local storage ──────────────────────────────────────
print("Anchoring to local storage...")
vault.anchor(created[2], backend="local")
print(f"  ✓ Anchored: {created[2].anchors[0].backend}")
print(f"    Tx ID:    {created[2].anchors[0].transaction_id[:24]}...\n")

# ── Merkle root ──────────────────────────────────────────────────
root = vault.compute_merkle_root()
print(f"Vault Merkle root: {root[:32]}...")
print(f"  (This single hash verifies all {len(vault)} memories)\n")

# ── Export ────────────────────────────────────────────────────────
print("Exporting memory to .dvmem format...")
path = vault.export_memory(created[2], "/tmp/my-memory.dvmem")
print(f"  ✓ Saved to {path}\n")

# ── Stats ────────────────────────────────────────────────────────
stats = vault.stats
print("Vault stats:")
print(f"  Total memories: {stats['total_memories']}")
print(f"  Encrypted:      {stats['encrypted']}")
print(f"  Anchored:       {stats['anchored']}")
print(f"  Tags:           {', '.join(stats['tags'])}")

print("\n✨ Done! Your memories are hashed, encrypted, signed, and verified.")
print("   Learn more: https://memory.diaryvault.com")
