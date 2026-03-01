# 🧠 DiaryVault Memory Layer

**Give agents context without giving up your data.**

An open-source, cryptographically verified memory layer that lets AI agents access user context — with selective sharing, hash verification, and full user control.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE) [![CI](https://img.shields.io/badge/CI-passing-brightgreen)]() [![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)]() [![PyPI](https://img.shields.io/pypi/v/diaryvault-memory)]() [![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)]()

---

## The Problem

AI agents are everywhere. They schedule your meetings, manage your tasks, and make decisions on your behalf. But they all face the same problem: **they don't know anything about you.**

Right now:
- **Agents** own execution and behavior
- **Platforms** own memory (logs, embeddings, context)
- **Users** own nothing durable or portable

Every platform stores its own version of "you" — and you can't verify it, control it, move it, or prove it hasn't been tampered with.

**There is no canonical user-owned memory layer. Until now.**

---

## Quick Start

```bash
pip install diaryvault-memory
```

### Create your vault

```python
from diaryvault_memory import MemoryVault

vault = MemoryVault(encryption_key="your-secret-key")

vault.create(content="I'm allergic to shellfish", tags=["health"])
vault.create(content="I work at a fintech startup in Seoul", tags=["work"])
vault.create(content="I prefer morning meetings before 10am", tags=["preference"])
vault.create(content="My salary is 150k", tags=["financial", "private"])
```

Every memory is SHA-256 hashed, AES-256 encrypted, HMAC signed, and timestamped.

### Share context with an agent — selectively

```python
from diaryvault_memory import ContextRequest

# Agent requests context
request = ContextRequest(
    agent_id="scheduling-agent-001",
    scope=["preference", "work"],
    purpose="Personalize meeting scheduling",
)

# User controls what gets shared (health and financial data blocked)
response = vault.share(request, denied_tags=["health", "financial", "private"])

print(response.memory_count)    # 2 (only preference + work)
print(response.scope_granted)   # ['preference', 'work']
print(response.scope_denied)    # []
print(response.verify_all())    # True — every memory is hash-verified

# Agent gets verified context:
for mem in response.shared_memories:
    print(f"  [{', '.join(mem.tags)}] {mem.content} (verified={mem.verified})")
    # [preference] I prefer morning meetings before 10am (verified=True)
    # [work] I work at a fintech startup in Seoul (verified=True)

# Agent CANNOT see: health data, salary, anything you didn't approve
```

The agent gets cryptographic proof that the context is authentic and unmodified. The user keeps full control of what gets shared.

---

## Why This Matters

| Today | With DiaryVault Memory Layer |
|---|---|
| Each platform stores its own version of you | You own one canonical memory vault |
| You can't verify what agents "remember" about you | Every memory is SHA-256 hashed and verifiable |
| Context is siloed and non-portable | Open `.dvmem` format — export and move freely |
| Platforms can modify your data without your knowledge | HMAC signatures detect any tampering |
| Agents get everything or nothing | Selective sharing by tags — you choose what to share |
| No proof of when data was created | RFC 3339 timestamps with optional blockchain anchoring |

---

## How It Works

```
┌─────────────────────────────────────────────────────────┐
│                    USER'S VAULT                          │
│  preferences · health · work · financial · personal     │
│  All encrypted. All hashed. All signed.                 │
└─────────────────┬───────────────────────────────────────┘
                  │
          Agent requests context
          (scope + purpose)
                  │
                  ▼
┌─────────────────────────────────────────────────────────┐
│              SELECTIVE SHARING                            │
│  User (or policy) decides what tags to share             │
│  Denied tags are never exposed                           │
│  Each shared memory includes hash + signature            │
└─────────────────┬───────────────────────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────────────────────┐
│              VERIFIED CONTEXT                             │
│  Agent receives: content + hash + signature              │
│  Agent can verify: integrity, authenticity               │
│  Agent cannot: access other memories, forge proofs       │
│  Vault merkle root included for full integrity check     │
└─────────────────────────────────────────────────────────┘
```

---

## Core Features

**🔐 AES-256-GCM Encryption** — Every memory encrypted client-side. Your key never leaves your device.

**🔗 SHA-256 + HMAC Verification** — Content hashing and signing. Tamper with one byte and verification fails.

**🤖 Agent Context Layer** — `ContextRequest` / `ContextResponse` protocol for agents to request and receive verified user context.

**🏷️ Selective Sharing** — Share by tags. Block by tags. Users decide what agents can see, per request.

**🌳 Merkle Tree Integrity** — Compute a single hash for your entire vault. Prove nothing has been added, removed, or modified.

**📦 Open `.dvmem` Format** — Documented JSON format. No vendor lock-in. Export and import freely.

**🌐 Blockchain Anchoring** — Optionally anchor hashes to Arweave or Ethereum L2 for permanent, third-party-verifiable proof.

**🏠 Self-Hostable** — Runs entirely on your hardware. No cloud. No accounts. No trust required.

---

## Use Cases

| Use Case | Description |
|---|---|
| **Agent Personalization** | Give agents verified context without giving up your data |
| **Portable Identity** | One vault, many agents — your context moves with you |
| **Data Sovereignty** | Prove what you shared, when, and with whom |
| **AI Twin Training** | Structured, verified life data for training your personal AI |
| **Digital Legacy** | Preserve your life story with cryptographic permanence |
| **Legal Evidence** | Timestamped, tamper-proof personal records |
| **Health Timeline** | Verifiable medical history and symptom tracking |

---

## Architecture

Built on four principles:

1. **Privacy First** — Encryption happens client-side before anything leaves your device
2. **Verify Everything** — Every operation produces a cryptographic proof
3. **Own Your Data** — Open formats, open code, export anytime
4. **Permanence Optional** — Choose your storage backend: local, cloud, or blockchain

See [ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full technical deep dive, threat model, and `.dvmem` format specification.

---

## The Bigger Picture

DiaryVault Memory Layer is one half of a trust equation for the agent era:

- **Agent trust** — Can I trust what this agent did? → [authe.me](https://authe.me)
- **Data trust** — Can I trust the data the agent is using about me? → DiaryVault Memory Layer

**Trust = Agent behavior + Data integrity.**

---

## Roadmap

- [x] Core SDK — hash, encrypt, verify, store
- [x] Memory format spec (`.dvmem`)
- [x] Agent context layer — selective, verified sharing (v0.2)
- [ ] Arweave anchoring (v0.3)
- [ ] Ethereum L2 anchoring (v0.3)
- [ ] AI synthesis agents (v0.4)
- [ ] Photo/voice capture agents (v0.5)
- [ ] Dead man's switch (v0.6)
- [ ] Personal AI training export (v0.7)
- [ ] Mobile SDK (v0.8)
- [ ] DiaryVault app integration (v1.0)

---

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

Priority areas:
- Agent framework integrations (OpenClaw, LangChain, CrewAI)
- Storage backend adapters (IPFS, Filecoin, Ceramic)
- Language SDKs (TypeScript, Rust, Go)
- Documentation and tutorials

---

## Philosophy

> "The palest ink is better than the best memory." — Chinese Proverb

Your memories belong to you. Not to a platform. Not to a corporation. Not to an algorithm.

The Memory Layer is infrastructure for a future where every human has a verified, portable, private record of their existence — and every agent they interact with can be given exactly the context they need, nothing more.

**This is not a product. It's a protocol. Build on it.**

---

## License

MIT — Use it. Fork it. Build on it.

**Own your data. Share it on your terms.**

[diaryvault.com](https://diaryvault.com) · [@diaryvault](https://twitter.com/diaryvaultinc)
