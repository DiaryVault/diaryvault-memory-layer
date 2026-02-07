# Architecture — DiaryVault Memory Layer

## Overview

The Memory Layer is a four-layer system that transforms raw human experiences into cryptographically verified, encrypted, permanent memory records.

```
┌──────────────────────────────────────────────────────────────────┐
│                        APPLICATIONS                               │
│  DiaryVault App · CLI · Third-party integrations · AI Agents      │
├──────────────────────────────────────────────────────────────────┤
│                        MEMORY VAULT SDK                           │
│  Python · TypeScript (planned) · Rust (planned) · Go (planned)    │
├───────────┬───────────┬────────────────┬────────────────────────┤
│  CAPTURE  │ SYNTHESIS │  VERIFICATION  │     PERMANENCE          │
│  LAYER    │ LAYER     │  LAYER         │     LAYER               │
│           │           │                │                          │
│  Manual   │ AI Narr.  │  SHA-256       │  Local Encrypted        │
│  Agents   │ Summary   │  AES-256-GCM   │  Arweave                │
│  API      │ Patterns  │  HMAC-SHA256   │  Ethereum L2            │
│  Import   │ Emotion   │  Merkle Trees  │  IPFS                   │
└───────────┴───────────┴────────────────┴────────────────────────┘
```

## Design Principles

### 1. Privacy First
All encryption happens client-side. The encryption key never leaves the user's device. Even if someone gains access to the storage backend, they see only ciphertext. We use AES-256-GCM which provides both confidentiality (no one can read it) and authenticity (no one can tamper with it undetected).

### 2. Verify Everything
Every operation produces a cryptographic proof. When you create a memory, you get a SHA-256 hash (content fingerprint), an HMAC signature (proof of authorship), and a timestamp. These three pieces together form an unforgeable record.

### 3. Own Your Data
The `.dvmem` format is open and documented. You can export your entire vault at any time. No lock-in. No proprietary formats. If DiaryVault disappears tomorrow, your memories survive.

### 4. Permanence is Optional
Not everyone needs blockchain anchoring. The system works perfectly with local encrypted storage. Blockchain anchoring is an opt-in layer for those who want maximum tamper resistance.

---

## Layer Details

### Capture Layer

The capture layer is responsible for getting data into the system.

```
Sources:
├── Manual Entry       → User types/speaks a journal entry
├── AI Agents          → Autonomous agents that capture context
│   ├── Calendar Agent → Summarizes daily schedule
│   ├── Photo Agent    → Processes and describes photos
│   ├── Health Agent   → Aggregates health/fitness data
│   └── Custom Agents  → User-defined capture agents
├── API Integration    → Programmatic entry creation
└── Import             → Bulk import from other formats
```

**Agent Architecture (v0.2+)**

Agents are pluggable Python classes that implement the `CaptureAgent` interface:

```python
class CaptureAgent(ABC):
    @abstractmethod
    async def capture(self, context: dict) -> list[Memory]:
        """Capture memories from a data source."""
        ...

    @abstractmethod
    def schedule(self) -> str:
        """Cron expression for capture frequency."""
        ...
```

Agents run on the user's device or server. They never send unencrypted data externally.

### Synthesis Layer

The synthesis layer uses AI to enrich raw captures into meaningful narratives.

```
Raw Input → [AI Synthesis] → Enriched Memory
                │
                ├── Narrative Generation
                │   "You had 3 meetings and went to the gym"
                │   → "A productive Tuesday. Back-to-back strategy
                │      sessions in the morning, then a solid workout
                │      to decompress. You mentioned feeling optimistic
                │      about the product direction."
                │
                ├── Pattern Detection
                │   "You've journaled about career anxiety 4 times
                │    this month — that's up from 1 last month."
                │
                ├── Emotional Analysis
                │   Sentiment tracking, mood classification
                │
                └── Cross-referencing
                    Links memories that share themes, people, locations
```

The synthesis layer is LLM-agnostic. Bring your own model:
- OpenAI API
- Anthropic Claude API
- Local models (Llama, Mistral via Ollama)
- Any OpenAI-compatible endpoint

### Verification Layer

The cryptographic core of the system.

**Hashing (SHA-256)**
```
content: "Today was a good day"
    → SHA-256
    → "a1b2c3d4e5f6..."  (64-char hex string)

Change one character:
content: "Today was a Good day"
    → SHA-256
    → "9f8e7d6c5b4a..."  (completely different hash)
```

**Encryption (AES-256-GCM)**
```
plaintext + key + nonce
    → AES-256-GCM
    → ciphertext + authentication tag

Features:
- 256-bit key strength (unbreakable with current technology)
- GCM mode provides authentication (detects tampering)
- Unique nonce per encryption (prevents pattern analysis)
```

**Signing (HMAC-SHA256)**
```
content_hash + signing_key
    → HMAC-SHA256
    → signature (proves who created the hash)
```

**Merkle Trees (Batch Verification)**
```
         [Root Hash]           ← Anchor this ONE hash
          /        \
    [Hash AB]    [Hash CD]
     /    \       /    \
  [H(A)] [H(B)] [H(C)] [H(D)]  ← Individual memory hashes
    |      |      |      |
   Mem1   Mem2   Mem3   Mem4
```

One root hash can verify thousands of memories. This makes batch anchoring extremely cost-efficient.

### Permanence Layer

Where verified hashes are anchored for tamper-proof permanence.

| Backend | Cost | Permanence | Speed | Best For |
|---------|------|------------|-------|----------|
| Local | Free | Device lifetime | Instant | Development, self-hosting |
| Arweave | ~$0.005/KB | 200+ years | ~2 min | Long-term archival |
| Ethereum L2 | ~$0.01/tx | Blockchain lifetime | ~2 sec | Proof-of-existence |
| IPFS | Free (pinning costs) | While pinned | ~30 sec | Content distribution |

**Important**: Only the hash goes on-chain. Your content stays encrypted on your device or in your chosen storage. The blockchain merely proves that at time T, content with hash H existed.

---

## Data Format: `.dvmem`

The DiaryVault Memory Format is an open JSON-based format.

```json
{
  "dvmem_version": "1.0",
  "encoding": "utf-8",
  "payload": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "version": "1.0.0",
    "content": "...",
    "content_type": "text/plain",
    "hash": "a1b2c3d4e5f6...",
    "encrypted_content": "...",
    "nonce": "...",
    "signature": "...",
    "created_at": "2025-02-07T14:32:01+00:00",
    "status": "signed",
    "metadata": {
      "tags": ["daily", "career"],
      "location": null,
      "mood": "optimistic",
      "source": "manual",
      "agent_id": null,
      "ai_enriched": false,
      "custom": {}
    },
    "anchors": []
  },
  "verification": {
    "hash": "a1b2c3d4e5f6...",
    "signature": "7g8h9i0j...",
    "anchors": []
  }
}
```

---

## Security Model

### Threat Model

| Threat | Mitigation |
|--------|------------|
| Storage breach | AES-256-GCM encryption. Attacker sees only ciphertext. |
| Content tampering | SHA-256 hash detects any modification. |
| Hash forgery | HMAC signature proves authorship. |
| Replay attacks | Unique nonce per encryption + timestamps. |
| Key compromise | User responsibility. Future: hardware key support. |
| Quantum computing | SHA-256 remains secure. AES-256 quantum-resistant. Future: post-quantum upgrade path. |

### What We DON'T Do
- We don't store your encryption key
- We don't transmit unencrypted content
- We don't have a backdoor
- We don't use proprietary encryption
- We can't read your memories even if compelled

---

## Integration with DiaryVault App

The Memory Layer is the open-source foundation. The DiaryVault app (diaryvault.com) is the consumer product built on top:

```
┌─────────────────────────────────────┐
│         DiaryVault App               │  ← Proprietary
│  Beautiful UI · Mobile apps          │
│  AI journaling · Social features     │
├─────────────────────────────────────┤
│      DiaryVault Memory Layer         │  ← Open Source (MIT)
│  SDK · Crypto · Anchoring · Format   │
└─────────────────────────────────────┘
```

The app adds:
- Polished journaling UX (iOS, Android, Web)
- AI-powered writing prompts and reflection
- Cloud sync (encrypted end-to-end)
- Premium AI synthesis features
- Managed anchoring service

The SDK provides:
- All cryptographic operations
- Local-first storage
- Open data format
- Self-hosting capability
- API for third-party integrations

---

## Roadmap

### v0.1 (Current) — Foundation
- Core SDK: hash, encrypt, verify, sign
- Memory data model and `.dvmem` format
- Local anchor backend
- Python package

### v0.2 — AI Agents
- Agent framework and interface
- Calendar capture agent
- Daily summary synthesis agent
- LLM integration (OpenAI, Anthropic, local)

### v0.3 — Blockchain Anchoring
- Arweave backend
- Ethereum L2 backend (Base)
- IPFS backend
- Batch Merkle anchoring

### v0.4 — Rich Capture
- Photo agent with AI description
- Voice note agent with transcription
- Health data agent (Apple Health, Google Fit)
- Location timeline agent

### v0.5 — Dead Man's Switch
- Configurable inactivity threshold
- Designated beneficiary access
- Multi-signature key splitting
- Time-locked encryption

### v0.6 — Personal AI Export
- Structured export for AI fine-tuning
- Conversation-format export
- Embedding generation for RAG
- Personal knowledge graph

### v1.0 — DiaryVault Integration
- Full integration with DiaryVault app
- Managed anchoring service
- Cross-device sync with E2E encryption
- Premium AI features
