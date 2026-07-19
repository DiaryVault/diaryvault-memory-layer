<p align="center">
  <img src="assets/diaryvault-logo.png" alt="DiaryVault" width="88">
</p>

<h1 align="center">DiaryVault Memory Layer</h1>

<p align="center">
  An open source Python SDK for portable, tamper evident personal memory records.
</p>

<p align="center">
  Store memories locally, share only selected context, and export selected records into open formats for retrieval and personal AI systems.
</p>

## Status

The current release is **v0.4.0 Alpha**.

Available now:

* Local encrypted memory storage
* SHA 256 content hashing
* AES 256 GCM encryption
* HMAC SHA 256 signatures
* Tamper detection
* Local proof records
* Selective context sharing
* JSONL dataset export
* RAG ready chunks
* Conversation history export
* Personal knowledge graph export
* Portable `.dvmem` records
* Reviewable memory drafts
* AI suggestion provenance
* Explicit approval and rejection
* Draft revision history
* Approval-aware exports

Not implemented:

* Arweave anchoring
* Ethereum anchoring
* IPFS storage
* AI synthesis or model calls
* Mobile SDKs
* Cloud synchronization
* Direct production app integration

`LocalAnchor` is the only supported anchor backend. The Arweave and Ethereum classes are currently placeholders.

## Why this exists

AI systems increasingly use personal history as context.

That creates a trust problem. A model may infer details, summarize events, or propose meaning. Those suggestions should not silently become part of a person’s permanent memory record.

The principle guiding this project is:

> AI may suggest. People confirm.

The current SDK provides storage, verification, selective sharing, and export primitives.

Version 0.4 adds explicit drafts, AI suggestions, revisions, and user approval records.

## Installation

```bash
pip install diaryvault-memory
```

For development:

```bash
git clone https://github.com/DiaryVault/diaryvault-memory-layer.git
cd diaryvault-memory-layer

python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

## Create and verify a memory

```python
from diaryvault_memory import MemoryVault

vault = MemoryVault(
    encryption_key="replace-with-a-private-secret",
    storage_dir="./memory-data",
)

memory = vault.create(
    content="She laughed when the dog sneezed.",
    tags=["family", "milestone"],
)

assert vault.verify(memory)

print(memory.id)
print(memory.hash)
```

A `Memory` object is mutable in Python. The stored hash and signature make later changes detectable.

```python
memory.content = "Changed content"

assert not vault.verify(memory)
```

## Share selected context

Agents request a declared scope. The vault owner controls what is actually shared.

```python
from diaryvault_memory import ContextRequest, MemoryVault

vault = MemoryVault(
    encryption_key="replace-with-a-private-secret",
    storage_dir="./memory-data",
)

request = ContextRequest(
    agent_id="family-story-agent",
    scope=["family", "milestone"],
    purpose="Prepare a private family recap",
    max_memories=5,
)

response = vault.share(
    request,
    allowed_tags=["milestone"],
    denied_tags=["private"],
)

assert response.verify_all()

for shared_memory in response.shared_memories:
    print(shared_memory.content)
```

A context response records:

* The requesting agent
* The declared purpose
* Requested, granted, and denied scopes
* Shared memory hashes
* Verification state
* The vault Merkle root

## Export for personal AI systems

```python
from diaryvault_memory import MemoryVault, VaultExporter

vault = MemoryVault(
    encryption_key="replace-with-a-private-secret",
    storage_dir="./memory-data",
)

exporter = VaultExporter(vault)

chunks = exporter.to_rag_chunks(tags=["family"])
graph = exporter.to_knowledge_graph(tags=["family"])
history = exporter.to_conversation_history(tags=["family"])

exporter.to_jsonl(
    "family-memories.jsonl",
    format="openai",
    tags=["family"],
)
```

Supported export surfaces:

| Export | Purpose |
|---|---|
| JSONL | Portable datasets and fine tuning inputs |
| RAG chunks | Embedding and retrieval pipelines |
| Conversation history | Assistant context |
| Knowledge graph | Memory, tag, date, and relationship nodes |
| Approved manifest | Approval, revision, and suggestion provenance |
| `.dvmem` | Portable individual memory records |

Exports may contain plaintext personal information. Applications should require explicit user approval before exporting or sharing sensitive memories.

## Cryptographic model

The SDK uses:

* SHA 256 for content fingerprints
* AES 256 GCM for local encryption
* HMAC SHA 256 for integrity signatures
* Merkle roots for batch verification

These primitives provide encrypted local storage and tamper detection.

They do not independently prove legal authorship, independently trusted timestamps, public blockchain existence, or user approval of AI generated claims.

An HMAC signature demonstrates possession of the same secret key. A local anchor proves only what is present in the local proof store.

## Roadmap

### Completed

* **v0.1**: Local vault, hashing, encryption, signatures, verification, and `.dvmem`
* **v0.2**: Selective and verified agent context sharing
* **v0.3**: JSONL, RAG, conversation, and knowledge graph exports
* **v0.4**: Drafts, suggestions, provenance, approval, rejection, revisions, and approval-aware exports

### Next

* Export permission records
* Revocation records
* Approved media attachment manifests
* Read only family sharing
* Timeline and relationship graph exports
* A documented bridge to the DiaryVault consumer product

Blockchain anchoring, generalized capture agents, health records, dead man switches, and additional language SDKs are not current priorities.

## Relationship to DiaryVault

This repository explores the open trust and portability primitives behind DiaryVault’s product philosophy.

It is currently a standalone Python SDK. It is not yet the storage implementation used by the production DiaryVault iOS and Android applications.

The consumer product is available at [diaryvault.com](https://diaryvault.com).

## Development

```bash
python -m ruff check sdk tests examples
python -m pytest tests/ -v
python -m build
```

The current suite contains 85 tests.

## Security

This project is Alpha software and has not received an independent security audit.

Do not use it as the sole system for legal evidence, medical records, regulated records, or irreplaceable archival storage.

Never commit encryption keys or private memory exports to source control.

## License

MIT
