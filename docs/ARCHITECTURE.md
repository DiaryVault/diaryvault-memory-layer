# DiaryVault Memory Layer Architecture

## Purpose

DiaryVault Memory Layer is a standalone Python SDK for creating, storing, verifying, selectively sharing, and exporting personal memory records.

The current package provides storage and trust primitives. It does not call AI models and it does not decide whether inferred details are true.

The principle guiding future development is:

> AI may suggest. People confirm.

## Current architecture

```text
Application
    |
    v
MemoryVault
    |
    +-- Memory model
    |
    +-- MemoryCrypto
    |     +-- SHA 256 hashing
    |     +-- AES 256 GCM encryption
    |     +-- HMAC SHA 256 signing
    |     +-- Merkle roots
    |
    +-- Local storage
    |
    +-- LocalAnchor
    |
    +-- Context sharing
    |     +-- ContextRequest
    |     +-- SharedMemory
    |     +-- ContextResponse
    |
    +-- VaultExporter
          +-- JSONL
          +-- RAG chunks
          +-- Conversation history
          +-- Knowledge graph
```

## Memory lifecycle

```text
Content captured
    |
    v
Content hashed
    |
    v
Content encrypted
    |
    v
Hash signed
    |
    v
Record stored locally
    |
    +-- Verify later
    +-- Share selected context
    +-- Export selected data
```

The Python `Memory` object is mutable.

The record is tamper evident rather than immutable. If content changes after creation, verification fails because the stored hash no longer matches the current content.

## Memory model

A `Memory` contains:

* A unique identifier
* Plaintext content in the active Python object
* Optional encrypted content
* A SHA 256 hash
* An HMAC signature
* An AES GCM nonce
* A creation timestamp
* Tags and metadata
* Anchor records
* A lifecycle status

The plaintext content remains available on the active object so the SDK can search, share, and export memories.

Applications handling sensitive data must control process memory, logs, backups, exported files, and access to the storage directory.

## Cryptographic boundaries

### SHA 256

SHA 256 creates a deterministic content fingerprint.

It detects modification when the current content is compared with the stored hash.

### AES 256 GCM

AES 256 GCM encrypts content using a key derived from the secret supplied by the caller.

Encryption happens in the caller's Python process.

The SDK does not transmit keys or content. An integrating application can still transmit them, so network and infrastructure security remain application responsibilities.

### HMAC SHA 256

HMAC signs the content hash using a key derived from the caller supplied secret.

This demonstrates possession of the same secret. It is not a public digital signature and does not independently establish legal authorship.

### Merkle roots

A Merkle root summarizes a collection of memory hashes.

It can reveal whether a verified collection differs from the collection used to create the root.

The current implementation does not publish roots to an independently trusted timestamping system.

## Storage

`MemoryVault` writes memory records to the configured local storage directory.

Local storage provides:

* Offline operation
* A user selected storage location
* Encrypted payload persistence
* No required DiaryVault service

Local storage alone does not provide:

* Cloud backup
* Multi device synchronization
* Independent timestamps
* Operating system access control
* Key recovery
* Guaranteed permanence

## Anchoring

`LocalAnchor` is the only supported anchor backend.

It records memory hashes and related metadata in a local JSON proof store.

The package includes placeholder `ArweaveAnchor` and `EthereumAnchor` classes. They raise `NotImplementedError` and must not be presented as supported backends.

## Selective context sharing

The context layer separates an agent request from the final disclosure decision.

```text
Agent declares requested scope and purpose
    |
    v
Vault owner applies allowed and denied tags
    |
    v
Vault selects matching memories
    |
    v
ContextResponse contains only granted records
```

A context response includes verification data. The receiving application still needs a secure channel and an appropriate authorization model.

## Export layer

`VaultExporter` supports:

* OpenAI style JSONL
* Anthropic style JSONL
* Generic JSONL
* RAG chunks
* Conversation history
* Knowledge graphs
* Summary metadata

Exports are portable and may contain plaintext.

Exporting creates a new copy outside the encrypted vault. Applications should treat export as an explicit disclosure action.

## Supported trust claims

The SDK can support these claims:

* Stored content can be encrypted locally.
* Later content modification can be detected.
* A caller can selectively disclose memories by tag.
* Shared records can include hashes and verification state.
* Records can be exported in portable formats.

The SDK cannot currently support these claims:

* A memory is legally admissible evidence.
* A timestamp was independently witnessed.
* A record exists on a public blockchain.
* Cloud data is end to end encrypted.
* An AI generated field was confirmed by a person.
* A deleted export has been revoked from every recipient.

## v0.4 review workflow

```text
Capture
    |
    v
MemoryDraft
    |
    +-- Original user supplied fields
    |
    +-- Suggestion records
    |     +-- Suggested value
    |     +-- Model or source
    |     +-- Process version
    |     +-- Creation timestamp
    |     +-- Confidence when available
    |
    v
User review
    |
    +-- Approve
    +-- Edit
    +-- Reject
    |
    v
ConfirmedMemory
    |
    +-- Confirmed fields
    +-- Approval record
    +-- Revision history
    +-- Integrity hash
```

Core rules:

1. Suggested values are never represented as confirmed values.
2. Confirmation requires an explicit user action.
3. Edits preserve suggestion provenance.
4. Exports distinguish source content, suggestions, and confirmed content.
5. Revisions create new verification material rather than silently rewriting history.
6. Deletion and revocation are separate from integrity verification.

## Relationship to the DiaryVault product

This SDK is not currently wired into the production DiaryVault mobile applications.

A future integration should begin with a narrow approved memory bridge.

```text
Approved DiaryVault Memory Card
    |
    v
Portable memory manifest
    |
    v
Memory Layer verification and selective sharing
```

Synthetic fixtures should be used for the reference implementation. Production user data should not be required.

## Version history

### v0.1

* Memory model
* Local vault
* Hashing
* Encryption
* HMAC signatures
* Local anchors
* `.dvmem` records

### v0.2

* Context requests
* Selective sharing
* Allowed and denied tags
* Shared memory verification
* Merkle roots on context responses

### v0.3

* JSONL exports
* RAG chunks
* Conversation history
* Knowledge graph exports

### v0.4

* Persisted draft records
* Suggestion provenance
* Acceptance and rejection
* Confirmed field overrides
* Explicit approval records
* Revision history
* Approval-aware exports
