# Contributing to DiaryVault Memory Layer

Thank you for contributing.

The project is currently focused on portable, user controlled memory records and a review first workflow for AI suggested memories.

## Setup

```bash
git clone https://github.com/DiaryVault/diaryvault-memory-layer.git
cd diaryvault-memory-layer

python3 -m venv .venv
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
python -m pip install build ruff
```

## Required checks

```bash
python -m ruff check sdk tests examples
python -m pytest tests/ -v
python -m build
```

The current suite contains 122 tests.

## Current priorities

Contributions are especially useful in these areas:

* Draft, suggestion, approval, and revision schemas
* Provenance for AI suggested fields
* Portable approved memory manifests
* Permission and revocation semantics
* Export safety and privacy controls
* Security review
* Documentation and runnable examples
* Compatibility for existing `.dvmem` records

The following areas are not current priorities:

* Blockchain backends
* Health record integrations
* Dead man switches
* Autonomous capture agents
* Additional language SDKs
* Generalized identity protocols

## Pull requests

Keep each pull request focused.

New behavior should include:

* Type hints
* Public docstrings
* Tests
* Backward compatibility notes
* Privacy and trust boundary notes where relevant

Before opening a pull request:

```bash
python -m ruff check sdk tests examples
python -m pytest tests/ -v
git diff --check
```

## Security issues

Do not open a public issue containing private memory data, encryption keys, or a working exploit.

Use synthetic fixtures in tests and examples.

## Conduct

Be constructive, specific, and respectful.
