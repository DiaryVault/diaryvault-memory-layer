# Contributing to DiaryVault Memory Layer

Thanks for your interest in contributing! This project is open to everyone.

## Quick Start

```bash
# Fork and clone the repo
git clone https://github.com/YOUR_USERNAME/diaryvault-memory-layer.git
cd diaryvault-memory-layer

# Install dev dependencies
pip install cryptography pytest pytest-cov

# Run the tests
python -m pytest tests/ -v

# All 28 tests should pass before you submit a PR
```

## How to Contribute

**Found a bug?** Open an issue with steps to reproduce it.

**Have an idea?** Open an issue to discuss before building. This saves everyone time.

**Want to code?** Fork → branch → code → test → PR. Keep PRs focused on one thing.

## Priority Areas

We'd especially love help with:

- **Storage backends** — IPFS, Filecoin, Ceramic adapters
- **AI agent plugins** — new capture agents for different data sources
- **Language SDKs** — TypeScript, Rust, Go ports
- **Security audits** — review the crypto implementation
- **Documentation** — tutorials, examples, guides
- **Mobile** — iOS/Android integration patterns

## Code Style

- Python 3.10+
- Type hints on all public methods
- Docstrings on all public classes and methods
- Tests for all new functionality
- Keep dependencies minimal

## Running Tests

```bash
# Full test suite
python -m pytest tests/ -v

# With coverage
python -m pytest tests/ -v --cov=sdk/diaryvault_memory --cov-report=term-missing
```

## Commit Messages

Keep them short and clear:
- `Add IPFS anchor backend`
- `Fix Merkle proof verification for odd-length lists`
- `Update README with new examples`

## Code of Conduct

Be kind. Be constructive. We're all here to build something meaningful.

## Questions?

Open an issue or find us on [Discord](https://discord.gg/diaryvault).
