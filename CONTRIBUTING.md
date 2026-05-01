# Contributing to CTF Agent

Thank you for your interest in contributing! This document provides guidelines for contributing to the project.

## How to Contribute

### Reporting Issues

- Use GitHub Issues to report bugs
- Include reproduction steps, expected vs actual behavior
- Include your Python version and OS

### Suggesting Features

- Open a GitHub Issue with the `enhancement` label
- Describe the use case and expected behavior

### Pull Requests

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run tests: `pytest tests/ -v`
5. Run linting: `ruff check src/ tests/`
6. Commit with a clear message
7. Push and create a PR

### Code Style

- Follow PEP 8
- Use type hints
- Write docstrings for public functions
- Keep functions focused and small
- Line length: 100 characters

### Adding New Tools

To add a new security tool:

1. Add the tool definition to `src/agent/tools/registry.py`
2. Create a wrapper in the appropriate module (`web.py`, `crypto.py`, etc.)
3. Add tests in `tests/`
4. Update documentation in `docs/`

Example:
```python
# In registry.py
ToolInfo(
    name="my_tool",
    description="What it does",
    command="my_tool",
    category="web",
    check_cmd="my_tool --version",
)
```

### Adding New Challenge Categories

1. Add the category to `ChallengeCategory` enum in `classifier.py`
2. Add keywords and patterns to `CATEGORY_INDICATORS`
3. Add tests
4. Update documentation

## Development Setup

```bash
git clone https://github.com/xunzhang85/Agent.git
cd Agent
pip install -e ".[dev,tools]"
pre-commit install

# Run tests
pytest tests/ -v

# Run linting
ruff check src/ tests/
black --check src/ tests/
```

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
