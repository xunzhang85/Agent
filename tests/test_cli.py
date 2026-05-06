"""Tests for CLI helpers."""

import pytest

from agent.cli import _parse_interactive_solve


def test_interactive_solve_parses_url_and_category():
    parsed = _parse_interactive_solve(
        "/solve http://example.ctf --category web --timeout 120 --no-cache"
    )

    assert parsed["url"] == "http://example.ctf"
    assert parsed["text"] is None
    assert parsed["category"] == "web"
    assert parsed["timeout"] == 120
    assert parsed["no_cache"] is True


def test_interactive_solve_parses_quoted_text():
    parsed = _parse_interactive_solve('/solve "decrypt this RSA ciphertext" -C crypto')

    assert parsed["url"] is None
    assert parsed["text"] == "decrypt this RSA ciphertext"
    assert parsed["category"] == "crypto"


def test_interactive_solve_rejects_unknown_options():
    with pytest.raises(ValueError, match="Unknown option"):
        _parse_interactive_solve("/solve http://example.ctf --cat web")
