"""Tests for the CryptoTools module."""

import pytest
from agent.tools.crypto import CryptoTools


class TestCryptoTools:
    """Test suite for cryptographic tools."""

    def test_base64_decode(self):
        """Base64 decoding should work correctly."""
        assert CryptoTools.base64_decode("SGVsbG8gV29ybGQ=") == "Hello World"

    def test_base64_encode(self):
        """Base64 encoding should work correctly."""
        assert CryptoTools.base64_encode("Hello World") == "SGVsbG8gV29ybGQ="

    def test_hex_decode(self):
        """Hex decoding should work correctly."""
        assert CryptoTools.hex_decode("48656c6c6f") == "Hello"

    def test_rot13(self):
        """ROT13 should encode/decode correctly."""
        assert CryptoTools.rot13("Hello") == "Uryyb"
        assert CryptoTools.rot13("Uryyb") == "Hello"

    def test_caesar_bruteforce(self):
        """Caesar brute force should return all 26 shifts."""
        results = CryptoTools.caesar_bruteforce("Uryyb")
        assert len(results) == 26
        assert results[13] == "Hello"  # ROT13

    def test_xor(self):
        """XOR should produce correct output."""
        data = b"Hello"
        key = b"key"
        encrypted = CryptoTools.xor(data, key)
        decrypted = CryptoTools.xor(encrypted, key)
        assert decrypted == data

    def test_frequency_analysis(self):
        """Frequency analysis should return sorted frequencies."""
        freq = CryptoTools.frequency_analysis("aaabbc")
        assert freq["a"] > freq["b"]
        assert abs(sum(freq.values()) - 1.0) < 0.01
