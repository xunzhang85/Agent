"""Tests for the enhanced Classifier."""

import pytest
from agent.categories.classifier import ChallengeClassifier, ChallengeCategory, ClassificationResult


class TestEnhancedClassifier:
    """Test suite for the enhanced classifier with confidence scoring."""

    def setup_method(self):
        self.classifier = ChallengeClassifier()

    def test_confidence_scoring(self):
        """Classification should return confidence scores."""
        result = self.classifier.classify_with_confidence(
            url="http://target.com/login.php?id=1",
            text="SQL injection vulnerability in login form",
        )
        assert result.category == ChallengeCategory.WEB
        assert result.confidence > 0.3
        assert result.scores.get("web", 0) > 0

    def test_matched_keywords(self):
        """Classification should track matched keywords."""
        result = self.classifier.classify_with_confidence(
            text="buffer overflow in gets() function to overwrite return address",
        )
        assert result.category == ChallengeCategory.PWN
        assert len(result.matched_keywords) > 0

    def test_multiple_signals(self):
        """Multiple signals should increase confidence."""
        result = self.classifier.classify_with_confidence(
            url="http://target.com/admin/login.php",
            text="Find SQL injection in the admin login form, bypass authentication",
        )
        assert result.category == ChallengeCategory.WEB
        assert result.confidence > 0.5

    def test_file_extension_forensics(self):
        """PCAP files should strongly indicate forensics."""
        result = self.classifier.classify_with_confidence(filename="capture.pcap")
        assert result.category == ChallengeCategory.FORENSICS
        assert result.confidence > 0.5

    def test_crypto_rsa(self):
        """RSA-related text should classify as crypto with high confidence."""
        result = self.classifier.classify_with_confidence(
            text="Given RSA public key (n, e) and ciphertext c, decrypt the message. The modulus can be factored.",
        )
        assert result.category == ChallengeCategory.CRYPTO
        assert result.confidence > 0.4

    def test_reverse_engineering(self):
        """Reverse engineering keywords should classify correctly."""
        result = self.classifier.classify_with_confidence(
            text="Reverse engineer this obfuscated binary, find the serial key validation algorithm",
        )
        assert result.category == ChallengeCategory.REVERSE

    def test_unknown_low_confidence(self):
        """Ambiguous text should return unknown with low confidence."""
        result = self.classifier.classify_with_confidence(text="Hello world")
        assert result.category == ChallengeCategory.UNKNOWN
        assert result.confidence == 0.0

    def test_explicit_hint_override(self):
        """Explicit hint should override with 100% confidence."""
        result = self.classifier.classify_with_confidence(
            text="Some ambiguous text",
            category_hint="pwn",
        )
        assert result.category == ChallengeCategory.PWN
        assert result.confidence == 1.0

    def test_netcat_pwn(self):
        """Netcat connection should indicate pwn."""
        result = self.classifier.classify_with_confidence(
            text="Connect to nc challenge.ctf.com 1337 and exploit the binary",
        )
        assert result.category == ChallengeCategory.PWN
