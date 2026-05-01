"""Tests for the Challenge Classifier."""

import pytest
from agent.categories.classifier import ChallengeClassifier, ChallengeCategory


class TestChallengeClassifier:
    """Test suite for automatic challenge classification."""

    def setup_method(self):
        self.classifier = ChallengeClassifier()

    def test_web_challenge_by_url(self):
        """Web challenges with HTTP URLs should be classified correctly."""
        result = self.classifier.classify(url="http://challenge.ctf.com/login.php")
        assert result == ChallengeCategory.WEB

    def test_web_challenge_by_keywords(self):
        """Web challenges with SQL injection keywords."""
        result = self.classifier.classify(text="Find the SQL injection vulnerability")
        assert result == ChallengeCategory.WEB

    def test_crypto_challenge(self):
        """Crypto challenges should be detected."""
        result = self.classifier.classify(
            text="Decrypt this RSA encrypted message with the given public key"
        )
        assert result == ChallengeCategory.CRYPTO

    def test_pwn_challenge(self):
        """Pwn challenges with buffer overflow keywords."""
        result = self.classifier.classify(
            text="Exploit the buffer overflow to get a shell"
        )
        assert result == ChallengeCategory.PWN

    def test_reverse_challenge(self):
        """Reverse engineering challenges."""
        result = self.classifier.classify(
            text="Reverse engineer this binary using disassembly and decompile"
        )
        assert result == ChallengeCategory.REVERSE

    def test_forensics_challenge(self):
        """Forensics challenges with memory dump."""
        result = self.classifier.classify(
            text="Analyze this memory dump to find hidden data"
        )
        assert result == ChallengeCategory.FORENSICS

    def test_file_extension_pcap(self):
        """PCAP files should be classified as forensics."""
        result = self.classifier.classify(filename="capture.pcap")
        assert result == ChallengeCategory.FORENSICS

    def test_file_extension_pem(self):
        """PEM files should be classified as crypto."""
        result = self.classifier.classify(filename="key.pem")
        assert result == ChallengeCategory.CRYPTO

    def test_explicit_hint(self):
        """Explicit category hint should override classification."""
        result = self.classifier.classify(
            text="Some ambiguous text",
            category_hint="web",
        )
        assert result == ChallengeCategory.WEB

    def test_unknown_challenge(self):
        """Ambiguous text should return unknown."""
        result = self.classifier.classify(text="Hello world")
        assert result == ChallengeCategory.UNKNOWN

    def test_combined_signals(self):
        """Multiple signals should strengthen classification."""
        result = self.classifier.classify(
            url="http://target.com/admin",
            text="Find the SQL injection in the login form",
        )
        assert result == ChallengeCategory.WEB
