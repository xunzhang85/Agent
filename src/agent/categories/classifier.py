"""
Challenge Classifier

Automatically classifies CTF challenges into categories based on
URL patterns, file types, and challenge descriptions.
"""

import re
import logging
from enum import Enum
from typing import Optional

logger = logging.getLogger(__name__)


class ChallengeCategory(Enum):
    """CTF challenge categories."""

    WEB = "web"
    CRYPTO = "crypto"
    PWN = "pwn"
    REVERSE = "reverse"
    FORENSICS = "forensics"
    MISC = "misc"
    OSINT = "osint"
    MOBILE = "mobile"
    HARDWARE = "hardware"
    UNKNOWN = "unknown"


# Keywords and patterns for classification
CATEGORY_INDICATORS = {
    ChallengeCategory.WEB: {
        "keywords": [
            "sql", "injection", "xss", "csrf", "ssrf", "web", "http",
            "cookie", "session", "upload", "lfi", "rfi", "sqli",
            "directory", "api", "rest", "graphql", "authentication",
            "authorization", "bypass", "waf", "burp", "proxy",
        ],
        "url_patterns": [
            r"https?://", r"\.php", r"\.asp", r"\.jsp", r"/api/",
            r"/admin", r"/login", r"/upload",
        ],
        "file_extensions": [".php", ".html", ".js", ".asp", ".jsp"],
    },
    ChallengeCategory.CRYPTO: {
        "keywords": [
            "encrypt", "decrypt", "cipher", "rsa", "aes", "des",
            "hash", "md5", "sha", "base64", "hex", "xor", "rot13",
            "caesar", "vigenere", "key", "private", "public",
            "certificate", "signature", "crypto",
        ],
        "url_patterns": [],
        "file_extensions": [".pem", ".key", ".crt", ".enc"],
    },
    ChallengeCategory.PWN: {
        "keywords": [
            "buffer", "overflow", "stack", "heap", "format string",
            "rop", "shellcode", "got", "plt", "ret2libc", "pwn",
            "binary", "exploit", "segfault", "vulnerability", "patch",
            "ret2win", "one_gadget",
        ],
        "url_patterns": [r"nc\s+", r"netcat"],
        "file_extensions": [".elf", ".bin", ""],
    },
    ChallengeCategory.REVERSE: {
        "keywords": [
            "reverse", "disassemble", "decompile", "assembly",
            "obfuscate", "anti-debug", "unpack", "crack", "keygen",
            "ida", "ghidra", "radare", "angr", "binary analysis",
        ],
        "url_patterns": [],
        "file_extensions": [".exe", ".elf", ".dll", ".so", ".apk"],
    },
    ChallengeCategory.FORENSICS: {
        "keywords": [
            "forensic", "memory", "dump", "pcap", "network",
            "steganography", "steg", "image", "audio", "hidden",
            "metadata", "exif", "carve", "recover", "volatility",
            "disk", "image", "autopsy",
        ],
        "url_patterns": [],
        "file_extensions": [".pcap", ".mem", ".raw", ".img", ".dd", ".dmp"],
    },
    ChallengeCategory.MISC: {
        "keywords": [
            "programming", "algorithm", "math", "puzzle", "trivia",
            "osint", "recon", "scripting", "automation",
        ],
        "url_patterns": [],
        "file_extensions": [],
    },
}


class ChallengeClassifier:
    """
    Classifies CTF challenges into categories.

    Uses keyword matching, URL analysis, and file type detection
    to determine the most likely challenge category.
    """

    def __init__(self):
        self.indicators = CATEGORY_INDICATORS

    def classify(
        self,
        url: Optional[str] = None,
        text: Optional[str] = None,
        filename: Optional[str] = None,
        category_hint: Optional[str] = None,
    ) -> ChallengeCategory:
        """
        Classify a challenge based on available information.

        Args:
            url: Challenge URL
            text: Challenge description or hints
            filename: Associated filename
            category_hint: Explicit category hint

        Returns:
            ChallengeCategory enum value
        """
        # If explicit hint provided, try to match it first
        if category_hint:
            for cat in ChallengeCategory:
                if cat.value == category_hint.lower():
                    return cat

        scores: dict[ChallengeCategory, float] = {cat: 0.0 for cat in ChallengeCategory}

        combined_text = " ".join(filter(None, [url, text, filename])).lower()

        for category, indicators in self.indicators.items():
            # Keyword matching
            for keyword in indicators["keywords"]:
                if keyword in combined_text:
                    scores[category] += 1.0

            # URL pattern matching
            if url:
                for pattern in indicators["url_patterns"]:
                    if re.search(pattern, url, re.IGNORECASE):
                        scores[category] += 2.0

            # File extension matching
            if filename:
                for ext in indicators["file_extensions"]:
                    if filename.lower().endswith(ext):
                        scores[category] += 3.0

        # Find the highest scoring category
        if not any(scores.values()):
            return ChallengeCategory.UNKNOWN

        best_category = max(scores, key=scores.get)

        # If score is too low, return unknown
        if scores[best_category] < 1.0:
            return ChallengeCategory.UNKNOWN

        logger.info(
            f"Classified as {best_category.value} "
            f"(scores: {', '.join(f'{k.value}={v}' for k, v in scores.items() if v > 0)})"
        )

        return best_category

    def get_confidence(self, category: ChallengeCategory, scores: dict) -> float:
        """Get confidence score for a classification."""
        if category == ChallengeCategory.UNKNOWN:
            return 0.0
        total = sum(scores.values())
        if total == 0:
            return 0.0
        return scores.get(category, 0.0) / total
