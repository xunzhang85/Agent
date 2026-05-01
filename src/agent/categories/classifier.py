"""
Challenge Classifier (Optimized)

Enhanced with weighted scoring, context-aware classification,
and multi-signal fusion for higher accuracy.
"""

import re
import logging
from enum import Enum
from typing import Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


class ChallengeCategory(Enum):
    WEB = "web"
    CRYPTO = "crypto"
    PWN = "pwn"
    REVERSE = "reverse"
    FORENSICS = "forensics"
    MISC = "misc"
    OSINT = "osint"
    UNKNOWN = "unknown"


@dataclass
class ClassificationResult:
    """Classification result with confidence."""
    category: ChallengeCategory
    confidence: float
    scores: dict[str, float]
    matched_keywords: list[str]


# Weighted keyword sets per category
CATEGORY_INDICATORS = {
    ChallengeCategory.WEB: {
        "keywords": {
            # High weight (strong indicators)
            "sql injection": 5.0, "sqli": 5.0, "xss": 5.0, "csrf": 5.0,
            "ssrf": 5.0, "lfi": 5.0, "rfi": 5.0, "xxe": 5.0,
            "directory traversal": 4.0, "path traversal": 4.0,
            "file upload": 4.0, "authentication bypass": 4.0,
            "login": 3.0, "admin": 3.0, "cookie": 3.0, "session": 3.0,
            "waf bypass": 4.0, "webshell": 4.0,
            # Medium weight
            "web": 2.0, "http": 2.0, "api": 2.0, "rest": 2.0,
            "form": 2.0, "upload": 2.0, "redirect": 2.0,
            "parameter": 1.5, "endpoint": 1.5, "proxy": 1.5,
            # Low weight
            "curl": 1.0, "burp": 1.0, "cookie": 1.0,
        },
        "url_patterns": [
            (r"https?://", 3.0),
            (r"\.php", 2.0), (r"\.asp", 2.0), (r"\.jsp", 2.0),
            (r"/api/", 2.0), (r"/admin", 3.0), (r"/login", 3.0),
            (r"/upload", 3.0), (r"\?id=", 3.0), (r"\?page=", 3.0),
        ],
        "file_extensions": {".php": 3, ".html": 1, ".js": 1, ".asp": 3, ".jsp": 3},
    },
    ChallengeCategory.CRYPTO: {
        "keywords": {
            "rsa": 5.0, "aes": 5.0, "des": 4.0, "encrypt": 4.0, "decrypt": 4.0,
            "cipher": 4.0, "private key": 5.0, "public key": 4.0,
            "factor": 4.0, "modulus": 4.0, "exponent": 3.0,
            "hash": 3.0, "md5": 3.0, "sha256": 3.0, "sha1": 3.0,
            "base64": 2.0, "hex": 2.0, "xor": 3.0,
            "rot13": 4.0, "caesar": 4.0, "vigenere": 4.0,
            "frequency analysis": 4.0, "diffie": 4.0, "hellman": 4.0,
            "elliptic": 4.0, "discrete log": 4.0,
            "crypto": 3.0, "certificate": 2.0, "signature": 2.0,
        },
        "url_patterns": [],
        "file_extensions": {".pem": 4, ".key": 4, ".crt": 3, ".enc": 4},
    },
    ChallengeCategory.PWN: {
        "keywords": {
            "buffer overflow": 5.0, "stack overflow": 5.0, "heap overflow": 5.0,
            "format string": 5.0, "rop chain": 5.0, "ret2libc": 5.0,
            "shellcode": 4.0, "getshell": 4.0, "get shell": 4.0,
            "return address": 4.0, "eip overwrite": 4.0, "rip overwrite": 4.0,
            "got overwrite": 4.0, "plt": 3.0, "one_gadget": 4.0,
            "pwn": 3.0, "exploit": 3.0, "vulnerability": 2.0,
            "binary": 2.0, "elf": 2.0, "segfault": 3.0,
            "ret2win": 5.0, "ret2system": 5.0,
        },
        "url_patterns": [(r"nc\s+\S+\s+\d+", 5.0), (r"netcat", 3.0)],
        "file_extensions": {},
    },
    ChallengeCategory.REVERSE: {
        "keywords": {
            "reverse engineer": 5.0, "reverse engineering": 5.0,
            "disassemble": 4.0, "decompile": 4.0, "decompilation": 4.0,
            "assembly": 3.0, "obfuscate": 4.0, "obfuscated": 4.0,
            "anti-debug": 4.0, "anti-debugging": 4.0,
            "unpack": 3.0, "packed": 3.0, "upx": 3.0,
            "crack": 3.0, "keygen": 4.0, "serial key": 4.0, "license": 3.0,
            "ida": 3.0, "ghidra": 3.0, "radare": 3.0, "angr": 3.0,
            "binary analysis": 3.0, "opcode": 3.0,
        },
        "url_patterns": [],
        "file_extensions": {".exe": 3, ".elf": 3, ".dll": 3, ".so": 2, ".apk": 3},
    },
    ChallengeCategory.FORENSICS: {
        "keywords": {
            "memory dump": 5.0, "memory forensics": 5.0, "ram dump": 5.0,
            "pcap": 5.0, "packet capture": 5.0, "wireshark": 4.0,
            "steganography": 5.0, "steg": 4.0, "hidden in image": 4.0,
            "metadata": 3.0, "exif": 4.0, "exiftool": 3.0,
            "carve": 4.0, "recover": 3.0, "deleted file": 4.0,
            "disk image": 4.0, "forensic": 4.0, "volatility": 4.0,
            "network capture": 4.0, "traffic analysis": 4.0,
            "file carving": 4.0, "autopsy": 3.0,
        },
        "url_patterns": [],
        "file_extensions": {".pcap": 5, ".mem": 5, ".raw": 4, ".img": 4, ".dd": 4, ".dmp": 4},
    },
    ChallengeCategory.MISC: {
        "keywords": {
            "programming": 3.0, "algorithm": 3.0, "math": 2.0,
            "puzzle": 2.0, "scripting": 3.0, "automation": 2.0,
            "osint": 4.0, "recon": 3.0, "open source": 2.0,
        },
        "url_patterns": [],
        "file_extensions": {},
    },
}


class ChallengeClassifier:
    """
    Enhanced classifier with weighted scoring and confidence.
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
        """Classify a challenge, returning the best match."""
        result = self.classify_with_confidence(url, text, filename, category_hint)
        return result.category

    def classify_with_confidence(
        self,
        url: Optional[str] = None,
        text: Optional[str] = None,
        filename: Optional[str] = None,
        category_hint: Optional[str] = None,
    ) -> ClassificationResult:
        """
        Classify with full confidence breakdown.

        Returns ClassificationResult with scores and matched keywords.
        """
        # Explicit hint
        if category_hint:
            for cat in ChallengeCategory:
                if cat.value == category_hint.lower():
                    return ClassificationResult(
                        category=cat, confidence=1.0, scores={}, matched_keywords=["hint"],
                    )

        scores: dict[str, float] = {cat.value: 0.0 for cat in ChallengeCategory}
        all_matched = []
        combined = " ".join(filter(None, [url, text, filename])).lower()

        for category, indicators in self.indicators.items():
            cat_score = 0.0
            matched = []

            # Keyword matching with weights
            for keyword, weight in indicators["keywords"].items():
                if keyword.lower() in combined:
                    cat_score += weight
                    matched.append(keyword)

            # URL pattern matching
            if url:
                for pattern, weight in indicators.get("url_patterns", []):
                    if re.search(pattern, url, re.IGNORECASE):
                        cat_score += weight
                        matched.append(f"url:{pattern}")

            # File extension matching
            if filename:
                for ext, weight in indicators.get("file_extensions", {}).items():
                    if filename.lower().endswith(ext):
                        cat_score += weight
                        matched.append(f"file:{ext}")

            scores[category.value] = cat_score
            all_matched.extend(matched)

        if not any(scores.values()):
            return ClassificationResult(
                category=ChallengeCategory.UNKNOWN, confidence=0.0,
                scores=scores, matched_keywords=[],
            )

        best_cat = max(scores, key=scores.get)
        best_score = scores[best_cat]
        total = sum(scores.values())
        confidence = best_score / total if total > 0 else 0.0

        if best_score < 1.0:
            return ClassificationResult(
                category=ChallengeCategory.UNKNOWN, confidence=0.0,
                scores=scores, matched_keywords=all_matched,
            )

        return ClassificationResult(
            category=ChallengeCategory(best_cat),
            confidence=min(confidence, 1.0),
            scores=scores,
            matched_keywords=all_matched,
        )
