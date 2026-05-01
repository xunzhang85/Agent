"""
Reviewer - Result Validation Module (Optimized)

Enhanced with multi-pattern detection, confidence scoring,
context-aware analysis, and false positive filtering.
"""

import re
import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

# Comprehensive flag patterns with confidence weights
FLAG_PATTERNS = [
    # Standard CTF formats (high confidence)
    (r"flag\{[^}]{1,100}\}", 1.0),
    (r"FLAG\{[^}]{1,100}\}", 1.0),
    (r"CTF\{[^}]{1,100}\}", 1.0),
    (r"ctf\{[^}]{1,100}\}", 1.0),
    # Platform-specific (high confidence)
    (r"HTB\{[^}]+\}", 1.0),
    (r"THM\{[^}]+\}", 1.0),
    (r"PICOCTF\{[^}]+\}", 1.0),
    (r"picoCTF\{[^}]+\}", 1.0),
    (r"ACTF\{[^}]+\}", 1.0),
    (r"SECCON\{[^}]+\}", 1.0),
    (r"ASIS\{[^}]+\}", 1.0),
    (r"DDCTF\{[^}]+\}", 1.0),
    (r"RCTF\{[^}]+\}", 1.0),
    (r"XCTF\{[^}]+\}", 1.0),
    (r"BJD\{[^}]+\}", 1.0),
    (r"HGAME\{[^}]+\}", 1.0),
    (r"NCTF\{[^}]+\}", 1.0),
    (r"WMCTF\{[^}]+\}", 1.0),
    (r"INSHack\{[^}]+\}", 1.0),
    (r"corctf\{[^}]+\}", 1.0),
    (r"justCTF\{[^}]+\}", 1.0),
    # Generic wrapped formats
    (r"[A-Z][A-Z0-9_]{2,20}\{[^}]{3,200}\}", 0.9),
    # Quoted flags
    (r"['\"]flag['\"]:\s*['\"]([^'\"]+)['\"]", 0.8),
    (r"[Ff]lag[:=]\s*([^\s,;]{5,100})", 0.7),
    # Base64 encoded flags (check decoded)
    (r"[A-Za-z0-9+/]{20,}={0,2}", 0.3),  # Low confidence, needs context
]

# False positive patterns to exclude
FALSE_POSITIVES = [
    r"flag\{test\}",
    r"flag\{example\}",
    r"flag\{your_flag_here\}",
    r"flag\{placeholder\}",
    r"CTF\{example\}",
]


@dataclass
class ReviewResult:
    """Result of reviewing execution output."""
    flag_found: bool = False
    flag: Optional[str] = None
    should_stop: bool = False
    new_hint: Optional[str] = None
    confidence: float = 0.0
    feedback: str = ""
    all_candidates: list[str] = None

    def __post_init__(self):
        if self.all_candidates is None:
            self.all_candidates = []


class Reviewer:
    """
    Enhanced reviewer with multi-pattern detection and confidence scoring.
    """

    def __init__(self, custom_patterns: Optional[list[tuple[str, float]]] = None):
        self.patterns = FLAG_PATTERNS.copy()
        if custom_patterns:
            self.patterns.extend(custom_patterns)
        self._compiled = [(re.compile(p, re.IGNORECASE), w) for p, w in self.patterns]
        self._fp_compiled = [re.compile(p, re.IGNORECASE) for p in FALSE_POSITIVES]

    def review(self, output: str, category: str = "unknown", steps: Optional[list[str]] = None) -> ReviewResult:
        """Review output for flags with confidence scoring."""
        candidates = []

        for pattern, weight in self._compiled:
            matches = pattern.findall(output)
            for match in matches:
                if isinstance(match, tuple):
                    match = match[0] if match else ""
                if not match or len(match) < 4:
                    continue
                if self._is_false_positive(match):
                    continue
                if self._is_valid_flag(match):
                    candidates.append((match, weight))

        # Also check for base64 encoded flags
        b64_flags = self._check_base64_flags(output)
        candidates.extend(b64_flags)

        if candidates:
            # Sort by confidence, pick highest
            candidates.sort(key=lambda x: x[1], reverse=True)
            best_flag, best_confidence = candidates[0]

            return ReviewResult(
                flag_found=True,
                flag=best_flag,
                should_stop=True,
                confidence=best_confidence,
                feedback=f"Flag found: {best_flag} (confidence: {best_confidence:.0%})",
                all_candidates=[c[0] for c in candidates],
            )

        # Progress analysis
        hint = self._analyze_progress(output, category, steps)

        return ReviewResult(
            flag_found=False,
            should_stop=False,
            new_hint=hint,
            confidence=0.0,
            feedback="No flag found yet",
        )

    def _is_false_positive(self, candidate: str) -> bool:
        for fp in self._fp_compiled:
            if fp.fullmatch(candidate):
                return True
        return False

    def _is_valid_flag(self, candidate: str) -> bool:
        if len(candidate) < 4:
            return False
        if re.match(r"^[A-Z][A-Z0-9_]*\{.+\}$", candidate):
            return True
        if re.match(r"^[a-z]+\{.+\}$", candidate) and len(candidate) > 8:
            return True
        return True

    def _check_base64_flags(self, text: str) -> list[tuple[str, float]]:
        """Check for base64-encoded flags."""
        import base64
        results = []
        b64_pattern = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")
        for match in b64_pattern.findall(text):
            try:
                decoded = base64.b64decode(match).decode("utf-8", errors="ignore")
                if re.search(r"(flag|ctf)\{[^}]+\}", decoded, re.IGNORECASE):
                    results.append((decoded, 0.95))
            except Exception:
                pass
        return results

    def _analyze_progress(self, output: str, category: str, steps: Optional[list[str]]) -> Optional[str]:
        hints = []
        output_lower = output.lower()

        # HTTP status hints
        if "404" in output or "not found" in output_lower:
            hints.append("404 detected - enumerate directories with gobuster/ffuf, try common paths")
        elif "403" in output or "forbidden" in output_lower:
            hints.append("403 forbidden - try path traversal, header bypass (X-Forwarded-For), or different methods")
        elif "401" in output or "unauthorized" in output_lower:
            hints.append("401 unauthorized - try default credentials, auth bypass, or JWT manipulation")

        # SQL hints
        if "sql" in output_lower or "syntax error" in output_lower or "mysql" in output_lower:
            hints.append("SQL indicators found - try UNION injection, boolean blind, or time-based blind SQLi")

        # File/path hints
        if "index.php" in output_lower or ".php" in output_lower:
            hints.append("PHP detected - try LFI, RFI, PHP wrappers (php://filter), or type juggling")

        # Binary hints
        if "segfault" in output_lower or "segmentation" in output_lower:
            hints.append("Segfault confirmed - buffer overflow viable, find offset with cyclic pattern")
        if "permission denied" in output_lower:
            hints.append("Permission denied - try privilege escalation, SUID binaries, or kernel exploits")

        # Encoding hints
        if "base64" in output_lower:
            hints.append("Base64 detected - decode and check for hidden data")
        if "hex" in output_lower and "0x" in output:
            hints.append("Hex data found - try hex decoding")

        # Category-specific hints
        if category == "web" and not hints:
            hints.append("Try: directory enumeration, parameter fuzzing, cookie manipulation, header injection")
        elif category == "crypto" and not hints:
            hints.append("Try: frequency analysis, known-plaintext attacks, factorization tools")
        elif category == "pwn" and not hints:
            hints.append("Try: checksec, find ROP gadgets, test different offsets, check for format string")

        return hints[0] if hints else None

    def validate_flag_format(self, flag: str, expected_format: Optional[str] = None) -> bool:
        if expected_format:
            return bool(re.match(expected_format, flag))
        return self._is_valid_flag(flag)
