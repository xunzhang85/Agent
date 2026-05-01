"""
Reviewer - Result Validation Module

Reviews execution results to detect flags, validate solutions,
and provide feedback for the planning loop.
"""

import re
import logging
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)

# Common CTF flag patterns
FLAG_PATTERNS = [
    r"flag\{[^}]+\}",
    r"FLAG\{[^}]+\}",
    r"CTF\{[^}]+\}",
    r"ctf\{[^}]+\}",
    r"HTB\{[^}]+\}",
    r"PICOCTF\{[^}]+\}",
    r"picoCTF\{[^}]+\}",
    r"ACTF\{[^}]+\}",
    r"SECCON\{[^}]+\}",
    r"D\{[^}]+\}",
    r"[A-Z0-9]{32}",  # MD5-like hashes (contextual)
    r"[a-f0-9]{64}",  # SHA256-like hashes (contextual)
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


class Reviewer:
    """
    Reviews execution results for CTF flags and solution quality.

    Performs pattern matching for common flag formats and
    evaluates whether the current approach is making progress.
    """

    def __init__(self, custom_patterns: Optional[list[str]] = None):
        self.patterns = FLAG_PATTERNS.copy()
        if custom_patterns:
            self.patterns.extend(custom_patterns)
        self._compiled = [re.compile(p, re.IGNORECASE) for p in self.patterns]

    def review(
        self,
        output: str,
        category: str = "unknown",
        steps: Optional[list[str]] = None,
    ) -> ReviewResult:
        """
        Review output for flags and provide feedback.

        Args:
            output: Combined output from execution steps
            category: Challenge category for context-aware review
            steps: All steps taken so far

        Returns:
            ReviewResult with flag detection and feedback
        """
        # Check for flags in output
        flag = self._extract_flag(output)
        if flag:
            return ReviewResult(
                flag_found=True,
                flag=flag,
                should_stop=True,
                confidence=1.0,
                feedback=f"Flag found: {flag}",
            )

        # Analyze progress
        hint = self._analyze_progress(output, category, steps)

        return ReviewResult(
            flag_found=False,
            should_stop=False,
            new_hint=hint,
            confidence=0.0,
            feedback="No flag found yet",
        )

    def _extract_flag(self, text: str) -> Optional[str]:
        """Extract flag from text using pattern matching."""
        for pattern in self._compiled:
            matches = pattern.findall(text)
            for match in matches:
                # Filter out common false positives
                if self._is_valid_flag(match):
                    return match
        return None

    def _is_valid_flag(self, candidate: str) -> bool:
        """Validate a potential flag candidate."""
        # Too short is likely not a flag
        if len(candidate) < 4:
            return False

        # Filter common false positives for hash patterns
        if re.match(r"^[a-f0-9]{32}$", candidate):
            # Could be an MD5, check context
            return False  # Conservative: don't auto-detect hashes as flags

        if re.match(r"^[a-f0-9]{64}$", candidate):
            return False  # SHA256 hash, not a flag

        # Known flag format patterns are always valid
        if re.match(r"^[A-Z]+\{.+\}$", candidate):
            return True

        return True

    def _analyze_progress(
        self,
        output: str,
        category: str,
        steps: Optional[list[str]],
    ) -> Optional[str]:
        """Analyze execution output for hints about next steps."""
        hints = []

        # Check for common indicators
        if "404" in output or "Not Found" in output:
            hints.append("Target returned 404, try different paths or enumerate directories")

        if "403" in output or "Forbidden" in output:
            hints.append("Access forbidden, try bypass techniques or different endpoints")

        if "SQL" in output.upper() or "syntax error" in output.lower():
            hints.append("SQL-related output detected, try SQL injection techniques")

        if "permission denied" in output.lower():
            hints.append("Permission denied, try privilege escalation")

        if "timeout" in output.lower():
            hints.append("Connection timeout, target may be down or filtered")

        if "base64" in output.lower():
            hints.append("Base64 encoding detected, try decoding")

        if category == "web":
            if "cookie" in output.lower():
                hints.append("Cookies found, try modifying them")
            if "header" in output.lower():
                hints.append("Check response headers for hidden information")

        if hints:
            return hints[0]  # Return the most relevant hint
        return None

    def validate_flag_format(self, flag: str, expected_format: Optional[str] = None) -> bool:
        """
        Validate if a string matches expected flag format.

        Args:
            flag: The flag string to validate
            expected_format: Optional regex pattern for expected format

        Returns:
            True if the flag matches the expected format
        """
        if expected_format:
            return bool(re.match(expected_format, flag))

        # Default: check against known patterns
        return self._is_valid_flag(flag)
