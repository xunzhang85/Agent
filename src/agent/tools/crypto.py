"""
Cryptography Tools

Wrappers for cryptographic analysis and decryption tools.
"""

import subprocess
import hashlib
import base64
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class CryptoTools:
    """Cryptography tool wrappers."""

    @staticmethod
    def base64_decode(data: str) -> str:
        """Decode base64 string."""
        try:
            return base64.b64decode(data).decode("utf-8", errors="replace")
        except Exception as e:
            return f"Error: {e}"

    @staticmethod
    def base64_encode(data: str) -> str:
        """Encode string to base64."""
        return base64.b64encode(data.encode()).decode()

    @staticmethod
    def hex_decode(data: str) -> str:
        """Decode hex string."""
        try:
            return bytes.fromhex(data).decode("utf-8", errors="replace")
        except Exception as e:
            return f"Error: {e}"

    @staticmethod
    def rot13(data: str) -> str:
        """Apply ROT13 cipher."""
        result = []
        for c in data:
            if "a" <= c <= "z":
                result.append(chr((ord(c) - ord("a") + 13) % 26 + ord("a")))
            elif "A" <= c <= "Z":
                result.append(chr((ord(c) - ord("A") + 13) % 26 + ord("A")))
            else:
                result.append(c)
        return "".join(result)

    @staticmethod
    def caesar_bruteforce(data: str) -> dict[int, str]:
        """Try all Caesar cipher shifts."""
        results = {}
        for shift in range(26):
            decoded = []
            for c in data:
                if "a" <= c <= "z":
                    decoded.append(chr((ord(c) - ord("a") - shift) % 26 + ord("a")))
                elif "A" <= c <= "Z":
                    decoded.append(chr((ord(c) - ord("A") - shift) % 26 + ord("A")))
                else:
                    decoded.append(c)
            results[shift] = "".join(decoded)
        return results

    @staticmethod
    def hash_crack(hash_value: str, hash_type: str = "md5", wordlist: Optional[str] = None) -> dict:
        """
        Attempt to crack a hash using john or hashcat.

        Returns:
            Dict with 'cracked', 'password', 'method'
        """
        if not wordlist:
            wordlist = "/usr/share/wordlists/rockyou.txt"

        # Try john first
        try:
            with open("/tmp/ctf_hash.txt", "w") as f:
                f.write(hash_value)

            result = subprocess.run(
                ["john", f"--format={hash_type}", "/tmp/ctf_hash.txt"],
                capture_output=True, text=True, timeout=60,
            )

            # Get the result
            show = subprocess.run(
                ["john", "--show", "/tmp/ctf_hash.txt"],
                capture_output=True, text=True, timeout=10,
            )

            if ":" in show.stdout:
                password = show.stdout.split(":")[1].strip()
                return {"cracked": True, "password": password, "method": "john"}

        except Exception as e:
            logger.debug(f"John failed: {e}")

        return {"cracked": False, "password": None, "method": "none"}

    @staticmethod
    def openssl_decrypt(
        data: str,
        cipher: str = "aes-256-cbc",
        key: Optional[str] = None,
        iv: Optional[str] = None,
    ) -> str:
        """Decrypt data using openssl."""
        cmd = ["openssl", "enc", f"-{cipher}", "-d", "-a"]

        if key:
            cmd.extend(["-K", key])
        if iv:
            cmd.extend(["-iv", iv])

        try:
            result = subprocess.run(
                cmd,
                input=data,
                capture_output=True,
                text=True,
                timeout=30,
            )
            return result.stdout or result.stderr
        except Exception as e:
            return f"Error: {e}"

    @staticmethod
    def xor(data: bytes, key: bytes) -> bytes:
        """XOR data with a repeating key."""
        return bytes(d ^ key[i % len(key)] for i, d in enumerate(data))

    @staticmethod
    def frequency_analysis(text: str) -> dict[str, float]:
        """Perform frequency analysis on text."""
        freq = {}
        total = 0
        for c in text.lower():
            if c.isalpha():
                freq[c] = freq.get(c, 0) + 1
                total += 1
        return {k: v / total for k, v in sorted(freq.items(), key=lambda x: -x[1])}
