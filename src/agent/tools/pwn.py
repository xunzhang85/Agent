"""
Binary Exploitation (Pwn) Tools

Wrappers for binary analysis and exploitation tools.
"""

import subprocess
import re
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class PwnTools:
    """Binary exploitation tool wrappers."""

    @staticmethod
    def checksec(binary: str) -> dict:
        """
        Check binary security properties.

        Returns:
            Dict with security feature flags (NX, ASLR, PIE, RELRO, etc.)
        """
        try:
            result = subprocess.run(
                ["checksec", f"--file={binary}"],
                capture_output=True, text=True, timeout=10,
            )
            output = result.stdout

            return {
                "relro": "Full RELRO" in output or "Partial RELRO" in output,
                "full_relro": "Full RELRO" in output,
                "stack_canary": "Canary found" in output,
                "nx": "NX enabled" in output,
                "pie": "PIE enabled" in output,
                "rpath": "RPATH" in output,
                "runpath": "RUNPATH" in output,
                "raw": output,
            }
        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    def file_info(binary: str) -> dict:
        """Get file type and architecture info."""
        try:
            result = subprocess.run(
                ["file", binary],
                capture_output=True, text=True, timeout=10,
            )
            output = result.stdout

            info = {"raw": output}

            if "ELF" in output:
                info["type"] = "ELF"
                if "64-bit" in output:
                    info["arch"] = "x86_64"
                else:
                    info["arch"] = "i386"
                if "statically linked" in output:
                    info["linking"] = "static"
                else:
                    info["linking"] = "dynamic"
            elif "PE32" in output:
                info["type"] = "PE"
            elif "Mach-O" in output:
                info["type"] = "Mach-O"

            return info
        except Exception as e:
            return {"error": str(e)}

    @staticmethod
    def strings(binary: str, min_length: int = 4) -> list[str]:
        """Extract printable strings from binary."""
        try:
            result = subprocess.run(
                ["strings", f"-n{min_length}", binary],
                capture_output=True, text=True, timeout=30,
            )
            return result.stdout.strip().split("\n")
        except Exception as e:
            return [f"Error: {e}"]

    @staticmethod
    def find_gadgets(binary: str, tool: str = "ropper") -> list[str]:
        """Find ROP gadgets in binary."""
        try:
            if tool == "ropper":
                result = subprocess.run(
                    ["ropper", "-f", binary, "--search", "pop rdi"],
                    capture_output=True, text=True, timeout=60,
                )
            else:
                result = subprocess.run(
                    ["ROPgadget", "--binary", binary],
                    capture_output=True, text=True, timeout=60,
                )
            return result.stdout.strip().split("\n")[:50]
        except Exception as e:
            return [f"Error: {e}"]

    @staticmethod
    def disassemble(binary: str, function: str = "main", tool: str = "radare2") -> str:
        """Disassemble a function from binary."""
        try:
            if tool == "radare2":
                result = subprocess.run(
                    ["r2", "-q", "-c", f"aaa; s {function}; pd 50", binary],
                    capture_output=True, text=True, timeout=60,
                )
            else:
                result = subprocess.run(
                    ["objdump", "-d", "-M", "intel", binary],
                    capture_output=True, text=True, timeout=30,
                )
            return result.stdout[:5000]
        except Exception as e:
            return f"Error: {e}"

    @staticmethod
    def generate_payload(
        payload_type: str = "cyclic",
        length: int = 100,
        offset: Optional[int] = None,
        address: Optional[str] = None,
    ) -> bytes:
        """
        Generate exploitation payloads.

        Args:
            payload_type: 'cyclic', 'pattern', 'shellcode'
            length: Payload length
            offset: Offset to return address
            address: Address to overwrite (hex string)
        """
        if payload_type == "cyclic":
            # Generate cyclic pattern
            try:
                result = subprocess.run(
                    ["cyclic", str(length)],
                    capture_output=True, text=True, timeout=10,
                )
                return result.stdout.encode()
            except Exception:
                return b"A" * length

        elif payload_type == "pattern":
            # De Bruijn pattern
            return PwnTools._de_bruijn(length)

        return b"A" * length

    @staticmethod
    def _de_bruijn(length: int) -> bytes:
        """Generate a De Bruijn sequence for offset finding."""
        alphabet = b"abcdefghijklmnopqrstuvwxyz"
        sequence = b""
        n = 4
        while len(sequence) < length:
            for a in alphabet:
                for b in alphabet:
                    for c in alphabet:
                        for d in alphabet:
                            sequence += bytes([a, b, c, d])
                            if len(sequence) >= length:
                                return sequence[:length]
        return sequence[:length]
