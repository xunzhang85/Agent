"""
Forensics Tools

Wrappers for digital forensics and steganography analysis.
"""

import subprocess
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class ForensicsTools:
    """Forensics tool wrappers."""

    @staticmethod
    def binwalk_scan(file_path: str, extract: bool = False) -> dict:
        """
        Scan file for embedded files and signatures.

        Returns:
            Dict with 'signatures', 'extracted_files'
        """
        try:
            cmd = ["binwalk"]
            if extract:
                cmd.append("-e")
            cmd.append(file_path)

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=60,
            )
            return {
                "output": result.stdout,
                "signatures": [
                    line.strip()
                    for line in result.stdout.split("\n")
                    if line.strip() and not line.startswith("DECIMAL")
                ],
            }
        except Exception as e:
            return {"output": "", "signatures": [], "error": str(e)}

    @staticmethod
    def steghide_extract(file_path: str, passphrase: str = "") -> dict:
        """
        Extract hidden data using steghide.

        Returns:
            Dict with 'success', 'output', 'error'
        """
        try:
            result = subprocess.run(
                ["steghide", "extract", "-sf", file_path, "-p", passphrase, "-f"],
                capture_output=True, text=True, timeout=30,
            )
            return {
                "success": result.returncode == 0,
                "output": result.stdout,
                "error": result.stderr,
            }
        except Exception as e:
            return {"success": False, "output": "", "error": str(e)}

    @staticmethod
    def exiftool(file_path: str) -> dict:
        """Extract metadata from file."""
        try:
            result = subprocess.run(
                ["exiftool", file_path],
                capture_output=True, text=True, timeout=30,
            )
            metadata = {}
            for line in result.stdout.split("\n"):
                if ":" in line:
                    key, _, value = line.partition(":")
                    metadata[key.strip()] = value.strip()
            return {"metadata": metadata, "raw": result.stdout}
        except Exception as e:
            return {"metadata": {}, "error": str(e)}

    @staticmethod
    def volatility_analyze(memory_dump: str, plugin: str = "imageinfo") -> str:
        """
        Analyze memory dump using Volatility.

        Args:
            memory_dump: Path to memory dump file
            plugin: Volatility plugin to run
        """
        try:
            result = subprocess.run(
                ["vol.py", "-f", memory_dump, plugin],
                capture_output=True, text=True, timeout=300,
            )
            return result.stdout[:10000]
        except Exception as e:
            return f"Volatility error: {e}"

    @staticmethod
    def carve_files(file_path: str, output_dir: str = "/tmp/carved") -> list[str]:
        """Carve embedded files from a binary."""
        import os
        os.makedirs(output_dir, exist_ok=True)

        try:
            result = subprocess.run(
                ["foremost", "-i", file_path, "-o", output_dir],
                capture_output=True, text=True, timeout=120,
            )

            carved = []
            for root, dirs, files in os.walk(output_dir):
                for f in files:
                    carved.append(os.path.join(root, f))
            return carved
        except Exception as e:
            return [f"Error: {e}"]

    @staticmethod
    def pcap_analysis(pcap_file: str) -> dict:
        """Analyze pcap file using tshark."""
        try:
            # Summary
            summary = subprocess.run(
                ["tshark", "-r", pcap_file, "-q", "-z", "io,stat,0"],
                capture_output=True, text=True, timeout=60,
            )

            # HTTP streams
            http = subprocess.run(
                ["tshark", "-r", pcap_file, "-Y", "http", "-T", "fields", "-e", "http.host"],
                capture_output=True, text=True, timeout=60,
            )

            # Credentials
            creds = subprocess.run(
                ["tshark", "-r", pcap_file, "-Y", "http.authorization"],
                capture_output=True, text=True, timeout=60,
            )

            return {
                "summary": summary.stdout[:3000],
                "http_hosts": list(set(http.stdout.strip().split("\n"))) if http.stdout else [],
                "credentials": creds.stdout[:2000] if creds.stdout else "",
            }
        except Exception as e:
            return {"error": str(e)}
