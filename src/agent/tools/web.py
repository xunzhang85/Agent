"""
Web Security Tools

Wrappers for web exploitation tools: SQL injection, XSS, SSRF, etc.
"""

import subprocess
import logging
import urllib.parse
from typing import Optional

logger = logging.getLogger(__name__)


class WebTools:
    """Web security tool wrappers."""

    @staticmethod
    def curl(
        url: str,
        method: str = "GET",
        headers: Optional[dict] = None,
        data: Optional[str] = None,
        follow_redirects: bool = True,
        timeout: int = 30,
    ) -> dict:
        """
        Execute HTTP request using curl.

        Returns:
            Dict with 'status', 'headers', 'body', 'error'
        """
        cmd = ["curl", "-s", "-w", "\n%{http_code}"]

        if method != "GET":
            cmd.extend(["-X", method])
        if headers:
            for k, v in headers.items():
                cmd.extend(["-H", f"{k}: {v}"])
        if data:
            cmd.extend(["-d", data])
        if follow_redirects:
            cmd.append("-L")

        cmd.append(url)

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            lines = result.stdout.rsplit("\n", 1)
            body = lines[0] if len(lines) > 1 else ""
            status = lines[-1].strip() if len(lines) > 1 else "0"

            return {
                "status": int(status) if status.isdigit() else 0,
                "body": body,
                "error": result.stderr,
            }
        except Exception as e:
            return {"status": 0, "body": "", "error": str(e)}

    @staticmethod
    def nmap_scan(
        target: str,
        ports: str = "1-1000",
        scripts: Optional[list[str]] = None,
        timeout: int = 120,
    ) -> dict:
        """
        Run nmap scan on target.

        Returns:
            Dict with 'open_ports', 'services', 'raw_output'
        """
        cmd = ["nmap", "-sV", "-p", ports, "--open"]

        if scripts:
            cmd.extend(["--script", ",".join(scripts)])

        cmd.append(target)

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            return {
                "open_ports": WebTools._parse_nmap_ports(result.stdout),
                "raw_output": result.stdout,
                "error": result.stderr,
            }
        except subprocess.TimeoutExpired:
            return {"open_ports": [], "raw_output": "", "error": "Scan timed out"}
        except Exception as e:
            return {"open_ports": [], "raw_output": "", "error": str(e)}

    @staticmethod
    def _parse_nmap_ports(output: str) -> list[dict]:
        """Parse nmap output for open ports."""
        ports = []
        for line in output.split("\n"):
            if "/tcp" in line and "open" in line:
                parts = line.split()
                if len(parts) >= 3:
                    port = parts[0].split("/")[0]
                    service = parts[2] if len(parts) > 2 else "unknown"
                    ports.append({"port": int(port), "service": service})
        return ports

    @staticmethod
    def gobuster(
        url: str,
        wordlist: str = "/usr/share/wordlists/dirb/common.txt",
        extensions: str = "php,html,txt",
        timeout: int = 300,
    ) -> dict:
        """
        Directory enumeration with gobuster.

        Returns:
            Dict with 'found_paths', 'raw_output'
        """
        cmd = [
            "gobuster", "dir",
            "-u", url,
            "-w", wordlist,
            "-x", extensions,
            "-q",  # Quiet
        ]

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            paths = [
                line.split()[0]
                for line in result.stdout.split("\n")
                if line.strip() and "(Status:" in line
            ]
            return {"found_paths": paths, "raw_output": result.stdout}
        except Exception as e:
            return {"found_paths": [], "raw_output": "", "error": str(e)}

    @staticmethod
    def sqlmap_scan(
        url: str,
        data: Optional[str] = None,
        cookie: Optional[str] = None,
        level: int = 1,
        risk: int = 1,
        timeout: int = 300,
    ) -> dict:
        """
        SQL injection scan with sqlmap.

        Returns:
            Dict with 'injectable', 'databases', 'raw_output'
        """
        cmd = ["sqlmap", "-u", url, "--batch", f"--level={level}", f"--risk={risk}"]

        if data:
            cmd.extend(["--data", data])
        if cookie:
            cmd.extend(["--cookie", cookie])

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
            injectable = "is vulnerable" in result.stdout or "injectable" in result.stdout
            return {
                "injectable": injectable,
                "raw_output": result.stdout,
                "error": result.stderr,
            }
        except Exception as e:
            return {"injectable": False, "raw_output": "", "error": str(e)}
