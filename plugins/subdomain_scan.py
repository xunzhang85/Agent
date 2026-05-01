"""
Example Plugin: Subdomain Scanner

To create your own plugin:
1. Create a .py file in the plugins/ directory
2. Define TOOL_INFO dict with name, description, category
3. Define a run() function that takes the target as argument
"""

import subprocess

TOOL_INFO = {
    "name": "subdomain_scan",
    "description": "Enumerate subdomains using dig and wordlist",
    "category": "web",
    "check_cmd": "dig -v",
}


def run(target: str) -> str:
    """
    Scan for subdomains of a target domain.

    Args:
        target: Domain name to scan (e.g., "example.com")

    Returns:
        Found subdomains as string
    """
    wordlist = ["www", "mail", "ftp", "admin", "api", "dev", "staging", "test", "blog"]
    found = []

    for sub in wordlist:
        domain = f"{sub}.{target}"
        try:
            result = subprocess.run(
                ["dig", "+short", domain],
                capture_output=True, text=True, timeout=5,
            )
            if result.stdout.strip():
                found.append(f"{domain} -> {result.stdout.strip()}")
        except Exception:
            pass

    return "\n".join(found) if found else "No subdomains found"
