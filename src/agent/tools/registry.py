"""
Tool Registry - Security Tool Management

Central registry for all security tools available to the agent.
Handles tool discovery, validation, and execution wrappers.
"""

import subprocess
import shutil
import logging
from dataclasses import dataclass, field
from typing import Optional, Callable

logger = logging.getLogger(__name__)


@dataclass
class ToolInfo:
    """Information about a registered tool."""

    name: str
    description: str
    command: str
    category: str  # web, crypto, pwn, reverse, forensics, misc
    installed: bool = False
    version: str = ""
    check_cmd: str = ""  # Command to check if tool is installed
    install_cmd: str = ""  # Command to install the tool


# Built-in tool definitions
BUILTIN_TOOLS = [
    ToolInfo(
        name="nmap",
        description="Network exploration and security auditing",
        command="nmap",
        category="network",
        check_cmd="nmap --version",
    ),
    ToolInfo(
        name="curl",
        description="Transfer data from/to servers",
        command="curl",
        category="web",
        check_cmd="curl --version",
    ),
    ToolInfo(
        name="sqlmap",
        description="Automatic SQL injection and database takeover",
        command="sqlmap",
        category="web",
        check_cmd="sqlmap --version",
    ),
    ToolInfo(
        name="nikto",
        description="Web server scanner",
        command="nikto",
        category="web",
        check_cmd="nikto -Version",
    ),
    ToolInfo(
        name="gdb",
        description="GNU Debugger",
        command="gdb",
        category="pwn",
        check_cmd="gdb --version",
    ),
    ToolInfo(
        name="radare2",
        description="Reverse engineering framework",
        command="r2",
        category="reverse",
        check_cmd="r2 -v",
    ),
    ToolInfo(
        name="binwalk",
        description="Firmware analysis tool",
        command="binwalk",
        category="forensics",
        check_cmd="binwalk --help",
    ),
    ToolInfo(
        name="strings",
        description="Extract printable strings from files",
        command="strings",
        category="reverse",
        check_cmd="strings --version",
    ),
    ToolInfo(
        name="file",
        description="Determine file type",
        command="file",
        category="forensics",
        check_cmd="file --version",
    ),
    ToolInfo(
        name="openssl",
        description="Cryptography toolkit",
        command="openssl",
        category="crypto",
        check_cmd="openssl version",
    ),
    ToolInfo(
        name="python3",
        description="Python interpreter for custom scripts",
        command="python3",
        category="misc",
        check_cmd="python3 --version",
    ),
    ToolInfo(
        name="john",
        description="John the Ripper password cracker",
        command="john",
        category="crypto",
        check_cmd="john --help",
    ),
    ToolInfo(
        name="hashcat",
        description="Advanced password recovery",
        command="hashcat",
        category="crypto",
        check_cmd="hashcat --version",
    ),
    ToolInfo(
        name="steghide",
        description="Steganography tool",
        command="steghide",
        category="forensics",
        check_cmd="steghide --version",
    ),
    ToolInfo(
        name="volatility",
        description="Memory forensics framework",
        command="vol.py",
        category="forensics",
        check_cmd="vol.py --help",
    ),
    ToolInfo(
        name="ropper",
        description="ROP gadget finder",
        command="ropper",
        category="pwn",
        check_cmd="ropper --version",
    ),
    ToolInfo(
        name="checksec",
        description="Check binary security properties",
        command="checksec",
        category="pwn",
        check_cmd="checksec --help",
    ),
    ToolInfo(
        name="gobuster",
        description="Directory/file brute-forcing",
        command="gobuster",
        category="web",
        check_cmd="gobuster version",
    ),
    ToolInfo(
        name="ffuf",
        description="Web fuzzer",
        command="ffuf",
        category="web",
        check_cmd="ffuf -V",
    ),
    ToolInfo(
        name="hydra",
        description="Network logon cracker",
        command="hydra",
        category="web",
        check_cmd="hydra -h",
    ),
]


class ToolRegistry:
    """
    Registry for security tools.

    Manages tool discovery, availability checking, and provides
    a unified interface for tool execution.
    """

    def __init__(self, auto_discover: bool = True):
        self.tools: dict[str, ToolInfo] = {}
        self._custom_tools: dict[str, Callable] = {}

        # Register built-in tools
        for tool in BUILTIN_TOOLS:
            self.tools[tool.name] = tool

        if auto_discover:
            self.discover()

    def discover(self) -> dict[str, bool]:
        """
        Discover which tools are installed on the system.

        Returns:
            Dict mapping tool name to availability status
        """
        results = {}
        for name, tool in self.tools.items():
            if tool.check_cmd:
                try:
                    result = subprocess.run(
                        tool.check_cmd,
                        shell=True,
                        capture_output=True,
                        timeout=5,
                    )
                    tool.installed = result.returncode == 0
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    tool.installed = False
            else:
                tool.installed = shutil.which(tool.command) is not None

            results[name] = tool.installed

        return results

    def get_available(self, category: Optional[str] = None) -> list[ToolInfo]:
        """Get list of available tools, optionally filtered by category."""
        tools = [t for t in self.tools.values() if t.installed]
        if category:
            tools = [t for t in tools if t.category == category]
        return tools

    def is_available(self, tool_name: str) -> bool:
        """Check if a specific tool is available."""
        tool = self.tools.get(tool_name)
        return tool is not None and tool.installed

    def register_custom(self, name: str, func: Callable, description: str = ""):
        """Register a custom tool function."""
        self._custom_tools[name] = func
        self.tools[name] = ToolInfo(
            name=name,
            description=description or f"Custom tool: {name}",
            command=name,
            category="custom",
            installed=True,
        )

    def get_tool(self, name: str) -> Optional[ToolInfo]:
        """Get tool info by name."""
        return self.tools.get(name)

    def list_tools(self) -> list[dict]:
        """List all registered tools with their status."""
        return [
            {
                "name": t.name,
                "description": t.description,
                "category": t.category,
                "installed": t.installed,
            }
            for t in self.tools.values()
        ]

    def summary(self) -> str:
        """Get a summary of tool availability."""
        available = sum(1 for t in self.tools.values() if t.installed)
        total = len(self.tools)
        return f"Tools: {available}/{total} available"
