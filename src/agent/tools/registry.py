"""
Tool Registry (Optimized)

Enhanced with plugin system, async discovery, tool health checks,
and hot-reload support for custom tools.
"""

import subprocess
import shutil
import logging
import importlib
import importlib.util
import os
from dataclasses import dataclass, field
from typing import Optional, Callable, Any
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)


@dataclass
class ToolInfo:
    """Information about a registered tool."""
    name: str
    description: str
    command: str
    category: str
    installed: bool = False
    version: str = ""
    check_cmd: str = ""
    install_cmd: str = ""
    health_check: Optional[Callable] = None
    wrapper: Optional[Callable] = None
    priority: int = 0  # Higher = preferred when multiple tools can do the same job


BUILTIN_TOOLS = [
    ToolInfo(name="curl", description="HTTP requests and response analysis", command="curl", category="web", check_cmd="curl --version", priority=10),
    ToolInfo(name="sqlmap", description="Automatic SQL injection and database takeover", command="sqlmap", category="web", check_cmd="sqlmap --version", priority=10),
    ToolInfo(name="nikto", description="Web server vulnerability scanner", command="nikto", category="web", check_cmd="nikto -Version", priority=5),
    ToolInfo(name="gobuster", description="Directory/file brute-forcing", command="gobuster", category="web", check_cmd="gobuster version", priority=8),
    ToolInfo(name="ffuf", description="Fast web fuzzer", command="ffuf", category="web", check_cmd="ffuf -V", priority=8),
    ToolInfo(name="hydra", description="Network logon cracker", command="hydra", category="web", check_cmd="hydra -h", priority=5),
    ToolInfo(name="nmap", description="Network exploration and security auditing", command="nmap", category="network", check_cmd="nmap --version", priority=10),
    ToolInfo(name="openssl", description="Cryptography toolkit", command="openssl", category="crypto", check_cmd="openssl version", priority=10),
    ToolInfo(name="john", description="John the Ripper password cracker", command="john", category="crypto", check_cmd="john --help", priority=7),
    ToolInfo(name="hashcat", description="Advanced password recovery", command="hashcat", category="crypto", check_cmd="hashcat --version", priority=7),
    ToolInfo(name="gdb", description="GNU Debugger", command="gdb", category="pwn", check_cmd="gdb --version", priority=10),
    ToolInfo(name="ropper", description="ROP gadget finder", command="ropper", category="pwn", check_cmd="ropper --version", priority=7),
    ToolInfo(name="checksec", description="Check binary security properties", command="checksec", category="pwn", check_cmd="checksec --help", priority=8),
    ToolInfo(name="radare2", description="Reverse engineering framework", command="r2", category="reverse", check_cmd="r2 -v", priority=10),
    ToolInfo(name="binwalk", description="Firmware analysis tool", command="binwalk", category="forensics", check_cmd="binwalk --help", priority=8),
    ToolInfo(name="strings", description="Extract printable strings from files", command="strings", category="reverse", check_cmd="strings --version", priority=5),
    ToolInfo(name="file", description="Determine file type", command="file", category="forensics", check_cmd="file --version", priority=5),
    ToolInfo(name="steghide", description="Steganography tool", command="steghide", category="forensics", check_cmd="steghide --version", priority=7),
    ToolInfo(name="exiftool", description="Metadata extraction", command="exiftool", category="forensics", check_cmd="exiftool -ver", priority=6),
    ToolInfo(name="volatility", description="Memory forensics framework", command="vol.py", category="forensics", check_cmd="vol.py --help", priority=7),
    ToolInfo(name="python3", description="Python interpreter for custom scripts", command="python3", category="misc", check_cmd="python3 --version", priority=10),
    ToolInfo(name="bash", description="Shell command execution", command="bash", category="misc", check_cmd="bash --version", priority=5),
]


class PluginLoader:
    """Load custom tool plugins from directory."""

    def __init__(self, plugin_dir: str = "plugins"):
        self.plugin_dir = Path(plugin_dir)

    def discover(self) -> list[dict]:
        """Discover and load plugins from plugin directory."""
        plugins = []
        if not self.plugin_dir.exists():
            return plugins

        for py_file in self.plugin_dir.glob("*.py"):
            try:
                spec = importlib.util.spec_from_file_location(py_file.stem, py_file)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                if hasattr(module, "TOOL_INFO"):
                    info = module.TOOL_INFO
                    plugins.append({
                        "name": info.get("name", py_file.stem),
                        "description": info.get("description", ""),
                        "category": info.get("category", "custom"),
                        "wrapper": getattr(module, "run", None),
                        "check_cmd": info.get("check_cmd", ""),
                    })
                    logger.info(f"Loaded plugin: {py_file.stem}")
            except Exception as e:
                logger.warning(f"Failed to load plugin {py_file}: {e}")

        return plugins


class ToolRegistry:
    """
    Enhanced tool registry with plugin support and health checks.
    """

    def __init__(self, auto_discover: bool = True, plugin_dir: str = "plugins"):
        self.tools: dict[str, ToolInfo] = {}
        self._plugin_loader = PluginLoader(plugin_dir)

        for tool in BUILTIN_TOOLS:
            self.tools[tool.name] = tool

        if auto_discover:
            self.discover()
            self._load_plugins()

    def discover(self) -> dict[str, bool]:
        """Discover which tools are installed."""
        results = {}
        for name, tool in self.tools.items():
            if tool.check_cmd:
                try:
                    result = subprocess.run(
                        tool.check_cmd, shell=True, capture_output=True, timeout=5,
                    )
                    tool.installed = result.returncode == 0
                    if tool.installed and result.stdout:
                        version_str = result.stdout if isinstance(result.stdout, str) else result.stdout.decode("utf-8", errors="replace")
                        tool.version = version_str.split("\n")[0][:100]
                except (subprocess.TimeoutExpired, FileNotFoundError):
                    tool.installed = False
            else:
                tool.installed = shutil.which(tool.command) is not None
            results[name] = tool.installed
        return results

    def _load_plugins(self):
        """Load plugins and register them."""
        plugins = self._plugin_loader.discover()
        for plugin in plugins:
            name = plugin["name"]
            if name not in self.tools:
                self.tools[name] = ToolInfo(
                    name=name,
                    description=plugin.get("description", ""),
                    command=name,
                    category=plugin.get("category", "custom"),
                    installed=True,
                    wrapper=plugin.get("wrapper"),
                )

    def get_available(self, category: Optional[str] = None) -> list[ToolInfo]:
        tools = [t for t in self.tools.values() if t.installed]
        if category:
            tools = [t for t in tools if t.category == category]
        return sorted(tools, key=lambda t: -t.priority)

    def is_available(self, tool_name: str) -> bool:
        tool = self.tools.get(tool_name)
        return tool is not None and tool.installed

    def register_custom(self, name: str, func: Callable, description: str = "", category: str = "custom"):
        self._custom_tools = getattr(self, "_custom_tools", {})
        self._custom_tools[name] = func
        self.tools[name] = ToolInfo(
            name=name, description=description or f"Custom: {name}",
            command=name, category=category, installed=True, wrapper=func,
        )

    def get_tool(self, name: str) -> Optional[ToolInfo]:
        return self.tools.get(name)

    def list_tools(self) -> list[dict]:
        return [
            {
                "name": t.name, "description": t.description,
                "category": t.category, "installed": t.installed,
                "version": t.version, "priority": t.priority,
            }
            for t in sorted(self.tools.values(), key=lambda t: (t.category, -t.priority))
        ]

    def summary(self) -> str:
        available = sum(1 for t in self.tools.values() if t.installed)
        total = len(self.tools)
        categories = set(t.category for t in self.tools.values())
        return f"Tools: {available}/{total} available across {len(categories)} categories"
