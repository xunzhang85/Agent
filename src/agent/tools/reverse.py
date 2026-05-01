"""
Reverse Engineering Tools

Wrappers for disassembly, decompilation, and binary analysis.
"""

import subprocess
import logging
from typing import Optional

logger = logging.getLogger(__name__)


class ReverseTools:
    """Reverse engineering tool wrappers."""

    @staticmethod
    def radare2_analyze(binary: str, commands: Optional[list[str]] = None) -> str:
        """
        Run radare2 analysis commands.

        Args:
            binary: Path to binary
            commands: List of r2 commands to execute
        """
        if not commands:
            commands = ["aaa", "afl", "s main", "pdf"]

        cmd_str = "; ".join(commands)
        try:
            result = subprocess.run(
                ["r2", "-q", "-c", cmd_str, binary],
                capture_output=True, text=True, timeout=120,
            )
            return result.stdout[:10000]
        except Exception as e:
            return f"Error: {e}"

    @staticmethod
    def ghidra_decompile(
        binary: str,
        script_path: Optional[str] = None,
        ghidra_home: Optional[str] = None,
    ) -> str:
        """
        Decompile binary using Ghidra (headless mode).

        Requires Ghidra to be installed.
        """
        if not ghidra_home:
            ghidra_home = "/opt/ghidra"

        try:
            cmd = [
                f"{ghidra_home}/support/analyzeHeadless",
                "/tmp/ghidra_project",
                "CTF_Analysis",
                "-import", binary,
            ]
            if script_path:
                cmd.extend(["-postScript", script_path])

            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300,
            )
            return result.stdout[:10000]
        except Exception as e:
            return f"Ghidra error: {e}"

    @staticmethod
    def angr_explore(binary: str, target_addr: Optional[str] = None) -> str:
        """
        Use angr for symbolic execution to find paths.

        Args:
            binary: Path to binary
            target_addr: Target address to reach (hex)
        """
        script = f"""
import angr
import sys

p = angr.Project('{binary}', auto_load_libs=False)
state = p.factory.entry_state()
simgr = p.factory.simulation_manager(state)

{'simgr.explore(find=0x' + target_addr + ')' if target_addr else 'simgr.explore()'}

if simgr.found:
    found = simgr.found[0]
    print("Found path!")
    print("Input:", found.posix.dumps(0))
else:
    print("No path found")
"""
        try:
            result = subprocess.run(
                ["python3", "-c", script],
                capture_output=True, text=True, timeout=120,
            )
            return result.stdout or result.stderr
        except Exception as e:
            return f"angr error: {e}"

    @staticmethod
    def objdump(binary: str, sections: bool = True, disassemble: bool = True) -> str:
        """Run objdump on binary."""
        cmd = ["objdump"]
        if sections:
            cmd.append("-h")
        if disassemble:
            cmd.extend(["-d", "-M", "intel"])
        cmd.append(binary)

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30,
            )
            return result.stdout[:10000]
        except Exception as e:
            return f"Error: {e}"

    @staticmethod
    def readelf(binary: str) -> dict:
        """Extract ELF information."""
        info = {}
        try:
            # Headers
            result = subprocess.run(
                ["readelf", "-h", binary],
                capture_output=True, text=True, timeout=10,
            )
            info["headers"] = result.stdout

            # Sections
            result = subprocess.run(
                ["readelf", "-S", binary],
                capture_output=True, text=True, timeout=10,
            )
            info["sections"] = result.stdout

            # Symbols
            result = subprocess.run(
                ["readelf", "-s", binary],
                capture_output=True, text=True, timeout=10,
            )
            info["symbols"] = result.stdout

            return info
        except Exception as e:
            return {"error": str(e)}
