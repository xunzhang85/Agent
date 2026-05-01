"""
Executor - Task Execution Module

Executes planned actions using the tool registry.
Supports sandboxed execution via Docker containers.
"""

import subprocess
import logging
import tempfile
import os
from dataclasses import dataclass, field
from typing import Optional

from agent.tools.registry import ToolRegistry

logger = logging.getLogger(__name__)


@dataclass
class ExecutionResult:
    """Result of executing an action."""

    success: bool
    output: str = ""
    error: str = ""
    return_code: int = 0
    tool: str = ""
    command: str = ""
    elapsed_time: float = 0.0


class Executor:
    """
    Executes CTF solving actions.

    Supports both local and sandboxed (Docker) execution.
    Maintains a tool registry for capability management.
    """

    def __init__(
        self,
        model: str = "gpt-4o",
        provider: str = "openai",
        api_key: Optional[str] = None,
        sandbox_enabled: bool = True,
        sandbox_image: str = "ctf-agent:sandbox",
        timeout: int = 60,
    ):
        self.model = model
        self.provider = provider
        self.api_key = api_key
        self.sandbox_enabled = sandbox_enabled
        self.sandbox_image = sandbox_image
        self.timeout = timeout
        self.tool_registry = ToolRegistry()
        self._working_dir = tempfile.mkdtemp(prefix="ctf_agent_")

    def execute(self, action, timeout: Optional[int] = None) -> ExecutionResult:
        """
        Execute a single action.

        Args:
            action: Action object with tool, command, args
            timeout: Command timeout in seconds

        Returns:
            ExecutionResult with output or error
        """
        import time
        start = time.time()
        effective_timeout = timeout or self.timeout

        tool = action.tool
        command = action.command

        logger.info(f"Executing [{tool}]: {command[:100]}")

        try:
            if self.sandbox_enabled:
                result = self._execute_sandboxed(command, effective_timeout)
            else:
                result = self._execute_local(command, effective_timeout)

            elapsed = time.time() - start
            return ExecutionResult(
                success=result.returncode == 0,
                output=result.stdout[:5000] if result.stdout else "",
                error=result.stderr[:2000] if result.stderr else "",
                return_code=result.returncode,
                tool=tool,
                command=command,
                elapsed_time=elapsed,
            )

        except subprocess.TimeoutExpired:
            return ExecutionResult(
                success=False,
                error=f"Command timed out after {effective_timeout}s",
                tool=tool,
                command=command,
                elapsed_time=effective_timeout,
            )
        except Exception as e:
            logger.error(f"Execution error: {e}")
            return ExecutionResult(
                success=False,
                error=str(e),
                tool=tool,
                command=command,
                elapsed_time=time.time() - start,
            )

    def _execute_local(self, command: str, timeout: int) -> subprocess.CompletedProcess:
        """Execute command locally."""
        return subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=self._working_dir,
        )

    def _execute_sandboxed(self, command: str, timeout: int) -> subprocess.CompletedProcess:
        """Execute command inside Docker sandbox."""
        docker_cmd = [
            "docker", "run", "--rm",
            "--memory=2g",
            "--cpus=1",
            "--network=ctf-net",
            "--read-only",
            "--tmpfs", "/tmp:size=512m",
            "-v", f"{self._working_dir}:/workspace",
            "-w", "/workspace",
            self.sandbox_image,
            "bash", "-c", command,
        ]
        return subprocess.run(
            docker_cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    def reconnaissance(self, url: Optional[str] = None, text: Optional[str] = None) -> ExecutionResult:
        """
        Perform initial reconnaissance on a challenge.

        Gathers basic information about the target.
        """
        commands = []

        if url:
            commands.extend([
                f"curl -s -I -L {url}",
                f"curl -s {url} | head -100",
            ])

        if text:
            # Extract potential URLs, IPs, ports from text
            commands.append(f"echo '{text[:500]}' | grep -oE 'https?://[^ ]+'")

        if not commands:
            return ExecutionResult(
                success=True,
                output="No reconnaissance targets identified",
                tool="recon",
            )

        combined = " && ".join(commands)
        return self.execute(
            type("Action", (), {"tool": "recon", "command": combined})(),
            timeout=30,
        )

    def cleanup(self):
        """Clean up temporary files."""
        import shutil
        try:
            shutil.rmtree(self._working_dir, ignore_errors=True)
        except Exception:
            pass
