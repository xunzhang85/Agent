"""
Executor - Task Execution Module (Optimized)

Async execution, result caching, better error handling, and
sandboxed Docker execution with resource limits.
"""

import asyncio
import subprocess
import logging
import tempfile
import time
import hashlib
import os
from dataclasses import dataclass
from typing import Optional
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

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
    cached: bool = False


class CommandCache:
    """Cache for command results to avoid re-execution."""

    def __init__(self, ttl: int = 300):
        self._cache: dict[str, tuple[float, ExecutionResult]] = {}
        self._ttl = ttl

    def _key(self, command: str) -> str:
        return hashlib.md5(command.encode()).hexdigest()

    def get(self, command: str) -> Optional[ExecutionResult]:
        key = self._key(command)
        if key in self._cache:
            ts, result = self._cache[key]
            if time.time() - ts < self._ttl:
                result.cached = True
                return result
            del self._cache[key]
        return None

    def put(self, command: str, result: ExecutionResult):
        self._cache[self._key(command)] = (time.time(), result)


class Executor:
    """
    Async-capable executor with caching and sandbox support.

    Supports parallel execution of independent commands.
    """

    def __init__(
        self,
        model: str = "gpt-4o",
        provider: str = "openai",
        api_key: Optional[str] = None,
        sandbox_enabled: bool = True,
        sandbox_image: str = "ctf-agent:sandbox",
        timeout: int = 60,
        max_workers: int = 4,
        cache_ttl: int = 300,
    ):
        self.sandbox_enabled = sandbox_enabled
        self.sandbox_image = sandbox_image
        self.timeout = timeout
        self.tool_registry = ToolRegistry()
        self._working_dir = tempfile.mkdtemp(prefix="ctf_agent_")
        self._pool = ThreadPoolExecutor(max_workers=max_workers)
        self._cache = CommandCache(ttl=cache_ttl)

    def execute(self, action, timeout: Optional[int] = None) -> ExecutionResult:
        """Sync execute an action."""
        return asyncio.run(self.async_execute(action, timeout))

    async def async_execute(self, action, timeout: Optional[int] = None) -> ExecutionResult:
        """Async execute an action."""
        effective_timeout = timeout or self.timeout
        command = action.command
        tool = action.tool

        # Check cache
        cached = self._cache.get(command)
        if cached:
            logger.debug(f"Cache hit for [{tool}]: {command[:60]}")
            return cached

        logger.info(f"Executing [{tool}]: {command[:100]}")
        start = time.time()

        try:
            loop = asyncio.get_event_loop()
            if self.sandbox_enabled:
                result = await loop.run_in_executor(
                    self._pool, self._execute_sandboxed, command, effective_timeout,
                )
            else:
                result = await loop.run_in_executor(
                    self._pool, self._execute_local, command, effective_timeout,
                )

            elapsed = time.time() - start
            exec_result = ExecutionResult(
                success=result.returncode == 0,
                output=result.stdout[:8000] if result.stdout else "",
                error=result.stderr[:3000] if result.stderr else "",
                return_code=result.returncode,
                tool=tool, command=command, elapsed_time=elapsed,
            )

            # Cache successful results
            if exec_result.success and exec_result.output:
                self._cache.put(command, exec_result)

            return exec_result

        except subprocess.TimeoutExpired:
            return ExecutionResult(
                success=False, error=f"Command timed out after {effective_timeout}s",
                tool=tool, command=command, elapsed_time=effective_timeout,
            )
        except Exception as e:
            logger.error(f"Execution error: {e}")
            return ExecutionResult(
                success=False, error=str(e),
                tool=tool, command=command, elapsed_time=time.time() - start,
            )

    def _execute_local(self, command: str, timeout: int) -> subprocess.CompletedProcess:
        return subprocess.run(
            command, shell=True, capture_output=True, text=True,
            timeout=timeout, cwd=self._working_dir,
        )

    def _execute_sandboxed(self, command: str, timeout: int) -> subprocess.CompletedProcess:
        docker_cmd = [
            "docker", "run", "--rm",
            "--memory=2g", "--cpus=1", "--network=ctf-net",
            "--read-only", "--tmpfs", "/tmp:size=512m",
            "--security-opt", "no-new-privileges:true",
            "-v", f"{self._working_dir}:/workspace",
            "-w", "/workspace",
            self.sandbox_image, "bash", "-c", command,
        ]
        return subprocess.run(docker_cmd, capture_output=True, text=True, timeout=timeout)

    async def async_reconnaissance(self, url=None, text=None) -> ExecutionResult:
        """Async reconnaissance."""
        commands = []
        if url:
            commands.extend([
                f"curl -s -I -L --max-time 10 {url}",
                f"curl -s --max-time 10 {url} | head -150",
            ])
        if text:
            # Extract URLs from text
            commands.append(f"echo '{text[:500]}' | grep -oE 'https?://[^ ]+' || true")

        if not commands:
            return ExecutionResult(success=True, output="No reconnaissance targets", tool="recon")

        combined = " && ".join(commands)
        action = type("Action", (), {"tool": "recon", "command": combined})()
        return await self.async_execute(action, timeout=30)

    def cleanup(self):
        """Clean up resources."""
        import shutil
        self._pool.shutdown(wait=False)
        try:
            shutil.rmtree(self._working_dir, ignore_errors=True)
        except Exception:
            pass
