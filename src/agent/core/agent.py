"""
CTFAgent - Main Agent Controller (Optimized)

Orchestrates the Planner, Executor, and Reviewer to solve CTF challenges.
Implements async execution, caching, and streaming support.
"""

import asyncio
import time
import logging
import hashlib
import json
from dataclasses import dataclass, field
from typing import Optional, AsyncGenerator, Callable
from pathlib import Path

from agent.core.planner import Planner, Plan
from agent.core.executor import Executor, ExecutionResult
from agent.core.reviewer import Reviewer, ReviewResult
from agent.core.memory import Memory
from agent.categories.classifier import ChallengeClassifier, ChallengeCategory

logger = logging.getLogger(__name__)


@dataclass
class SolveResult:
    """Result of a CTF challenge solving attempt."""

    success: bool
    flag: Optional[str] = None
    category: Optional[str] = None
    steps: list[str] = field(default_factory=list)
    iterations: int = 0
    elapsed_time: float = 0.0
    error: Optional[str] = None
    cached: bool = False
    solve_id: str = ""

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "flag": self.flag,
            "category": self.category,
            "steps": self.steps,
            "iterations": self.iterations,
            "elapsed_time": self.elapsed_time,
            "error": self.error,
            "cached": self.cached,
            "solve_id": self.solve_id,
        }

    def __str__(self) -> str:
        if self.success:
            cache_tag = " [cached]" if self.cached else ""
            return f"✅ Solved! Flag: {self.flag}{cache_tag} ({self.iterations} iter, {self.elapsed_time:.1f}s)"
        return f"❌ Failed: {self.error} ({self.iterations} iter, {self.elapsed_time:.1f}s)"


class ResultCache:
    """Simple in-memory + disk cache for solve results."""

    def __init__(self, cache_dir: str = ".cache"):
        self._memory: dict[str, SolveResult] = {}
        self._cache_dir = Path(cache_dir)
        self._cache_dir.mkdir(exist_ok=True)
        self._load_disk_cache()

    def _key(self, url: Optional[str], text: Optional[str], category: Optional[str]) -> str:
        content = f"{url or ''}|{text or ''}|{category or ''}"
        return hashlib.md5(content.encode()).hexdigest()

    def _load_disk_cache(self):
        cache_file = self._cache_dir / "results.json"
        if cache_file.exists():
            try:
                data = json.loads(cache_file.read_text())
                for k, v in data.items():
                    self._memory[k] = SolveResult(**v)
            except Exception:
                pass

    def _save_disk_cache(self):
        cache_file = self._cache_dir / "results.json"
        try:
            data = {k: v.to_dict() for k, v in self._memory.items()}
            cache_file.write_text(json.dumps(data, indent=2))
        except Exception:
            pass

    def get(self, url: Optional[str], text: Optional[str], category: Optional[str]) -> Optional[SolveResult]:
        key = self._key(url, text, category)
        result = self._memory.get(key)
        if result:
            result.cached = True
        return result

    def put(self, url: Optional[str], text: Optional[str], category: Optional[str], result: SolveResult):
        key = self._key(url, text, category)
        self._memory[key] = result
        self._save_disk_cache()


class CTFAgent:
    """
    Main CTF Agent with async support, caching, and streaming.

    Usage:
        # Sync
        agent = CTFAgent(model="gpt-4o")
        result = agent.solve(challenge_url="http://target.ctf.com")

        # Async
        result = await agent.asolve(challenge_url="http://target.ctf.com")

        # Streaming
        async for event in agent.solve_stream(challenge_url="http://target.ctf.com"):
            print(event)
    """

    def __init__(
        self,
        model: str = "gpt-4o",
        provider: str = "openai",
        api_key: Optional[str] = None,
        max_iterations: int = 20,
        timeout: int = 600,
        retry_on_failure: bool = True,
        max_retries: int = 3,
        sandbox_enabled: bool = True,
        cache_enabled: bool = True,
        on_progress: Optional[Callable] = None,
    ):
        self.model = model
        self.provider = provider
        self.max_iterations = max_iterations
        self.timeout = timeout
        self.retry_on_failure = retry_on_failure
        self.max_retries = max_retries
        self.on_progress = on_progress

        self.memory = Memory()
        self.classifier = ChallengeClassifier()
        self.planner = Planner(model=model, provider=provider, api_key=api_key)
        self.executor = Executor(
            model=model, provider=provider, api_key=api_key,
            sandbox_enabled=sandbox_enabled,
        )
        self.reviewer = Reviewer()
        self.cache = ResultCache() if cache_enabled else None

        logger.info(f"CTFAgent initialized: model={model}, provider={provider}")

    def _emit(self, event_type: str, data: dict):
        """Emit progress event to callback."""
        if self.on_progress:
            try:
                self.on_progress({"type": event_type, **data})
            except Exception:
                pass

    def solve(
        self,
        challenge_url: Optional[str] = None,
        challenge_text: Optional[str] = None,
        category: Optional[str] = None,
        timeout: Optional[int] = None,
        use_cache: bool = True,
    ) -> SolveResult:
        """Synchronous solve wrapper."""
        return asyncio.run(self.asolve(challenge_url, challenge_text, category, timeout, use_cache))

    async def asolve(
        self,
        challenge_url: Optional[str] = None,
        challenge_text: Optional[str] = None,
        category: Optional[str] = None,
        timeout: Optional[int] = None,
        use_cache: bool = True,
    ) -> SolveResult:
        """Async solve a CTF challenge."""
        import uuid
        solve_id = str(uuid.uuid4())[:8]
        start_time = time.time()
        effective_timeout = timeout or self.timeout
        steps = []
        iterations = 0

        # Check cache
        if use_cache and self.cache:
            cached = self.cache.get(challenge_url, challenge_text, category)
            if cached:
                cached.solve_id = solve_id
                self._emit("cached", {"solve_id": solve_id})
                return cached

        # Classify
        if not category:
            category = self.classifier.classify(url=challenge_url, text=challenge_text).value
            self._emit("classified", {"category": category, "solve_id": solve_id})

        # Reconnaissance
        recon_result = await self.executor.async_reconnaissance(challenge_url, challenge_text)
        if recon_result.output:
            steps.append(f"[Recon] {recon_result.output[:300]}")
            self.memory.add("recon", recon_result.output)
            self._emit("recon", {"output": recon_result.output[:200], "solve_id": solve_id})

        # Main solving loop
        for attempt in range(self.max_retries if self.retry_on_failure else 1):
            while iterations < self.max_iterations:
                elapsed = time.time() - start_time
                if elapsed > effective_timeout:
                    return self._make_result(
                        False, None, category, steps, iterations, elapsed,
                        "Timeout exceeded", solve_id,
                    )

                iterations += 1
                self._emit("iteration", {"n": iterations, "solve_id": solve_id})

                # Plan
                context = self.memory.get_context()
                plan = await self.planner.async_plan(
                    challenge_url=challenge_url,
                    challenge_text=challenge_text,
                    category=category,
                    context=context,
                    previous_steps=steps,
                )

                if not plan.actions:
                    break

                steps.append(f"[Plan] {plan.reasoning[:200]}")
                self._emit("plan", {"reasoning": plan.reasoning[:200], "solve_id": solve_id})

                # Execute actions (parallel where possible)
                results = await self._execute_actions(plan.actions)
                for action, result in zip(plan.actions, results):
                    if result.output:
                        steps.append(f"[Exec:{action.tool}] {result.output[:200]}")
                        self.memory.add(f"exec:{action.tool}", result.output)
                    if result.error:
                        steps.append(f"[Error:{action.tool}] {result.error[:200]}")
                        self.memory.add(f"error:{action.tool}", result.error)

                self._emit("executed", {
                    "tools": [a.tool for a in plan.actions],
                    "solve_id": solve_id,
                })

                # Review
                all_output = "\n".join(steps)
                review = self.reviewer.review(output=all_output, category=category, steps=steps)

                if review.flag_found:
                    elapsed = time.time() - start_time
                    result = self._make_result(
                        True, review.flag, category, steps, iterations, elapsed,
                        solve_id=solve_id,
                    )
                    if self.cache:
                        self.cache.put(challenge_url, challenge_text, category, result)
                    self._emit("solved", {"flag": review.flag, "solve_id": solve_id})
                    return result

                if review.should_stop:
                    break

                if review.new_hint:
                    self.memory.add("hint", review.new_hint)

            # Retry
            if attempt < self.max_retries - 1 and self.retry_on_failure:
                self.memory.add("retry", f"Attempt {attempt + 1} failed, retrying with different approach")
                self._emit("retry", {"attempt": attempt + 2, "solve_id": solve_id})

        elapsed = time.time() - start_time
        return self._make_result(
            False, None, category, steps, iterations, elapsed,
            "Max iterations/retries exhausted", solve_id,
        )

    async def solve_stream(
        self,
        challenge_url: Optional[str] = None,
        challenge_text: Optional[str] = None,
        category: Optional[str] = None,
    ) -> AsyncGenerator[dict, None]:
        """Streaming solve - yields events as they happen."""
        self.on_progress = lambda event: None  # Events come via yield

        import uuid
        solve_id = str(uuid.uuid4())[:8]
        start_time = time.time()
        steps = []
        iterations = 0

        if not category:
            category = self.classifier.classify(url=challenge_url, text=challenge_text).value
            yield {"type": "classified", "category": category, "solve_id": solve_id}

        recon = await self.executor.async_reconnaissance(challenge_url, challenge_text)
        if recon.output:
            steps.append(f"[Recon] {recon.output[:300]}")
            self.memory.add("recon", recon.output)
            yield {"type": "recon", "output": recon.output[:200], "solve_id": solve_id}

        for attempt in range(self.max_retries if self.retry_on_failure else 1):
            while iterations < self.max_iterations:
                if time.time() - start_time > self.timeout:
                    yield {"type": "timeout", "solve_id": solve_id}
                    return

                iterations += 1
                yield {"type": "iteration", "n": iterations, "solve_id": solve_id}

                context = self.memory.get_context()
                plan = await self.planner.async_plan(
                    challenge_url=challenge_url,
                    challenge_text=challenge_text,
                    category=category,
                    context=context,
                    previous_steps=steps,
                )

                if not plan.actions:
                    yield {"type": "no_plan", "solve_id": solve_id}
                    break

                steps.append(f"[Plan] {plan.reasoning[:200]}")
                yield {"type": "plan", "reasoning": plan.reasoning[:200], "actions": len(plan.actions), "solve_id": solve_id}

                results = await self._execute_actions(plan.actions)
                for action, result in zip(plan.actions, results):
                    if result.output:
                        steps.append(f"[Exec:{action.tool}] {result.output[:200]}")
                        self.memory.add(f"exec:{action.tool}", result.output)
                    yield {"type": "exec", "tool": action.tool, "success": result.success, "output": result.output[:100], "solve_id": solve_id}

                review = self.reviewer.review(output="\n".join(steps), category=category, steps=steps)
                if review.flag_found:
                    yield {"type": "solved", "flag": review.flag, "iterations": iterations, "elapsed": time.time() - start_time, "solve_id": solve_id}
                    return

                if review.should_stop:
                    yield {"type": "stopped", "solve_id": solve_id}
                    break

                if review.new_hint:
                    self.memory.add("hint", review.new_hint)
                    yield {"type": "hint", "hint": review.new_hint, "solve_id": solve_id}

            if attempt < self.max_retries - 1 and self.retry_on_failure:
                yield {"type": "retry", "attempt": attempt + 2, "solve_id": solve_id}

        yield {"type": "failed", "error": "Max iterations exhausted", "iterations": iterations, "elapsed": time.time() - start_time, "solve_id": solve_id}

    async def _execute_actions(self, actions: list) -> list[ExecutionResult]:
        """Execute actions, running independent ones in parallel."""
        # Group by dependency (simple heuristic: same-tool sequential, different-tool parallel)
        if len(actions) <= 1:
            return [await self.executor.async_execute(a) for a in actions]

        # Check if actions are independent (different tools)
        tools = set(a.tool for a in actions)
        if len(tools) == len(actions):
            # All different tools - run in parallel
            return await asyncio.gather(*[self.executor.async_execute(a) for a in actions])
        else:
            # Some share tools - run sequentially for safety
            return [await self.executor.async_execute(a) for a in actions]

    def _make_result(
        self, success, flag, category, steps, iterations, elapsed,
        error=None, solve_id="",
    ) -> SolveResult:
        return SolveResult(
            success=success, flag=flag, category=category, steps=steps,
            iterations=iterations, elapsed_time=elapsed, error=error, solve_id=solve_id,
        )
