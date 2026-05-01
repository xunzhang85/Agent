"""
CTFAgent - Main Agent Controller

Orchestrates the Planner, Executor, and Reviewer to solve CTF challenges.
Implements the core solve loop with retry logic and memory management.
"""

import time
import logging
from dataclasses import dataclass, field
from typing import Optional

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

    def __str__(self) -> str:
        if self.success:
            return f"✅ Solved! Flag: {self.flag} ({self.iterations} iterations, {self.elapsed_time:.1f}s)"
        return f"❌ Failed: {self.error} ({self.iterations} iterations, {self.elapsed_time:.1f}s)"


class CTFAgent:
    """
    Main CTF Agent that orchestrates the solving pipeline.

    The agent follows a Plan → Execute → Review loop:
    1. Planner analyzes the challenge and generates a strategy
    2. Executor performs the actual operations (scanning, exploitation, etc.)
    3. Reviewer validates results and checks for flags
    4. Memory maintains context across iterations

    Usage:
        agent = CTFAgent(model="gpt-4o")
        result = agent.solve(challenge_url="http://target.ctf.com")
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
    ):
        self.model = model
        self.provider = provider
        self.max_iterations = max_iterations
        self.timeout = timeout
        self.retry_on_failure = retry_on_failure
        self.max_retries = max_retries

        # Initialize core components
        self.memory = Memory()
        self.classifier = ChallengeClassifier()
        self.planner = Planner(model=model, provider=provider, api_key=api_key)
        self.executor = Executor(
            model=model,
            provider=provider,
            api_key=api_key,
            sandbox_enabled=sandbox_enabled,
        )
        self.reviewer = Reviewer()

        logger.info(f"CTFAgent initialized with model={model}, provider={provider}")

    def solve(
        self,
        challenge_url: Optional[str] = None,
        challenge_text: Optional[str] = None,
        category: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> SolveResult:
        """
        Solve a CTF challenge.

        Args:
            challenge_url: URL of the challenge (for web/network challenges)
            challenge_text: Text description of the challenge
            category: Challenge category (web, crypto, pwn, reverse, forensics, misc)
            timeout: Override default timeout in seconds

        Returns:
            SolveResult with the flag and execution details
        """
        start_time = time.time()
        effective_timeout = timeout or self.timeout
        steps = []
        iterations = 0

        logger.info(f"Starting solve: url={challenge_url}, category={category}")

        # Step 0: Classify the challenge if category not provided
        if not category:
            category = self.classifier.classify(
                url=challenge_url, text=challenge_text
            ).value
            logger.info(f"Auto-detected category: {category}")

        # Step 1: Initial reconnaissance
        recon_result = self.executor.reconnaissance(challenge_url, challenge_text)
        if recon_result.output:
            steps.append(f"[Recon] {recon_result.output[:200]}")
            self.memory.add("reconnaissance", recon_result.output)

        # Main solving loop
        for attempt in range(self.max_retries if self.retry_on_failure else 1):
            while iterations < self.max_iterations:
                elapsed = time.time() - start_time
                if elapsed > effective_timeout:
                    logger.warning(f"Timeout reached ({effective_timeout}s)")
                    return SolveResult(
                        success=False,
                        category=category,
                        steps=steps,
                        iterations=iterations,
                        elapsed_time=elapsed,
                        error="Timeout exceeded",
                    )

                iterations += 1
                logger.info(f"Iteration {iterations}/{self.max_iterations}")

                # Plan: Generate next step
                context = self.memory.get_context()
                plan = self.planner.plan(
                    challenge_url=challenge_url,
                    challenge_text=challenge_text,
                    category=category,
                    context=context,
                    previous_steps=steps,
                )

                if not plan.actions:
                    logger.warning("Planner returned no actions")
                    break

                steps.append(f"[Plan] {plan.reasoning}")

                # Execute: Perform the planned actions
                for action in plan.actions:
                    result = self.executor.execute(action)

                    if result.output:
                        steps.append(f"[Exec:{action.tool}] {result.output[:200]}")
                        self.memory.add(f"exec:{action.tool}", result.output)

                    if result.error:
                        steps.append(f"[Error:{action.tool}] {result.error[:200]}")
                        self.memory.add(f"error:{action.tool}", result.error)

                # Review: Check if we found the flag
                all_output = "\n".join(steps)
                review = self.reviewer.review(
                    output=all_output,
                    category=category,
                    steps=steps,
                )

                if review.flag_found:
                    elapsed = time.time() - start_time
                    logger.info(f"Flag found: {review.flag}")
                    return SolveResult(
                        success=True,
                        flag=review.flag,
                        category=category,
                        steps=steps,
                        iterations=iterations,
                        elapsed_time=elapsed,
                    )

                if review.should_stop:
                    logger.info("Reviewer suggests stopping")
                    break

                if review.new_hint:
                    self.memory.add("hint", review.new_hint)

            # Reset for retry
            if attempt < self.max_retries - 1 and self.retry_on_failure:
                logger.info(f"Retrying (attempt {attempt + 2}/{self.max_retries})")
                self.memory.add("retry", f"Attempt {attempt + 1} failed, retrying...")

        elapsed = time.time() - start_time
        return SolveResult(
            success=False,
            category=category,
            steps=steps,
            iterations=iterations,
            elapsed_time=elapsed,
            error="Max iterations/retries exhausted",
        )
