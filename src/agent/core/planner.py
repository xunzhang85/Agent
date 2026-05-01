"""
Planner - Task Planning Module

Uses LLM to analyze CTF challenges and generate step-by-step solving strategies.
Implements chain-of-thought reasoning for complex problem decomposition.
"""

import json
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class Action:
    """A single action to be executed."""

    tool: str
    command: str
    args: dict = field(default_factory=dict)
    description: str = ""
    priority: int = 0


@dataclass
class Plan:
    """A plan consisting of multiple actions."""

    reasoning: str
    actions: list[Action] = field(default_factory=list)
    confidence: float = 0.0
    strategy: str = ""


PLANNER_SYSTEM_PROMPT = """You are an expert CTF (Capture The Flag) challenge solver.
Your role is to analyze challenges and create step-by-step solving strategies.

Available tools:
- nmap: Network scanning and service discovery
- curl/http: HTTP requests and response analysis
- sqlmap: SQL injection detection and exploitation
- nikto: Web server vulnerability scanning
- gdb: GNU Debugger for binary analysis
- radare2: Reverse engineering framework
- pwntools: Binary exploitation toolkit
- binwalk: Firmware analysis and extraction
- strings: Extract printable strings from files
- file: File type identification
- openssl: Cryptographic operations
- python: Execute Python scripts
- bash: Execute shell commands

For each challenge, provide:
1. Analysis of the challenge type and potential vulnerabilities
2. A step-by-step plan with specific tool commands
3. Expected outputs and alternative approaches

Output JSON format:
{
    "reasoning": "Your analysis...",
    "strategy": "overall strategy name",
    "confidence": 0.0-1.0,
    "actions": [
        {
            "tool": "tool_name",
            "command": "specific command",
            "args": {},
            "description": "what this does",
            "priority": 1
        }
    ]
}
"""


class Planner:
    """
    LLM-powered task planner for CTF challenges.

    Analyzes challenge context and generates a sequence of actions
    using chain-of-thought reasoning.
    """

    def __init__(
        self,
        model: str = "gpt-4o",
        provider: str = "openai",
        api_key: Optional[str] = None,
    ):
        self.model = model
        self.provider = provider
        self.api_key = api_key
        self._client = None

    def _get_client(self):
        """Lazy initialization of LLM client."""
        if self._client is None:
            if self.provider == "openai":
                from openai import OpenAI
                self._client = OpenAI(api_key=self.api_key)
            elif self.provider == "anthropic":
                import anthropic
                self._client = anthropic.Anthropic(api_key=self.api_key)
            elif self.provider == "deepseek":
                from openai import OpenAI
                self._client = OpenAI(
                    api_key=self.api_key,
                    base_url="https://api.deepseek.com/v1",
                )
            else:
                raise ValueError(f"Unsupported provider: {self.provider}")
        return self._client

    def _call_llm(self, system_prompt: str, user_prompt: str) -> str:
        """Call the LLM with the given prompts."""
        client = self._get_client()

        if self.provider == "anthropic":
            response = client.messages.create(
                model=self.model,
                max_tokens=4096,
                system=system_prompt,
                messages=[{"role": "user", "content": user_prompt}],
            )
            return response.content[0].text
        else:
            response = client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=0.1,
                max_tokens=4096,
            )
            return response.choices[0].message.content

    def plan(
        self,
        challenge_url: Optional[str] = None,
        challenge_text: Optional[str] = None,
        category: str = "unknown",
        context: str = "",
        previous_steps: list[str] | None = None,
    ) -> Plan:
        """
        Generate a solving plan for a CTF challenge.

        Args:
            challenge_url: URL of the challenge
            challenge_text: Text description of the challenge
            category: Challenge category
            context: Previous context from memory
            previous_steps: Steps already taken

        Returns:
            Plan with actions to execute
        """
        user_prompt = f"""Challenge Category: {category}
Challenge URL: {challenge_url or 'N/A'}
Challenge Description: {challenge_text or 'N/A'}

Previous Context:
{context or 'None'}

Previous Steps:
{chr(10).join(previous_steps[-10:]) if previous_steps else 'None (first iteration)'}

Analyze this challenge and provide the next set of actions to solve it.
Output ONLY valid JSON."""

        try:
            response = self._call_llm(PLANNER_SYSTEM_PROMPT, user_prompt)
            # Extract JSON from response
            response = response.strip()
            if response.startswith("```"):
                response = response.split("```")[1]
                if response.startswith("json"):
                    response = response[4:]

            data = json.loads(response)

            actions = []
            for action_data in data.get("actions", []):
                actions.append(
                    Action(
                        tool=action_data.get("tool", "bash"),
                        command=action_data.get("command", ""),
                        args=action_data.get("args", {}),
                        description=action_data.get("description", ""),
                        priority=action_data.get("priority", 0),
                    )
                )

            return Plan(
                reasoning=data.get("reasoning", ""),
                actions=actions,
                confidence=data.get("confidence", 0.5),
                strategy=data.get("strategy", "general"),
            )

        except (json.JSONDecodeError, KeyError, Exception) as e:
            logger.error(f"Planner error: {e}")
            # Fallback: create a basic reconnaissance plan
            return Plan(
                reasoning=f"LLM parsing failed ({e}), falling back to basic recon",
                actions=[
                    Action(
                        tool="curl",
                        command=f"curl -s -I {challenge_url}" if challenge_url else "echo 'No URL provided'",
                        description="Basic HTTP reconnaissance",
                    )
                ],
                confidence=0.2,
                strategy="fallback",
            )
