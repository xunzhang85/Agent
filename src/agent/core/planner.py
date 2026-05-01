"""
Planner - Task Planning Module (Optimized)

Enhanced with better prompting, few-shot examples, structured output,
and async LLM calls.
"""

import json
import logging
import asyncio
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
    depends_on: Optional[str] = None  # Tool dependency


@dataclass
class Plan:
    """A plan consisting of multiple actions."""
    reasoning: str
    actions: list[Action] = field(default_factory=list)
    confidence: float = 0.0
    strategy: str = ""
    alternative_plans: list[str] = field(default_factory=list)


# Few-shot examples for each category
FEW_SHOT_EXAMPLES = {
    "web": """
Example - SQL Injection:
Challenge: Login form at http://target.com/login
Analysis: Login form likely vulnerable to SQL injection. Test with basic payloads.
Actions:
1. curl -s http://target.com/login (inspect form)
2. sqlmap -u "http://target.com/login" --data="user=admin&pass=test" --batch (automated SQLi)
3. curl -s "http://target.com/login" --data "user=admin'--&pass=x" (manual bypass)
""",

    "crypto": """
Example - Weak RSA:
Challenge: RSA with small e and factorable n
Analysis: n can be factored using factordb or Fermat's method.
Actions:
1. python3 -c "import math; n=...; [print(i) for i in range(2,int(math.sqrt(n))+1) if n%i==0]" (factor)
2. python3 -c "from Crypto.Util.number import long_to_bytes; print(long_to_bytes(pow(c,d,n)))" (decrypt)
""",

    "pwn": """
Example - Buffer Overflow:
Challenge: Binary with gets() call, NX enabled
Analysis: Classic stack buffer overflow. Need to find offset and overwrite return address.
Actions:
1. checksec --file=./vuln (check protections)
2. python3 -c "from pwn import *; print(cyclic(100))" (generate pattern)
3. gdb -q ./vuln -ex "run <<< $(python3 -c 'print(cyclic(100))')" -ex "info registers rsp" (find offset)
4. python3 -c "from pwn import *; p=remote('target',1337); p.sendline(b'A'*offset+p64(win_addr)); p.interactive()" (exploit)
""",

    "reverse": """
Example - Crackme:
Challenge: Binary asks for serial key
Analysis: Need to reverse the validation algorithm.
Actions:
1. file ./crackme (identify binary type)
2. strings ./crackme | grep -i key (look for strings)
3. r2 -q -c "aaa; s sym.check; pdf" ./crackme (disassemble validation)
4. python3 -c "reverse_engineered_algorithm()" (generate key)
""",

    "forensics": """
Example - Memory Dump:
Challenge: Find password in memory dump
Analysis: Use volatility to extract process memory and credentials.
Actions:
1. file dump.mem (identify file type)
2. vol.py -f dump.mem imageinfo (identify OS profile)
3. vol.py -f dump.mem --profile=... pslist (list processes)
4. vol.py -f dump.mem --profile=... dumpfiles -D output (extract files)
""",
}

PLANNER_SYSTEM_PROMPT = """You are an elite CTF (Capture The Flag) challenge solver with deep expertise in cybersecurity.
Your role is to analyze challenges and create precise, actionable solving strategies.

## Your Expertise
- Web Application Security (SQLi, XSS, SSRF, authentication bypass)
- Cryptography (RSA, AES, classical ciphers, hash cracking)
- Binary Exploitation (buffer overflow, ROP, format strings, heap)
- Reverse Engineering (disassembly, decompilation, anti-debug)
- Digital Forensics (memory analysis, network captures, steganography)

## Available Tools
| Tool | Category | Best For |
|------|----------|----------|
| curl | web | HTTP requests, response inspection |
| sqlmap | web | Automated SQL injection |
| nikto | web | Web server scanning |
| gobuster | web | Directory enumeration |
| ffuf | web | Web fuzzing |
| nmap | network | Port scanning, service detection |
| gdb | pwn | Debugging, exploit development |
| ropper | pwn | ROP gadget finding |
| checksec | pwn | Binary security analysis |
| radare2 | reverse | Disassembly, analysis |
| binwalk | forensics | Firmware extraction |
| steghide | forensics | Steganography |
| exiftool | forensics | Metadata extraction |
| volatility | forensics | Memory forensics |
| openssl | crypto | Cryptographic operations |
| john | crypto | Password cracking |
| python3 | misc | Custom scripts, calculations |
| bash | misc | Shell commands, piping |

## Response Format
Output ONLY valid JSON:
{
    "reasoning": "Step-by-step analysis of the challenge. What type is it? What vulnerabilities might exist? What's the attack surface?",
    "strategy": "strategy_name (e.g., 'sql_injection_exploit', 'buffer_overflow', 'rsa_factorization')",
    "confidence": 0.0-1.0,
    "alternative_plans": ["fallback strategy 1", "fallback strategy 2"],
    "actions": [
        {
            "tool": "tool_name",
            "command": "exact command to run",
            "args": {},
            "description": "what this step does and why",
            "priority": 1,
            "depends_on": null
        }
    ]
}

## Rules
1. Start with reconnaissance, then analysis, then exploitation
2. Each action should be a single, concrete command
3. Prioritize automated tools over manual commands
4. Include fallback approaches in alternative_plans
5. Be specific - use actual URLs, file names, and parameters from the challenge
"""


class Planner:
    """LLM-powered task planner with async support and few-shot learning."""

    def __init__(self, model: str = "gpt-4o", provider: str = "openai", api_key: Optional[str] = None):
        self.model = model
        self.provider = provider
        self.api_key = api_key
        self._client = None

    def _get_client(self):
        if self._client is None:
            if self.provider == "openai":
                from openai import OpenAI
                self._client = OpenAI(api_key=self.api_key)
            elif self.provider == "anthropic":
                import anthropic
                self._client = anthropic.Anthropic(api_key=self.api_key)
            elif self.provider == "deepseek":
                from openai import OpenAI
                self._client = OpenAI(api_key=self.api_key, base_url="https://api.deepseek.com/v1")
            elif self.provider == "ollama":
                from openai import OpenAI
                self._client = OpenAI(api_key="ollama", base_url="http://localhost:11434/v1")
            else:
                raise ValueError(f"Unsupported provider: {self.provider}")
        return self._client

    def _build_prompt(self, challenge_url, challenge_text, category, context, previous_steps):
        """Build a rich prompt with few-shot examples."""
        few_shot = FEW_SHOT_EXAMPLES.get(category, "")

        recent_steps = previous_steps[-15:] if previous_steps else []
        steps_text = "\n".join(recent_steps) if recent_steps else "None (first iteration)"

        return f"""## Challenge
Category: {category}
URL: {challenge_url or 'N/A'}
Description: {challenge_text or 'N/A'}

## Context from Memory
{context or 'No prior context'}

## Steps Already Taken
{steps_text}

{f'## Reference Example{chr(10)}{few_shot}' if few_shot else ''}

Analyze this challenge and provide the NEXT set of actions to progress toward the flag.
If previous steps failed, try a DIFFERENT approach. Be specific and actionable.
Output ONLY valid JSON."""

    def _call_llm(self, system_prompt: str, user_prompt: str) -> str:
        client = self._get_client()
        if self.provider == "anthropic":
            response = client.messages.create(
                model=self.model, max_tokens=4096, temperature=0.1,
                system=system_prompt,
                messages=[{"role": "user", "content": user_prompt}],
            )
            return response.content[0].text
        else:
            response = client.chat.completions.create(
                model=self.model, temperature=0.1, max_tokens=4096,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
            )
            return response.choices[0].message.content

    async def async_call_llm(self, system_prompt: str, user_prompt: str) -> str:
        """Async LLM call using thread pool."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._call_llm, system_prompt, user_prompt)

    def plan(self, challenge_url=None, challenge_text=None, category="unknown",
             context="", previous_steps=None) -> Plan:
        """Sync plan generation."""
        user_prompt = self._build_prompt(challenge_url, challenge_text, category, context, previous_steps or [])
        try:
            response = self._call_llm(PLANNER_SYSTEM_PROMPT, user_prompt)
            return self._parse_plan(response)
        except Exception as e:
            logger.error(f"Planner error: {e}")
            return self._fallback_plan(challenge_url, e)

    async def async_plan(self, challenge_url=None, challenge_text=None, category="unknown",
                         context="", previous_steps=None) -> Plan:
        """Async plan generation."""
        user_prompt = self._build_prompt(challenge_url, challenge_text, category, context, previous_steps or [])
        try:
            response = await self.async_call_llm(PLANNER_SYSTEM_PROMPT, user_prompt)
            return self._parse_plan(response)
        except Exception as e:
            logger.error(f"Planner error: {e}")
            return self._fallback_plan(challenge_url, e)

    def _parse_plan(self, response: str) -> Plan:
        """Parse LLM response into a Plan object."""
        response = response.strip()
        if response.startswith("```"):
            lines = response.split("\n")
            response = "\n".join(lines[1:-1] if lines[-1].strip() == "```" else lines[1:])

        data = json.loads(response)
        actions = []
        for a in data.get("actions", []):
            actions.append(Action(
                tool=a.get("tool", "bash"),
                command=a.get("command", ""),
                args=a.get("args", {}),
                description=a.get("description", ""),
                priority=a.get("priority", 0),
                depends_on=a.get("depends_on"),
            ))

        return Plan(
            reasoning=data.get("reasoning", ""),
            actions=actions,
            confidence=data.get("confidence", 0.5),
            strategy=data.get("strategy", "general"),
            alternative_plans=data.get("alternative_plans", []),
        )

    def _fallback_plan(self, url, error) -> Plan:
        """Fallback plan when LLM fails."""
        actions = []
        if url:
            actions.append(Action(
                tool="curl", command=f"curl -s -I -L {url}",
                description="HTTP header inspection",
            ))
            actions.append(Action(
                tool="curl", command=f"curl -s {url} | head -200",
                description="Page content inspection",
            ))
        return Plan(
            reasoning=f"LLM error ({error}), using fallback reconnaissance",
            actions=actions, confidence=0.1, strategy="fallback",
        )
