# Example Challenge Solutions

## Web Challenge: SQL Injection

**Challenge:** Find the admin password on a login page.

```python
from agent import CTFAgent

agent = CTFAgent(model="gpt-4o")
result = agent.solve(
    challenge_url="http://challenge.ctf.com/login",
    category="web",
)
# Agent will:
# 1. Recon: curl the login page
# 2. Plan: Identify SQL injection point
# 3. Execute: Use sqlmap to extract data
# 4. Review: Check for flag in output
```

## Crypto Challenge: RSA

**Challenge:** Decrypt an RSA-encrypted message with a weak key.

```python
result = agent.solve(
    challenge_text="""
    Given: n=..., e=..., c=...
    The prime factors are close together.
    Decrypt the message.
    """,
    category="crypto",
)
# Agent will:
# 1. Analyze the RSA parameters
# 2. Factor n using Fermat's method
# 3. Compute private key d
# 4. Decrypt c to get the flag
```

## Pwn Challenge: Buffer Overflow

**Challenge:** Exploit a binary to get a shell.

```python
result = agent.solve(
    challenge_url="nc challenge.ctf.com 1337",
    category="pwn",
)
# Agent will:
# 1. Download and analyze the binary
# 2. Check security properties (checksec)
# 3. Find the vulnerability (buffer overflow)
# 4. Craft the exploit payload
# 5. Send it and capture the flag
```

## Reverse Challenge: Keygen

**Challenge:** Write a keygen for a registration program.

```python
result = agent.solve(
    challenge_text="Reverse engineer the binary to generate valid license keys",
    category="reverse",
)
# Agent will:
# 1. Disassemble the binary (radare2)
# 2. Identify the key validation algorithm
# 3. Write a keygen script
# 4. Generate a valid key
```

## Forensics: Memory Dump

**Challenge:** Extract hidden data from a memory dump.

```python
result = agent.solve(
    challenge_text="Analyze the memory dump to find the hidden password",
    category="forensics",
)
# Agent will:
# 1. Identify the OS profile (volatility)
# 2. List running processes
# 3. Extract command history
# 4. Find the hidden password
```

## Batch Solving

Solve multiple challenges at once:

```python
challenges = [
    {"url": "http://ctf1.com/web1", "category": "web"},
    {"url": "http://ctf1.com/crypto1", "category": "crypto"},
    {"url": "http://ctf1.com/pwn1", "category": "pwn"},
]

for ch in challenges:
    result = agent.solve(**ch)
    print(f"{ch['url']}: {'✅' if result.success else '❌'} {result.flag or result.error}")
```
