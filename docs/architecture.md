# Architecture

## System Overview

The CTF Agent follows a multi-agent architecture inspired by [CAI](https://github.com/aliasrobotics/CAI) and [NYU CTF Agents](https://github.com/NYU-LLM-CTF/nyuctf_agents).

```
┌─────────────────────────────────────────────────────────┐
│                    CTF Agent Framework                    │
├─────────┬─────────────┬──────────────┬───────────────────┤
│ Planner │  Executor   │   Reviewer   │     Memory        │
│         │             │              │                   │
│  LLM    │  Tool       │  Flag        │  Context          │
│  Chain  │  Execution  │  Detection   │  Management       │
│  of     │  Docker     │  Progress    │  History          │
│  Thought│  Sandbox    │  Analysis    │  Hints            │
├─────────┴─────────────┴──────────────┴───────────────────┤
│                     Tool Registry                         │
├──────┬──────┬──────┬──────┬──────┬──────┬────────────────┤
│ Web  │Crypto│ Pwn  │Revers│Forens│ Misc │ Custom Tools   │
└──────┴──────┴──────┴──────┴──────┴──────┴────────────────┘
```

## Core Components

### 1. Planner

The Planner uses an LLM to analyze challenges and generate step-by-step solving strategies. It implements chain-of-thought reasoning to decompose complex problems.

**Input:**
- Challenge URL and/or description
- Category (auto-detected or specified)
- Previous execution context from Memory
- Steps already taken

**Output:**
- A `Plan` object containing:
  - `reasoning`: Analysis of the challenge
  - `actions`: List of `Action` objects to execute
  - `confidence`: How confident the planner is (0-1)
  - `strategy`: Name of the chosen strategy

### 2. Executor

The Executor performs the actual operations using the Tool Registry. It supports both local and sandboxed (Docker) execution.

**Capabilities:**
- Execute shell commands
- Run security tools (nmap, sqlmap, etc.)
- Write and execute Python scripts
- Perform HTTP requests
- Docker sandbox isolation

### 3. Reviewer

The Reviewer validates execution results and checks for flags.

**Responsibilities:**
- Pattern matching for flag formats (flag{}, CTF{}, HTB{}, etc.)
- Progress analysis (are we making headway?)
- Hint generation for next steps
- Solution quality assessment

### 4. Memory

The Memory module maintains context across iterations using a sliding window approach.

**Features:**
- Categorized entries (recon, exec, hint, error, flag)
- Importance-based eviction (1-5 scale)
- Context window for Planner
- JSON export for analysis

## Solve Loop

```
1. INPUT: Challenge URL / Description
       ↓
2. CLASSIFY: Auto-detect category (web/crypto/pwn/...)
       ↓
3. RECON: Initial reconnaissance
       ↓
4. LOOP (max_iterations):
   ├── PLAN: LLM generates next actions
   ├── EXECUTE: Run actions via tools
   ├── REVIEW: Check for flags
   ├── FOUND? → Return flag
   └── NOT FOUND → Update memory, continue loop
       ↓
5. RETRY: If failed, reset and try different approach
       ↓
6. OUTPUT: SolveResult (success/failure + details)
```

## Tool Registry

The Tool Registry manages 20+ built-in security tools:

| Category | Tools |
|----------|-------|
| Web | curl, sqlmap, nikto, gobuster, ffuf, hydra |
| Crypto | openssl, john, hashcat |
| Pwn | gdb, ropper, checksec, pwntools |
| Reverse | radare2, ghidra, angr, objdump |
| Forensics | binwalk, steghide, exiftool, volatility, foremost |
| Misc | python3, bash |

Tools are auto-discovered on startup. Custom tools can be registered via the API.
