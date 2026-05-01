# CTF Agent - AI-Powered CTF Auto-Solver

Welcome to the **CTF Agent** documentation.

## Overview

CTF Agent is a multi-agent framework that uses Large Language Models to automatically solve Capture The Flag (CTF) cybersecurity challenges. It combines planning, execution, and review capabilities with a rich library of security tools.

## Quick Links

- [Getting Started](getting-started.md) — Installation and first steps
- [Architecture](architecture.md) — How the agent works
- [Tools](tools.md) — Available security tools
- [Challenges](challenges.md) — Example challenge solutions

## Features

- 🤖 **Multi-Agent Architecture** — Planner, Executor, and Reviewer work together
- 🔧 **20+ Security Tools** — nmap, sqlmap, gdb, radare2, and more
- 📦 **Sandboxed Execution** — Docker-based isolation for safe exploit testing
- 📊 **Automated CI/CD** — GitHub Actions for testing and deployment
- 🔌 **Multi-LLM Support** — OpenAI, Anthropic, DeepSeek, Ollama

## Quick Start

```bash
git clone https://github.com/xunzhang85/Agent.git
cd Agent
pip install -e ".[dev]"
agent solve --url http://challenge.ctf.com --category web
```

## License

MIT License — see [LICENSE](https://github.com/xunzhang85/Agent/blob/main/LICENSE)
