# Getting Started

## Prerequisites

- Python 3.10+
- Docker (optional, for sandboxed execution)
- An LLM API key (OpenAI, Anthropic, or DeepSeek)

## Installation

### From Source (Recommended)

```bash
git clone https://github.com/xunzhang85/Agent.git
cd Agent
pip install -e ".[dev,tools]"
```

### Docker

```bash
docker-compose up -d
docker exec -it ctf-agent agent solve --url http://target.ctf.com
```

## Configuration

1. Copy the example config:
   ```bash
   cp configs/config.example.yaml configs/config.yaml
   ```

2. Edit `configs/config.yaml` with your settings:
   ```yaml
   llm:
     provider: openai
     model: gpt-4o
     api_key: ${OPENAI_API_KEY}
   ```

3. Set your API key:
   ```bash
   export OPENAI_API_KEY="sk-..."
   ```

## Usage

### Command Line

```bash
# Solve a web challenge
agent solve --url http://challenge.ctf.com --category web

# Solve with challenge description
agent solve --text "Decrypt this RSA ciphertext" --category crypto

# Interactive mode
agent interactive

# List available tools
agent tools
```

### Python API

```python
from agent import CTFAgent

agent = CTFAgent(model="gpt-4o")
result = agent.solve(
    challenge_url="http://challenge.ctf.com",
    category="web",
)

if result.success:
    print(f"Flag: {result.flag}")
else:
    print(f"Failed: {result.error}")
```

## Next Steps

- Read the [Architecture](architecture.md) guide to understand how the agent works
- Check the [Tools](tools.md) reference for available security tools
- See [Challenges](challenges.md) for example solutions
