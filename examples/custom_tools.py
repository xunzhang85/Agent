"""
Example: Using Custom Tools

Demonstrates how to register and use custom tools with the agent.
"""

from agent import CTFAgent
from agent.tools.registry import ToolRegistry


def custom_subdomain_scanner(domain: str) -> str:
    """Custom subdomain enumeration tool."""
    import subprocess
    try:
        result = subprocess.run(
            ["dig", "+short", f"subdomain.{domain}"],
            capture_output=True, text=True, timeout=10,
        )
        return f"Found: {result.stdout.strip()}"
    except Exception as e:
        return f"Error: {e}"


def main():
    # Create agent
    agent = CTFAgent(model="gpt-4o")

    # Register custom tool
    agent.executor.tool_registry.register_custom(
        "subdomain_scan",
        custom_subdomain_scanner,
        description="Enumerate subdomains of a target domain",
    )

    # Use agent with custom tool
    result = agent.solve(
        challenge_url="http://challenge.ctf.com",
        category="web",
    )

    print(f"Result: {result}")


if __name__ == "__main__":
    main()
