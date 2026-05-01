"""
CLI - Command Line Interface (Optimized)

Enhanced with richer output, solve replay, batch mode, and plugin management.
"""

import sys
import json
import asyncio
import logging
import click
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.live import Live
from rich.tree import Tree
from rich.syntax import Syntax

console = Console()


@click.group()
@click.version_option(version="0.2.0", prog_name="ctf-agent")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.option("--config", "-c", type=click.Path(), help="Config file path")
@click.pass_context
def main(ctx, verbose, config):
    """🤖 CTF Agent - AI-Powered CTF Auto-Solver"""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    ctx.obj["config"] = config
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")


@main.command()
@click.option("--url", "-u", help="Challenge URL")
@click.option("--text", "-t", help="Challenge description")
@click.option("--category", "-C", type=click.Choice(
    ["web", "crypto", "pwn", "reverse", "forensics", "misc", "auto"],
), default="auto", help="Challenge category")
@click.option("--model", "-m", default="gpt-4o", help="LLM model")
@click.option("--provider", "-p", default="openai", help="LLM provider")
@click.option("--timeout", type=int, default=600, help="Timeout in seconds")
@click.option("--output", "-o", type=click.Path(), help="Output JSON file")
@click.option("--no-cache", is_flag=True, help="Disable result caching")
@click.option("--stream", "-s", is_flag=True, help="Stream solving progress")
@click.pass_context
def solve(ctx, url, text, category, model, provider, timeout, output, no_cache, stream):
    """🎯 Solve a CTF challenge."""
    from agent.core.agent import CTFAgent

    if not url and not text:
        console.print("[red]Error: Provide --url or --text[/red]")
        sys.exit(1)

    cat = None if category == "auto" else category

    console.print(Panel(
        f"[bold cyan]Challenge[/bold cyan]\n"
        f"  URL:      {url or 'N/A'}\n"
        f"  Category: {category}\n"
        f"  Model:    {model} ({provider})\n"
        f"  Timeout:  {timeout}s\n"
        f"  Cache:    {'off' if no_cache else 'on'}",
        title="🤖 CTF Agent v0.2", border_style="blue",
    ))

    agent = CTFAgent(model=model, provider=provider, timeout=timeout, cache_enabled=not no_cache)

    if stream:
        asyncio.run(_solve_stream(agent, url, text, cat, output))
    else:
        with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), console=console) as progress:
            task = progress.add_task("🧠 Analyzing and solving...", total=None)
            result = agent.solve(challenge_url=url, challenge_text=text, category=cat, timeout=timeout, use_cache=not no_cache)
            progress.update(task, completed=True)

        _display_result(result, output)


async def _solve_stream(agent, url, text, cat, output):
    """Stream solve progress in real-time."""
    console.print("\n[bold]📡 Streaming solve progress...[/bold]\n")
    steps = []

    async for event in agent.solve_stream(challenge_url=url, challenge_text=text, category=cat):
        etype = event.get("type", "")
        if etype == "classified":
            console.print(f"  📂 Category: [cyan]{event['category']}[/cyan]")
        elif etype == "recon":
            console.print(f"  🔍 Recon: {event['output'][:100]}")
        elif etype == "iteration":
            console.print(f"\n  🔄 Iteration {event['n']}...")
        elif etype == "plan":
            console.print(f"  📋 Plan: {event['reasoning'][:120]} ({event['actions']} actions)")
        elif etype == "exec":
            status = "[green]✅[/green]" if event["success"] else "[red]❌[/red]"
            console.print(f"    {status} {event['tool']}: {event['output'][:80]}")
        elif etype == "solved":
            console.print(Panel(
                f"[bold green]🎉 SOLVED![/bold green]\n\n"
                f"  🏷️  Flag: [bold yellow]{event['flag']}[/bold yellow]\n"
                f"  🔄 Iterations: {event['iterations']}\n"
                f"  ⏱️  Time: {event['elapsed']:.1f}s",
                title="✅ Result", border_style="green",
            ))
        elif etype == "failed":
            console.print(f"\n  [red]❌ Failed: {event['error']}[/red]")
        elif etype == "hint":
            console.print(f"  💡 Hint: {event['hint'][:100]}")
        elif etype == "retry":
            console.print(f"  🔁 Retrying (attempt {event['attempt']})...")


def _display_result(result, output):
    """Display solve result."""
    if result.success:
        cache_tag = " [dim][cached][/dim]" if result.cached else ""
        console.print(Panel(
            f"[bold green]✅ Solved!{cache_tag}[/bold green]\n\n"
            f"  🏷️  Flag: [bold yellow]{result.flag}[/bold yellow]\n"
            f"  📂 Category: {result.category}\n"
            f"  🔄 Iterations: {result.iterations}\n"
            f"  ⏱️  Time: {result.elapsed_time:.1f}s\n"
            f"  🆔 ID: {result.solve_id}",
            title="🎉 Result", border_style="green",
        ))
    else:
        console.print(Panel(
            f"[bold red]❌ Failed[/bold red]\n\n"
            f"  Error: {result.error}\n"
            f"  📂 Category: {result.category}\n"
            f"  🔄 Iterations: {result.iterations}\n"
            f"  ⏱️  Time: {result.elapsed_time:.1f}s",
            title="Result", border_style="red",
        ))

    if result.steps:
        console.print("\n[bold]📝 Steps:[/bold]")
        for i, step in enumerate(result.steps[-20:], 1):  # Show last 20
            color = "green" if "[Exec" in step else "yellow" if "[Plan" in step else "red" if "[Error" in step else "white"
            console.print(f"  [{color}]{i}. {step[:150]}[/{color}]")

    if output:
        with open(output, "w") as f:
            json.dump(result.to_dict(), f, indent=2, ensure_ascii=False)
        console.print(f"\n[dim]💾 Saved to {output}[/dim]")


@main.command()
@click.option("--file", "-f", type=click.Path(exists=True), required=True, help="Challenges file (JSON/CSV)")
@click.option("--output", "-o", type=click.Path(), default="results/batch.json", help="Output file")
@click.option("--parallel", "-j", type=int, default=3, help="Parallel workers")
@click.pass_context
def batch(ctx, file, output, parallel):
    """📋 Batch solve multiple challenges."""
    from agent.core.agent import CTFAgent

    with open(file) as f:
        if file.endswith(".json"):
            challenges = json.load(f)
        else:
            # Simple CSV: url,category per line
            challenges = []
            for line in f:
                parts = line.strip().split(",")
                challenges.append({"url": parts[0], "category": parts[1] if len(parts) > 1 else None})

    console.print(f"[cyan]📋 Loading {len(challenges)} challenges (parallel={parallel})[/cyan]")

    agent = CTFAgent()
    results = []

    with Progress(console=console) as progress:
        task = progress.add_task("Solving...", total=len(challenges))
        for ch in challenges:
            result = agent.solve(
                challenge_url=ch.get("url"),
                challenge_text=ch.get("text"),
                category=ch.get("category"),
            )
            results.append(result.to_dict())
            status = "✅" if result.success else "❌"
            progress.update(task, advance=1, description=f"{status} {ch.get('url', 'unknown')[:40]}")

    Path(output).parent.mkdir(parents=True, exist_ok=True)
    with open(output, "w") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    solved = sum(1 for r in results if r["success"])
    console.print(f"\n[bold]Results: {solved}/{len(results)} solved[/bold]")
    console.print(f"[dim]💾 Saved to {output}[/dim]")


@main.command()
@click.pass_context
def interactive(ctx):
    """💬 Interactive solving mode."""
    from agent.core.agent import CTFAgent

    console.print(Panel(
        "[bold]Interactive CTF Agent[/bold]\n\n"
        "Commands:\n"
        "  /solve <url>   - Solve a challenge\n"
        "  /tools         - List available tools\n"
        "  /history       - Show solve history\n"
        "  /stats         - Show statistics\n"
        "  /clear         - Clear memory\n"
        "  /quit          - Exit",
        title="🤖 Interactive Mode", border_style="cyan",
    ))

    agent = CTFAgent()

    while True:
        try:
            user_input = console.input("\n[bold cyan]ctf> [/bold cyan]")
        except (EOFError, KeyboardInterrupt):
            break

        cmd = user_input.strip()
        if not cmd:
            continue
        if cmd in ("/quit", "/exit", "/q"):
            break
        elif cmd == "/tools":
            _show_tools()
        elif cmd == "/history":
            _show_history()
        elif cmd == "/stats":
            summary = agent.memory.get_summary()
            console.print(Panel(json.dumps(summary, indent=2), title="📊 Memory Stats"))
        elif cmd == "/clear":
            agent.memory.clear()
            console.print("[green]Memory cleared[/green]")
        elif cmd.startswith("/solve "):
            target = cmd[7:].strip()
            url = target if target.startswith("http") else None
            text = None if url else target
            result = agent.solve(challenge_url=url, challenge_text=text)
            _display_result(result, None)
        else:
            # Treat as challenge text
            result = agent.solve(challenge_text=cmd)
            _display_result(result, None)

    console.print("[dim]👋 Goodbye![/dim]")


@main.command()
def tools():
    """🔧 List available security tools."""
    _show_tools()


def _show_tools():
    from agent.tools.registry import ToolRegistry
    registry = ToolRegistry()

    table = Table(title="🔧 Security Tools", show_lines=True)
    table.add_column("Tool", style="cyan", min_width=12)
    table.add_column("Category", style="magenta")
    table.add_column("Priority", style="dim")
    table.add_column("Status", style="yellow")
    table.add_column("Description")

    for tool in registry.list_tools():
        status = "[green]✅ Ready[/green]" if tool["installed"] else "[red]❌ Missing[/red]"
        table.add_row(tool["name"], tool["category"], str(tool["priority"]), status, tool["description"])

    console.print(table)
    console.print(f"\n[bold]{registry.summary()}[/bold]")


@main.command()
def history():
    """📊 Show solving history."""
    _show_history()


def _show_history():
    results_dir = Path("results")
    if not results_dir.exists():
        console.print("[yellow]No results found.[/yellow]")
        return

    table = Table(title="📊 Solving History")
    table.add_column("File")
    table.add_column("Category", style="magenta")
    table.add_column("Status")
    table.add_column("Iterations", style="cyan")
    table.add_column("Time")
    table.add_column("Cached")

    for f in sorted(results_dir.glob("*.json")):
        try:
            data = json.loads(f.read_text())
            if isinstance(data, list):
                for d in data:
                    _add_history_row(table, f.stem, d)
            else:
                _add_history_row(table, f.stem, data)
        except Exception:
            pass

    console.print(table)


def _add_history_row(table, name, data):
    status = "[green]✅[/green]" if data.get("success") else "[red]❌[/red]"
    cached = "[dim]yes[/dim]" if data.get("cached") else ""
    table.add_row(
        name, data.get("category", "?"), status,
        str(data.get("iterations", "?")),
        f"{data.get('elapsed_time', 0):.1f}s", cached,
    )


@main.command()
@click.option("--port", type=int, default=8080, help="Server port")
@click.option("--host", default="0.0.0.0", help="Bind host")
def serve(port, host):
    """🌐 Start web dashboard."""
    from agent.web import start_web
    start_web(port=port, host=host)


if __name__ == "__main__":
    main()
