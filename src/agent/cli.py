"""
CLI - Command Line Interface

Main entry point for the CTF Agent.
"""

import sys
import json
import logging
import click
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()


@click.group()
@click.version_option(version="0.1.0", prog_name="ctf-agent")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.option("--config", "-c", type=click.Path(), help="Config file path")
@click.pass_context
def main(ctx, verbose, config):
    """🤖 CTF Agent - AI-Powered CTF Auto-Solver"""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    ctx.obj["config"] = config

    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


@main.command()
@click.option("--url", "-u", help="Challenge URL")
@click.option("--text", "-t", help="Challenge description")
@click.option("--category", "-C", type=click.Choice(
    ["web", "crypto", "pwn", "reverse", "forensics", "misc", "auto"],
    case_sensitive=False,
), default="auto", help="Challenge category")
@click.option("--model", "-m", default="gpt-4o", help="LLM model to use")
@click.option("--provider", "-p", default="openai", help="LLM provider")
@click.option("--timeout", type=int, default=600, help="Timeout in seconds")
@click.option("--output", "-o", type=click.Path(), help="Output file for results")
@click.pass_context
def solve(ctx, url, text, category, model, provider, timeout, output):
    """🎯 Solve a CTF challenge."""
    from agent.core.agent import CTFAgent

    if not url and not text:
        console.print("[red]Error: Provide --url or --text[/red]")
        sys.exit(1)

    cat = None if category == "auto" else category

    console.print(Panel(
        f"[bold]Challenge[/bold]\n"
        f"URL: {url or 'N/A'}\n"
        f"Category: {category}\n"
        f"Model: {model} ({provider})",
        title="🤖 CTF Agent",
        border_style="blue",
    ))

    agent = CTFAgent(
        model=model,
        provider=provider,
        timeout=timeout,
    )

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Solving challenge...", total=None)
        result = agent.solve(
            challenge_url=url,
            challenge_text=text,
            category=cat,
            timeout=timeout,
        )
        progress.update(task, completed=True)

    # Display results
    if result.success:
        console.print(Panel(
            f"[bold green]✅ Solved![/bold green]\n\n"
            f"Flag: [bold yellow]{result.flag}[/bold yellow]\n"
            f"Category: {result.category}\n"
            f"Iterations: {result.iterations}\n"
            f"Time: {result.elapsed_time:.1f}s",
            title="🎉 Result",
            border_style="green",
        ))
    else:
        console.print(Panel(
            f"[bold red]❌ Failed[/bold red]\n\n"
            f"Error: {result.error}\n"
            f"Category: {result.category}\n"
            f"Iterations: {result.iterations}\n"
            f"Time: {result.elapsed_time:.1f}s",
            title="Result",
            border_style="red",
        ))

    # Show steps
    if result.steps:
        console.print("\n[bold]Steps taken:[/bold]")
        for i, step in enumerate(result.steps, 1):
            console.print(f"  {i}. {step[:150]}")

    # Save output
    if output:
        with open(output, "w") as f:
            json.dump({
                "success": result.success,
                "flag": result.flag,
                "category": result.category,
                "iterations": result.iterations,
                "elapsed_time": result.elapsed_time,
                "error": result.error,
                "steps": result.steps,
            }, f, indent=2)
        console.print(f"\n[dim]Results saved to {output}[/dim]")


@main.command()
@click.option("--file", "-f", type=click.Path(exists=True), required=True,
              help="File containing challenge list")
@click.option("--output", "-o", type=click.Path(), default="results/batch_results.json",
              help="Output file")
@click.pass_context
def batch(ctx, file, output):
    """📋 Batch solve multiple challenges."""
    console.print(f"[yellow]Batch mode loading challenges from {file}...[/yellow]")
    # TODO: Implement batch solving
    console.print("[yellow]Batch mode not yet implemented[/yellow]")


@main.command()
@click.pass_context
def interactive(ctx):
    """💬 Start interactive solving mode."""
    console.print(Panel(
        "[bold]Interactive CTF Agent[/bold]\n\n"
        "Type your challenge description or URL.\n"
        "Commands: /solve, /history, /tools, /quit",
        title="🤖 Interactive Mode",
        border_style="cyan",
    ))

    from agent.core.agent import CTFAgent
    agent = CTFAgent()

    while True:
        try:
            user_input = console.input("\n[bold cyan]> [/bold cyan]")
        except (EOFError, KeyboardInterrupt):
            break

        if not user_input.strip():
            continue
        if user_input.strip() in ("/quit", "/exit", "/q"):
            break
        if user_input.strip() == "/tools":
            from agent.tools.registry import ToolRegistry
            registry = ToolRegistry()
            table = Table(title="Available Tools")
            table.add_column("Tool", style="cyan")
            table.add_column("Category", style="green")
            table.add_column("Status", style="yellow")
            for tool in registry.list_tools():
                status = "✅" if tool["installed"] else "❌"
                table.add_row(tool["name"], tool["category"], status)
            console.print(table)
            continue

        # Solve
        url = None
        text = user_input
        if user_input.startswith("http"):
            url = user_input
            text = None

        result = agent.solve(challenge_url=url, challenge_text=text)
        if result.success:
            console.print(f"[green]✅ Flag: {result.flag}[/green]")
        else:
            console.print(f"[red]❌ {result.error}[/red]")

    console.print("[dim]Goodbye![/dim]")


@main.command()
def tools():
    """🔧 List available security tools."""
    from agent.tools.registry import ToolRegistry

    registry = ToolRegistry()
    table = Table(title="🔧 Security Tools")
    table.add_column("Tool", style="cyan", min_width=12)
    table.add_column("Category", style="green")
    table.add_column("Status", style="yellow")
    table.add_column("Description")

    for tool in registry.list_tools():
        status = "[green]✅ Ready[/green]" if tool["installed"] else "[red]❌ Missing[/red]"
        table.add_row(tool["name"], tool["category"], status, tool["description"])

    console.print(table)
    console.print(f"\n{registry.summary()}")


@main.command()
def history():
    """📊 Show solving history."""
    results_dir = Path("results")
    if not results_dir.exists():
        console.print("[yellow]No results found.[/yellow]")
        return

    table = Table(title="📊 Solving History")
    table.add_column("Challenge")
    table.add_column("Category")
    table.add_column("Status")
    table.add_column("Time")

    for result_file in sorted(results_dir.glob("*.json")):
        try:
            with open(result_file) as f:
                data = json.load(f)
            status = "[green]✅[/green]" if data.get("success") else "[red]❌[/red]"
            table.add_row(
                result_file.stem,
                data.get("category", "unknown"),
                status,
                f"{data.get('elapsed_time', 0):.1f}s",
            )
        except Exception:
            pass

    console.print(table)


@main.command()
@click.option("--port", type=int, default=8080, help="Server port")
def serve(port):
    """🌐 Start web dashboard."""
    console.print(f"[yellow]Web dashboard not yet implemented (port: {port})[/yellow]")
    # TODO: Implement web dashboard


if __name__ == "__main__":
    main()
