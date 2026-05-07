"""
CLI - Command Line Interface (Optimized)

Enhanced with richer output, solve replay, batch mode, and plugin management.
"""

import sys
import json
import asyncio
import logging
import argparse
import shlex
import click
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()
CATEGORIES = ["web", "crypto", "pwn", "reverse", "forensics", "misc", "auto"]
INTERACTIVE_HELP = (
    "Commands:\n"
    "  /solve <url> [--category web] - Solve a challenge\n"
    "  /tools         - List available tools\n"
    "  /history       - Show solve history\n"
    "  /stats         - Show memory statistics\n"
    "  /config        - Show active runtime config\n"
    "  /clear         - Clear memory\n"
    "  /quit          - Exit"
)


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


def _load_runtime_config(ctx) -> dict:
    from agent.utils.config import load_config

    return load_config(ctx.obj.get("config") if ctx and ctx.obj else None)


def _agent_kwargs(ctx, model=None, provider=None, timeout=None, sandbox_enabled=None) -> dict:
    from agent.utils.config import get_bool, get_float, get_int

    config = _load_runtime_config(ctx)
    llm = config.get("llm", {})
    sandbox_cfg = config.get("sandbox", {})
    fallback = llm.get("fallback") or {}

    return {
        "model": model or llm.get("model") or "gpt-4o",
        "provider": provider or llm.get("provider") or "openai",
        "api_key": llm.get("api_key"),
        "base_url": llm.get("base_url"),
        "temperature": get_float(config, ("llm", "temperature"), 0.1),
        "max_tokens": get_int(config, ("llm", "max_tokens"), 4096),
        "timeout": timeout or get_int(config, ("agent", "timeout"), 600),
        "max_iterations": get_int(config, ("agent", "max_iterations"), 20),
        "retry_on_failure": get_bool(config, ("agent", "retry_on_failure"), True),
        "max_retries": get_int(config, ("agent", "max_retries"), 3),
        "sandbox_enabled": sandbox_enabled if sandbox_enabled is not None else sandbox_cfg.get("enabled"),
        "fallback_model": fallback.get("model"),
        "fallback_provider": fallback.get("provider"),
        "fallback_api_key": fallback.get("api_key"),
        "fallback_base_url": fallback.get("base_url"),
    }


@main.command()
@click.option("--url", "-u", help="Challenge URL")
@click.option("--text", "-t", help="Challenge description")
@click.option("--category", "-C", type=click.Choice(CATEGORIES), default="auto", help="Challenge category")
@click.option("--model", "-m", default=None, help="LLM model")
@click.option("--provider", "-p", default=None, help="LLM provider")
@click.option("--timeout", type=int, default=600, help="Timeout in seconds")
@click.option("--output", "-o", type=click.Path(), help="Output JSON file")
@click.option("--no-cache", is_flag=True, help="Disable result caching")
@click.option("--stream", "-s", is_flag=True, help="Stream solving progress")
@click.option("--sandbox/--no-sandbox", default=None, help="Force Docker sandbox on/off. Default: config/auto.")
@click.pass_context
def solve(ctx, url, text, category, model, provider, timeout, output, no_cache, stream, sandbox):
    """🎯 Solve a CTF challenge."""
    from agent.core.agent import CTFAgent

    if not url and not text:
        console.print("[red]Error: Provide --url or --text[/red]")
        sys.exit(1)

    cat = None if category == "auto" else category
    kwargs = _agent_kwargs(ctx, model=model, provider=provider, timeout=timeout, sandbox_enabled=sandbox)

    fallback_info = f"{kwargs.get('fallback_model') or 'none'} ({kwargs.get('fallback_provider') or '-'})" if kwargs.get('fallback_model') else "none"
    console.print(Panel(
        f"[bold cyan]Challenge[/bold cyan]\n"
        f"  URL:      {url or 'N/A'}\n"
        f"  Category: {category}\n"
        f"  Model:    {kwargs['model']} ({kwargs['provider']})\n"
        f"  Fallback: {fallback_info}\n"
        f"  Timeout:  {timeout}s\n"
        f"  Cache:    {'off' if no_cache else 'on'}",
        title="🤖 CTF Agent v0.2", border_style="blue",
    ))

    agent = CTFAgent(**kwargs, cache_enabled=not no_cache)

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
    import asyncio
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

    kwargs = _agent_kwargs(ctx)
    results = []

    async def _solve_one(ch, idx):
        with CTFAgent(**kwargs) as agent:
            result = await agent.asolve(
                challenge_url=ch.get("url"),
                challenge_text=ch.get("text"),
                category=ch.get("category"),
            )
        return idx, result

    async def _run_batch():
        semaphore = asyncio.Semaphore(parallel)
        async def _limited(ch, idx):
            async with semaphore:
                return await _solve_one(ch, idx)

        tasks = [_limited(ch, i) for i, ch in enumerate(challenges)]
        completed = []

        with Progress(console=console) as progress:
            task = progress.add_task("Solving...", total=len(challenges))
            for coro in asyncio.as_completed(tasks):
                idx, result = await coro
                completed.append((idx, result))
                status = "✅" if result.success else "❌"
                progress.update(task, advance=1, description=f"{status} challenges...")

        # Restore original order
        completed.sort(key=lambda x: x[0])
        return [r.to_dict() for _, r in completed]

    results = asyncio.run(_run_batch())

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
        f"{INTERACTIVE_HELP}",
        title="🤖 Interactive Mode", border_style="cyan",
    ))

    kwargs = _agent_kwargs(ctx)
    agent = CTFAgent(**kwargs)

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
        elif cmd in ("/help", "/h", "?"):
            console.print(Panel(INTERACTIVE_HELP, title="Help", border_style="cyan"))
        elif cmd == "/tools":
            _show_tools()
        elif cmd == "/history":
            _show_history()
        elif cmd == "/stats":
            summary = agent.memory.get_summary()
            console.print(Panel(json.dumps(summary, indent=2), title="📊 Memory Stats"))
        elif cmd == "/config":
            safe_config = {
                "model": kwargs["model"],
                "provider": kwargs["provider"],
                "base_url_configured": bool(kwargs.get("base_url")),
                "timeout": kwargs["timeout"],
                "max_iterations": kwargs["max_iterations"],
                "max_retries": kwargs["max_retries"],
                "sandbox_enabled": kwargs["sandbox_enabled"],
                "api_key_configured": bool(kwargs.get("api_key")),
            }
            console.print(Panel(json.dumps(safe_config, indent=2), title="⚙️ Runtime Config"))
        elif cmd == "/clear":
            agent.memory.clear()
            console.print("[green]Memory cleared[/green]")
        elif cmd.startswith("/solve "):
            try:
                parsed = _parse_interactive_solve(cmd)
            except ValueError as exc:
                console.print(f"[red]Error: {exc}[/red]")
                continue

            run_agent = agent
            if parsed["model"] or parsed["provider"]:
                run_agent = CTFAgent(**_agent_kwargs(ctx, model=parsed["model"], provider=parsed["provider"]))

            result = run_agent.solve(
                challenge_url=parsed["url"],
                challenge_text=parsed["text"],
                category=parsed["category"],
                timeout=parsed["timeout"],
                use_cache=not parsed["no_cache"],
            )
            _display_result(result, None)
        else:
            # Treat as challenge text
            result = agent.solve(challenge_text=cmd)
            _display_result(result, None)

    console.print("[dim]👋 Goodbye![/dim]")


def _parse_interactive_solve(command: str) -> dict:
    """Parse `/solve` commands without appending options to the URL."""
    try:
        tokens = shlex.split(command)
    except ValueError as exc:
        raise ValueError(f"Invalid quoting: {exc}") from exc

    parser = argparse.ArgumentParser(prog="/solve", add_help=False)
    parser.add_argument("target", nargs="?")
    parser.add_argument("--url", "-u")
    parser.add_argument("--text", "-t")
    parser.add_argument("--category", "-C", choices=CATEGORIES)
    parser.add_argument("--model", "-m")
    parser.add_argument("--provider", "-p")
    parser.add_argument("--timeout", type=int)
    parser.add_argument("--no-cache", action="store_true")

    try:
        args, unknown = parser.parse_known_args(tokens[1:])
    except SystemExit as exc:
        raise ValueError("Usage: /solve <url-or-text> [--category web] [--timeout 300]") from exc

    if unknown:
        raise ValueError(f"Unknown option(s): {' '.join(unknown)}")

    url = args.url
    text = args.text
    if not url and not text and args.target:
        if args.target.startswith(("http://", "https://")):
            url = args.target
        else:
            text = args.target

    if not url and not text:
        raise ValueError("Usage: /solve <url-or-text> [--category web]")

    return {
        "url": url,
        "text": text,
        "category": None if args.category in (None, "auto") else args.category,
        "model": args.model,
        "provider": args.provider,
        "timeout": args.timeout,
        "no_cache": args.no_cache,
    }


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
@click.pass_context
def serve(ctx, port, host):
    """🌐 Start web dashboard."""
    from agent.web import start_web
    start_web(port=port, host=host, config_path=ctx.obj.get("config"))


@main.command(name="web")
@click.option("--port", type=int, default=8080, help="Server port")
@click.option("--host", default="127.0.0.1", help="Bind host")
@click.pass_context
def web_dashboard(ctx, port, host):
    """🌐 Start web dashboard (alias for serve)."""
    from agent.web import start_web
    start_web(port=port, host=host, config_path=ctx.obj.get("config"))


if __name__ == "__main__":
    main()
