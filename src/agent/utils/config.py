"""
Configuration Management

Handles loading, validation, and environment variable substitution
for agent configuration files.
"""

import os
import re
import yaml
import logging
import copy
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

DEFAULT_CONFIG = {
    "llm": {
        "provider": "openai",
        "model": "gpt-4o",
        "api_key": None,
        "base_url": None,
        "temperature": 0.1,
        "max_tokens": 4096,
    },
    "agent": {
        "max_iterations": 20,
        "timeout": 600,
        "retry_on_failure": True,
        "max_retries": 3,
    },
    "sandbox": {
        "enabled": True,
        "image": "ctf-agent:sandbox",
        "memory_limit": "2g",
        "network": "ctf-net",
    },
    "tools": {
        "enabled": [
            "nmap", "curl", "sqlmap", "nikto", "gdb",
            "radare2", "binwalk", "strings", "file", "openssl",
            "python3", "gobuster", "ffuf",
        ],
    },
    "output": {
        "format": "json",
        "directory": "./results",
        "verbose": True,
    },
}


def load_config(config_path: Optional[str] = None) -> dict[str, Any]:
    """
    Load configuration from file with environment variable substitution.

    Args:
        config_path: Path to config file. If None, uses default locations.

    Returns:
        Merged configuration dict
    """
    config = copy.deepcopy(DEFAULT_CONFIG)

    if config_path is None:
        # Search for config in standard locations
        search_paths = [
            Path("configs/config.yaml"),
            Path("configs/config.yml"),
            Path("~/.ctf-agent/config.yaml").expanduser(),
            Path("/etc/ctf-agent/config.yaml"),
        ]
        for path in search_paths:
            if path.exists():
                config_path = str(path)
                break

    if config_path and Path(config_path).exists():
        try:
            with open(config_path) as f:
                raw = f.read()

            # Substitute environment variables: ${VAR_NAME}
            def env_sub(match):
                var_name = match.group(1)
                return os.environ.get(var_name, match.group(0))

            raw = re.sub(r"\$\{(\w+)\}", env_sub, raw)
            user_config = yaml.safe_load(raw) or {}

            config = _deep_merge(config, user_config)
            logger.info(f"Loaded config from {config_path}")

        except Exception as e:
            logger.warning(f"Failed to load config from {config_path}: {e}")

    # Environment variable overrides
    env_overrides = {
        "CTF_AGENT_MODEL": ("llm", "model"),
        "CTF_AGENT_PROVIDER": ("llm", "provider"),
        "CTF_AGENT_BASE_URL": ("llm", "base_url"),
        "OPENAI_BASE_URL": ("llm", "base_url"),
        "OPENAI_API_KEY": ("llm", "api_key"),
        "LLM_API_KEY": ("llm", "api_key"),
        "CTF_AGENT_TIMEOUT": ("agent", "timeout"),
        "CTF_AGENT_MAX_ITERATIONS": ("agent", "max_iterations"),
        "CTF_AGENT_SANDBOX_ENABLED": ("sandbox", "enabled"),
    }

    for env_var, path in env_overrides.items():
        value = os.environ.get(env_var)
        if value:
            _set_nested(config, path, value)

    api_key = config.get("llm", {}).get("api_key")
    if isinstance(api_key, str) and api_key.startswith("${") and api_key.endswith("}"):
        config["llm"]["api_key"] = None
    base_url = config.get("llm", {}).get("base_url")
    if isinstance(base_url, str):
        base_url = base_url.strip()
        config["llm"]["base_url"] = base_url.rstrip("/") if base_url else None

    return config


def get_bool(config: dict[str, Any], path: tuple[str, ...], default: bool = False) -> bool:
    """Read a nested boolean config value with string coercion."""
    value = _get_nested(config, path, default)
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "yes", "1", "on"}:
            return True
        if normalized in {"false", "no", "0", "off"}:
            return False
    return bool(value)


def get_int(config: dict[str, Any], path: tuple[str, ...], default: int) -> int:
    """Read a nested integer config value with safe fallback."""
    value = _get_nested(config, path, default)
    try:
        return int(value)
    except (TypeError, ValueError):
        logger.warning("Invalid integer config %s=%r, using %s", ".".join(path), value, default)
        return default


def get_float(config: dict[str, Any], path: tuple[str, ...], default: float) -> float:
    """Read a nested float config value with safe fallback."""
    value = _get_nested(config, path, default)
    try:
        return float(value)
    except (TypeError, ValueError):
        logger.warning("Invalid float config %s=%r, using %s", ".".join(path), value, default)
        return default


def _deep_merge(base: dict, override: dict) -> dict:
    """Deep merge two dicts, override takes precedence."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _get_nested(d: dict, path: tuple[str, ...], default: Any = None) -> Any:
    current: Any = d
    for key in path:
        if not isinstance(current, dict) or key not in current:
            return default
        current = current[key]
    return current


def _set_nested(d: dict, path: tuple, value: Any) -> None:
    """Set a nested dict value by path."""
    if isinstance(value, str):
        if value.lower() in {"true", "yes", "1", "on"}:
            value = True
        elif value.lower() in {"false", "no", "0", "off"}:
            value = False
        elif value.isdigit():
            value = int(value)
    for key in path[:-1]:
        d = d.setdefault(key, {})
    d[path[-1]] = value
