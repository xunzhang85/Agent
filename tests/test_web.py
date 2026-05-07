"""Tests for the web dashboard server helpers."""

from agent.web import AgentHTTPServer, WebHandler


def test_web_server_safe_config_exposes_mimo_defaults_without_secrets(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        """
llm:
  provider: openai
  model: MiMo-V2.5-Pro
  api_key: secret-value
  base_url: https://token-plan-sgp.xiaomimimo.com/v1
agent:
  timeout: 120
sandbox:
  enabled: false
""",
        encoding="utf-8",
    )

    server = AgentHTTPServer(("127.0.0.1", 0), WebHandler, config_path=str(config_path))
    try:
        safe = server.safe_config()
    finally:
        server.server_close()

    assert safe["model"] == "MiMo-V2.5-Pro"
    assert safe["provider"] == "openai"
    assert safe["timeout"] == 120
    assert safe["sandbox_enabled"] is False
    assert safe["api_key_configured"] is True
    assert safe["base_url_configured"] is True
    assert "secret-value" not in str(safe)
