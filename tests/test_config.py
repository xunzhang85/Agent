"""Tests for configuration helpers."""

from agent.utils.config import get_bool, get_float, get_int, load_config


def test_load_config_keeps_openai_compatible_base_url(tmp_path):
    config_path = tmp_path / "config.yaml"
    config_path.write_text(
        """
llm:
  provider: openai
  model: MiMo-V2.5-Pro
  api_key: test-key
  base_url: https://token-plan-sgp.xiaomimimo.com/v1/
""",
        encoding="utf-8",
    )

    config = load_config(str(config_path))

    assert config["llm"]["model"] == "MiMo-V2.5-Pro"
    assert config["llm"]["base_url"] == "https://token-plan-sgp.xiaomimimo.com/v1"


def test_get_bool_handles_string_false():
    config = {"agent": {"retry_on_failure": "false"}}

    assert get_bool(config, ("agent", "retry_on_failure"), True) is False


def test_get_int_falls_back_on_invalid_value():
    config = {"agent": {"timeout": "not-a-number"}}

    assert get_int(config, ("agent", "timeout"), 600) == 600


def test_get_float_falls_back_on_invalid_value():
    config = {"llm": {"temperature": "warm"}}

    assert get_float(config, ("llm", "temperature"), 0.1) == 0.1
