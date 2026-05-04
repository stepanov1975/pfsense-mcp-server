"""Tests for pfSense MCP configuration loading."""

from pathlib import Path

import pytest

from pfsense_mcp import PfSenseWebGuiClient
from pfsense_mcp.config import ConfigError, PfSenseConfig, load_config


def test_package_exports_webgui_client() -> None:
    assert PfSenseWebGuiClient is not None


def write_env(tmp_path: Path, content: str) -> Path:
    env_path = tmp_path / ".env"
    env_path.write_text(content, encoding="utf-8")
    return env_path


def test_load_config_reads_required_webgui_settings_and_defaults_to_read_only(tmp_path: Path) -> None:
    credential = "fixture-credential-value"
    env_path = write_env(
        tmp_path,
        "\n".join(
            [
                "PFSENSE_BASE_URL=https://192.0.2.1:8843",
                "PFSENSE_USERNAME=readonly-user",
                f"PFSENSE_PASSWORD={credential}",
                "PFSENSE_MCP_READ_ONLY=true",
            ]
        ),
    )

    config = load_config(env_path)

    assert config == PfSenseConfig(
        base_url="https://192.0.2.1:8843",
        username="readonly-user",
        password=credential,
        read_only=True,
    )


def test_load_config_rejects_missing_required_values(tmp_path: Path) -> None:
    env_path = write_env(tmp_path, "PFSENSE_BASE_URL=https://192.0.2.1:8843\n")

    with pytest.raises(ConfigError, match="PFSENSE_USERNAME, PFSENSE_PASSWORD"):
        load_config(env_path)


def test_load_config_defaults_to_read_only_when_flag_is_absent(tmp_path: Path) -> None:
    credential = "fixture-credential-value"
    env_path = write_env(
        tmp_path,
        "\n".join(
            [
                "PFSENSE_BASE_URL=https://192.0.2.1:8843",
                "PFSENSE_USERNAME=readonly-user",
                f"PFSENSE_PASSWORD={credential}",
            ]
        ),
    )

    assert load_config(env_path).read_only is True


def test_load_config_rejects_cleartext_base_url_by_default(tmp_path: Path) -> None:
    credential = "fixture-credential-value"
    env_path = write_env(
        tmp_path,
        "\n".join(
            [
                "PFSENSE_BASE_URL=http://192.0.2.1:8843",
                "PFSENSE_USERNAME=readonly-user",
                f"PFSENSE_PASSWORD={credential}",
                "PFSENSE_MCP_READ_ONLY=true",
            ]
        ),
    )

    with pytest.raises(ConfigError, match="HTTPS"):
        load_config(env_path)


def test_load_config_rejects_malformed_base_url(tmp_path: Path) -> None:
    credential = "fixture-credential-value"
    env_path = write_env(
        tmp_path,
        "\n".join(
            [
                "PFSENSE_BASE_URL=not-a-url",
                "PFSENSE_USERNAME=readonly-user",
                f"PFSENSE_PASSWORD={credential}",
                "PFSENSE_MCP_READ_ONLY=true",
            ]
        ),
    )

    with pytest.raises(ConfigError, match="valid URL"):
        load_config(env_path)


def test_load_config_requires_read_only_mode_by_default(tmp_path: Path) -> None:
    credential = "fixture-credential-value"
    env_path = write_env(
        tmp_path,
        "\n".join(
            [
                "PFSENSE_BASE_URL=https://192.0.2.1:8843",
                "PFSENSE_USERNAME=readonly-user",
                f"PFSENSE_PASSWORD={credential}",
                "PFSENSE_MCP_READ_ONLY=false",
            ]
        ),
    )

    with pytest.raises(ConfigError, match="read-only"):
        load_config(env_path)


def test_config_repr_redacts_password() -> None:
    credential = "fixture-credential-value"
    config = PfSenseConfig(
        base_url="https://192.0.2.1:8843",
        username="readonly-user",
        password=credential,
        read_only=True,
    )

    representation = repr(config)

    assert credential not in representation
    assert "password=" in representation
    assert "[REDACTED]" in representation
