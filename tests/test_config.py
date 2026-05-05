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


@pytest.mark.parametrize(
    "base_url",
    [
        "https://user@192.0.2.1:8843",
        "https://@192.0.2.1:8843",
        "https://:@192.0.2.1:8843",
        "https://192.0.2.1:8843/status_arp.php",
        "https://192.0.2.1:8843?next=status_arp.php",
        "https://192.0.2.1:8843/#dashboard",
    ],
)
def test_load_config_requires_base_url_to_be_https_origin_only(tmp_path: Path, base_url: str) -> None:
    credential = "fixture-credential-value"
    env_path = write_env(
        tmp_path,
        "\n".join(
            [
                f"PFSENSE_BASE_URL={base_url}",
                "PFSENSE_USERNAME=readonly-user",
                f"PFSENSE_PASSWORD={credential}",
                "PFSENSE_MCP_READ_ONLY=true",
            ]
        ),
    )

    with pytest.raises(ConfigError, match="origin URL"):
        load_config(env_path)


def test_load_config_reads_transport_safety_options(tmp_path: Path) -> None:
    credential = "fixture-credential-value"
    env_path = write_env(
        tmp_path,
        "\n".join(
            [
                "PFSENSE_BASE_URL=https://192.0.2.1:8843",
                "PFSENSE_USERNAME=readonly-user",
                f"PFSENSE_PASSWORD={credential}",
                "PFSENSE_MCP_READ_ONLY=true",
                "PFSENSE_VERIFY_TLS=false",
                "PFSENSE_TIMEOUT_SECONDS=3.5",
                "PFSENSE_MAX_RESPONSE_BYTES=4096",
            ]
        ),
    )

    config = load_config(env_path)

    assert config.verify_tls is False
    assert config.timeout_seconds == 3.5
    assert config.max_response_bytes == 4096


def test_load_config_can_use_env_path_from_environment(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
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
    monkeypatch.setenv("PFSENSE_MCP_ENV_PATH", str(env_path))

    assert load_config().base_url == "https://192.0.2.1:8843"


@pytest.mark.parametrize("base_url", ["https://192.0.2.1:bad", "https://192.0.2.1:99999"])
def test_load_config_rejects_invalid_base_url_ports(tmp_path: Path, base_url: str) -> None:
    credential = "fixture-credential-value"
    env_path = write_env(
        tmp_path,
        "\n".join(
            [
                f"PFSENSE_BASE_URL={base_url}",
                "PFSENSE_USERNAME=readonly-user",
                f"PFSENSE_PASSWORD={credential}",
                "PFSENSE_MCP_READ_ONLY=true",
            ]
        ),
    )

    with pytest.raises(ConfigError, match="valid port"):
        load_config(env_path)


@pytest.mark.parametrize("timeout_value", ["nan", "inf", "-inf"])
def test_load_config_rejects_non_finite_timeouts(tmp_path: Path, timeout_value: str) -> None:
    credential = "fixture-credential-value"
    env_path = write_env(
        tmp_path,
        "\n".join(
            [
                "PFSENSE_BASE_URL=https://192.0.2.1:8843",
                "PFSENSE_USERNAME=readonly-user",
                f"PFSENSE_PASSWORD={credential}",
                "PFSENSE_MCP_READ_ONLY=true",
                f"PFSENSE_TIMEOUT_SECONDS={timeout_value}",
            ]
        ),
    )

    with pytest.raises(ConfigError, match="positive finite number"):
        load_config(env_path)
