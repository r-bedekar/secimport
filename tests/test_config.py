"""Tests for config loader."""


import pytest

from secimport.config.loader import SecimportConfig, SourceConfig, load_config


class TestSourceConfig:
    def test_minimal(self):
        cfg = SourceConfig(name="test", connector="qualys", base_url="https://example.com")
        assert cfg.auth_type == "api_key"
        assert cfg.verify_ssl is True

    def test_full(self):
        cfg = SourceConfig(
            name="prod_scanner",
            connector="qualys",
            base_url="https://qualys.example.com",
            auth_type="basic",
            credentials={"username": "u", "password": "p"},
            timeout=60,
        )
        assert cfg.timeout == 60


class TestSecimportConfig:
    def test_empty(self):
        cfg = SecimportConfig()
        assert cfg.sources == []
        assert cfg.outputs == []
        assert cfg.enrichment.deduplicate is True


class TestLoadConfig:
    def test_load_basic(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
sources:
  - name: test_scanner
    connector: qualys
    base_url: https://qualys.example.com
    auth_type: basic
    credentials:
      username: admin
      password: secret

outputs:
  - type: json
    path: ./output.json
""")
        cfg = load_config(config_file)
        assert len(cfg.sources) == 1
        assert cfg.sources[0].name == "test_scanner"
        assert cfg.sources[0].connector == "qualys"
        assert len(cfg.outputs) == 1
        assert cfg.outputs[0].type == "json"

    def test_env_substitution(self, tmp_path, monkeypatch):
        monkeypatch.setenv("TEST_USER", "my_user")
        monkeypatch.setenv("TEST_PASS", "my_pass")

        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
sources:
  - name: env_test
    connector: qualys
    base_url: https://example.com
    credentials:
      username: ${TEST_USER}
      password: ${TEST_PASS}
""")
        cfg = load_config(config_file)
        assert cfg.sources[0].credentials["username"] == "my_user"
        assert cfg.sources[0].credentials["password"] == "my_pass"

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            load_config("/nonexistent/path.yaml")

    def test_empty_config(self, tmp_path):
        config_file = tmp_path / "empty.yaml"
        config_file.write_text("")
        cfg = load_config(config_file)
        assert cfg.sources == []

    def test_enrichment_config(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text("""
enrichment:
  deduplicate: false
  gap_sources:
    - ["crowdstrike", "qualys"]
""")
        cfg = load_config(config_file)
        assert cfg.enrichment.deduplicate is False
        assert cfg.enrichment.gap_sources == [["crowdstrike", "qualys"]]
