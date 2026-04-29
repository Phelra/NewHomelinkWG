"""Unit tests for dashboard.py core functions."""
import json
import tempfile
from pathlib import Path

import pytest

import dashboard
from homelinkwg.config import _parse_kv_config, load_config, CONFIG_FILE, _config_cache
from homelinkwg.auth import verify_password


class TestParseKvConfig:
    """Tests for _parse_kv_config."""

    def test_empty_file(self):
        """Empty file returns empty dict."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.conf') as f:
            f.write('')
            path = Path(f.name)
        try:
            result = _parse_kv_config(path)
            assert result == {}
        finally:
            path.unlink()

    def test_basic_parsing(self):
        """Parse basic key=value pairs."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.conf') as f:
            f.write('KEY1=value1\nKEY2=value2\n')
            path = Path(f.name)
        try:
            result = _parse_kv_config(path)
            assert result == {'KEY1': 'value1', 'KEY2': 'value2'}
        finally:
            path.unlink()

    def test_skip_comments(self):
        """Skip lines starting with #."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.conf') as f:
            f.write('# Comment\nKEY=value\n# Another comment\n')
            path = Path(f.name)
        try:
            result = _parse_kv_config(path)
            assert result == {'KEY': 'value'}
        finally:
            path.unlink()

    def test_skip_blank_lines(self):
        """Skip blank and whitespace-only lines."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.conf') as f:
            f.write('KEY1=value1\n\n  \nKEY2=value2\n')
            path = Path(f.name)
        try:
            result = _parse_kv_config(path)
            assert result == {'KEY1': 'value1', 'KEY2': 'value2'}
        finally:
            path.unlink()

    def test_values_with_equals(self):
        """Handle values containing '='."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.conf') as f:
            f.write('KEY=value=with=equals\n')
            path = Path(f.name)
        try:
            result = _parse_kv_config(path)
            assert result == {'KEY': 'value=with=equals'}
        finally:
            path.unlink()

    def test_missing_file(self):
        """Missing file returns empty dict."""
        result = _parse_kv_config(Path('/nonexistent/file.conf'))
        assert result == {}


class TestVerifyPassword:
    """Tests for verify_password."""

    def test_verify_correct_password(self):
        """Verify correct password."""
        import bcrypt
        password = 'test_password'
        hash_str = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        assert verify_password(password, hash_str) is True

    def test_verify_incorrect_password(self):
        """Reject incorrect password."""
        import bcrypt
        password = 'test_password'
        wrong_password = 'wrong_password'
        hash_str = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        assert verify_password(wrong_password, hash_str) is False

    def test_verify_invalid_hash(self):
        """Handle invalid hash gracefully."""
        assert verify_password('password', 'invalid_hash') is False

    def test_verify_empty_password(self):
        """Handle empty password."""
        import bcrypt
        hash_str = bcrypt.hashpw(b'', bcrypt.gensalt()).decode()
        assert verify_password('', hash_str) is True


class TestLoadConfig:
    """Tests for load_config."""

    def test_load_valid_config(self, monkeypatch):
        """Load valid config.json."""
        config_data = {
            'ports': [{'local_port': 8096, 'remote_host': '192.168.1.1', 'remote_port': 8096}],
            'dashboard': {'port': 5555},
            'vpn': {'interface': 'wg0'},
        }
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            json.dump(config_data, f)
            path = Path(f.name)

        try:
            import homelinkwg.config as cfg_module
            monkeypatch.setattr(cfg_module, 'CONFIG_FILE', path)
            monkeypatch.setattr(cfg_module, '_config_cache', {'value': None, 'mtime_ns': None, 'loaded_at': 0.0})
            result = load_config()
            assert result['ports'] == config_data['ports']
            assert result['dashboard']['port'] == 5555
        finally:
            path.unlink()

    def test_load_empty_config_uses_defaults(self, monkeypatch):
        """Empty config file uses defaults."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            f.write('')
            path = Path(f.name)

        try:
            import homelinkwg.config as cfg_module
            monkeypatch.setattr(cfg_module, 'CONFIG_FILE', path)
            monkeypatch.setattr(cfg_module, '_config_cache', {'value': None, 'mtime_ns': None, 'loaded_at': 0.0})
            result = load_config()
            assert result['ports'] == []
            assert result['dashboard']['port'] == 5555
        finally:
            path.unlink()

    def test_load_invalid_json_uses_defaults(self, monkeypatch):
        """Invalid JSON falls back to defaults."""
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            f.write('{invalid json}')
            path = Path(f.name)

        try:
            import homelinkwg.config as cfg_module
            monkeypatch.setattr(cfg_module, 'CONFIG_FILE', path)
            monkeypatch.setattr(cfg_module, '_config_cache', {'value': None, 'mtime_ns': None, 'loaded_at': 0.0})
            result = load_config()
            assert result['ports'] == []
        finally:
            path.unlink()


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
