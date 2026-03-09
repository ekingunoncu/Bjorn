"""
Integration tests for MCP WiFi wrapper functions and tool call
logging in mcp_server.py.

Tests the wifi_* wrapper functions, WIFI_AVAILABLE flag behavior,
_log_tool_call / get_tool_call_log, and TOOL_FUNCTIONS registry.
"""

import os
import sys
import types
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

# ── Module-level stubs (before importing mcp_server) ──────────

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Provide init_shared stub
_fake_sd = MagicMock()
_fake_sd.output_dir = "/tmp/bjorn_test/data/output"
_fake_sd.passwordsfile = "/tmp/bjorn_test/resources/passwords.txt"
_fake_sd.shared_config_json = "/tmp/bjorn_test/config/shared.json"
_fake_sd.actions_file = "/tmp/bjorn_test/config/actions.json"
_fake_sd.configdir = "/tmp/bjorn_test/config"
_fake_sd.datadir = "/tmp/bjorn_test/data"
_fake_sd.actions_dir = "/tmp/bjorn_test/actions"
_fake_sd.resourcesdir = "/tmp/bjorn_test/resources"
_fake_sd.currentdir = "/tmp/bjorn_test"
_fake_sd.backupdir = "/tmp/bjorn_test/backup/backups"
_fake_sd.scan_results_dir = "/tmp/bjorn_test/data/output/scan_results"
_fake_sd.datastolendir = "/tmp/bjorn_test/data/output/data_stolen"
_fake_sd.webconsolelog = "/tmp/bjorn_test/data/logs/webconsole.log"
_fake_sd.vuln_summary_file = "/tmp/bjorn_test/data/output/vulns.csv"
_fake_sd.sshfile = "/tmp/bjorn_test/data/output/crackedpwd/ssh.csv"
_fake_sd.smbfile = "/tmp/bjorn_test/data/output/crackedpwd/smb.csv"
_fake_sd.ftpfile = "/tmp/bjorn_test/data/output/crackedpwd/ftp.csv"
_fake_sd.telnetfile = "/tmp/bjorn_test/data/output/crackedpwd/tel.csv"
_fake_sd.sqlfile = "/tmp/bjorn_test/data/output/crackedpwd/sql.csv"
_fake_sd.rdpfile = "/tmp/bjorn_test/data/output/crackedpwd/rdp.csv"
_fake_sd.bjornorch_status = "running"
_fake_sd.bjornstatustext2 = "Scanning"
_fake_sd.targetnbr = 5
_fake_sd.portnbr = 12
_fake_sd.vulnnbr = 3
_fake_sd.crednbr = 2
_fake_sd.datanbr = 1
_fake_sd.zombiesnbr = 0
_fake_sd.levelnbr = 7
_fake_sd.coinnbr = 42
_fake_sd.bjorn_instance = None
_fake_sd.read_data.return_value = []

_init_mod = types.ModuleType("init_shared")
_init_mod.shared_data = _fake_sd
sys.modules.setdefault("init_shared", _init_mod)

# Provide logger stub
_logger_mod = types.ModuleType("logger")


class _StubLogger:
    def __init__(self, *a, **kw):
        pass
    def debug(self, *a, **kw):
        pass
    def info(self, *a, **kw):
        pass
    def warning(self, *a, **kw):
        pass
    def error(self, *a, **kw):
        pass
    def critical(self, *a, **kw):
        pass
    def success(self, *a, **kw):
        pass


_logger_mod.Logger = _StubLogger
sys.modules.setdefault("logger", _logger_mod)

# Mock the mcp import so MCP_AVAILABLE is False in mcp_server
# (we test tool functions, not the MCP protocol layer)
_fake_mcp = types.ModuleType("mcp")
_fake_mcp_server = types.ModuleType("mcp.server")
_fake_mcp_fastmcp = types.ModuleType("mcp.server.fastmcp")


class _FakeFastMCP:
    def __init__(self, name):
        self.name = name
    def tool(self):
        def decorator(fn):
            return fn
        return decorator
    def resource(self, uri):
        def decorator(fn):
            return fn
        return decorator


_fake_mcp_fastmcp.FastMCP = _FakeFastMCP
sys.modules.setdefault("mcp", _fake_mcp)
sys.modules.setdefault("mcp.server", _fake_mcp_server)
sys.modules.setdefault("mcp.server.fastmcp", _fake_mcp_fastmcp)

# Build a fake wifi_manager module with a mock wifi_mgr.
# Use direct assignment to override the real wifi_manager that
# test_wifi_manager.py may have loaded, since mcp_server needs
# to import wifi_mgr from our mock.
_fake_wm = types.ModuleType("wifi_manager")
_mock_wifi_mgr = MagicMock()
_fake_wm.wifi_mgr = _mock_wifi_mgr
_fake_wm.WiFiManager = MagicMock
sys.modules["wifi_manager"] = _fake_wm

# Now import mcp_server
import mcp_server
from mcp_server import (
    wifi_analyze,
    wifi_list_clients,
    wifi_deauth,
    wifi_capture_handshake,
    wifi_capture_pmkid,
    wifi_crack_wpa,
    wifi_crack_wps,
    wifi_crack_wep,
    wifi_evil_twin,
    wifi_karma_attack,
    wifi_get_handshakes,
    wifi_get_cracked,
    wifi_security_report,
    _log_tool_call,
    get_tool_call_log,
    _tool_call_log,
    _tool_call_log_lock,
    TOOL_FUNCTIONS,
    TOOL_SCHEMAS,
)


# ── Helpers ────────────────────────────────────────────────────

@pytest.fixture(autouse=True)
def clear_tool_log_and_mocks():
    """Reset the tool call log and wifi mock between tests."""
    with _tool_call_log_lock:
        _tool_call_log.clear()
    _mock_wifi_mgr.reset_mock()
    yield
    with _tool_call_log_lock:
        _tool_call_log.clear()
    _mock_wifi_mgr.reset_mock()


@pytest.fixture()
def enable_wifi():
    """Temporarily set WIFI_AVAILABLE = True."""
    original = mcp_server.WIFI_AVAILABLE
    mcp_server.WIFI_AVAILABLE = True
    yield
    mcp_server.WIFI_AVAILABLE = original


@pytest.fixture()
def disable_wifi():
    """Temporarily set WIFI_AVAILABLE = False."""
    original = mcp_server.WIFI_AVAILABLE
    mcp_server.WIFI_AVAILABLE = False
    yield
    mcp_server.WIFI_AVAILABLE = original


# ══════════════════════════════════════════════════════════════
# WIFI_AVAILABLE flag behavior
# ══════════════════════════════════════════════════════════════

class TestWifiAvailableFlag:
    """All wifi_* wrappers must return an error dict when the
    wifi_manager module is unavailable.
    """

    def test_analyze_unavailable(self, disable_wifi):
        result = wifi_analyze()
        assert result == {"error": "WiFi manager not available"}

    def test_list_clients_unavailable(self, disable_wifi):
        result = wifi_list_clients("AA:BB:CC:DD:EE:FF", 6)
        assert "error" in result

    def test_deauth_unavailable(self, disable_wifi):
        result = wifi_deauth("AA:BB:CC:DD:EE:FF", 6)
        assert "error" in result

    def test_capture_handshake_unavailable(self, disable_wifi):
        result = wifi_capture_handshake(
            "AA:BB:CC:DD:EE:FF", 6
        )
        assert "error" in result

    def test_capture_pmkid_unavailable(self, disable_wifi):
        result = wifi_capture_pmkid(
            "AA:BB:CC:DD:EE:FF", 6
        )
        assert "error" in result

    def test_crack_wpa_unavailable(self, disable_wifi):
        result = wifi_crack_wpa("/tmp/capture.cap")
        assert "error" in result

    def test_crack_wps_unavailable(self, disable_wifi):
        result = wifi_crack_wps("AA:BB:CC:DD:EE:FF", 6)
        assert "error" in result

    def test_crack_wep_unavailable(self, disable_wifi):
        result = wifi_crack_wep("AA:BB:CC:DD:EE:FF", 6)
        assert "error" in result

    def test_evil_twin_unavailable(self, disable_wifi):
        result = wifi_evil_twin("TestNet", 6)
        assert "error" in result

    def test_karma_unavailable(self, disable_wifi):
        result = wifi_karma_attack()
        assert "error" in result

    def test_get_handshakes_unavailable(self, disable_wifi):
        result = wifi_get_handshakes()
        assert "error" in result

    def test_get_cracked_unavailable(self, disable_wifi):
        result = wifi_get_cracked()
        assert "error" in result

    def test_security_report_unavailable(self, disable_wifi):
        result = wifi_security_report()
        assert "error" in result


# ══════════════════════════════════════════════════════════════
# WiFi wrapper delegation (WIFI_AVAILABLE = True)
# ══════════════════════════════════════════════════════════════

class TestWifiWrapperDelegation:
    """When WIFI_AVAILABLE is True, each wrapper must forward
    to the corresponding wifi_mgr method.
    """

    def test_wifi_analyze_delegates(self, enable_wifi):
        expected = {"success": True, "networks": []}
        _mock_wifi_mgr.analyze_networks.return_value = expected

        result = wifi_analyze(
            target_bssid="AA:BB:CC:DD:EE:FF",
            channel=6, scan_duration=10,
        )

        assert result == expected
        _mock_wifi_mgr.analyze_networks.assert_called_once_with(
            "AA:BB:CC:DD:EE:FF", 6, 10
        )

    def test_wifi_analyze_defaults(self, enable_wifi):
        expected = {"success": True, "networks": []}
        _mock_wifi_mgr.analyze_networks.return_value = expected

        result = wifi_analyze()

        _mock_wifi_mgr.analyze_networks.assert_called_with(
            None, None, 15
        )

    def test_wifi_list_clients_delegates(self, enable_wifi):
        expected = {"success": True, "clients": []}
        _mock_wifi_mgr.list_clients.return_value = expected

        result = wifi_list_clients(
            "AA:BB:CC:DD:EE:FF", 6, duration=20
        )

        assert result == expected
        _mock_wifi_mgr.list_clients.assert_called_once_with(
            "AA:BB:CC:DD:EE:FF", 6, 20
        )

    def test_wifi_deauth_delegates(self, enable_wifi):
        expected = {"success": True, "count": 10}
        _mock_wifi_mgr.send_deauth.return_value = expected

        result = wifi_deauth(
            "AA:BB:CC:DD:EE:FF", 6,
            client_mac="11:22:33:44:55:66", count=10,
        )

        assert result == expected
        _mock_wifi_mgr.send_deauth.assert_called_once_with(
            "AA:BB:CC:DD:EE:FF", 6, "11:22:33:44:55:66", 10
        )

    def test_wifi_deauth_broadcast_default(self, enable_wifi):
        _mock_wifi_mgr.send_deauth.return_value = {}

        wifi_deauth("AA:BB:CC:DD:EE:FF", 6)

        _mock_wifi_mgr.send_deauth.assert_called_with(
            "AA:BB:CC:DD:EE:FF", 6, None, 10
        )

    def test_wifi_capture_handshake_delegates(self, enable_wifi):
        expected = {"success": True, "capture_file": "/t.cap"}
        _mock_wifi_mgr.capture_handshake.return_value = expected

        result = wifi_capture_handshake(
            "AA:BB:CC:DD:EE:FF", 6,
            client_mac="11:22:33:44:55:66",
            deauth_count=3, timeout=60,
        )

        assert result == expected
        _mock_wifi_mgr.capture_handshake.assert_called_once_with(
            "AA:BB:CC:DD:EE:FF", 6, "11:22:33:44:55:66", 3, 60
        )

    def test_wifi_capture_pmkid_delegates(self, enable_wifi):
        expected = {"success": True, "hash_file": "/h.16800"}
        _mock_wifi_mgr.capture_pmkid.return_value = expected

        result = wifi_capture_pmkid(
            "AA:BB:CC:DD:EE:FF", 6, timeout=30
        )

        assert result == expected
        _mock_wifi_mgr.capture_pmkid.assert_called_once_with(
            "AA:BB:CC:DD:EE:FF", 6, 30
        )

    def test_wifi_crack_wpa_delegates(self, enable_wifi):
        expected = {"success": True, "password": "pw123"}
        _mock_wifi_mgr.crack_wpa.return_value = expected

        result = wifi_crack_wpa(
            "/data/cap.cap", wordlist="/wl.txt"
        )

        assert result == expected
        _mock_wifi_mgr.crack_wpa.assert_called_once_with(
            "/data/cap.cap", "/wl.txt"
        )

    def test_wifi_crack_wpa_default_wordlist(self, enable_wifi):
        _mock_wifi_mgr.crack_wpa.return_value = {}

        wifi_crack_wpa("/data/cap.cap")

        _mock_wifi_mgr.crack_wpa.assert_called_with(
            "/data/cap.cap", None
        )

    def test_wifi_crack_wps_delegates(self, enable_wifi):
        expected = {"success": True, "pin": "12345678"}
        _mock_wifi_mgr.crack_wps.return_value = expected

        result = wifi_crack_wps(
            "AA:BB:CC:DD:EE:FF", 6,
            timeout=120, pixie_dust=False,
        )

        assert result == expected
        _mock_wifi_mgr.crack_wps.assert_called_once_with(
            "AA:BB:CC:DD:EE:FF", 6, 120, False
        )

    def test_wifi_crack_wep_delegates(self, enable_wifi):
        expected = {"success": True, "key": "ABCDEF"}
        _mock_wifi_mgr.crack_wep.return_value = expected

        result = wifi_crack_wep(
            "AA:BB:CC:DD:EE:FF", 6, timeout=100
        )

        assert result == expected
        _mock_wifi_mgr.crack_wep.assert_called_once_with(
            "AA:BB:CC:DD:EE:FF", 6, 100
        )

    def test_wifi_evil_twin_delegates(self, enable_wifi):
        expected = {"success": True, "credentials_captured": 0}
        _mock_wifi_mgr.evil_twin.return_value = expected

        result = wifi_evil_twin("TestNet", 6, duration=60)

        assert result == expected
        _mock_wifi_mgr.evil_twin.assert_called_once_with(
            "TestNet", 6, duration=60
        )

    def test_wifi_karma_delegates(self, enable_wifi):
        expected = {"success": True, "duration": 120}
        _mock_wifi_mgr.karma_attack.return_value = expected

        result = wifi_karma_attack(duration=120)

        assert result == expected
        _mock_wifi_mgr.karma_attack.assert_called_once_with(120)

    def test_wifi_get_handshakes_delegates(self, enable_wifi):
        expected = {"success": True, "captures": [], "count": 0}
        _mock_wifi_mgr.get_handshakes.return_value = expected

        result = wifi_get_handshakes()

        assert result == expected
        _mock_wifi_mgr.get_handshakes.assert_called_once()

    def test_wifi_get_cracked_delegates(self, enable_wifi):
        expected = {
            "success": True, "credentials": [], "count": 0,
        }
        _mock_wifi_mgr.get_cracked.return_value = expected

        result = wifi_get_cracked()

        assert result == expected
        _mock_wifi_mgr.get_cracked.assert_called_once()

    def test_wifi_security_report_delegates(self, enable_wifi):
        expected = {"success": True, "summary": {}}
        _mock_wifi_mgr.security_report.return_value = expected

        result = wifi_security_report()

        assert result == expected
        _mock_wifi_mgr.security_report.assert_called_once()


# ══════════════════════════════════════════════════════════════
# Tool Call Logging
# ══════════════════════════════════════════════════════════════

class TestToolCallLogging:
    """Test _log_tool_call and get_tool_call_log."""

    def test_log_creates_entry(self):
        _log_tool_call(
            "wifi_analyze",
            {"channel": 6},
            {"success": True, "networks": []},
        )

        log = get_tool_call_log()
        assert len(log) == 1
        assert log[0]["tool"] == "wifi_analyze"
        assert log[0]["success"] is True

    def test_log_records_timestamp(self):
        _log_tool_call("test_tool", {}, {})

        log = get_tool_call_log()
        # Format is HH:MM:SS
        assert len(log[0]["timestamp"]) == 8
        assert ":" in log[0]["timestamp"]

    def test_log_records_args(self):
        _log_tool_call(
            "wifi_deauth",
            {"bssid": "AA:BB", "count": 5},
            {},
        )

        log = get_tool_call_log()
        assert log[0]["args"]["bssid"] == "AA:BB"
        assert log[0]["args"]["count"] == 5

    def test_log_truncates_result_preview(self):
        long_result = {"data": "x" * 1000}
        _log_tool_call("big_result", {}, long_result)

        log = get_tool_call_log()
        assert len(log[0]["result_preview"]) <= 500

    def test_log_detects_error_in_result(self):
        _log_tool_call(
            "fail_tool", {},
            {"error": "something broke"},
        )

        log = get_tool_call_log()
        assert log[0]["success"] is False

    def test_log_success_when_no_error(self):
        _log_tool_call(
            "ok_tool", {},
            {"status": "all good"},
        )

        log = get_tool_call_log()
        assert log[0]["success"] is True

    def test_log_caps_at_max_entries(self):
        for i in range(150):
            _log_tool_call(f"tool_{i}", {}, {})

        log = get_tool_call_log()
        assert len(log) == 100

    def test_log_fifo_order(self):
        for i in range(110):
            _log_tool_call(f"tool_{i}", {}, {})

        log = get_tool_call_log()
        # Oldest 10 should have been evicted
        assert log[0]["tool"] == "tool_10"
        assert log[-1]["tool"] == "tool_109"

    def test_get_tool_call_log_returns_copy(self):
        _log_tool_call("test", {}, {})

        log1 = get_tool_call_log()
        log2 = get_tool_call_log()
        assert log1 is not log2
        assert log1 == log2


# ══════════════════════════════════════════════════════════════
# TOOL_FUNCTIONS and TOOL_SCHEMAS registry
# ══════════════════════════════════════════════════════════════

class TestToolRegistry:
    """Verify the tool registry is correctly populated."""

    WIFI_TOOL_NAMES = [
        "wifi_analyze",
        "wifi_list_clients",
        "wifi_deauth",
        "wifi_capture_handshake",
        "wifi_capture_pmkid",
        "wifi_crack_wpa",
        "wifi_crack_wps",
        "wifi_crack_wep",
        "wifi_evil_twin",
        "wifi_karma_attack",
        "wifi_get_handshakes",
        "wifi_get_cracked",
        "wifi_security_report",
    ]

    def test_all_wifi_tools_in_functions_map(self):
        for name in self.WIFI_TOOL_NAMES:
            assert name in TOOL_FUNCTIONS, (
                f"{name} missing from TOOL_FUNCTIONS"
            )

    def test_all_wifi_tools_in_schemas(self):
        schema_names = {s["name"] for s in TOOL_SCHEMAS}
        for name in self.WIFI_TOOL_NAMES:
            assert name in schema_names, (
                f"{name} missing from TOOL_SCHEMAS"
            )

    def test_schemas_have_required_fields(self):
        for schema in TOOL_SCHEMAS:
            assert "name" in schema
            assert "description" in schema
            assert "input_schema" in schema
            assert schema["input_schema"]["type"] == "object"

    def test_wifi_analyze_schema_params(self):
        schema = next(
            s for s in TOOL_SCHEMAS
            if s["name"] == "wifi_analyze"
        )
        props = schema["input_schema"]["properties"]
        assert "target_bssid" in props
        assert "channel" in props
        assert "scan_duration" in props
        # None are required
        assert schema["input_schema"]["required"] == []

    def test_wifi_deauth_required_params(self):
        schema = next(
            s for s in TOOL_SCHEMAS
            if s["name"] == "wifi_deauth"
        )
        required = schema["input_schema"]["required"]
        assert "bssid" in required
        assert "channel" in required

    def test_tool_functions_are_callable(self):
        for name, func in TOOL_FUNCTIONS.items():
            assert callable(func), (
                f"{name} is not callable"
            )

    def test_non_wifi_tools_also_present(self):
        core_tools = [
            "get_status", "get_network_data",
            "get_alive_hosts", "get_credentials",
            "get_config",
        ]
        for name in core_tools:
            assert name in TOOL_FUNCTIONS


# ══════════════════════════════════════════════════════════════
# Error handling in wrapper param conversion
# ══════════════════════════════════════════════════════════════

class TestWrapperParamConversion:
    """Verify empty-string-to-None conversion in wrappers."""

    def test_analyze_empty_bssid_becomes_none(self, enable_wifi):
        _mock_wifi_mgr.analyze_networks.return_value = {}

        wifi_analyze(target_bssid="", channel=0)

        _mock_wifi_mgr.analyze_networks.assert_called_with(
            None, None, 15
        )

    def test_deauth_empty_client_becomes_none(self, enable_wifi):
        _mock_wifi_mgr.send_deauth.return_value = {}

        wifi_deauth(
            "AA:BB:CC:DD:EE:FF", 6, client_mac=""
        )

        _mock_wifi_mgr.send_deauth.assert_called_with(
            "AA:BB:CC:DD:EE:FF", 6, None, 10
        )

    def test_handshake_empty_client_becomes_none(
        self, enable_wifi
    ):
        _mock_wifi_mgr.capture_handshake.return_value = {}

        wifi_capture_handshake(
            "AA:BB:CC:DD:EE:FF", 6, client_mac=""
        )

        _mock_wifi_mgr.capture_handshake.assert_called_with(
            "AA:BB:CC:DD:EE:FF", 6, None, 5, 120
        )

    def test_crack_wpa_empty_wordlist_becomes_none(
        self, enable_wifi
    ):
        _mock_wifi_mgr.crack_wpa.return_value = {}

        wifi_crack_wpa("/data/cap.cap", wordlist="")

        _mock_wifi_mgr.crack_wpa.assert_called_with(
            "/data/cap.cap", None
        )


# ══════════════════════════════════════════════════════════════
# Subprocess failure in non-WiFi MCP functions
# ══════════════════════════════════════════════════════════════

class TestMcpSubprocessFailures:
    """Test error handling in scan_wifi, connect_wifi, etc."""

    def test_scan_wifi_subprocess_failure(self):
        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.communicate.return_value = (
            "", "scan failed"
        )

        with patch(
            "subprocess.Popen", return_value=mock_proc
        ):
            result = mcp_server.scan_wifi()

        assert "error" in result

    def test_disconnect_wifi_subprocess_failure(self):
        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.communicate.return_value = (
            "", "not connected"
        )

        with patch(
            "subprocess.Popen", return_value=mock_proc
        ):
            result = mcp_server.disconnect_wifi()

        assert "error" in result

    def test_scan_wifi_exception(self):
        with patch(
            "subprocess.Popen",
            side_effect=OSError("no iwlist"),
        ):
            result = mcp_server.scan_wifi()

        assert "error" in result
