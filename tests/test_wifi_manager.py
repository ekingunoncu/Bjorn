"""
Integration tests for wifi_manager.WiFiManager.

Every public method is tested with mocked subprocess calls
and filesystem operations so no real hardware is required.
"""

import csv
import io
import os
import re
import signal
import sys
import types
from datetime import datetime
from unittest.mock import (
    MagicMock, PropertyMock, call, mock_open,
    patch, ANY,
)

import pytest

# ── Module-level patches applied before import ────────────────
# wifi_manager.py imports shared_data and Logger at module level,
# so we install mocks in sys.modules before the import happens.

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Build a fake shared_data singleton for module-level usage
_fake_sd = MagicMock()
_fake_sd.output_dir = "/tmp/bjorn_test/data/output"
_fake_sd.passwordsfile = "/tmp/bjorn_test/resources/passwords.txt"

# Provide init_shared as a module with shared_data attribute
_init_shared_mod = types.ModuleType("init_shared")
_init_shared_mod.shared_data = _fake_sd
sys.modules.setdefault("init_shared", _init_shared_mod)

# Provide a stub Logger
_logger_mod = types.ModuleType("logger")


class _StubLogger:
    """No-op logger that accepts any constructor args."""

    def __init__(self, *args, **kwargs):
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

# Now safe to import wifi_manager
import wifi_manager
from wifi_manager import WiFiManager, IFACE, BLOCKED_IFACES


# ── Helpers ────────────────────────────────────────────────────

SAMPLE_AIRODUMP_CSV = (
    "BSSID, First time seen, Last time seen, channel, Speed, "
    "Privacy, Cipher, Authentication, Power, # beacons, # IV, "
    "LAN IP, ID-length, ESSID, Key\r\n"
    "AA:BB:CC:DD:EE:FF, 2026-03-09 10:00:00, "
    "2026-03-09 10:01:00,  6, 54, WPA2, CCMP, PSK, -42, "
    "100, 50, 0.0.0.0, 8, TestNet, \r\n"
    "11:22:33:44:55:66, 2026-03-09 10:00:00, "
    "2026-03-09 10:01:00,  1, 54, WEP, WEP, OPN, -70, "
    "30, 10, 0.0.0.0, 7, WeakNet, \r\n"
    "\r\n"
    "Station MAC, First time seen, Last time seen, Power, "
    "# packets, BSSID, Probed ESSIDs\r\n"
    "FF:EE:DD:CC:BB:AA, 2026-03-09 10:00:05, "
    "2026-03-09 10:01:00, -55, 200, "
    "AA:BB:CC:DD:EE:FF, TestNet\r\n"
)


def _run_cmd_side_effect(cmd, **kwargs):
    """Generic _run_cmd mock returning success."""
    result = MagicMock()
    result.returncode = 0
    result.stdout = ""
    result.stderr = ""
    return result


# ── Fixture: patched WiFiManager ──────────────────────────────

@pytest.fixture()
def mgr():
    """Create a WiFiManager with _ensure_dirs and _run_cmd mocked.

    This prevents real filesystem creation and real subprocess
    calls.  Each test can further patch individual methods.
    """
    with patch.object(WiFiManager, "_ensure_dirs"):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="", stderr=""
            )
            manager = WiFiManager()
    return manager


# ── _validate_interface ───────────────────────────────────────

class TestValidateInterface:
    """Ensure protected interfaces are rejected."""

    def test_blocks_wlan0(self, mgr):
        with pytest.raises(ValueError, match="protected"):
            mgr._validate_interface("wlan0")

    def test_blocks_eth0(self, mgr):
        with pytest.raises(ValueError, match="protected"):
            mgr._validate_interface("eth0")

    def test_blocks_usb0(self, mgr):
        with pytest.raises(ValueError, match="protected"):
            mgr._validate_interface("usb0")

    def test_allows_wlan1(self, mgr):
        # Should not raise
        mgr._validate_interface("wlan1")

    def test_allows_wlan2(self, mgr):
        mgr._validate_interface("wlan2")


# ── _run_cmd ──────────────────────────────────────────────────

class TestRunCmd:
    """Test subprocess wrapper."""

    def test_successful_command(self, mgr):
        with patch("subprocess.run") as mock_run:
            result = MagicMock(
                returncode=0, stdout="ok", stderr=""
            )
            mock_run.return_value = result
            code, out, err = mgr._run_cmd(["echo", "hi"])
            assert code == 0
            assert out == "ok"

    def test_timeout_expired(self, mgr):
        import subprocess
        with patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(
                cmd="test", timeout=5
            ),
        ):
            code, out, err = mgr._run_cmd(
                ["sleep", "999"], timeout=5
            )
            assert code == -1
            assert "timed out" in err.lower()

    def test_tool_not_found(self, mgr):
        with patch(
            "subprocess.run",
            side_effect=FileNotFoundError("no tool"),
        ):
            code, out, err = mgr._run_cmd(["nosuchcmd"])
            assert code == -127
            assert "not installed" in err.lower()


# ── _sanitize_bssid / _ts ────────────────────────────────────

class TestHelpers:
    """Test small utility methods."""

    def test_sanitize_bssid(self, mgr):
        assert mgr._sanitize_bssid(
            "aa:bb:cc:dd:ee:ff"
        ) == "AA-BB-CC-DD-EE-FF"

    def test_ts_format(self, mgr):
        ts = mgr._ts()
        assert re.match(r"^\d{8}-\d{6}$", ts)


# ── _extract_bssid_from_cap ──────────────────────────────────

class TestExtractBssid:

    def test_extracts_from_filename(self, mgr):
        path = (
            "/data/handshakes/"
            "hs-AA-BB-CC-DD-EE-FF-20260309-100000-01.cap"
        )
        assert mgr._extract_bssid_from_cap(
            path
        ) == "AA:BB:CC:DD:EE:FF"

    def test_returns_empty_on_no_match(self, mgr):
        assert mgr._extract_bssid_from_cap(
            "/data/random.cap"
        ) == ""


# ── _extract_ssid_from_aircrack ───────────────────────────────

class TestExtractSsid:

    def test_extracts_ssid(self, mgr):
        output = "Opening file...\nESSID: MyNetwork\nDone"
        assert mgr._extract_ssid_from_aircrack(
            output
        ) == "MyNetwork"

    def test_returns_unknown_on_none(self, mgr):
        assert mgr._extract_ssid_from_aircrack(None) == "Unknown"

    def test_returns_unknown_on_no_match(self, mgr):
        assert mgr._extract_ssid_from_aircrack(
            "no ssid here"
        ) == "Unknown"


# ── _parse_airodump_csv ───────────────────────────────────────

class TestParseAirodumpCsv:

    def test_parses_networks_and_clients(self, mgr, tmp_path):
        csv_file = tmp_path / "scan-01.csv"
        csv_file.write_text(SAMPLE_AIRODUMP_CSV)

        result = mgr._parse_airodump_csv(str(csv_file))

        assert len(result["networks"]) == 2
        assert result["networks"][0]["bssid"] == "AA:BB:CC:DD:EE:FF"
        assert result["networks"][0]["channel"] == 6
        assert result["networks"][0]["encryption"] == "WPA2"
        assert result["networks"][0]["ssid"] == "TestNet"

        assert len(result["clients"]) == 1
        assert result["clients"][0]["mac"] == "FF:EE:DD:CC:BB:AA"
        assert result["clients"][0]["bssid"] == "AA:BB:CC:DD:EE:FF"

    def test_handles_missing_file(self, mgr, tmp_path):
        result = mgr._parse_airodump_csv(
            str(tmp_path / "missing")
        )
        assert result["networks"] == []
        assert result["clients"] == []

    def test_finds_suffixed_file(self, mgr, tmp_path):
        # airodump appends -01.csv
        csv_file = tmp_path / "scan-01.csv"
        csv_file.write_text(SAMPLE_AIRODUMP_CSV)

        result = mgr._parse_airodump_csv(
            str(tmp_path / "scan")
        )
        assert len(result["networks"]) == 2

    def test_client_count_incremented(self, mgr, tmp_path):
        csv_file = tmp_path / "scan-01.csv"
        csv_file.write_text(SAMPLE_AIRODUMP_CSV)

        result = mgr._parse_airodump_csv(str(csv_file))
        # First network has one associated client
        net_aa = [
            n for n in result["networks"]
            if n["bssid"] == "AA:BB:CC:DD:EE:FF"
        ][0]
        assert net_aa["clients_count"] == 1


# ── analyze_networks ──────────────────────────────────────────

class TestAnalyzeNetworks:

    @patch("time.sleep")
    @patch.object(WiFiManager, "_disable_monitor_mode")
    @patch.object(WiFiManager, "_check_tool", return_value=False)
    @patch.object(
        WiFiManager, "_parse_airodump_csv",
        return_value={
            "networks": [
                {
                    "bssid": "AA:BB:CC:DD:EE:FF",
                    "ssid": "TestNet",
                    "channel": 6,
                    "encryption": "WPA2",
                    "cipher": "CCMP",
                    "signal": -42,
                    "hidden": False,
                    "clients_count": 0,
                }
            ],
            "clients": [],
        },
    )
    @patch.object(WiFiManager, "_stop_bg")
    @patch.object(WiFiManager, "_run_cmd_bg")
    @patch.object(
        WiFiManager, "_enable_monitor_mode",
        return_value="wlan1mon",
    )
    def test_success(
        self, mock_mon, mock_bg, mock_stop,
        mock_parse, mock_check, mock_dis, mock_sleep,
        mgr,
    ):
        proc = MagicMock()
        mock_bg.return_value = proc

        result = mgr.analyze_networks(scan_duration=1)

        assert result["success"] is True
        assert result["count"] == 1
        assert result["networks"][0]["ssid"] == "TestNet"
        mock_mon.assert_called_once()
        mock_dis.assert_called_once()

    @patch("time.sleep")
    @patch.object(WiFiManager, "_disable_monitor_mode")
    @patch.object(
        WiFiManager, "_run_cmd_bg", return_value=None
    )
    @patch.object(
        WiFiManager, "_enable_monitor_mode",
        return_value="wlan1mon",
    )
    def test_tool_missing(
        self, mock_mon, mock_bg, mock_dis, mock_sleep, mgr
    ):
        result = mgr.analyze_networks(scan_duration=1)

        assert result["success"] is False
        assert "not installed" in result["error"]

    @patch("time.sleep")
    @patch.object(WiFiManager, "_disable_monitor_mode")
    @patch.object(WiFiManager, "_check_tool", return_value=True)
    @patch.object(
        WiFiManager, "_parse_airodump_csv",
        return_value={
            "networks": [
                {
                    "bssid": "AA:BB:CC:DD:EE:FF",
                    "ssid": "WPSNet",
                    "channel": 6,
                    "encryption": "WPA2",
                    "cipher": "CCMP",
                    "signal": -50,
                    "hidden": False,
                    "clients_count": 0,
                }
            ],
            "clients": [],
        },
    )
    @patch.object(WiFiManager, "_stop_bg")
    @patch.object(WiFiManager, "_run_cmd_bg")
    @patch.object(
        WiFiManager, "_enable_monitor_mode",
        return_value="wlan1mon",
    )
    def test_wps_detection_via_wash(
        self, mock_mon, mock_bg, mock_stop,
        mock_parse, mock_check, mock_dis, mock_sleep,
        mgr,
    ):
        mock_bg.return_value = MagicMock()
        wash_output = "AA:BB:CC:DD:EE:FF  6  -50  1.0  Lck  WPSNet"

        def side_effect_run(cmd, **kwargs):
            result = MagicMock()
            if isinstance(cmd, list) and cmd[0] == "wash":
                result.returncode = 0
                result.stdout = wash_output
                result.stderr = ""
            else:
                result.returncode = 0
                result.stdout = ""
                result.stderr = ""
            return result

        with patch("subprocess.run", side_effect=side_effect_run):
            result = mgr.analyze_networks(scan_duration=1)

        assert result["success"] is True
        assert result["networks"][0]["wps_enabled"] is True


# ── list_clients ──────────────────────────────────────────────

class TestListClients:

    @patch("time.sleep")
    @patch.object(WiFiManager, "_disable_monitor_mode")
    @patch.object(
        WiFiManager, "_parse_airodump_csv",
        return_value={
            "networks": [],
            "clients": [
                {
                    "mac": "FF:EE:DD:CC:BB:AA",
                    "bssid": "AA:BB:CC:DD:EE:FF",
                    "signal": -55,
                    "packets": 200,
                    "probes": "TestNet",
                }
            ],
        },
    )
    @patch.object(WiFiManager, "_stop_bg")
    @patch.object(WiFiManager, "_run_cmd_bg")
    @patch.object(
        WiFiManager, "_enable_monitor_mode",
        return_value="wlan1mon",
    )
    def test_success(
        self, mock_mon, mock_bg, mock_stop,
        mock_parse, mock_dis, mock_sleep, mgr,
    ):
        mock_bg.return_value = MagicMock()

        result = mgr.list_clients(
            "AA:BB:CC:DD:EE:FF", 6, duration=1
        )

        assert result["success"] is True
        assert result["count"] == 1
        assert result["clients"][0]["mac"] == "FF:EE:DD:CC:BB:AA"

    @patch("time.sleep")
    @patch.object(WiFiManager, "_disable_monitor_mode")
    @patch.object(
        WiFiManager, "_run_cmd_bg", return_value=None
    )
    @patch.object(
        WiFiManager, "_enable_monitor_mode",
        return_value="wlan1mon",
    )
    def test_tool_missing(
        self, mock_mon, mock_bg, mock_dis, mock_sleep, mgr
    ):
        result = mgr.list_clients(
            "AA:BB:CC:DD:EE:FF", 6, duration=1
        )
        assert result["success"] is False


# ── send_deauth ───────────────────────────────────────────────

class TestSendDeauth:

    @patch.object(WiFiManager, "_disable_monitor_mode")
    @patch.object(
        WiFiManager, "_enable_monitor_mode",
        return_value="wlan1mon",
    )
    def test_broadcast_deauth(self, mock_mon, mock_dis, mgr):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="", stderr=""
            )
            result = mgr.send_deauth(
                "AA:BB:CC:DD:EE:FF", 6, count=5
            )

        assert result["success"] is True
        assert result["count"] == 5
        assert result["target"] == "broadcast"

    @patch.object(WiFiManager, "_disable_monitor_mode")
    @patch.object(
        WiFiManager, "_enable_monitor_mode",
        return_value="wlan1mon",
    )
    def test_targeted_deauth(self, mock_mon, mock_dis, mgr):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="", stderr=""
            )
            result = mgr.send_deauth(
                "AA:BB:CC:DD:EE:FF", 6,
                client_mac="FF:EE:DD:CC:BB:AA", count=3,
            )

        assert result["success"] is True
        assert result["target"] == "FF:EE:DD:CC:BB:AA"

    @patch.object(WiFiManager, "_disable_monitor_mode")
    @patch.object(
        WiFiManager, "_enable_monitor_mode",
        return_value="wlan1mon",
    )
    def test_aireplay_failure(self, mock_mon, mock_dis, mgr):
        with patch("subprocess.run") as mock_run:
            # iwconfig channel set succeeds, aireplay fails
            results = [
                MagicMock(returncode=0, stdout="", stderr=""),
                MagicMock(
                    returncode=1, stdout="",
                    stderr="injection failed"
                ),
            ]
            mock_run.side_effect = results

            result = mgr.send_deauth(
                "AA:BB:CC:DD:EE:FF", 6
            )

        assert result["success"] is False
        assert "failed" in result["error"]


# ── capture_handshake ─────────────────────────────────────────

class TestCaptureHandshake:

    @patch("time.sleep")
    @patch("os.path.exists")
    @patch.object(WiFiManager, "_disable_monitor_mode")
    @patch.object(WiFiManager, "_stop_bg")
    @patch.object(WiFiManager, "_run_cmd_bg")
    @patch.object(
        WiFiManager, "_enable_monitor_mode",
        return_value="wlan1mon",
    )
    def test_handshake_captured(
        self, mock_mon, mock_bg, mock_stop,
        mock_dis, mock_exists, mock_sleep, mgr,
    ):
        mock_bg.return_value = MagicMock()
        mock_exists.return_value = True

        with patch("subprocess.run") as mock_run:
            # Deauth call, then aircrack-ng check
            mock_run.side_effect = [
                MagicMock(
                    returncode=0, stdout="", stderr=""
                ),
                MagicMock(
                    returncode=0,
                    stdout="1 handshake captured",
                    stderr="",
                ),
            ]
            result = mgr.capture_handshake(
                "AA:BB:CC:DD:EE:FF", 6, timeout=25
            )

        assert result["success"] is True
        assert "capture_file" in result

    @patch("time.sleep")
    @patch("os.path.exists", return_value=False)
    @patch.object(WiFiManager, "_disable_monitor_mode")
    @patch.object(WiFiManager, "_stop_bg")
    @patch.object(
        WiFiManager, "_run_cmd_bg", return_value=None
    )
    @patch.object(
        WiFiManager, "_enable_monitor_mode",
        return_value="wlan1mon",
    )
    def test_airodump_missing(
        self, mock_mon, mock_bg, mock_stop,
        mock_dis, mock_exists, mock_sleep, mgr,
    ):
        result = mgr.capture_handshake(
            "AA:BB:CC:DD:EE:FF", 6, timeout=5
        )
        assert result["success"] is False
        assert "not installed" in result["error"]


# ── capture_pmkid ─────────────────────────────────────────────

class TestCapturePmkid:

    @patch("time.sleep")
    @patch("os.path.getsize", return_value=1024)
    @patch("os.path.exists", return_value=True)
    @patch("os.unlink")
    @patch.object(WiFiManager, "_disable_monitor_mode")
    @patch.object(WiFiManager, "_stop_bg")
    @patch.object(WiFiManager, "_run_cmd_bg")
    @patch.object(
        WiFiManager, "_enable_monitor_mode",
        return_value="wlan1mon",
    )
    def test_pmkid_captured(
        self, mock_mon, mock_bg, mock_stop,
        mock_dis, mock_unlink, mock_exists,
        mock_size, mock_sleep, mgr,
    ):
        mock_bg.return_value = MagicMock()

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="", stderr=""
            )
            with patch("builtins.open", mock_open()):
                result = mgr.capture_pmkid(
                    "AA:BB:CC:DD:EE:FF", 6, timeout=1
                )

        assert result["success"] is True
        assert "hash_file" in result

    @patch("time.sleep")
    @patch("os.unlink")
    @patch.object(WiFiManager, "_disable_monitor_mode")
    @patch.object(WiFiManager, "_stop_bg")
    @patch.object(
        WiFiManager, "_run_cmd_bg", return_value=None
    )
    @patch.object(
        WiFiManager, "_enable_monitor_mode",
        return_value="wlan1mon",
    )
    def test_tool_missing(
        self, mock_mon, mock_bg, mock_stop,
        mock_dis, mock_unlink, mock_sleep, mgr,
    ):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="", stderr=""
            )
            with patch("builtins.open", mock_open()):
                result = mgr.capture_pmkid(
                    "AA:BB:CC:DD:EE:FF", 6, timeout=1
                )

        assert result["success"] is False
        assert "not installed" in result["error"]


# ── crack_wpa ─────────────────────────────────────────────────

class TestCrackWpa:

    @patch("os.path.exists", return_value=True)
    @patch.object(
        WiFiManager, "_append_cracked"
    )
    @patch.object(
        WiFiManager, "_extract_ssid_from_aircrack",
        return_value="TestNet",
    )
    @patch.object(
        WiFiManager, "_extract_bssid_from_cap",
        return_value="AA:BB:CC:DD:EE:FF",
    )
    def test_key_found(
        self, mock_bssid, mock_ssid, mock_append,
        mock_exists, mgr,
    ):
        aircrack_out = (
            "KEY FOUND! [ mysecretpass ]\n"
            "ESSID: TestNet\n"
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout=aircrack_out, stderr=""
            )
            result = mgr.crack_wpa(
                "/data/hs-AA-BB-CC-DD-EE-FF-01.cap"
            )

        assert result["success"] is True
        assert result["password"] == "mysecretpass"
        mock_append.assert_called_once()

    @patch("os.path.exists", return_value=True)
    @patch.object(
        WiFiManager, "_extract_bssid_from_cap",
        return_value="AA:BB:CC:DD:EE:FF",
    )
    def test_key_not_found(
        self, mock_bssid, mock_exists, mgr,
    ):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1,
                stdout="Passphrase not in dictionary",
                stderr="",
            )
            result = mgr.crack_wpa(
                "/data/hs-AA-BB-CC-DD-EE-FF-01.cap"
            )

        assert result["success"] is False
        assert "not found" in result["error"].lower()

    def test_capture_file_missing(self, mgr):
        with patch("os.path.exists", return_value=False):
            result = mgr.crack_wpa("/data/no_such.cap")

        assert result["success"] is False
        assert "not found" in result["error"].lower()

    @patch("os.path.exists")
    @patch.object(
        WiFiManager, "_check_tool", return_value=True
    )
    def test_pmkid_hashcat_success(
        self, mock_check, mock_exists, mgr
    ):
        mock_exists.return_value = True
        hashcat_out = (
            "hash:cracked_password\n"
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=hashcat_out,
                stderr="",
            )
            result = mgr.crack_wpa(
                "/data/pmkid.16800"
            )

        assert result["success"] is True
        assert result["password"] == "cracked_password"
        assert result["method"] == "pmkid"


# ── crack_wps ─────────────────────────────────────────────────

class TestCrackWps:

    @patch.object(WiFiManager, "_append_cracked")
    @patch.object(WiFiManager, "_disable_monitor_mode")
    @patch.object(
        WiFiManager, "_enable_monitor_mode",
        return_value="wlan1mon",
    )
    def test_wps_cracked(
        self, mock_mon, mock_dis, mock_append, mgr
    ):
        reaver_out = (
            "[+] WPS PIN: '12345678'\n"
            "[+] WPA PSK: 'my_wifi_pass'\n"
        )
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout=reaver_out, stderr=""
            )
            result = mgr.crack_wps(
                "AA:BB:CC:DD:EE:FF", 6, timeout=10
            )

        assert result["success"] is True
        assert result["pin"] == "12345678"
        assert result["psk"] == "my_wifi_pass"
        mock_append.assert_called_once()

    @patch.object(WiFiManager, "_disable_monitor_mode")
    @patch.object(
        WiFiManager, "_enable_monitor_mode",
        return_value="wlan1mon",
    )
    def test_wps_not_cracked(self, mock_mon, mock_dis, mgr):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1,
                stdout="[!] WPS transaction failed",
                stderr="",
            )
            result = mgr.crack_wps(
                "AA:BB:CC:DD:EE:FF", 6, timeout=10
            )

        assert result["success"] is False

    @patch.object(WiFiManager, "_disable_monitor_mode")
    @patch.object(
        WiFiManager, "_enable_monitor_mode",
        return_value="wlan1mon",
    )
    def test_pixie_dust_flag(
        self, mock_mon, mock_dis, mgr
    ):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1, stdout="", stderr=""
            )
            result = mgr.crack_wps(
                "AA:BB:CC:DD:EE:FF", 6,
                pixie_dust=True, timeout=10,
            )

            # Verify -K 1 was passed for pixie dust
            call_args = mock_run.call_args
            cmd = call_args[0][0]
            assert "-K" in cmd
            assert "1" in cmd


# ── crack_wep ─────────────────────────────────────────────────

class TestCrackWep:

    @patch("time.sleep")
    @patch("os.path.exists", return_value=True)
    @patch.object(WiFiManager, "_append_cracked")
    @patch.object(WiFiManager, "_disable_monitor_mode")
    @patch.object(WiFiManager, "_stop_bg")
    @patch.object(WiFiManager, "_run_cmd_bg")
    @patch.object(
        WiFiManager, "_enable_monitor_mode",
        return_value="wlan1mon",
    )
    def test_wep_cracked(
        self, mock_mon, mock_bg, mock_stop,
        mock_dis, mock_append, mock_exists,
        mock_sleep, mgr,
    ):
        mock_bg.return_value = MagicMock()

        crack_out = "KEY FOUND! [ AB:CD:EF:01:23 ]"
        call_count = [0]

        def run_side_effect(cmd, **kwargs):
            call_count[0] += 1
            result = MagicMock()
            if isinstance(cmd, list) and cmd[0] == "aircrack-ng":
                result.returncode = 0
                result.stdout = crack_out
                result.stderr = ""
            else:
                result.returncode = 0
                result.stdout = ""
                result.stderr = ""
            return result

        with patch("subprocess.run", side_effect=run_side_effect):
            # Set short timeout so loop runs once
            result = mgr.crack_wep(
                "AA:BB:CC:DD:EE:FF", 6, timeout=35
            )

        assert result["success"] is True
        assert result["key"] == "ABCDEF0123"
        mock_append.assert_called_once()


# ── evil_twin ─────────────────────────────────────────────────

class TestEvilTwin:

    @patch("time.sleep")
    @patch.object(WiFiManager, "_disable_monitor_mode")
    @patch.object(WiFiManager, "_stop_bg")
    @patch.object(WiFiManager, "_run_cmd_bg")
    @patch.object(WiFiManager, "_run_cmd")
    def test_already_running(
        self, mock_cmd, mock_bg, mock_stop,
        mock_dis, mock_sleep, mgr,
    ):
        mgr._evil_twin_running = True
        result = mgr.evil_twin("TestNet", 6, duration=1)
        assert result["success"] is False
        assert "already running" in result["error"]

    @patch("time.sleep")
    @patch.object(WiFiManager, "_disable_monitor_mode")
    @patch.object(WiFiManager, "_stop_bg")
    @patch.object(WiFiManager, "_run_cmd_bg")
    @patch.object(WiFiManager, "_run_cmd")
    def test_hostapd_missing(
        self, mock_cmd, mock_bg, mock_stop,
        mock_dis, mock_sleep, mgr,
    ):
        mgr._evil_twin_running = False
        mgr._monitor_active = False
        mock_cmd.return_value = (0, "", "")
        # hostapd bg returns None (not installed)
        mock_bg.return_value = None

        with patch("builtins.open", mock_open()):
            with patch("os.makedirs"):
                result = mgr.evil_twin(
                    "TestNet", 6, duration=1
                )

        assert result["success"] is False
        assert "not installed" in result["error"]


# ── karma_attack ──────────────────────────────────────────────

class TestKarmaAttack:

    @patch("time.sleep")
    @patch("os.path.exists", return_value=True)
    @patch.object(WiFiManager, "_disable_monitor_mode")
    @patch.object(WiFiManager, "_stop_bg")
    @patch.object(WiFiManager, "_run_cmd_bg")
    @patch.object(
        WiFiManager, "_enable_monitor_mode",
        return_value="wlan1mon",
    )
    def test_success(
        self, mock_mon, mock_bg, mock_stop,
        mock_dis, mock_exists, mock_sleep, mgr,
    ):
        mock_bg.return_value = MagicMock()

        with patch(
            "builtins.open",
            mock_open(read_data="line1\nline2\n"),
        ):
            result = mgr.karma_attack(duration=1)

        assert result["success"] is True
        assert result["duration"] == 1

    @patch("time.sleep")
    @patch.object(WiFiManager, "_disable_monitor_mode")
    @patch.object(WiFiManager, "_stop_bg")
    @patch.object(WiFiManager, "_run_cmd_bg")
    @patch.object(
        WiFiManager, "_enable_monitor_mode",
        return_value="wlan1mon",
    )
    def test_mdk4_and_mdk3_missing(
        self, mock_mon, mock_bg, mock_stop,
        mock_dis, mock_sleep, mgr,
    ):
        # Both mdk4 and mdk3 return None
        mock_bg.return_value = None

        result = mgr.karma_attack(duration=1)

        assert result["success"] is False
        assert "not installed" in result["error"]


# ── get_handshakes ────────────────────────────────────────────

class TestGetHandshakes:

    def test_lists_cap_and_pmkid_files(self, mgr, tmp_path):
        hs_dir = tmp_path / "handshakes"
        pm_dir = tmp_path / "pmkid"
        hs_dir.mkdir()
        pm_dir.mkdir()

        cap = hs_dir / "hs-AA-BB-CC-DD-EE-FF-20260309-01.cap"
        cap.write_bytes(b"\x00" * 100)
        pmk = pm_dir / "pmkid-11-22-33-44-55-66-20260309.16800"
        pmk.write_bytes(b"\x00" * 50)

        with patch(
            "wifi_manager.HANDSHAKE_DIR", str(hs_dir)
        ), patch(
            "wifi_manager.PMKID_DIR", str(pm_dir)
        ):
            result = mgr.get_handshakes()

        assert result["success"] is True
        assert result["count"] == 2
        types_found = {c["type"] for c in result["captures"]}
        assert "handshake" in types_found
        assert "pmkid" in types_found

    def test_empty_dirs(self, mgr, tmp_path):
        hs_dir = tmp_path / "handshakes"
        pm_dir = tmp_path / "pmkid"
        hs_dir.mkdir()
        pm_dir.mkdir()

        with patch(
            "wifi_manager.HANDSHAKE_DIR", str(hs_dir)
        ), patch(
            "wifi_manager.PMKID_DIR", str(pm_dir)
        ):
            result = mgr.get_handshakes()

        assert result["success"] is True
        assert result["count"] == 0


# ── get_cracked ───────────────────────────────────────────────

class TestGetCracked:

    def test_reads_csv(self, mgr, tmp_path):
        csv_file = tmp_path / "cracked.csv"
        csv_file.write_text(
            "BSSID,SSID,Encryption,Password,Method,Timestamp\n"
            "AA:BB:CC:DD:EE:FF,TestNet,WPA2,secret,"
            "handshake,2026-03-09T10:00:00\n"
        )

        with patch(
            "wifi_manager.CRACKED_CSV", str(csv_file)
        ):
            result = mgr.get_cracked()

        assert result["success"] is True
        assert result["count"] == 1
        assert result["credentials"][0]["password"] == "secret"

    def test_no_csv(self, mgr, tmp_path):
        with patch(
            "wifi_manager.CRACKED_CSV",
            str(tmp_path / "missing.csv"),
        ):
            result = mgr.get_cracked()

        assert result["success"] is True
        assert result["count"] == 0


# ── security_report ───────────────────────────────────────────

class TestSecurityReport:

    @patch.object(
        WiFiManager, "get_cracked",
        return_value={
            "success": True,
            "credentials": [
                {
                    "bssid": "AA:BB:CC:DD:EE:FF",
                    "password": "cracked123",
                }
            ],
            "count": 1,
        },
    )
    @patch.object(
        WiFiManager, "analyze_networks",
        return_value={
            "success": True,
            "networks": [
                {
                    "bssid": "AA:BB:CC:DD:EE:FF",
                    "ssid": "TestNet",
                    "channel": 6,
                    "encryption": "WPA2",
                    "signal": -42,
                    "wps_enabled": False,
                    "hidden": False,
                    "clients_count": 2,
                },
                {
                    "bssid": "11:22:33:44:55:66",
                    "ssid": "OpenNet",
                    "channel": 1,
                    "encryption": "OPN",
                    "signal": -70,
                    "wps_enabled": False,
                    "hidden": False,
                    "clients_count": 0,
                },
            ],
            "count": 2,
        },
    )
    def test_generates_report(
        self, mock_analyze, mock_cracked, mgr, tmp_path
    ):
        with patch(
            "wifi_manager.REPORTS_DIR", str(tmp_path)
        ):
            result = mgr.security_report()

        assert result["success"] is True
        assert result["summary"]["total_networks"] == 2
        assert result["summary"]["vulnerable_networks"] >= 1
        assert result["summary"]["cracked_networks"] == 1

        # Open network should be CRITICAL
        open_net = [
            a for a in result["assessments"]
            if a["ssid"] == "OpenNet"
        ][0]
        assert open_net["risk_level"] == "CRITICAL"

    @patch.object(
        WiFiManager, "analyze_networks",
        return_value={
            "success": False,
            "error": "no adapter",
        },
    )
    def test_scan_failure(self, mock_analyze, mgr):
        result = mgr.security_report()
        assert result["success"] is False
        assert "scan failed" in result["error"].lower()


# ── _safe decorator ───────────────────────────────────────────

class TestSafeDecorator:
    """The @_safe decorator catches all exceptions."""

    def test_returns_error_dict_on_exception(self, mgr):
        with patch.object(
            WiFiManager, "_enable_monitor_mode",
            side_effect=RuntimeError("adapter gone"),
        ):
            result = mgr.analyze_networks()

        assert result["success"] is False
        assert "adapter gone" in result["error"]


# ── _enable_monitor_mode ──────────────────────────────────────

class TestEnableMonitorMode:

    def test_already_active(self, mgr):
        mgr._monitor_active = True
        mgr._monitor_iface = "wlan1mon"

        with patch.object(
            WiFiManager, "_detect_monitor_iface",
            return_value="wlan1mon",
        ):
            result = mgr._enable_monitor_mode()

        assert result == "wlan1mon"

    def test_raises_on_failure(self, mgr):
        mgr._monitor_active = False
        mgr._monitor_iface = None

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1, stdout="", stderr="fail"
            )
            with patch("time.sleep"):
                with pytest.raises(RuntimeError):
                    mgr._enable_monitor_mode()


# ── _check_tool ───────────────────────────────────────────────

class TestCheckTool:

    def test_tool_exists(self, mgr):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0, stdout="/usr/bin/aircrack-ng",
                stderr="",
            )
            assert mgr._check_tool("aircrack-ng") is True

    def test_tool_missing(self, mgr):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=1, stdout="", stderr=""
            )
            assert mgr._check_tool("nosuchbin") is False
