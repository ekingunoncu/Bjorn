"""
Shared fixtures for WiFi manager and MCP WiFi tool tests.

Mocks subprocess calls, shared_data, Logger, and filesystem
operations so tests run without real hardware or root access.
"""

import os
import sys
import types
from unittest.mock import MagicMock, patch

import pytest

# ── Ensure project root is importable ──────────────────────────
PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.abspath(__file__))
)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


# ── Shared mock for shared_data ────────────────────────────────

@pytest.fixture()
def mock_shared_data():
    """Return a MagicMock that mimics the shared_data singleton.

    Attributes used by wifi_manager and mcp_server are set to
    sensible temp-directory paths so path-joins succeed.
    """
    sd = MagicMock()
    sd.output_dir = "/tmp/bjorn_test/data/output"
    sd.passwordsfile = "/tmp/bjorn_test/resources/passwords.txt"
    sd.dictionarydir = "/tmp/bjorn_test/resources"
    sd.shared_config_json = "/tmp/bjorn_test/config/shared.json"
    sd.actions_file = "/tmp/bjorn_test/config/actions.json"
    sd.configdir = "/tmp/bjorn_test/config"
    sd.datadir = "/tmp/bjorn_test/data"
    sd.actions_dir = "/tmp/bjorn_test/actions"
    sd.resourcesdir = "/tmp/bjorn_test/resources"
    sd.currentdir = "/tmp/bjorn_test"
    sd.backupdir = "/tmp/bjorn_test/backup/backups"
    sd.scan_results_dir = "/tmp/bjorn_test/data/output/scan_results"
    sd.datastolendir = "/tmp/bjorn_test/data/output/data_stolen"
    sd.webconsolelog = "/tmp/bjorn_test/data/logs/webconsole.log"
    sd.vuln_summary_file = "/tmp/bjorn_test/data/output/vulns.csv"
    sd.sshfile = "/tmp/bjorn_test/data/output/crackedpwd/ssh.csv"
    sd.smbfile = "/tmp/bjorn_test/data/output/crackedpwd/smb.csv"
    sd.ftpfile = "/tmp/bjorn_test/data/output/crackedpwd/ftp.csv"
    sd.telnetfile = "/tmp/bjorn_test/data/output/crackedpwd/tel.csv"
    sd.sqlfile = "/tmp/bjorn_test/data/output/crackedpwd/sql.csv"
    sd.rdpfile = "/tmp/bjorn_test/data/output/crackedpwd/rdp.csv"
    sd.bjornorch_status = "running"
    sd.bjornstatustext2 = "Scanning"
    sd.targetnbr = 5
    sd.portnbr = 12
    sd.vulnnbr = 3
    sd.crednbr = 2
    sd.datanbr = 1
    sd.zombiesnbr = 0
    sd.levelnbr = 7
    sd.coinnbr = 42
    sd.bjorn_instance = None
    sd.wifichanged = False
    sd.orchestrator_should_exit = False
    sd.read_data.return_value = []
    sd.config = {}
    sd.default_config = {}
    return sd


@pytest.fixture()
def mock_logger():
    """Return a no-op Logger mock."""
    lgr = MagicMock()
    lgr.debug = MagicMock()
    lgr.info = MagicMock()
    lgr.warning = MagicMock()
    lgr.error = MagicMock()
    lgr.critical = MagicMock()
    return lgr


@pytest.fixture()
def mock_subprocess_run():
    """Patch subprocess.run to return a successful result."""
    result = MagicMock()
    result.returncode = 0
    result.stdout = ""
    result.stderr = ""
    with patch("subprocess.run", return_value=result) as m:
        m._result = result
        yield m


@pytest.fixture()
def mock_subprocess_popen():
    """Patch subprocess.Popen to return a mock process."""
    proc = MagicMock()
    proc.pid = 12345
    proc.poll.return_value = None
    proc.wait.return_value = 0
    proc.communicate.return_value = ("", "")
    proc.returncode = 0
    proc._wifi_fh = None
    with patch("subprocess.Popen", return_value=proc) as m:
        m._proc = proc
        yield m


def make_run_result(returncode=0, stdout="", stderr=""):
    """Helper to build a subprocess.run-like result."""
    result = MagicMock()
    result.returncode = returncode
    result.stdout = stdout
    result.stderr = stderr
    return result
