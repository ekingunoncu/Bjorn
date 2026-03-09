#!/usr/bin/env python3
#mcp_server.py
#
# Bjorn MCP Server - Exposes Bjorn's capabilities via Model Context Protocol.
#
# Embedded mode: Started as a thread by Bjorn.py, SSE transport on configurable port.
#   Connect from Claude Desktop:
#     { "mcpServers": { "bjorn": { "url": "http://<pi-ip>:8081/sse" } } }
#
# Standalone mode: python mcp_server.py (stdio transport for local MCP clients)

import os
import sys
import json
import csv
import logging
import threading
import importlib
from datetime import datetime

# Ensure Bjorn modules are importable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from init_shared import shared_data
from logger import Logger

logger = Logger(name="mcp_server.py", level=logging.DEBUG)

# Graceful MCP import
try:
    from mcp.server.fastmcp import FastMCP
    MCP_AVAILABLE = True
except ImportError:
    MCP_AVAILABLE = False
    logger.warning("mcp package not installed. MCP server disabled. Install: pip install 'mcp[cli]'")


# ── Tool Functions ────────────────────────────────────────────────────────────
# Plain functions at module level so they can be used by both MCP server and
# chat handler (single source of truth).

def get_status() -> dict:
    """Get Bjorn's current operational status including alive hosts, open ports, credentials, and vulnerabilities."""
    try:
        data = shared_data.read_data()
        alive_hosts = [row for row in data if row.get('Alive') == '1']
        return {
            "bjorn_status": shared_data.bjornorch_status,
            "status_text": shared_data.bjornstatustext2,
            "alive_hosts": len(alive_hosts),
            "total_hosts": len(data),
            "targets": shared_data.targetnbr,
            "open_ports": shared_data.portnbr,
            "vulnerabilities": shared_data.vulnnbr,
            "credentials": shared_data.crednbr,
            "stolen_data": shared_data.datanbr,
            "zombies": shared_data.zombiesnbr,
            "level": shared_data.levelnbr,
            "coins": shared_data.coinnbr,
        }
    except Exception as exc:
        return {"error": str(exc)}


def get_network_data() -> dict:
    """Get the full network knowledge base with all discovered hosts, ports, and action results."""
    try:
        data = shared_data.read_data()
        return {
            "hosts": data,
            "total": len(data),
            "alive": len([r for r in data if r.get('Alive') == '1'])
        }
    except Exception as exc:
        return {"error": str(exc)}


def get_alive_hosts() -> list:
    """Get list of currently alive (reachable) hosts with their open ports."""
    try:
        data = shared_data.read_data()
        alive = []
        for row in data:
            if row.get('Alive') == '1':
                alive.append({
                    "ip": row.get('IPs'),
                    "mac": row.get('MAC Address'),
                    "hostname": row.get('Hostnames'),
                    "ports": row.get('Ports', '').split(';')
                })
        return alive
    except Exception as exc:
        return [{"error": str(exc)}]


def get_credentials() -> dict:
    """Get all cracked credentials organized by service type (SSH, SMB, FTP, Telnet, SQL, RDP)."""
    try:
        credentials = {}
        cred_files = {
            "ssh": shared_data.sshfile,
            "smb": shared_data.smbfile,
            "ftp": shared_data.ftpfile,
            "telnet": shared_data.telnetfile,
            "sql": shared_data.sqlfile,
            "rdp": shared_data.rdpfile,
        }
        for service, filepath in cred_files.items():
            if os.path.exists(filepath):
                with open(filepath, 'r') as fil:
                    reader = csv.DictReader(fil)
                    creds = list(reader)
                    if creds:
                        credentials[service] = creds
        return credentials if credentials else {"message": "No credentials cracked yet"}
    except Exception as exc:
        return {"error": str(exc)}


def get_vulnerabilities() -> dict:
    """Get discovered vulnerabilities from nmap scans."""
    try:
        vuln_file = shared_data.vuln_summary_file
        if os.path.exists(vuln_file):
            with open(vuln_file, 'r') as fil:
                reader = csv.DictReader(fil)
                vulns = list(reader)
            return {"vulnerabilities": vulns, "count": len(vulns)}
        return {"message": "No vulnerabilities discovered yet", "count": 0}
    except Exception as exc:
        return {"error": str(exc)}


def get_config() -> dict:
    """Get Bjorn's current configuration."""
    try:
        with open(shared_data.shared_config_json, 'r') as fil:
            return json.load(fil)
    except Exception as exc:
        return {"error": str(exc)}


def update_config(key: str, value: str) -> dict:
    """Update a single Bjorn configuration value.

    Args:
        key: Configuration key to update (e.g. 'scan_interval', 'manual_mode')
        value: New value (will be auto-converted to appropriate type)
    """
    try:
        with open(shared_data.shared_config_json, 'r') as fil:
            config = json.load(fil)

        if key not in config:
            return {"error": f"Unknown config key: {key}"}

        current = config[key]
        if isinstance(current, bool):
            config[key] = value.lower() in ('true', '1', 'yes')
        elif isinstance(current, int):
            config[key] = int(value)
        elif isinstance(current, float):
            config[key] = float(value)
        elif isinstance(current, list):
            config[key] = json.loads(value) if value.startswith('[') else value.split(',')
        else:
            config[key] = value

        with open(shared_data.shared_config_json, 'w') as fil:
            json.dump(config, fil, indent=4)

        shared_data.load_config()
        return {"status": "success", "key": key, "value": config[key]}
    except Exception as exc:
        return {"error": str(exc)}


def start_orchestrator() -> dict:
    """Start Bjorn's autonomous orchestrator to begin scanning and attacking."""
    try:
        if shared_data.bjorn_instance:
            shared_data.bjorn_instance.start_orchestrator()
            return {"status": "success", "message": "Orchestrator starting"}
        return {"error": "Bjorn instance not initialized"}
    except Exception as exc:
        return {"error": str(exc)}


def stop_orchestrator() -> dict:
    """Stop Bjorn's autonomous orchestrator."""
    try:
        if shared_data.bjorn_instance:
            shared_data.bjorn_instance.stop_orchestrator()
            shared_data.orchestrator_should_exit = True
            return {"status": "success", "message": "Orchestrator stopping"}
        return {"error": "Bjorn instance not initialized"}
    except Exception as exc:
        return {"error": str(exc)}


def execute_action(ip: str, port: str, action: str) -> dict:
    """Execute a specific security action on a target host.

    Args:
        ip: Target IP address
        port: Target port number
        action: Action class name (e.g. 'SSHBruteforce', 'FTPBruteforce', 'NmapVulnScanner')
    """
    try:
        with open(shared_data.actions_file, 'r') as fil:
            actions_config = json.load(fil)

        action_config = next((a for a in actions_config if a['b_class'] == action), None)
        if not action_config:
            return {"error": f"Action '{action}' not found"}

        module = importlib.import_module(f"actions.{action_config['b_module']}")
        action_instance = getattr(module, action)(shared_data)

        current_data = shared_data.read_data()
        row = next((r for r in current_data if r['IPs'] == ip), None)
        if not row:
            return {"error": f"No data found for IP: {ip}"}

        result = action_instance.execute(ip, port, row, action)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        row[action] = f"{result}_{timestamp}"
        shared_data.write_data(current_data)

        return {"status": result, "action": action, "target": f"{ip}:{port}", "timestamp": timestamp}
    except Exception as exc:
        return {"error": str(exc)}


def get_logs(lines: int = 50) -> str:
    """Get recent Bjorn logs.

    Args:
        lines: Number of log lines to return (default 50)
    """
    try:
        log_file = shared_data.webconsolelog
        if os.path.exists(log_file):
            with open(log_file, 'r') as fil:
                all_lines = fil.readlines()
            return ''.join(all_lines[-lines:])
        return "No logs available yet"
    except Exception as exc:
        return f"Error reading logs: {exc}"


def get_loot() -> dict:
    """Get list of stolen/exfiltrated files."""
    try:
        def list_files_recursive(directory):
            files = []
            if os.path.exists(directory):
                for entry in os.scandir(directory):
                    if entry.is_dir():
                        files.append({
                            "name": entry.name,
                            "type": "directory",
                            "children": list_files_recursive(entry.path)
                        })
                    else:
                        files.append({
                            "name": entry.name,
                            "type": "file",
                            "size": entry.stat().st_size
                        })
            return files

        return {"loot": list_files_recursive(shared_data.datastolendir)}
    except Exception as exc:
        return {"error": str(exc)}


# ── Wi-Fi & Network Management ───────────────────────────────────────────────

def scan_wifi() -> dict:
    """Scan for available Wi-Fi networks."""
    try:
        import subprocess
        result = subprocess.Popen(
            ['sudo', 'iwlist', 'wlan0', 'scan'],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        stdout, stderr = result.communicate()
        if result.returncode != 0:
            return {"error": stderr}

        networks = []
        for line in stdout.split('\n'):
            if 'ESSID' in line:
                ssid = line.split(':')[1].strip('"')
                if ssid and ssid not in networks:
                    networks.append(ssid)

        current = subprocess.Popen(
            ['iwgetid', '-r'], stdout=subprocess.PIPE, text=True
        )
        ssid_out, _ = current.communicate()
        current_ssid = ssid_out.strip() if current.returncode == 0 else ""

        return {"networks": networks, "current_ssid": current_ssid}
    except Exception as exc:
        return {"error": str(exc)}


def connect_wifi(ssid: str, password: str) -> dict:
    """Connect to a Wi-Fi network.

    Args:
        ssid: Wi-Fi network name
        password: Wi-Fi password
    """
    try:
        import subprocess
        import uuid as uuid_mod
        config_path = '/etc/NetworkManager/system-connections/preconfigured.nmconnection'
        with open(config_path, 'w') as fil:
            fil.write(f"""
[connection]
id=preconfigured
uuid={uuid_mod.uuid4()}
type=wifi
autoconnect=true

[wifi]
ssid={ssid}
mode=infrastructure

[wifi-security]
key-mgmt=wpa-psk
psk={password}

[ipv4]
method=auto

[ipv6]
method=auto
""")
        subprocess.Popen(['sudo', 'chmod', '600', config_path]).communicate()
        subprocess.Popen(['sudo', 'nmcli', 'connection', 'reload']).communicate()
        result = subprocess.Popen(
            'sudo nmcli connection up "preconfigured"',
            shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        stdout, stderr = result.communicate()
        if result.returncode != 0:
            return {"error": stderr}
        shared_data.wifichanged = True
        return {"status": "success", "message": f"Connected to {ssid}"}
    except Exception as exc:
        return {"error": str(exc)}


def disconnect_wifi() -> dict:
    """Disconnect from current Wi-Fi and clear saved connection."""
    try:
        import subprocess
        result = subprocess.Popen(
            'sudo nmcli connection down "preconfigured"',
            shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        stdout, stderr = result.communicate()
        if result.returncode != 0:
            return {"error": stderr}
        config_path = '/etc/NetworkManager/system-connections/preconfigured.nmconnection'
        with open(config_path, 'w') as fil:
            fil.write("")
        subprocess.Popen(['sudo', 'chmod', '600', config_path]).communicate()
        subprocess.Popen(['sudo', 'nmcli', 'connection', 'reload']).communicate()
        shared_data.wifichanged = False
        return {"status": "success", "message": "Disconnected from Wi-Fi"}
    except Exception as exc:
        return {"error": str(exc)}


# ── System Control ────────────────────────────────────────────────────────────

def reboot_system() -> dict:
    """Reboot the Raspberry Pi."""
    try:
        import subprocess
        subprocess.Popen('sudo reboot', shell=True,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return {"status": "success", "message": "System is rebooting"}
    except Exception as exc:
        return {"error": str(exc)}


def shutdown_system() -> dict:
    """Shutdown the Raspberry Pi."""
    try:
        import subprocess
        subprocess.Popen('sudo shutdown now', shell=True,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return {"status": "success", "message": "System is shutting down"}
    except Exception as exc:
        return {"error": str(exc)}


def restart_bjorn_service() -> dict:
    """Restart the bjorn systemd service."""
    try:
        import subprocess
        subprocess.Popen('sudo systemctl restart bjorn.service', shell=True,
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return {"status": "success", "message": "Bjorn service restarting"}
    except Exception as exc:
        return {"error": str(exc)}


# ── Data & Backup Management ─────────────────────────────────────────────────

def restore_default_config() -> dict:
    """Reset Bjorn configuration to default values."""
    try:
        shared_data.config = shared_data.default_config.copy()
        shared_data.save_config()
        return {"status": "success", "message": "Config restored to defaults"}
    except Exception as exc:
        return {"error": str(exc)}


def clear_data(mode: str = "light") -> dict:
    """Clear Bjorn's output data files.

    Args:
        mode: 'light' clears outputs/logs only, 'full' clears everything including config
    """
    try:
        import subprocess
        if mode == "full":
            command = (
                "sudo rm -rf config/*.json && sudo rm -rf data/*.csv && "
                "sudo rm -rf data/*.log && sudo rm -rf backup/backups/* && "
                "sudo rm -rf backup/uploads/* && sudo rm -rf data/output/data_stolen/* && "
                "sudo rm -rf data/output/crackedpwd/* && sudo rm -rf config/* && "
                "sudo rm -rf data/output/scan_results/* && sudo rm -rf data/logs/* && "
                "sudo rm -rf data/output/vulnerabilities/*"
            )
        else:
            command = (
                "sudo rm -rf data/*.log && sudo rm -rf data/output/data_stolen/* && "
                "sudo rm -rf data/output/crackedpwd/* && "
                "sudo rm -rf data/output/scan_results/* && sudo rm -rf data/logs/* && "
                "sudo rm -rf data/output/vulnerabilities/*"
            )
        result = subprocess.Popen(
            command, shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        stdout, stderr = result.communicate()
        if result.returncode != 0:
            return {"error": stderr}
        return {"status": "success", "message": f"Data cleared ({mode} mode)"}
    except Exception as exc:
        return {"error": str(exc)}


def initialize_csv() -> dict:
    """Reinitialize CSV files (netkb, livestatus, actions). Use after clear_data."""
    try:
        shared_data.generate_actions_json()
        shared_data.initialize_csv()
        shared_data.create_livestatusfile()
        return {"status": "success", "message": "CSV files initialized"}
    except Exception as exc:
        return {"error": str(exc)}


def create_backup() -> dict:
    """Create a ZIP backup of config, data, actions, and resources."""
    try:
        import zipfile
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_filename = f"backup_{timestamp}.zip"
        backup_path = os.path.join(shared_data.backupdir, backup_filename)
        with zipfile.ZipFile(backup_path, 'w') as backup_zip:
            for folder in [shared_data.configdir, shared_data.datadir,
                           shared_data.actions_dir, shared_data.resourcesdir]:
                for root, dirs, files in os.walk(folder):
                    for fil_name in files:
                        file_path = os.path.join(root, fil_name)
                        backup_zip.write(
                            file_path,
                            os.path.relpath(file_path, shared_data.currentdir)
                        )
        return {
            "status": "success",
            "filename": backup_filename,
            "path": backup_path
        }
    except Exception as exc:
        return {"error": str(exc)}


def list_backups() -> dict:
    """List available backup files."""
    try:
        backups = []
        if os.path.exists(shared_data.backupdir):
            for entry in os.scandir(shared_data.backupdir):
                if entry.name.endswith('.zip'):
                    backups.append({
                        "filename": entry.name,
                        "size": entry.stat().st_size,
                        "created": datetime.fromtimestamp(
                            entry.stat().st_ctime
                        ).strftime('%Y-%m-%d %H:%M:%S')
                    })
        return {"backups": backups}
    except Exception as exc:
        return {"error": str(exc)}


def get_scan_results() -> dict:
    """Get the latest network scan results (port scan table)."""
    try:
        scan_dir = shared_data.scan_results_dir
        result_files = [
            f for f in os.listdir(scan_dir) if f.startswith('result_')
        ]
        if not result_files:
            return {"message": "No scan results yet"}

        latest = max(
            [os.path.join(scan_dir, f) for f in result_files],
            key=os.path.getctime
        )
        with open(latest, 'r') as fil:
            reader = csv.DictReader(fil)
            rows = list(reader)
        return {
            "file": os.path.basename(latest),
            "results": rows,
            "count": len(rows)
        }
    except Exception as exc:
        return {"error": str(exc)}


# ── Tool Registry ─────────────────────────────────────────────────────────────
# Single source of truth for all tool metadata.
# Used by MCP server (auto-registration) and chat handler (Anthropic API schemas).

_TOOL_DEFS = [
    {"name": "get_status", "func": get_status,
     "description": "Get Bjorn's current operational status including alive hosts, open ports, credentials, and vulnerabilities",
     "params": {}},
    {"name": "get_network_data", "func": get_network_data,
     "description": "Get the full network knowledge base with all discovered hosts, ports, and action results",
     "params": {}},
    {"name": "get_alive_hosts", "func": get_alive_hosts,
     "description": "Get list of currently alive (reachable) hosts with their open ports",
     "params": {}},
    {"name": "get_credentials", "func": get_credentials,
     "description": "Get all cracked credentials organized by service type (SSH, SMB, FTP, Telnet, SQL, RDP)",
     "params": {}},
    {"name": "get_vulnerabilities", "func": get_vulnerabilities,
     "description": "Get discovered vulnerabilities from nmap scans",
     "params": {}},
    {"name": "get_config", "func": get_config,
     "description": "Get Bjorn's current configuration settings",
     "params": {}},
    {"name": "update_config", "func": update_config,
     "description": "Update a single Bjorn configuration value",
     "params": {
         "key": {"type": "string", "description": "Configuration key (e.g. 'scan_interval', 'manual_mode')", "required": True},
         "value": {"type": "string", "description": "New value (auto-converted to appropriate type)", "required": True},
     }},
    {"name": "start_orchestrator", "func": start_orchestrator,
     "description": "Start Bjorn's autonomous orchestrator for automated scanning and attacking",
     "params": {}},
    {"name": "stop_orchestrator", "func": stop_orchestrator,
     "description": "Stop Bjorn's autonomous orchestrator",
     "params": {}},
    {"name": "execute_action", "func": execute_action,
     "description": "Execute a specific security action on a target host",
     "params": {
         "ip": {"type": "string", "description": "Target IP address", "required": True},
         "port": {"type": "string", "description": "Target port number", "required": True},
         "action": {"type": "string", "description": "Action class name (e.g. 'SSHBruteforce', 'NmapVulnScanner')", "required": True},
     }},
    {"name": "get_logs", "func": get_logs,
     "description": "Get recent Bjorn logs",
     "params": {
         "lines": {"type": "integer", "description": "Number of log lines to return (default 50)", "required": False},
     }},
    {"name": "get_loot", "func": get_loot,
     "description": "List stolen/exfiltrated files from targets",
     "params": {}},
    {"name": "scan_wifi", "func": scan_wifi,
     "description": "Scan for available Wi-Fi networks",
     "params": {}},
    {"name": "connect_wifi", "func": connect_wifi,
     "description": "Connect to a Wi-Fi network",
     "params": {
         "ssid": {"type": "string", "description": "Wi-Fi network name", "required": True},
         "password": {"type": "string", "description": "Wi-Fi password", "required": True},
     }},
    {"name": "disconnect_wifi", "func": disconnect_wifi,
     "description": "Disconnect from current Wi-Fi and clear saved connection",
     "params": {}},
    {"name": "reboot_system", "func": reboot_system,
     "description": "Reboot the Raspberry Pi",
     "params": {}},
    {"name": "shutdown_system", "func": shutdown_system,
     "description": "Shutdown the Raspberry Pi",
     "params": {}},
    {"name": "restart_bjorn_service", "func": restart_bjorn_service,
     "description": "Restart the bjorn systemd service",
     "params": {}},
    {"name": "restore_default_config", "func": restore_default_config,
     "description": "Reset Bjorn configuration to default values",
     "params": {}},
    {"name": "clear_data", "func": clear_data,
     "description": "Clear Bjorn's output data files",
     "params": {
         "mode": {"type": "string", "description": "'light' clears outputs/logs, 'full' clears everything including config (default: light)", "required": False},
     }},
    {"name": "initialize_csv", "func": initialize_csv,
     "description": "Reinitialize CSV files (netkb, livestatus, actions). Use after clear_data",
     "params": {}},
    {"name": "create_backup", "func": create_backup,
     "description": "Create a ZIP backup of config, data, actions, and resources",
     "params": {}},
    {"name": "list_backups", "func": list_backups,
     "description": "List available backup files",
     "params": {}},
    {"name": "get_scan_results", "func": get_scan_results,
     "description": "Get the latest network scan results (port scan table)",
     "params": {}},
]

# Exported: name→function map and Anthropic API-compatible tool schemas
TOOL_FUNCTIONS = {t["name"]: t["func"] for t in _TOOL_DEFS}

TOOL_SCHEMAS = [
    {
        "name": t["name"],
        "description": t["description"],
        "input_schema": {
            "type": "object",
            "properties": {
                n: {"type": p["type"], "description": p["description"]}
                for n, p in t["params"].items()
            },
            "required": [n for n, p in t["params"].items() if p.get("required")],
        },
    }
    for t in _TOOL_DEFS
]


# ── MCP Server Registration ──────────────────────────────────────────────────

if MCP_AVAILABLE:
    mcp = FastMCP("bjorn")

    for _td in _TOOL_DEFS:
        mcp.tool()(_td["func"])

    @mcp.resource("bjorn://status")
    def resource_status() -> str:
        """Current Bjorn operational status."""
        return json.dumps(get_status(), indent=2)

    @mcp.resource("bjorn://netkb")
    def resource_netkb() -> str:
        """Network Knowledge Base - all discovered hosts and action results."""
        return json.dumps(get_network_data(), indent=2)

    @mcp.resource("bjorn://config")
    def resource_config() -> str:
        """Current Bjorn configuration."""
        return json.dumps(get_config(), indent=2)


# ── Embedded SSE Server Thread ───────────────────────────────────────────────

class MCPThread(threading.Thread):
    """Runs the MCP server with SSE transport as a daemon thread inside Bjorn.
    Clients connect via http://<host>:<port>/sse
    """

    def __init__(self, port=8081):
        super().__init__(daemon=True)
        self.port = port
        self._uvicorn_server = None

    def run(self):
        if not MCP_AVAILABLE:
            logger.warning("MCP thread skipped: mcp package not installed")
            return

        try:
            self._run_sse()
        except ImportError as exc:
            logger.warning(f"MCP SSE dependencies missing ({exc}). "
                           "Install: pip install 'mcp[cli]' uvicorn starlette")
        except Exception as exc:
            logger.error(f"MCP server error: {exc}")

    def _run_sse(self):
        import asyncio
        import uvicorn
        from starlette.applications import Starlette
        from starlette.routing import Mount, Route
        from mcp.server.sse import SseServerTransport

        sse = SseServerTransport("/messages/")
        mcp_server = mcp._mcp_server

        async def handle_sse(request):
            async with sse.connect_sse(
                request.scope, request.receive, request._send
            ) as (read_stream, write_stream):
                await mcp_server.run(
                    read_stream, write_stream,
                    mcp_server.create_initialization_options()
                )

        app = Starlette(routes=[
            Route("/sse", endpoint=handle_sse),
            Mount("/messages/", app=sse.handle_post_message),
        ])

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        config = uvicorn.Config(
            app, host="0.0.0.0", port=self.port, log_level="warning"
        )
        self._uvicorn_server = uvicorn.Server(config)
        logger.info(f"MCP SSE server listening on 0.0.0.0:{self.port}")
        loop.run_until_complete(self._uvicorn_server.serve())

    def shutdown(self):
        if self._uvicorn_server:
            self._uvicorn_server.should_exit = True
            logger.info("MCP server shutdown initiated")


if __name__ == "__main__":
    if not MCP_AVAILABLE:
        print("Error: mcp package not installed. Run: pip install 'mcp[cli]'")
        sys.exit(1)
    logger.info("Starting Bjorn MCP Server (standalone/stdio)...")
    mcp.run()
