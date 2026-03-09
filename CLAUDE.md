# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Bjorn is an autonomous network scanning and security testing tool designed for Raspberry Pi (Zero W/W2) with a 2.13-inch Waveshare e-Paper HAT display. It's a "Tamagotchi-like" offensive security framework that performs network reconnaissance, vulnerability assessment, brute-force attacks, and data exfiltration. Python 3.12+, MIT licensed.

## Commands

```bash
# Run
sudo python Bjorn.py

# Service management (on Raspberry Pi)
sudo systemctl start|stop|restart|status bjorn.service

# Install
sudo bash install_bjorn.sh

# Lint
pylint <file.py>          # Uses .pylintrc, fail-under=8
```

## Architecture

### Core Flow
`Bjorn.py` (entry point) → spawns threads for display, orchestrator, and web server. The **Orchestrator** (`orchestrator.py`) is the brain: it dynamically loads action modules from `actions/`, scans the network for live hosts, then executes attacks/scans against discovered targets using a semaphore-limited thread pool (max 10 concurrent).

### Key Modules
- **`shared.py` / `init_shared.py`**: Singleton shared data layer. All modules import `from init_shared import shared_data`. Manages config, file paths, CSV operations, display driver init.
- **`orchestrator.py`**: Loads actions from `config/actions.json`, manages execution lifecycle with parent-child relationships and retry logic.
- **`display.py` / `epd_helper.py`**: E-Paper HAT rendering. Supports EPD V2 and V4. Runs three background threads (main image, system status, vulnerability count).
- **`webapp.py`**: HTTP server on port 8000 with gzip compression. Serves dashboard pages from `web/`.
- **`logger.py`**: Custom Logger with Rich formatting, rotating file handlers (5MB, 2 backups), custom SUCCESS level (25). Logs to `data/logs/`.
- **`comment.py`**: Generates themed contextual comments displayed on the e-Paper screen.

### Threading Model
Main thread (lifecycle/Wi-Fi checks), display thread (EPD partial updates), shared data thread (system status every 25s), vulnerability count thread (every 300s), orchestrator thread (action execution), web server thread.

### Action Plugin System
Actions in `actions/` are auto-discovered. Each module must define:
```python
b_class = "ClassName"       # Class name
b_module = "module_name"    # Filename without .py
b_status = "status_key"     # Display status key
b_port = 22                 # Target port (or None)
b_parent = None             # Parent action name (or None)

class ClassName:
    def __init__(self, shared_data): ...
    def execute(self, ip, port, row, status_key): ...
```

Action categories: network scanning (`scanning.py`), vulnerability scanning (`nmap_vuln_scanner.py`), brute-force connectors (`ssh_connector.py`, `ftp_connector.py`, etc.), file stealing (`steal_files_ssh.py`, etc.).

### MCP Server & Tool Log
- **`mcp_server.py`**: MCP server exposing Bjorn tools (get_status, get_network_data, execute_action, wifi_analyze, etc.) and resources (bjorn://status, bjorn://netkb, bjorn://config). Runs embedded as SSE thread on port 8081 (configurable via `mcp_port`). Connect from Claude Desktop: `{"url": "http://<pi-ip>:8081/sse"}`. Also runnable standalone (`python mcp_server.py`, stdio). Includes 13 WiFi security tools via `wifi_manager.py`.
- **`wifi_manager.py`**: WiFi security testing module (analyze, deauth, handshake capture, WPA/WPS/WEP cracking, evil twin, KARMA). Uses wlan1 (external USB adapter) only; never touches wlan0.
- **MCP Tool Log UI**: `web/chat.html` shows recent MCP tool calls (tool name, args, result). Auto-refreshes every 5s. Accessible from toolbar.

### Data Storage
- **`config/shared_config.json`**: All runtime settings (scan intervals, port lists, blacklists, feature flags)
- **`data/netkb.csv`**: Network Knowledge Base (hosts, ports, vulnerabilities, action history)
- **`data/livestatus.csv`**: Real-time stats
- **`data/output/`**: Scan results, cracked passwords, stolen data, vulnerability reports

## Code Style (from .pylintrc)
- Max line length: 100 chars
- Naming: `snake_case` for functions/methods/variables, `PascalCase` for classes, `UPPER_CASE` for constants
- Max function args: 5, max locals: 15, max module lines: 2500
- Variable names must match `[a-z_][a-z0-9_]{2,30}$`
- Pylint ignores: `venv`, `node_modules`, `scripts` directories
