#chat_handler.py
#
# Chat handler for Bjorn's AI assistant.
# Uses the Anthropic API with tool use to provide an intelligent chat interface
# that can query Bjorn's state and execute actions.

import json
import os
import csv
import logging
import importlib
from datetime import datetime
from logger import Logger
from init_shared import shared_data

logger = Logger(name="chat_handler.py", level=logging.DEBUG)

# Tools the AI assistant can call
BJORN_TOOLS = [
    {
        "name": "get_network_status",
        "description": "Get current network scan results including alive hosts, open ports, and action statuses",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "get_credentials",
        "description": "Get all cracked credentials (SSH, SMB, FTP, Telnet, SQL, RDP)",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "get_vulnerabilities",
        "description": "Get discovered vulnerabilities from nmap scans",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "execute_action",
        "description": "Execute a security action on a target. Actions: SSHBruteforce, FTPBruteforce, SMBBruteforce, RDPBruteforce, TelnetBruteforce, SQLBruteforce, StealFilesSSH, StealFilesFTP, StealFilesSMB, StealFilesRDP, StealFilesTelnet, StealDataSQL, NmapVulnScanner",
        "input_schema": {
            "type": "object",
            "properties": {
                "ip": {"type": "string", "description": "Target IP address"},
                "port": {"type": "string", "description": "Target port number"},
                "action": {"type": "string", "description": "Action class name to execute"}
            },
            "required": ["ip", "port", "action"]
        }
    },
    {
        "name": "start_orchestrator",
        "description": "Start Bjorn's autonomous orchestrator for automated scanning and attacking",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "stop_orchestrator",
        "description": "Stop Bjorn's autonomous orchestrator",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "get_config",
        "description": "Get Bjorn's current configuration settings",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    },
    {
        "name": "update_config",
        "description": "Update a Bjorn configuration setting",
        "input_schema": {
            "type": "object",
            "properties": {
                "key": {"type": "string", "description": "Config key (e.g. 'scan_interval', 'manual_mode')"},
                "value": {"type": "string", "description": "New value"}
            },
            "required": ["key", "value"]
        }
    },
    {
        "name": "get_loot",
        "description": "List stolen/exfiltrated files from targets",
        "input_schema": {
            "type": "object",
            "properties": {},
            "required": []
        }
    }
]


def _build_system_prompt():
    """Build system prompt with current Bjorn state."""
    try:
        data = shared_data.read_data()
        alive = [r for r in data if r.get('Alive') == '1']
        alive_summary = ", ".join(
            [f"{r['IPs']} (ports: {r.get('Ports', 'none')})" for r in alive[:10]]
        )
    except Exception:
        alive_summary = "No scan data available"

    return f"""You are Bjorn's AI assistant, a Viking-themed cybersecurity companion embedded in the Bjorn autonomous security testing tool running on a Raspberry Pi with an e-Paper display.

You help the operator understand network reconnaissance results, recommend attack strategies, execute actions, and manage Bjorn's configuration.

Current Status:
- Orchestrator: {shared_data.bjornorch_status}
- Alive hosts: {shared_data.targetnbr}
- Open ports: {shared_data.portnbr}
- Credentials cracked: {shared_data.crednbr}
- Vulnerabilities found: {shared_data.vulnnbr}
- Data stolen: {shared_data.datanbr}
- Active hosts: {alive_summary}

You have tools to query network data, execute actions, manage configuration, and control the orchestrator. Use them when the operator asks about the network state or wants to perform actions.

Keep responses concise and actionable. This runs on a Raspberry Pi so be efficient with resources."""


def _execute_tool(tool_name, tool_input):
    """Execute a tool call and return the result as a JSON string."""
    try:
        if tool_name == "get_network_status":
            data = shared_data.read_data()
            alive = [r for r in data if r.get('Alive') == '1']
            result = {
                "alive_hosts": [{
                    "ip": r.get('IPs'),
                    "mac": r.get('MAC Address'),
                    "hostname": r.get('Hostnames'),
                    "ports": r.get('Ports', ''),
                } for r in alive],
                "total_hosts": len(data),
                "alive_count": len(alive),
            }
            if alive:
                try:
                    with open(shared_data.actions_file, 'r') as fil:
                        actions = json.load(fil)
                    action_names = [a['b_class'] for a in actions]
                    for host in result['alive_hosts']:
                        row = next((r for r in data if r['IPs'] == host['ip']), {})
                        host['actions'] = {
                            a: row.get(a, '') for a in action_names if row.get(a, '')
                        }
                except Exception:
                    pass
            return json.dumps(result, indent=2)

        elif tool_name == "get_credentials":
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
            return json.dumps(
                credentials if credentials else {"message": "No credentials cracked yet"}
            )

        elif tool_name == "get_vulnerabilities":
            vuln_file = shared_data.vuln_summary_file
            if os.path.exists(vuln_file):
                with open(vuln_file, 'r') as fil:
                    reader = csv.DictReader(fil)
                    vulns = list(reader)
                return json.dumps({"vulnerabilities": vulns, "count": len(vulns)})
            return json.dumps({"message": "No vulnerabilities discovered yet"})

        elif tool_name == "execute_action":
            target_ip = tool_input['ip']
            target_port = tool_input['port']
            action_name = tool_input['action']

            with open(shared_data.actions_file, 'r') as fil:
                actions_config = json.load(fil)

            action_config = next(
                (a for a in actions_config if a['b_class'] == action_name), None
            )
            if not action_config:
                return json.dumps({"error": f"Action '{action_name}' not found"})

            module = importlib.import_module(f"actions.{action_config['b_module']}")
            action_instance = getattr(module, action_name)(shared_data)

            current_data = shared_data.read_data()
            row = next((r for r in current_data if r['IPs'] == target_ip), None)
            if not row:
                return json.dumps({"error": f"No data found for IP: {target_ip}"})

            result = action_instance.execute(target_ip, target_port, row, action_name)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            row[action_name] = f"{result}_{timestamp}"
            shared_data.write_data(current_data)

            return json.dumps({
                "status": result,
                "action": action_name,
                "target": f"{target_ip}:{target_port}"
            })

        elif tool_name == "start_orchestrator":
            if shared_data.bjorn_instance:
                shared_data.bjorn_instance.start_orchestrator()
                return json.dumps({"status": "success", "message": "Orchestrator starting"})
            return json.dumps({"error": "Bjorn instance not initialized"})

        elif tool_name == "stop_orchestrator":
            if shared_data.bjorn_instance:
                shared_data.bjorn_instance.stop_orchestrator()
                shared_data.orchestrator_should_exit = True
                return json.dumps({"status": "success", "message": "Orchestrator stopping"})
            return json.dumps({"error": "Bjorn instance not initialized"})

        elif tool_name == "get_config":
            with open(shared_data.shared_config_json, 'r') as fil:
                return json.dumps(json.load(fil), indent=2)

        elif tool_name == "update_config":
            cfg_key = tool_input['key']
            cfg_value = tool_input['value']

            with open(shared_data.shared_config_json, 'r') as fil:
                config = json.load(fil)

            if cfg_key not in config:
                return json.dumps({"error": f"Unknown config key: {cfg_key}"})

            current = config[cfg_key]
            if isinstance(current, bool):
                config[cfg_key] = cfg_value.lower() in ('true', '1', 'yes')
            elif isinstance(current, int):
                config[cfg_key] = int(cfg_value)
            elif isinstance(current, float):
                config[cfg_key] = float(cfg_value)
            else:
                config[cfg_key] = cfg_value

            with open(shared_data.shared_config_json, 'w') as fil:
                json.dump(config, fil, indent=4)
            shared_data.load_config()

            return json.dumps({"status": "success", "key": cfg_key, "value": config[cfg_key]})

        elif tool_name == "get_loot":
            def list_recursive(directory):
                files = []
                if os.path.exists(directory):
                    for entry in os.scandir(directory):
                        if entry.is_dir():
                            files.append({
                                "name": entry.name,
                                "type": "dir",
                                "children": list_recursive(entry.path)
                            })
                        else:
                            files.append({
                                "name": entry.name,
                                "type": "file",
                                "size": entry.stat().st_size
                            })
                return files
            return json.dumps({"loot": list_recursive(shared_data.datastolendir)})

        else:
            return json.dumps({"error": f"Unknown tool: {tool_name}"})

    except Exception as exc:
        logger.error(f"Error executing tool {tool_name}: {exc}")
        return json.dumps({"error": str(exc)})


class ChatHandler:
    """Handles chat interactions with the Anthropic API."""

    def __init__(self):
        self.conversation_history = []
        self.client = None
        self._init_client()

    def _init_client(self):
        """Initialize the Anthropic client if an API key is available."""
        try:
            import anthropic
            api_key = (
                getattr(shared_data, 'anthropic_api_key', '')
                or os.environ.get('ANTHROPIC_API_KEY', '')
            )
            if api_key:
                self.client = anthropic.Anthropic(api_key=api_key)
                logger.info("Anthropic client initialized")
            else:
                logger.warning("No Anthropic API key configured")
        except ImportError:
            logger.error("anthropic package not installed. Run: pip install anthropic")
        except Exception as exc:
            logger.error(f"Error initializing Anthropic client: {exc}")

    def process_message(self, user_message):
        """Process a user message and return the AI response."""
        if not self.client:
            self._init_client()
            if not self.client:
                return {
                    "error": "Anthropic API key not configured. "
                    "Set 'anthropic_api_key' in Bjorn config or "
                    "ANTHROPIC_API_KEY environment variable."
                }

        self.conversation_history.append({
            "role": "user",
            "content": user_message
        })

        try:
            response = self._call_api()

            # Handle tool use loop
            while response.stop_reason == "tool_use":
                tool_results = []
                assistant_content = []

                for block in response.content:
                    if block.type == "text":
                        assistant_content.append({
                            "type": "text",
                            "text": block.text
                        })
                    elif block.type == "tool_use":
                        assistant_content.append({
                            "type": "tool_use",
                            "id": block.id,
                            "name": block.name,
                            "input": block.input
                        })
                        logger.info(f"Chat AI calling tool: {block.name}")
                        result = _execute_tool(block.name, block.input)
                        tool_results.append({
                            "type": "tool_result",
                            "tool_use_id": block.id,
                            "content": result
                        })

                self.conversation_history.append({
                    "role": "assistant",
                    "content": assistant_content
                })
                self.conversation_history.append({
                    "role": "user",
                    "content": tool_results
                })

                response = self._call_api()

            # Extract final text response
            assistant_text = ""
            final_content = []
            for block in response.content:
                if hasattr(block, 'text'):
                    assistant_text += block.text
                    final_content.append({
                        "type": "text",
                        "text": block.text
                    })

            self.conversation_history.append({
                "role": "assistant",
                "content": final_content
            })

            # Keep conversation history manageable
            if len(self.conversation_history) > 20:
                self.conversation_history = self.conversation_history[-16:]

            return {"response": assistant_text}

        except Exception as exc:
            logger.error(f"Error in chat: {exc}")
            if self.conversation_history and self.conversation_history[-1]["role"] == "user":
                self.conversation_history.pop()
            return {"error": str(exc)}

    def _call_api(self):
        """Make an API call to Anthropic."""
        return self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=1024,
            system=_build_system_prompt(),
            tools=BJORN_TOOLS,
            messages=self.conversation_history
        )

    def clear_history(self):
        """Clear conversation history."""
        self.conversation_history = []
        return {"status": "success", "message": "Conversation cleared"}


# Module-level singleton so state persists across HTTP requests
chat_handler = ChatHandler()
