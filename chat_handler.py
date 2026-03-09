#chat_handler.py
#
# Chat handler for Bjorn's AI assistant.
# Uses the Anthropic API with tool use to provide an intelligent chat interface
# that can query Bjorn's state and execute actions.
#
# Tool logic is imported from mcp_server.py (single source of truth).

import json
import os
import logging
from logger import Logger
from init_shared import shared_data
from mcp_server import TOOL_FUNCTIONS, TOOL_SCHEMAS

logger = Logger(name="chat_handler.py", level=logging.DEBUG)


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
    """Execute a tool call by dispatching to the shared tool functions from mcp_server."""
    func = TOOL_FUNCTIONS.get(tool_name)
    if not func:
        return json.dumps({"error": f"Unknown tool: {tool_name}"})
    try:
        result = func(**tool_input) if tool_input else func()
        return json.dumps(result, indent=2) if not isinstance(result, str) else result
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
            tools=TOOL_SCHEMAS,
            messages=self.conversation_history
        )

    def clear_history(self):
        """Clear conversation history."""
        self.conversation_history = []
        return {"status": "success", "message": "Conversation cleared"}


# Module-level singleton so state persists across HTTP requests
chat_handler = ChatHandler()
