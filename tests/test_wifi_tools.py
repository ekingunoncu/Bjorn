"""
Combined WiFi tools test entry point.

Run the full test suites with:  pytest tests/
  - tests/test_wifi_manager.py  (WiFiManager class)
  - tests/test_mcp_wifi_tools.py (MCP wrappers + tool log)
"""


def test_mcp_wifi_tools_module_importable():
    """Smoke test: test_mcp_wifi_tools can be imported."""
    from tests import test_mcp_wifi_tools
    assert hasattr(
        test_mcp_wifi_tools, "TestWifiAvailableFlag"
    )
    assert hasattr(
        test_mcp_wifi_tools, "TestToolCallLogging"
    )
    assert hasattr(
        test_mcp_wifi_tools, "TestToolRegistry"
    )
