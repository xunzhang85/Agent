"""Tests for the Tool Registry."""

import pytest
from agent.tools.registry import ToolRegistry


class TestToolRegistry:
    """Test suite for tool registry."""

    def setup_method(self):
        self.registry = ToolRegistry(auto_discover=False)

    def test_builtin_tools_registered(self):
        """Built-in tools should be registered."""
        assert self.registry.get_tool("nmap") is not None
        assert self.registry.get_tool("curl") is not None
        assert self.registry.get_tool("gdb") is not None

    def test_list_tools(self):
        """Listing tools should return all registered tools."""
        tools = self.registry.list_tools()
        assert len(tools) > 10
        assert any(t["name"] == "nmap" for t in tools)

    def test_register_custom_tool(self):
        """Custom tools should be registrable."""
        self.registry.register_custom(
            "my_scanner",
            lambda x: x,
            description="Custom scanner",
        )
        tool = self.registry.get_tool("my_scanner")
        assert tool is not None
        assert tool.installed is True

    def test_tool_categories(self):
        """Tools should have correct categories."""
        nmap = self.registry.get_tool("nmap")
        assert nmap.category == "network"

        sqlmap = self.registry.get_tool("sqlmap")
        assert sqlmap.category == "web"

    def test_discover(self):
        """Discover should check tool availability."""
        results = self.registry.discover()
        assert isinstance(results, dict)
        # python3 should always be available
        assert results.get("python3") is True

    def test_get_available(self):
        """Getting available tools should filter correctly."""
        self.registry.discover()
        available = self.registry.get_available()
        assert all(t.installed for t in available)
