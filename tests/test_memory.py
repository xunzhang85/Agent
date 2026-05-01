"""Tests for the Memory module."""

import pytest
from agent.core.memory import Memory


class TestMemory:
    """Test suite for memory management."""

    def setup_method(self):
        self.memory = Memory(max_entries=50, context_window=10)

    def test_add_entry(self):
        """Adding an entry should increase count."""
        self.memory.add("test", "test content")
        assert len(self.memory.entries) == 1

    def test_get_context(self):
        """Context should contain recent entries."""
        self.memory.add("recon", "Found port 80 open")
        self.memory.add("exec", "SQL injection successful")
        context = self.memory.get_context()
        assert "port 80" in context
        assert "SQL injection" in context

    def test_max_entries(self):
        """Memory should respect max entries limit."""
        memory = Memory(max_entries=5)
        for i in range(10):
            memory.add("test", f"entry {i}")
        assert len(memory.entries) <= 5

    def test_importance_ordering(self):
        """High importance entries should be kept over low ones."""
        memory = Memory(max_entries=3)
        memory.add("low", "low importance", importance=1)
        memory.add("high", "high importance", importance=5)
        memory.add("medium", "medium importance", importance=3)
        memory.add("overflow", "should evict low", importance=1)

        contents = [e.content for e in memory.entries]
        assert "high importance" in contents

    def test_clear(self):
        """Clear should remove all entries."""
        self.memory.add("test", "content")
        self.memory.clear()
        assert len(self.memory.entries) == 0

    def test_summary(self):
        """Summary should report correct statistics."""
        self.memory.add("recon", "recon result")
        self.memory.add("exec", "exec result")
        summary = self.memory.get_summary()
        assert summary["total_entries"] == 2
        assert "recon" in summary["categories"]
        assert "exec" in summary["categories"]

    def test_flag_history(self):
        """Flag history should track found flags."""
        self.memory.add_flag("flag{test}")
        assert len(self.memory._flag_history) == 1
        summary = self.memory.get_summary()
        assert summary["flags_found"] == 1

    def test_export_json(self):
        """Export should produce valid JSON."""
        self.memory.add("test", "content")
        json_str = self.memory.export_json()
        import json
        data = json.loads(json_str)
        assert "entries" in data
        assert len(data["entries"]) == 1
