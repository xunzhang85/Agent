"""
Memory - Context Management Module

Maintains conversation context and execution history for the agent.
Implements a sliding window approach to manage token limits.
"""

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class MemoryEntry:
    """A single memory entry."""

    timestamp: str
    category: str
    content: str
    importance: int = 1  # 1-5 scale


class Memory:
    """
    Context memory for the CTF Agent.

    Stores execution history, reconnaissance results, and learned hints.
    Provides context windows for the Planner and tracks the solving journey.
    """

    def __init__(self, max_entries: int = 100, context_window: int = 20):
        self.entries: list[MemoryEntry] = []
        self.max_entries = max_entries
        self.context_window = context_window
        self._flag_history: list[str] = []

    def add(self, category: str, content: str, importance: int = 1) -> None:
        """
        Add a new memory entry.

        Args:
            category: Type of memory (recon, exec, hint, error, etc.)
            content: The content to remember
            importance: Importance level (1-5)
        """
        entry = MemoryEntry(
            timestamp=datetime.now().isoformat(),
            category=category,
            content=content[:2000],  # Truncate very long content
            importance=min(max(importance, 1), 5),
        )
        self.entries.append(entry)

        # Evict old entries if over limit
        if len(self.entries) > self.max_entries:
            # Keep high-importance entries, remove low-importance ones
            self.entries.sort(key=lambda e: (e.importance, e.timestamp), reverse=True)
            self.entries = self.entries[: self.max_entries]

        logger.debug(f"Memory added [{category}]: {content[:100]}")

    def get_context(self, max_tokens: int = 4000) -> str:
        """
        Get formatted context for the Planner.

        Returns recent memory entries as a formatted string,
        prioritizing high-importance entries.

        Args:
            max_tokens: Approximate max tokens for context

        Returns:
            Formatted context string
        """
        # Get recent entries, sorted by importance then recency
        recent = sorted(
            self.entries[-self.context_window:],
            key=lambda e: (e.importance, e.timestamp),
            reverse=True,
        )

        context_parts = []
        char_count = 0
        max_chars = max_tokens * 4  # Rough token-to-char estimate

        for entry in recent:
            line = f"[{entry.category}] {entry.content}"
            if char_count + len(line) > max_chars:
                break
            context_parts.append(line)
            char_count += len(line)

        return "\n".join(reversed(context_parts))  # Chronological order

    def get_summary(self) -> dict:
        """Get a summary of memory state."""
        categories = {}
        for entry in self.entries:
            categories[entry.category] = categories.get(entry.category, 0) + 1

        return {
            "total_entries": len(self.entries),
            "categories": categories,
            "flags_found": len(self._flag_history),
        }

    def add_flag(self, flag: str) -> None:
        """Record a found flag."""
        self._flag_history.append(flag)
        self.add("flag", f"Found flag: {flag}", importance=5)

    def clear(self) -> None:
        """Clear all memory entries."""
        self.entries.clear()
        logger.info("Memory cleared")

    def export_json(self) -> str:
        """Export memory as JSON."""
        return json.dumps(
            {
                "entries": [
                    {
                        "timestamp": e.timestamp,
                        "category": e.category,
                        "content": e.content,
                        "importance": e.importance,
                    }
                    for e in self.entries
                ],
                "flags": self._flag_history,
            },
            indent=2,
        )
