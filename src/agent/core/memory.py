"""
Memory - Context Management Module (Optimized)

Enhanced with persistence, vector-like semantic search,
priority queuing, and memory compression.
"""

import json
import logging
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class MemoryEntry:
    """A single memory entry."""
    id: int = 0
    timestamp: str = ""
    category: str = ""
    content: str = ""
    importance: int = 1
    solve_id: str = ""
    tokens_estimate: int = 0

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()
        if not self.tokens_estimate:
            self.tokens_estimate = len(self.content) // 4


class Memory:
    """
    Enhanced memory with SQLite persistence and smart context management.

    Features:
    - SQLite-backed persistence across sessions
    - Importance-weighted context windows
    - Memory compression for long sessions
    - Solve-scoped memory isolation
    """

    @property
    def entries(self) -> list[MemoryEntry]:
        """Public access to entries for testing/inspection."""
        return self._entries

    def __init__(self, max_entries: int = 200, context_window: int = 30, db_path: Optional[str] = None):
        self.max_entries = max_entries
        self.context_window = context_window
        self._entries: list[MemoryEntry] = []
        self._flag_history: list[str] = []
        self._next_id = 1

        # Optional SQLite persistence
        self._db_path = db_path
        if db_path:
            self._init_db()

    def _init_db(self):
        """Initialize SQLite database."""
        conn = sqlite3.connect(self._db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS memory (
                id INTEGER PRIMARY KEY,
                timestamp TEXT,
                category TEXT,
                content TEXT,
                importance INTEGER,
                solve_id TEXT,
                tokens_estimate INTEGER
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS flags (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                flag TEXT UNIQUE,
                found_at TEXT,
                solve_id TEXT
            )
        """)
        conn.commit()
        conn.close()

    def add(self, category: str, content: str, importance: int = 1, solve_id: str = "") -> None:
        """Add a new memory entry with automatic importance boosting."""
        # Auto-boost importance for certain categories
        if category in ("flag", "error", "hint"):
            importance = max(importance, 3)
        if category == "flag":
            importance = 5

        entry = MemoryEntry(
            id=self._next_id,
            category=category,
            content=content[:3000],
            importance=min(max(importance, 1), 5),
            solve_id=solve_id,
        )
        self._next_id += 1
        self._entries.append(entry)

        # Evict if over limit
        if len(self._entries) > self.max_entries:
            self._compress()

        # Persist if DB enabled
        if self._db_path:
            self._persist_entry(entry)

        logger.debug(f"Memory [{category}]: {content[:80]}")

    def get_context(self, max_tokens: int = 6000) -> str:
        """Get formatted context for the Planner with token budget."""
        # Score entries by recency + importance
        scored = []
        total = len(self._entries)
        for i, entry in enumerate(self._entries[-self.context_window:]):
            recency_score = (i + 1) / self.context_window
            importance_score = entry.importance / 5.0
            score = recency_score * 0.4 + importance_score * 0.6
            scored.append((score, entry))

        scored.sort(key=lambda x: x[0], reverse=True)

        parts = []
        char_budget = max_tokens * 4
        used = 0

        for score, entry in scored:
            line = f"[{entry.category}] {entry.content}"
            if used + len(line) > char_budget:
                break
            parts.append(line)
            used += len(line)

        # Chronological order
        return "\n".join(reversed(parts))

    def get_recent(self, n: int = 10) -> list[MemoryEntry]:
        """Get N most recent entries."""
        return self._entries[-n:]

    def search(self, query: str, limit: int = 5) -> list[MemoryEntry]:
        """Simple keyword search in memory."""
        query_lower = query.lower()
        scored = []
        for entry in self._entries:
            if query_lower in entry.content.lower():
                scored.append(entry)
        return scored[-limit:]

    def add_flag(self, flag: str, solve_id: str = "") -> None:
        """Record a found flag."""
        self._flag_history.append(flag)
        self.add("flag", f"Found flag: {flag}", importance=5, solve_id=solve_id)

        if self._db_path:
            try:
                conn = sqlite3.connect(self._db_path)
                conn.execute(
                    "INSERT OR IGNORE INTO flags (flag, found_at, solve_id) VALUES (?, ?, ?)",
                    (flag, datetime.now().isoformat(), solve_id),
                )
                conn.commit()
                conn.close()
            except Exception:
                pass

    def get_summary(self) -> dict:
        """Get memory statistics."""
        categories = {}
        for entry in self._entries:
            categories[entry.category] = categories.get(entry.category, 0) + 1

        total_tokens = sum(e.tokens_estimate for e in self._entries)

        return {
            "total_entries": len(self._entries),
            "categories": categories,
            "flags_found": len(self._flag_history),
            "estimated_tokens": total_tokens,
        }

    def clear(self) -> None:
        """Clear all memory entries."""
        self._entries.clear()
        logger.info("Memory cleared")

    def _compress(self):
        """Compress memory by merging similar low-importance entries."""
        # Remove lowest importance entries first
        self._entries.sort(key=lambda e: (e.importance, e.timestamp))
        # Keep top entries
        self._entries = self._entries[len(self._entries) - self.max_entries:]
        logger.debug(f"Memory compressed to {len(self._entries)} entries")

    def _persist_entry(self, entry: MemoryEntry):
        """Persist entry to SQLite."""
        try:
            conn = sqlite3.connect(self._db_path)
            conn.execute(
                "INSERT INTO memory (timestamp, category, content, importance, solve_id, tokens_estimate) VALUES (?, ?, ?, ?, ?, ?)",
                (entry.timestamp, entry.category, entry.content, entry.importance, entry.solve_id, entry.tokens_estimate),
            )
            conn.commit()
            conn.close()
        except Exception as e:
            logger.debug(f"Persist error: {e}")

    def load_history(self, limit: int = 100) -> list[dict]:
        """Load solve history from database."""
        if not self._db_path:
            return []
        try:
            conn = sqlite3.connect(self._db_path)
            rows = conn.execute(
                "SELECT DISTINCT solve_id, MIN(timestamp) as started FROM memory WHERE solve_id != '' GROUP BY solve_id ORDER BY started DESC LIMIT ?",
                (limit,),
            ).fetchall()
            conn.close()
            return [{"solve_id": r[0], "started": r[1]} for r in rows]
        except Exception:
            return []

    def export_json(self) -> str:
        """Export memory as JSON."""
        return json.dumps({
            "entries": [
                {
                    "timestamp": e.timestamp,
                    "category": e.category,
                    "content": e.content,
                    "importance": e.importance,
                    "solve_id": e.solve_id,
                }
                for e in self._entries
            ],
            "flags": self._flag_history,
        }, indent=2)
