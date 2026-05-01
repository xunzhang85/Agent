"""Tests for the ResultCache."""

import pytest
import tempfile
import shutil
from agent.core.agent import ResultCache, SolveResult


class TestResultCache:
    """Test suite for result caching."""

    def setup_method(self):
        self.cache_dir = tempfile.mkdtemp()
        self.cache = ResultCache(cache_dir=self.cache_dir)

    def teardown_method(self):
        shutil.rmtree(self.cache_dir, ignore_errors=True)

    def test_cache_miss(self):
        """Cache miss should return None."""
        result = self.cache.get("http://target.com", None, None)
        assert result is None

    def test_cache_hit(self):
        """Cache hit should return cached result."""
        original = SolveResult(success=True, flag="flag{test}", category="web")
        self.cache.put("http://target.com", None, None, original)

        cached = self.cache.get("http://target.com", None, None)
        assert cached is not None
        assert cached.flag == "flag{test}"
        assert cached.cached is True

    def test_cache_different_keys(self):
        """Different challenges should have different cache entries."""
        r1 = SolveResult(success=True, flag="flag{one}")
        r2 = SolveResult(success=True, flag="flag{two}")

        self.cache.put("http://a.com", None, None, r1)
        self.cache.put("http://b.com", None, None, r2)

        assert self.cache.get("http://a.com", None, None).flag == "flag{one}"
        assert self.cache.get("http://b.com", None, None).flag == "flag{two}"

    def test_cache_persistence(self):
        """Cache should persist to disk."""
        original = SolveResult(success=True, flag="flag{persist}")
        self.cache.put("http://target.com", None, None, original)

        # Create new cache from same directory
        new_cache = ResultCache(cache_dir=self.cache_dir)
        cached = new_cache.get("http://target.com", None, None)
        assert cached is not None
        assert cached.flag == "flag{persist}"


class TestSolveResult:
    """Test suite for SolveResult."""

    def test_to_dict(self):
        """to_dict should serialize all fields."""
        result = SolveResult(
            success=True, flag="flag{test}", category="web",
            iterations=5, elapsed_time=10.5,
        )
        d = result.to_dict()
        assert d["success"] is True
        assert d["flag"] == "flag{test}"
        assert d["iterations"] == 5

    def test_str_success(self):
        """String representation for success."""
        result = SolveResult(success=True, flag="flag{test}", iterations=3, elapsed_time=5.0)
        assert "✅" in str(result)
        assert "flag{test}" in str(result)

    def test_str_failure(self):
        """String representation for failure."""
        result = SolveResult(success=False, error="timeout", iterations=10, elapsed_time=60.0)
        assert "❌" in str(result)
        assert "timeout" in str(result)
