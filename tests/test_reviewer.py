"""Tests for the Reviewer module."""

import pytest
from agent.core.reviewer import Reviewer


class TestReviewer:
    """Test suite for flag detection and review."""

    def setup_method(self):
        self.reviewer = Reviewer()

    def test_detect_flag_format(self):
        """Standard flag{...} format should be detected."""
        result = self.reviewer.review(output="The flag is flag{th1s_1s_th3_fl4g}")
        assert result.flag_found is True
        assert result.flag == "flag{th1s_1s_th3_fl4g}"

    def test_detect_uppercase_flag(self):
        """Uppercase FLAG{...} format should be detected."""
        result = self.reviewer.review(output="Found: FLAG{UPPER_CASE_FLAG}")
        assert result.flag_found is True
        assert result.flag == "FLAG{UPPER_CASE_FLAG}"

    def test_detect_ctf_flag(self):
        """CTF{...} format should be detected."""
        result = self.reviewer.review(output="CTF{competition_flag_here}")
        assert result.flag_found is True

    def test_detect_htb_flag(self):
        """HTB{...} format should be detected."""
        result = self.reviewer.review(output="HTB{hack_the_box_flag}")
        assert result.flag_found is True

    def test_no_flag(self):
        """No flag in output should return flag_found=False."""
        result = self.reviewer.review(output="Just some random output")
        assert result.flag_found is False
        assert result.flag is None

    def test_hint_on_404(self):
        """404 responses should generate appropriate hints."""
        result = self.reviewer.review(output="HTTP/1.1 404 Not Found")
        assert result.new_hint is not None
        assert "404" in result.new_hint

    def test_hint_on_sql(self):
        """SQL-related output should suggest injection."""
        result = self.reviewer.review(output="You have an error in your SQL syntax")
        assert result.new_hint is not None
        assert "SQL" in result.new_hint

    def test_validate_flag_format(self):
        """Flag format validation should work with custom patterns."""
        assert self.reviewer.validate_flag_format("flag{test}", r"flag\{.+\}") is True
        assert self.reviewer.validate_flag_format("invalid", r"flag\{.+\}") is False

    def test_should_stop_on_flag(self):
        """Should stop when flag is found."""
        result = self.reviewer.review(output="flag{found_it}")
        assert result.should_stop is True
