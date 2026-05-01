"""Tests for the Planner module."""

import pytest
from agent.core.planner import Planner, Plan, Action


class TestPlanner:
    """Test suite for the planner."""

    def test_action_creation(self):
        """Action should store all fields."""
        action = Action(
            tool="curl",
            command="curl -s http://target.com",
            description="Recon the target",
            priority=1,
        )
        assert action.tool == "curl"
        assert action.command == "curl -s http://target.com"
        assert action.priority == 1

    def test_plan_creation(self):
        """Plan should contain actions and metadata."""
        plan = Plan(
            reasoning="Test reasoning",
            actions=[Action(tool="curl", command="curl -s http://target.com")],
            confidence=0.8,
            strategy="web_recon",
        )
        assert len(plan.actions) == 1
        assert plan.confidence == 0.8
        assert plan.strategy == "web_recon"

    def test_fallback_plan(self):
        """Fallback plan should work without LLM."""
        planner = Planner(model="nonexistent", provider="openai")
        plan = planner._fallback_plan("http://target.com", "test error")
        assert len(plan.actions) > 0
        assert plan.confidence < 0.5
        assert "fallback" in plan.strategy

    def test_fallback_no_url(self):
        """Fallback without URL should have no actions."""
        planner = Planner(model="nonexistent", provider="openai")
        plan = planner._fallback_plan(None, "test error")
        assert len(plan.actions) == 0

    def test_build_prompt(self):
        """Prompt builder should include all context."""
        planner = Planner()
        prompt = planner._build_prompt(
            challenge_url="http://target.com",
            challenge_text="Find the SQL injection",
            category="web",
            context="Previous context",
            previous_steps=["Step 1", "Step 2"],
        )
        assert "http://target.com" in prompt
        assert "SQL injection" in prompt
        assert "web" in prompt
        assert "Previous context" in prompt
        assert "Step 1" in prompt

    def test_build_prompt_with_few_shot(self):
        """Prompt should include few-shot examples for known categories."""
        planner = Planner()
        for category in ["web", "crypto", "pwn", "reverse", "forensics"]:
            prompt = planner._build_prompt(
                challenge_url=None, challenge_text="test",
                category=category, context="", previous_steps=[],
            )
            assert "Example" in prompt
