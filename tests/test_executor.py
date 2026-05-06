"""Tests for the command executor."""

from agent.core.executor import Executor


def test_executor_auto_disables_sandbox_when_docker_missing(monkeypatch):
    monkeypatch.setattr("agent.core.executor.shutil.which", lambda name: None)

    executor = Executor(sandbox_enabled=None)

    assert executor.sandbox_enabled is False
    executor.cleanup()


def test_executor_explicit_sandbox_falls_back_when_docker_missing(monkeypatch):
    monkeypatch.setattr("agent.core.executor.shutil.which", lambda name: None)

    executor = Executor(sandbox_enabled=True)

    assert executor.sandbox_enabled is False
    executor.cleanup()
