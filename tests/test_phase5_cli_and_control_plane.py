"""
Phase 5 CLI & Control Plane Unit Tests (tests/test_phase5_cli_and_control_plane.py)
-----------------------------------------------------------------------------------
Validates:
1. Command-line interface parser definitions.
2. CLI health diagnostic and metrics dump subcommands.
"""

from unittest.mock import MagicMock
import pytest
from cli import _cmd_health_check, _cmd_metrics_dump, main


def test_cli_health_check_command(capsys):
    """Verify cli health check diagnostic output."""
    mock_args = MagicMock()
    _cmd_health_check(mock_args)
    captured = capsys.readouterr()
    assert "Auth N&Z Diagnostics" in captured.out
    assert "Environment:" in captured.out
    assert "ONLINE" in captured.out


def test_cli_metrics_dump_command(capsys):
    """Verify cli metrics dump command outputs Prometheus metrics."""
    mock_args = MagicMock()
    _cmd_metrics_dump(mock_args)
    captured = capsys.readouterr()
    assert "authnz_uptime_seconds" in captured.out
