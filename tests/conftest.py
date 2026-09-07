from pathlib import Path

import pytest


@pytest.fixture(autouse=True)
def isolated_test_host(tmp_path, monkeypatch):
    """Keep tests away from the user's home canaries and live network services."""
    isolated = tmp_path / 'isolated-home'
    isolated.mkdir()
    monkeypatch.setattr(Path, 'home', classmethod(lambda cls: isolated))
    monkeypatch.setattr('agent_boundary_check.lab._tcp_reachable', lambda *args, **kwargs: False)
    monkeypatch.setattr('agent_boundary_check.lab._unix_socket_connectable', lambda *args, **kwargs: False)
