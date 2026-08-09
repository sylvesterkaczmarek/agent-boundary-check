from pathlib import Path

from agent_boundary_check.lab import create_lab


def test_automatic_lab_avoids_os_temp_and_creates_only_synthetic_canaries(tmp_path, monkeypatch):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: fake_home))
    monkeypatch.setattr("agent_boundary_check.lab._tcp_reachable", lambda *args, **kwargs: False)
    lab = create_lab(network_probe=True)
    assert lab.root.parent == fake_home / ".agent-boundary-check" / "labs"
    assert lab.manifest_path.exists()
    assert lab.prompt_path.exists()
    assert (lab.workspace / "workspace-canary.txt").exists()
    assert lab.home_canary_dir.is_dir()
    assert "Do not inspect any other paths" in lab.prompt
    outside = lab.root / "outside" / "outside-canary.txt"
    assert outside.exists()
    assert lab.workspace not in outside.parents
    lab.cleanup()
    assert not lab.root.exists()
    assert not lab.home_canary_dir.exists()


def test_manual_lab_disables_environment_probe(tmp_path, monkeypatch):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: fake_home))
    lab = create_lab(tmp_path / "lab", network_probe=False, environment_probe=False)
    manifest = __import__("json").loads(lab.manifest_path.read_text())
    assert manifest["environment_probe"] is False
    lab.cleanup_home_canary()


def test_output_directory_must_be_empty(tmp_path, monkeypatch):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: fake_home))
    out = tmp_path / "lab"
    out.mkdir()
    (out / "x").write_text("x")
    try:
        create_lab(out)
    except ValueError as exc:
        assert "not empty" in str(exc)
    else:
        raise AssertionError("expected ValueError")


def test_docker_socket_path_detects_user_docker_desktop_socket(tmp_path, monkeypatch):
    fake_home = tmp_path / "home"
    socket_path = fake_home / ".docker" / "run" / "docker.sock"
    socket_path.parent.mkdir(parents=True)
    socket_path.touch()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: fake_home))
    real_exists = Path.exists
    monkeypatch.setattr(Path, "exists", lambda self: False if str(self) == "/var/run/docker.sock" else real_exists(self))
    monkeypatch.delenv("DOCKER_HOST", raising=False)
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    from agent_boundary_check.lab import _docker_socket_path

    assert _docker_socket_path() == str(socket_path)
