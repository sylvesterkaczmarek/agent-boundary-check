from pathlib import Path

import pytest

from agent_boundary_check.lab import create_lab


@pytest.fixture(autouse=True)
def isolated_host_baselines(monkeypatch):
    monkeypatch.setattr("agent_boundary_check.lab._tcp_reachable", lambda *args, **kwargs: False)
    monkeypatch.setattr("agent_boundary_check.lab._unix_socket_connectable", lambda *args, **kwargs: False)


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


@pytest.mark.parametrize("existing_output", [False, True])
@pytest.mark.parametrize("failure", [OSError, KeyboardInterrupt])
def test_creation_failure_removes_only_created_paths(tmp_path, monkeypatch, existing_output, failure):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: fake_home))
    output = tmp_path / "manual"
    if existing_output:
        output.mkdir()

    def fail_baseline(*args, **kwargs):
        raise failure("synthetic baseline failure")

    monkeypatch.setattr("agent_boundary_check.lab._tcp_reachable", fail_baseline)
    with pytest.raises(failure, match="synthetic baseline failure"):
        create_lab(output)
    assert not (fake_home / ".agent-boundary-check").exists()
    assert output.exists() is existing_output
    if existing_output:
        assert list(output.iterdir()) == []


def _symlink_directory(link, target):
    try:
        link.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("directory symlinks unavailable")


def test_cleanup_does_not_follow_replaced_canary_parent(tmp_path, monkeypatch):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: fake_home))
    lab = create_lab(network_probe=False)
    parent = lab.home_canary_dir.parent
    parent.rename(parent.with_name("original-canaries"))
    unrelated = tmp_path / "unrelated"
    unrelated_run = unrelated / lab.run_id
    unrelated_run.mkdir(parents=True)
    marker = unrelated_run / "keep.txt"
    marker.write_text("keep")
    _symlink_directory(parent, unrelated)

    lab.cleanup()
    assert marker.read_text() == "keep"


def test_creation_refuses_symlinked_managed_root(tmp_path, monkeypatch):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: fake_home))
    unrelated = tmp_path / "unrelated"
    unrelated.mkdir()
    _symlink_directory(fake_home / ".agent-boundary-check", unrelated)

    with pytest.raises(ValueError, match="symlink|redirect"):
        create_lab(network_probe=False)
    assert list(unrelated.iterdir()) == []


def test_remote_docker_host_does_not_fall_back_to_local_socket(tmp_path, monkeypatch):
    from agent_boundary_check.lab import _docker_socket_path

    monkeypatch.setenv("DOCKER_HOST", "tcp://127.0.0.1:2375")
    monkeypatch.setattr(Path, "exists", lambda self: True)
    assert _docker_socket_path() == ""


def test_automatic_creation_failure_removes_new_managed_parents(tmp_path, monkeypatch):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: fake_home))
    real_write = Path.write_text

    def fail_write(path, *args, **kwargs):
        if path.name == "probe_driver.py":
            raise OSError("synthetic disk failure")
        return real_write(path, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", fail_write)
    with pytest.raises(OSError, match="synthetic disk failure"):
        create_lab(network_probe=False)
    assert list(fake_home.iterdir()) == []


def test_creation_refuses_symlink_output_even_if_target_is_empty(tmp_path, monkeypatch):
    target = tmp_path / "target"
    target.mkdir()
    output = tmp_path / "output"
    _symlink_directory(output, target)
    with pytest.raises(ValueError, match="symlink|redirect"):
        create_lab(output, network_probe=False)
    assert list(target.iterdir()) == []


def test_cleanup_preserves_a_replacement_directory(tmp_path, monkeypatch):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: fake_home))
    lab = create_lab(network_probe=False)
    lab.home_canary_dir.rename(lab.home_canary_dir.with_name("original-canary"))
    lab.home_canary_dir.mkdir()
    marker = lab.home_canary_dir / "keep.txt"
    marker.write_text("keep")
    lab.cleanup()
    assert marker.read_text() == "keep"


def test_manual_cleanup_is_bound_to_original_lab_and_key(tmp_path, monkeypatch):
    from agent_boundary_check.lab import cleanup_home_canary_for_run

    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: fake_home))
    first = create_lab(tmp_path / "first", network_probe=False)
    second = create_lab(tmp_path / "second", network_probe=False)
    assert not cleanup_home_canary_for_run(
        first.run_id, lab_root=second.root, attestation_key=first.attestation_key,
    )
    assert not cleanup_home_canary_for_run(
        first.run_id, lab_root=first.root, attestation_key=second.attestation_key,
    )
    assert first.home_canary_dir.exists()
    assert cleanup_home_canary_for_run(
        first.run_id, lab_root=first.root, attestation_key=first.attestation_key,
    )
    assert not first.home_canary_dir.exists()
    assert second.home_canary_dir.exists()
    second.cleanup_home_canary()


def test_manual_cleanup_leaves_unrecognised_directories(tmp_path, monkeypatch):
    from agent_boundary_check.lab import cleanup_home_canary_for_run

    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: fake_home))
    lab = create_lab(tmp_path / "manual", network_probe=False)
    (lab.home_canary_dir / "ownership.json").unlink()
    assert not cleanup_home_canary_for_run(
        lab.run_id, lab_root=lab.root, attestation_key=lab.attestation_key,
    )
    assert (lab.home_canary_dir / "home-canary.txt").exists()
    lab.cleanup_home_canary()


def test_relative_socket_configuration_keeps_same_target_in_workspace(tmp_path, monkeypatch):
    import json

    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("DOCKER_HOST", "unix://docker.sock")
    monkeypatch.setenv("SSH_AUTH_SOCK", "ssh.sock")
    # Plain files are enough for inspecting paths; the baseline is stubbed.
    (tmp_path / "docker.sock").touch()
    (tmp_path / "ssh.sock").touch()
    lab = create_lab(network_probe=False)
    manifest = json.loads(lab.manifest_path.read_text())
    assert manifest["docker_socket_path"] == str(tmp_path / "docker.sock")
    assert manifest["ssh_agent_socket_path"] == str(tmp_path / "ssh.sock")
    lab.cleanup()


def test_manual_output_can_use_existing_parent_directory_alias(tmp_path):
    target = tmp_path / "target"
    target.mkdir()
    parent_alias = tmp_path / "alias"
    _symlink_directory(parent_alias, target)
    lab = create_lab(parent_alias / "manual", network_probe=False)
    assert lab.root == target / "manual"
    assert lab.manifest_path.exists()
    lab.cleanup_home_canary()
