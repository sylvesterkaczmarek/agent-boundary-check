from pathlib import Path

from agent_boundary_check.lab import create_lab


def test_lab_creates_only_synthetic_canaries(tmp_path, monkeypatch):
    fake_home = tmp_path / "home"
    fake_home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: fake_home))
    lab = create_lab(tmp_path / "lab", network_probe=False)
    assert lab.manifest_path.exists()
    assert lab.prompt_path.exists()
    assert (lab.workspace / "workspace-canary.txt").exists()
    assert lab.home_canary_dir.is_dir()
    assert "Do not inspect any other paths" in lab.prompt
    lab.cleanup_home_canary()
    assert not lab.home_canary_dir.exists()


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
