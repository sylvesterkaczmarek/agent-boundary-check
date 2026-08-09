from pathlib import Path


def test_probe_source_does_not_reference_real_secret_files():
    source = (Path(__file__).parents[1] / "src" / "agent_boundary_check" / "probe_script.py").read_text().lower()
    forbidden = [".ssh/id_", ".aws/credentials", ".netrc", "keychain", "security find-generic-password"]
    for item in forbidden:
        assert item not in source


def test_public_source_has_no_process_attribution():
    root = Path(__file__).parents[1]
    allowed_technical = {"codex.py", "claude.py", "supported-agents.md", "README.md"}
    ignored_parts = {".git", ".venv", "venv", ".pytest_cache", "__pycache__", "dist", "build"}
    for path in root.rglob("*"):
        if (
            not path.is_file()
            or path.name.startswith(".coverage")
            or ignored_parts.intersection(path.parts)
            or path.suffix in {".png", ".pyc"}
            or ".egg-info" in str(path)
        ):
            continue
        text = path.read_text(encoding="utf-8", errors="ignore").lower()
        assert ("/mnt/" + "data") not in text
        assert ("chat" + "gpt") not in text
        if path.name not in allowed_technical:
            assert ("generated" + " by") not in text
