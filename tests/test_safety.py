from pathlib import Path


def test_probe_source_does_not_reference_real_secret_files():
    source = (Path(__file__).parents[1] / "src" / "agent_boundary_check" / "probe_script.py").read_text().lower()
    forbidden = [".ssh/id_", ".aws/credentials", ".netrc", "keychain", "security find-generic-password"]
    for item in forbidden:
        assert item not in source


def test_public_source_has_no_process_attribution():
    root = Path(__file__).parents[1]
    allowed_technical = {"codex.py", "claude.py", "supported-agents.md", "README.md"}
    for path in root.rglob("*"):
        if not path.is_file() or ".git" in path.parts or path.suffix in {".png", ".pyc"}:
            continue
        text = path.read_text(encoding="utf-8", errors="ignore").lower()
        assert ("/mnt/" + "data") not in text
        assert ("chat" + "gpt") not in text
        # Product names are legitimate technical references in adapter/docs files.
        if path.name not in allowed_technical:
            assert ("generated" + " by") not in text
