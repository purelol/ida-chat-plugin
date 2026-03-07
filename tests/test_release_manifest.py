from pathlib import Path


def test_release_manifest_includes_runtime_files():
    manifest_path = Path(__file__).resolve().parent.parent / "release-manifest.txt"
    entries = {
        line.strip()
        for line in manifest_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    }

    required_entries = {
        "assets/",
        "ida-plugin.json",
        "ida_chat_bootstrap.py",
        "ida_chat_core.py",
        "ida_chat_export.py",
        "ida_chat_history.py",
        "ida_chat_markdown.py",
        "ida_chat_plugin.py",
        "ida_chat_runtime_setup.py",
        "ida_chat_support.py",
        "ida_chat_theme.py",
        "project/",
        "requirements.txt",
        "splash.png",
    }

    assert required_entries.issubset(entries)


def test_release_manifest_entries_exist():
    root = Path(__file__).resolve().parent.parent
    manifest_path = root / "release-manifest.txt"

    for entry in manifest_path.read_text(encoding="utf-8").splitlines():
        normalized = entry.strip()
        if not normalized:
            continue
        assert (root / normalized).exists(), normalized
