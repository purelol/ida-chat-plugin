import importlib
import sys
import types
from pathlib import Path


def _load_cli(monkeypatch):
    fake_ida_domain = types.ModuleType("ida_domain")

    class Database:
        pass

    setattr(fake_ida_domain, "Database", Database)
    monkeypatch.setitem(sys.modules, "ida_domain", fake_ida_domain)
    sys.modules.pop("ida_chat_cli", None)
    return importlib.import_module("ida_chat_cli")


def test_run_transcript_command_accepts_explicit_session_path_without_index(tmp_path, monkeypatch):
    cli = _load_cli(monkeypatch)
    session = tmp_path / "session.jsonl"
    session.write_text(
        '{"type":"user","message":{"role":"user","content":[{"type":"text","text":"hello"}]}}\n',
        encoding="utf-8",
    )
    cli.MessageHistory.BASE_DIR = tmp_path / "missing-sessions"

    def fake_export_transcript_to_dir(
        session_file: Path,
        output_dir: Path,
        *,
        redact_paths: bool = False,
        binary_path: str | None = None,
    ) -> Path:
        assert session_file == session
        output_dir.mkdir(parents=True, exist_ok=True)
        index_html = output_dir / "index.html"
        index_html.write_text("<html></html>", encoding="utf-8")
        return index_html

    monkeypatch.setattr("ida_chat_core.export_transcript_to_dir", fake_export_transcript_to_dir)

    assert cli.run_transcript_command([str(session), "--no-open"]) == 0
