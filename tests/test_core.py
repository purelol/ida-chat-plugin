import asyncio
from pathlib import Path
from typing import Any, cast

from claude_agent_sdk.types import HookContext, HookInput
from ida_chat_core import (
    IDAChatCore,
    _restrict_file_access,
    _load_system_prompt,
    _prepare_transcript_source,
    _resolve_tool_path,
    export_transcript,
    export_transcript_to_dir,
)
from ida_chat_support import ScriptApprovalRequest, ScriptDecision


class DummyCallback:
    def __init__(self):
        self.requests = []

    def on_turn_start(self, turn, max_turns):
        pass

    def on_thinking(self):
        pass

    def on_thinking_done(self):
        pass

    def on_tool_use(self, tool_name, details):
        pass

    def on_text(self, text):
        pass

    def on_script_code(self, request: ScriptApprovalRequest):
        self.requests.append(request)

    def on_script_output(self, output):
        pass

    def on_error(self, error):
        pass

    def on_result(self, num_turns, cost):
        pass


class FakeClient:
    def __init__(self):
        self.interrupted = False

    async def interrupt(self):
        self.interrupted = True


async def _approve(request: ScriptApprovalRequest) -> ScriptDecision:
    return "skip"


def test_prepare_transcript_source_redacts_paths(tmp_path):
    session = tmp_path / "session.jsonl"
    binary_path = tmp_path / "binary.i64"
    session.write_text(
        f'{{"type":"system","content":"cwd={Path.home()} binary={binary_path}"}}\n',
        encoding="utf-8",
    )
    redacted = _prepare_transcript_source(session, True, str(binary_path))
    content = redacted.read_text(encoding="utf-8")
    assert str(Path.home()) not in content
    assert str(binary_path) not in content
    assert "<binary-path>" in content


def test_export_transcript_to_dir_creates_output_directory(tmp_path, monkeypatch):
    session = tmp_path / "session.jsonl"
    session.write_text(
        '{"type":"user","message":{"role":"user","content":[{"type":"text","text":"hi"}]}}\n',
        encoding="utf-8",
    )
    output_dir = tmp_path / "nested" / "export"

    def fake_generate_html(source_session: Path, target_dir: Path) -> None:
        assert source_session == session
        assert target_dir == output_dir
        (target_dir / "index.html").write_text("<html></html>", encoding="utf-8")

    monkeypatch.setattr("ida_chat_core.claude_code_transcripts.generate_html", fake_generate_html)

    index_html = export_transcript_to_dir(session, output_dir)

    assert output_dir.exists()
    assert index_html == output_dir / "index.html"
    assert index_html.exists()


def test_export_transcript_creates_parent_directory_and_copies_pages(tmp_path, monkeypatch):
    session = tmp_path / "session.jsonl"
    session.write_text(
        '{"type":"user","message":{"role":"user","content":[{"type":"text","text":"hi"}]}}\n',
        encoding="utf-8",
    )
    output_path = tmp_path / "nested" / "report" / "chat.html"

    def fake_generate_html(_source_session: Path, target_dir: Path) -> None:
        (target_dir / "index.html").write_text("<html>index</html>", encoding="utf-8")
        (target_dir / "page-001.html").write_text("<html>page</html>", encoding="utf-8")

    monkeypatch.setattr("ida_chat_core.claude_code_transcripts.generate_html", fake_generate_html)

    export_transcript(session, output_path)

    assert output_path.exists()
    assert (output_path.parent / "page-001.html").exists()


def test_load_system_prompt_tolerates_missing_reference_docs(tmp_path, monkeypatch):
    prompt_file = tmp_path / "PROMPT.md"
    prompt_file.write_text("Base prompt", encoding="utf-8")

    missing_usage = tmp_path / "USAGE.md"
    missing_api = tmp_path / "API_REFERENCE.md"

    monkeypatch.setattr("ida_chat_core.PROMPT_FILE", prompt_file)
    monkeypatch.setattr("ida_chat_core.USAGE_FILE", missing_usage)
    monkeypatch.setattr("ida_chat_core.API_REFERENCE_FILE", missing_api)
    monkeypatch.setattr("ida_chat_core.IDA_UI_FILE", tmp_path / "IDA.md")
    monkeypatch.delenv("IDA_CHAT_INSIDE_IDA", raising=False)

    prompt = _load_system_prompt()

    assert "Base prompt" in prompt
    assert "USAGE.md" not in prompt


def test_resolve_tool_path_uses_project_dir_for_relative_paths(tmp_path, monkeypatch):
    project_dir = tmp_path / "project"
    project_dir.mkdir()
    monkeypatch.setattr("ida_chat_core.PROJECT_DIR", project_dir)

    resolved = _resolve_tool_path("docs/file.txt")

    assert resolved == (project_dir / "docs" / "file.txt").resolve()


def test_restrict_file_access_allows_relative_project_paths(tmp_path, monkeypatch):
    project_dir = tmp_path / "project"
    allowed_file = project_dir / "docs" / "file.txt"
    allowed_file.parent.mkdir(parents=True)
    allowed_file.write_text("ok", encoding="utf-8")
    monkeypatch.setattr("ida_chat_core.PROJECT_DIR", project_dir)
    monkeypatch.chdir(tmp_path)

    input_data = cast(
        HookInput,
        {"hook_event_name": "PreToolUse", "tool_input": {"file_path": "docs/file.txt"}},
    )
    hook_context = cast(HookContext, {"signal": cast(Any, None)})

    result = asyncio.run(
        _restrict_file_access(
            input_data,
            None,
            hook_context,
        )
    )

    assert result == {}


def test_interrupt_marks_client():
    callback = DummyCallback()
    core = IDAChatCore(db=object(), callback=callback)
    core.client = cast(Any, FakeClient())
    asyncio.run(core.interrupt())
    assert cast(FakeClient, core.client).interrupted is True


def test_script_approval_callback_only_waits_when_enabled():
    callback = DummyCallback()
    core = IDAChatCore(
        db=object(),
        callback=callback,
        script_approver=_approve,
        require_script_approval=True,
    )
    request = ScriptApprovalRequest(
        request_id="req",
        code="print(db.module)",
        script_index=1,
        total_scripts=1,
        risk="read-only",
        preview="print(db.module)",
        requires_approval=True,
    )

    decision = asyncio.run(core._decide_script(request))
    assert decision == "skip"
    assert callback.requests == [request]
