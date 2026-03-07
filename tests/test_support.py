from pathlib import Path

from ida_chat_support import (
    build_progress_timeline_steps,
    can_finalize_settings,
    PromptContext,
    apply_auth_environment,
    auth_mode_has_credentials,
    build_augmented_prompt,
    build_context_block,
    build_redaction_map,
    classify_script_risk,
    normalize_error_message,
    redact_text_paths,
    resolve_auth_environment,
)


def test_classify_script_risk():
    assert classify_script_risk("print(db.module)") == "read-only"
    assert classify_script_risk("db.functions.rename(foo, 'bar')") == "mutating"
    assert classify_script_risk("value = helper()") == "unknown"


def test_build_context_block_and_prompt():
    context = PromptContext(
        current_address="0x401000",
        current_function="main",
        selected_range="0x401000-0x401020",
        highlighted_token="vtable",
        current_line="mov eax, [rbx]",
    )

    block = build_context_block(context)
    assert "<ida_context>" in block
    assert "current_function: main" in block
    assert "highlighted_token: vtable" in block

    prompt = build_augmented_prompt("Explain this code", context)
    assert prompt.startswith("<ida_context>")
    assert prompt.endswith("Explain this code")


def test_redact_text_paths():
    binary_path = Path("/tmp/project/sample.i64")
    replacements = build_redaction_map(binary_path)
    text = f"user={Path.home()} binary={binary_path} dir={binary_path.parent}"
    redacted = redact_text_paths(text, replacements)
    assert str(Path.home()) not in redacted
    assert str(binary_path) not in redacted
    assert "<binary-path>" in redacted
    assert "<binary-dir>" in redacted


def test_normalize_error_message():
    assert normalize_error_message("Claude Code not found at /usr/local/bin/claude").startswith("Claude Code CLI")
    assert "UTF-8" in normalize_error_message("'ascii' codec can't decode byte 0xe2")
    assert "timeout" in normalize_error_message("control request timeout").lower()


def test_auth_mode_has_credentials():
    assert auth_mode_has_credentials("system") is True
    assert auth_mode_has_credentials("api_key", "") is False
    assert auth_mode_has_credentials("api_key", "sk-ant-123") is True
    assert auth_mode_has_credentials("oauth", "", cli_available=False) is False
    assert auth_mode_has_credentials("oauth", "", cli_available=True) is True
    assert auth_mode_has_credentials("oauth", "oauth-token", cli_available=False) is True


def test_resolve_auth_environment_preserves_system_env():
    resolved = resolve_auth_environment(
        "system",
        None,
        original_api_key="existing-api",
        original_oauth_token="existing-oauth",
    )
    assert resolved["ANTHROPIC_API_KEY"] == "existing-api"
    assert resolved["CLAUDE_CODE_OAUTH_TOKEN"] == "existing-oauth"


def test_apply_auth_environment_switches_modes_without_leaking_old_values():
    env = {
        "ANTHROPIC_API_KEY": "existing-api",
        "CLAUDE_CODE_OAUTH_TOKEN": "existing-oauth",
    }

    apply_auth_environment(
        env,
        "api_key",
        "new-api",
        original_api_key="existing-api",
        original_oauth_token="existing-oauth",
    )
    assert env["ANTHROPIC_API_KEY"] == "new-api"
    assert "CLAUDE_CODE_OAUTH_TOKEN" not in env

    apply_auth_environment(
        env,
        "system",
        None,
        original_api_key="existing-api",
        original_oauth_token="existing-oauth",
    )
    assert env["ANTHROPIC_API_KEY"] == "existing-api"
    assert env["CLAUDE_CODE_OAUTH_TOKEN"] == "existing-oauth"


def test_can_finalize_settings_requires_verified_state():
    assert can_finalize_settings("verified", "system") is True
    assert can_finalize_settings("unverified", "system") is False
    assert can_finalize_settings("verified", "api_key", "") is False
    assert can_finalize_settings("verified", "api_key", "sk-ant-123") is True


def test_build_progress_timeline_steps_numbers_steps_without_gaps():
    assert build_progress_timeline_steps(0, "Done", True) == [
        (1, "User", "complete"),
        (2, "Done", "complete"),
    ]
    assert build_progress_timeline_steps(0, "Thinking", False) == [
        (1, "User", "complete"),
        (2, "Thinking", "active"),
    ]
    assert build_progress_timeline_steps(2, "Done", True) == [
        (1, "User", "complete"),
        (2, "2 scripts", "complete"),
        (3, "Done", "complete"),
    ]
