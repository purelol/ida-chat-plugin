"""Shared pure-Python helpers for IDA Chat.

This module intentionally avoids importing IDA or Qt so it can be covered by
unit tests and reused by both the plugin and the CLI-facing core.
"""

from __future__ import annotations

import json
import os
import re
import shutil
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal, MutableMapping


FailurePhase = Literal["test", "connect", "query", "disconnect"]
ScriptRisk = Literal["read-only", "mutating", "unknown"]
ScriptDecision = Literal["approve", "skip", "cancel"]
VerificationState = Literal["verified", "verifying", "unverified"]

_MUTATING_PATTERNS = [
    r"\bset_[A-Za-z0-9_]+\s*\(",
    r"\brename[A-Za-z0-9_]*\s*\(",
    r"\bpatch[A-Za-z0-9_]*\s*\(",
    r"\bsave\s*\(",
    r"\bjumpto\s*\(",
    r"\bexecute_sync\s*\(",
    r"\bdel_current_plugin_setting\s*\(",
    r"\bset_current_plugin_setting\s*\(",
    r"\bwrite_text\s*\(",
    r"\bwrite_bytes\s*\(",
]

_READ_ONLY_PATTERNS = [
    r"\bprint\s*\(",
    r"\bget_[A-Za-z0-9_]+\s*\(",
    r"\blist_[A-Za-z0-9_]+\s*\(",
    r"\bfind_[A-Za-z0-9_]+\s*\(",
    r"\bto_ea\s*\(",
    r"\bfrom_ea\s*\(",
    r"\bread_[A-Za-z0-9_]+\s*\(",
]

_ASCII_ERROR_RE = re.compile(r"'ascii' codec can't decode byte", re.IGNORECASE)
_TIMEOUT_RE = re.compile(r"\btimeout\b", re.IGNORECASE)
_JSON_RE = re.compile(r"json|decode", re.IGNORECASE)
_AUTH_RE = re.compile(r"auth|api key|oauth|token|401|403|login", re.IGNORECASE)
_INTERRUPT_RE = re.compile(r"interrupt|cancel|terminated process|not ready for writing", re.IGNORECASE)


@dataclass(slots=True)
class DiagnosticReport:
    """Normalized diagnostics payload for plugin rendering."""

    phase: FailurePhase
    short_message: str
    raw_error: str
    cli_path: str
    version_output: str
    cwd: str
    auth_mode: str
    locale_env: dict[str, str]
    stderr_tail: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_text(self) -> str:
        lines = [
            f"Phase: {self.phase}",
            f"Summary: {self.short_message}",
            f"CLI: {self.cli_path or '(unknown)'}",
            f"Version: {self.version_output or '(unknown)'}",
            f"CWD: {self.cwd}",
            f"Auth: {self.auth_mode}",
            f"Locale: {json.dumps(self.locale_env, ensure_ascii=False)}",
        ]
        if self.stderr_tail:
            lines.append("Stderr tail:")
            lines.extend(f"  {line}" for line in self.stderr_tail)
        if self.raw_error:
            lines.append(f"Raw error: {self.raw_error}")
        return "\n".join(lines)


@dataclass(slots=True)
class ConnectionTestResult:
    """Structured connection test result."""

    success: bool
    message: str
    diagnostics: DiagnosticReport | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "success": self.success,
            "message": self.message,
            "diagnostics": self.diagnostics.to_dict() if self.diagnostics else None,
        }


@dataclass(slots=True)
class ScriptApprovalRequest:
    """Script preview and approval payload."""

    request_id: str
    code: str
    script_index: int
    total_scripts: int
    risk: ScriptRisk
    preview: str
    requires_approval: bool


@dataclass(slots=True)
class PromptContext:
    """Prompt context captured from the active IDA UI state."""

    current_address: str | None = None
    current_function: str | None = None
    selected_range: str | None = None
    highlighted_token: str | None = None
    current_line: str | None = None

    def is_empty(self) -> bool:
        return not any(asdict(self).values())


def find_claude_cli_path() -> str:
    """Best-effort lookup for the Claude Code CLI."""
    return shutil.which("claude") or ""


def auth_mode_has_credentials(
    auth_type: str,
    credential: str | None = None,
    *,
    cli_available: bool = False,
) -> bool:
    """Return whether an auth mode has enough local data to attempt use.

    `system` relies on existing machine-level configuration, so the UI cannot
    pre-validate it beyond letting the runtime attempt a connection test.
    `oauth` supports either Claude Code's local browser login or a pasted
    fallback token. `api_key` requires a non-empty key.
    """
    secret = (credential or "").strip()
    if auth_type == "api_key":
        return bool(secret)
    if auth_type == "oauth":
        return cli_available or bool(secret)
    return True


def resolve_auth_environment(
    auth_type: str | None,
    credential: str | None = None,
    *,
    original_api_key: str | None = None,
    original_oauth_token: str | None = None,
) -> dict[str, str | None]:
    """Resolve the auth-related environment values for the chosen mode."""
    secret = (credential or "").strip() or None
    resolved = {
        "ANTHROPIC_API_KEY": original_api_key,
        "CLAUDE_CODE_OAUTH_TOKEN": original_oauth_token,
    }

    if auth_type == "api_key":
        resolved["ANTHROPIC_API_KEY"] = secret
        resolved["CLAUDE_CODE_OAUTH_TOKEN"] = None
    elif auth_type == "oauth":
        resolved["ANTHROPIC_API_KEY"] = None
        resolved["CLAUDE_CODE_OAUTH_TOKEN"] = secret

    return resolved


def apply_auth_environment(
    target_env: MutableMapping[str, str],
    auth_type: str | None,
    credential: str | None = None,
    *,
    original_api_key: str | None = None,
    original_oauth_token: str | None = None,
) -> None:
    """Apply auth environment variables while preserving system defaults."""
    resolved = resolve_auth_environment(
        auth_type,
        credential,
        original_api_key=original_api_key,
        original_oauth_token=original_oauth_token,
    )
    for key, value in resolved.items():
        if value:
            target_env[key] = value
        else:
            target_env.pop(key, None)


def can_finalize_settings(
    verification_state: VerificationState,
    auth_type: str,
    credential: str | None = None,
    *,
    cli_available: bool = False,
) -> bool:
    """Return whether settings are ready to save/start."""
    return verification_state == "verified" and auth_mode_has_credentials(
        auth_type,
        credential,
        cli_available=cli_available,
    )


def build_progress_timeline_steps(
    script_count: int,
    current_stage: str,
    is_complete: bool,
) -> list[tuple[int, str, str]]:
    """Return numbered progress steps for the compact timeline UI."""
    steps: list[tuple[int, str, str]] = [(1, "User", "complete")]

    if script_count > 0:
        steps.append(
            (
                len(steps) + 1,
                f"{script_count} scripts",
                "complete" if is_complete else "active",
            )
        )

    if is_complete:
        steps.append((len(steps) + 1, "Done", "complete"))
    elif current_stage and current_stage != "User" and not current_stage.startswith("Script"):
        steps.append((len(steps) + 1, current_stage, "active"))

    return steps


def classify_script_risk(code: str) -> ScriptRisk:
    """Classify a generated IDA script using cheap heuristics."""
    normalized = code or ""
    if any(re.search(pattern, normalized) for pattern in _MUTATING_PATTERNS):
        return "mutating"
    if any(re.search(pattern, normalized) for pattern in _READ_ONLY_PATTERNS):
        return "read-only"
    return "unknown"


def format_script_preview(code: str, max_lines: int = 5) -> str:
    """Return a short preview string for script cards."""
    lines = [line.rstrip() for line in (code or "").strip().splitlines()]
    if not lines:
        return "(empty script)"
    preview = lines[:max_lines]
    if len(lines) > max_lines:
        preview.append(f"... ({len(lines) - max_lines} more lines)")
    return "\n".join(preview)


def summarize_tool_use(tool_name: str, tool_input: dict[str, Any]) -> str:
    """Build a human-sized description of a tool call."""
    if tool_name == "Read":
        return str(tool_input.get("file_path", ""))
    if tool_name in {"Grep", "Glob"}:
        return str(tool_input.get("pattern", ""))
    if tool_name == "Task":
        return str(tool_input.get("description", ""))
    if tool_name == "IDAPythonExec":
        return "Generated IDA Python script"
    return ", ".join(f"{key}={value}" for key, value in list(tool_input.items())[:3])


def normalize_error_message(raw_error: str) -> str:
    """Convert low-level exceptions into actionable summaries."""
    error = (raw_error or "").strip()
    lowered = error.lower()

    if "claude code not found" in lowered or "not found at" in lowered:
        return "Claude Code CLI is not installed or is not on PATH."
    if _ASCII_ERROR_RE.search(error):
        return "Claude output used a non-UTF-8 locale; restart with UTF-8 locale settings."
    if _TIMEOUT_RE.search(error):
        return "Claude did not respond before the timeout."
    if _AUTH_RE.search(error):
        return "Authentication failed. Check the configured Claude login, OAuth token, or API key."
    if _JSON_RE.search(error):
        return "Claude returned malformed or truncated output."
    if _INTERRUPT_RE.search(error):
        return "The request was interrupted before Claude finished responding."
    if "working directory does not exist" in lowered:
        return "The configured project directory does not exist."
    return error or "Unknown Claude connection error."


def build_locale_env_summary(env: dict[str, str] | None = None) -> dict[str, str]:
    """Capture locale-related environment variables for diagnostics."""
    source = env if env is not None else os.environ
    keys = ("LANG", "LC_ALL", "LC_CTYPE", "PYTHONUTF8", "PYTHONIOENCODING")
    return {key: source.get(key, "") for key in keys if source.get(key) is not None}


def build_context_block(context: PromptContext | None) -> str:
    """Serialize prompt context into a compact hidden block for the model."""
    if context is None or context.is_empty():
        return ""

    lines = ["<ida_context>"]
    if context.current_address:
        lines.append(f"current_address: {context.current_address}")
    if context.current_function:
        lines.append(f"current_function: {context.current_function}")
    if context.selected_range:
        lines.append(f"selected_range: {context.selected_range}")
    if context.highlighted_token:
        lines.append(f"highlighted_token: {context.highlighted_token}")
    if context.current_line:
        lines.append(f"current_line: {context.current_line}")
    lines.append("</ida_context>")
    return "\n".join(lines)


def build_augmented_prompt(user_input: str, context: PromptContext | None) -> str:
    """Prepend a structured context block to the user prompt when available."""
    context_block = build_context_block(context)
    if not context_block:
        return user_input
    return f"{context_block}\n\nUser request:\n{user_input}"


def build_redaction_map(binary_path: str | Path | None = None) -> dict[str, str]:
    """Build deterministic path replacements for transcript redaction."""
    replacements: dict[str, str] = {}
    home = str(Path.home())
    if home:
        replacements[home] = "~"

    if binary_path:
        binary = Path(binary_path)
        replacements[str(binary)] = "<binary-path>"
        replacements[str(binary.parent)] = "<binary-dir>"

    return replacements


def redact_text_paths(text: str, replacements: dict[str, str]) -> str:
    """Replace absolute paths inside a transcript or error string."""
    redacted = text
    for needle, replacement in sorted(replacements.items(), key=lambda item: len(item[0]), reverse=True):
        if needle:
            redacted = redacted.replace(needle, replacement)
    return redacted


def normalize_session_entries(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Convert raw JSONL session entries into display-ready message items."""
    items: list[dict[str, Any]] = []
    pending_tools: dict[str, str] = {}

    for entry in entries:
        entry_type = entry.get("type")
        if entry_type == "system":
            items.append(
                {
                    "kind": "system",
                    "text": entry.get("content", ""),
                    "level": entry.get("level", "info"),
                }
            )
            continue

        message = entry.get("message", {})
        content = message.get("content", [])
        if not isinstance(content, list):
            continue

        for block in content:
            if not isinstance(block, dict):
                continue
            block_type = block.get("type")
            if block_type == "text":
                items.append(
                    {
                        "kind": "user" if entry_type == "user" else "assistant",
                        "text": block.get("text", ""),
                    }
                )
            elif block_type == "tool_use":
                tool_name = block.get("name", "")
                tool_id = block.get("id", "")
                pending_tools[tool_id] = tool_name
                if tool_name == "IDAPythonExec":
                    code = str(block.get("input", {}).get("code", ""))
                    items.append(
                        {
                            "kind": "script",
                            "code": code,
                            "risk": classify_script_risk(code),
                            "requires_approval": False,
                        }
                    )
                else:
                    items.append(
                        {
                            "kind": "tool",
                            "tool_name": tool_name,
                            "details": summarize_tool_use(tool_name, block.get("input", {})),
                        }
                    )
            elif block_type == "tool_result":
                tool_name = pending_tools.get(block.get("tool_use_id", ""), "")
                result_content = block.get("content", "")
                if isinstance(result_content, list):
                    text = "\n".join(
                        str(item.get("text", ""))
                        for item in result_content
                        if isinstance(item, dict) and item.get("type") == "text"
                    )
                else:
                    text = str(result_content)
                items.append(
                    {
                        "kind": "output" if tool_name == "IDAPythonExec" else "tool_result",
                        "text": text,
                        "is_error": bool(block.get("is_error")),
                    }
                )

    return items
