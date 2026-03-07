"""Single-file HTML transcript export for IDA Chat."""

from __future__ import annotations

from datetime import datetime
import html
import json
from pathlib import Path
from typing import Any

from ida_chat_markdown import build_web_syntax_css, render_web_markdown
from ida_chat_support import normalize_session_entries
from ida_chat_theme import build_ui_colors

_COLLAPSE_THRESHOLD = 10


def _load_entries(session_file: Path) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for raw_line in session_file.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload, dict):
            entries.append(payload)
    return entries


def _load_metadata(session_file: Path) -> dict[str, Any]:
    metadata_path = session_file.with_name(f"{session_file.stem}.meta.json")
    if not metadata_path.exists():
        return {}
    try:
        data = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _format_timestamp(value: object) -> str:
    if not value:
        return "N/A"
    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return str(value)
    return dt.astimezone().strftime("%d %b %Y · %I:%M %p")


def _default_title(session_file: Path, entries: list[dict[str, Any]]) -> str:
    for entry in entries:
        if entry.get("type") != "user":
            continue
        message = entry.get("message", {})
        if not isinstance(message, dict):
            continue
        content = message.get("content", [])
        if not isinstance(content, list):
            continue
        for block in content:
            if isinstance(block, dict) and block.get("type") == "text":
                text = str(block.get("text", "")).strip()
                if text:
                    words = text.split()
                    return " ".join(words[:6])
    return session_file.stem


def _binary_label(binary_path: str | None, session_file: Path) -> str:
    if binary_path:
        return Path(binary_path).name
    return session_file.stem


def _tone_class(kind: str) -> str:
    if kind == "danger":
        return "danger"
    if kind == "success":
        return "success"
    if kind == "warning":
        return "warning"
    return "info"


def _message_kind_label(kind: str) -> str:
    labels = {
        "user": "User",
        "assistant": "Assistant",
        "tool": "Tool",
        "script": "Generated Script",
        "output": "Output",
        "tool_result": "Tool Result",
        "system": "System",
    }
    return labels.get(kind, kind.title())


def _risk_chip_label(risk: object) -> str:
    normalized = str(risk or "unknown")
    if normalized == "read-only":
        return "Read-only"
    if normalized == "mutating":
        return "Mutating"
    return "Needs review"


def _risk_chip_class(risk: object) -> str:
    normalized = str(risk or "unknown")
    if normalized == "read-only":
        return "success"
    if normalized == "mutating":
        return "danger"
    return "warning"


def _markdown_to_html(text: str) -> str:
    return render_web_markdown(text)


def _code_block_html(text: str, title: str) -> str:
    return (
        '<div class="transcript-card">'
        f'<div class="transcript-card-header"><span>{html.escape(title)}</span></div>'
        f'<pre class="code-block"><code>{html.escape(text)}</code></pre>'
        "</div>"
    )


def _details_block(title: str, body_html: str, open_by_default: bool = False) -> str:
    open_attr = " open" if open_by_default else ""
    return (
        f'<details class="transcript-disclosure"{open_attr}>'
        f'<summary>{html.escape(title)}</summary>'
        f'<div class="transcript-disclosure-body">{body_html}</div>'
        "</details>"
    )


def _render_item(item: dict[str, Any]) -> str:
    kind = str(item.get("kind") or "assistant")
    if kind == "user":
        return (
            '<article class="transcript-message transcript-message-user">'
            '<div class="message-meta"><span class="eyebrow-chip">User</span></div>'
            f'<div class="user-bubble">{_markdown_to_html(str(item.get("text", "")))}</div>'
            "</article>"
        )

    if kind == "assistant":
        return (
            '<article class="transcript-message transcript-message-assistant">'
            '<div class="assistant-rail"><span class="assistant-dot">●</span></div>'
            '<div class="assistant-body">'
            '<div class="message-meta"><span class="eyebrow-chip">Assistant</span></div>'
            f'<div class="message-prose">{_markdown_to_html(str(item.get("text", "")))}</div>'
            "</div></article>"
        )

    if kind == "tool":
        details = str(item.get("details", "")).strip()
        tool_name = str(item.get("tool_name", "Tool"))
        body = (
            f'<strong>{html.escape(tool_name)}</strong>'
            + (f"<span>{html.escape(details)}</span>" if details else "")
        )
        return (
            '<article class="transcript-message transcript-message-tool">'
            '<div class="assistant-rail"><span class="assistant-dot assistant-dot-info">●</span></div>'
            f'<div class="tool-banner">{body}</div>'
            "</article>"
        )

    if kind == "script":
        risk = _risk_chip_class(item.get("risk"))
        risk_label = _risk_chip_label(item.get("risk"))
        code = str(item.get("code", ""))
        return (
            '<article class="transcript-message transcript-message-script">'
            '<div class="assistant-rail"><span class="assistant-dot assistant-dot-warning">●</span></div>'
            '<div class="transcript-card">'
            '<div class="transcript-card-header">'
            '<span>Generated IDA Python</span>'
            f'<span class="status-chip status-chip-{risk}">{html.escape(risk_label)}</span>'
            "</div>"
            f'<pre class="code-block"><code>{html.escape(code)}</code></pre>'
            "</div></article>"
        )

    if kind in {"output", "tool_result"}:
        text = str(item.get("text", ""))
        is_error = bool(item.get("is_error"))
        line_count = len(text.strip().splitlines())
        body_html = _code_block_html(text, "Output")
        if line_count > _COLLAPSE_THRESHOLD:
            body_html = _details_block("Output", body_html)
        tone = "danger" if is_error else "success"
        dot = "assistant-dot-danger" if is_error else "assistant-dot-success"
        return (
            f'<article class="transcript-message transcript-message-output transcript-message-{tone}">'
            f'<div class="assistant-rail"><span class="assistant-dot {dot}">●</span></div>'
            f'<div class="output-shell">{body_html}</div>'
            "</article>"
        )

    if kind == "system":
        level = _tone_class("danger" if item.get("level") == "error" else "info")
        return (
            '<article class="transcript-message transcript-message-system">'
            f'<div class="notice-banner notice-banner-{level}">'
            f'<span class="notice-label">{html.escape(_message_kind_label(kind))}</span>'
            f'<span>{_markdown_to_html(str(item.get("text", "")))}</span>'
            "</div></article>"
        )

    return (
        '<article class="transcript-message">'
        f'<div class="message-prose">{_markdown_to_html(str(item.get("text", "")))}</div>'
        "</article>"
    )


def _theme_vars(colors: dict[str, object]) -> str:
    mapped = {
        "app-bg": colors["app_bg"],
        "header-bg": colors["header_bg"],
        "surface": colors["surface"],
        "surface-alt": colors["surface_alt"],
        "surface-elevated": colors["surface_elevated"],
        "text": colors["text"],
        "text-muted": colors["text_muted"],
        "text-subtle": colors["text_subtle"],
        "border": colors["border"],
        "border-light": colors["border_light"],
        "accent": colors["accent"],
        "accent-hover": colors["accent_hover"],
        "accent-text": colors["accent_text"],
        "ring": colors["ring"],
        "link": colors["link"],
        "info-soft": colors["info_soft"],
        "info-border": colors["info_border"],
        "info-text": colors["info_text"],
        "success-soft": colors["success_soft"],
        "success-border": colors["success_border"],
        "success-text": colors["success_text"],
        "warning-soft": colors["warning_soft"],
        "warning-border": colors["warning_border"],
        "warning-text": colors["warning_text"],
        "danger-soft": colors["danger_soft"],
        "danger-border": colors["danger_border"],
        "danger-text": colors["danger_text"],
        "code-bg": colors["code_bg"],
        "code-bg-alt": colors["code_bg_alt"],
        "code-border": colors["code_border"],
        "code-text": colors["code_text"],
        "radius-xs": f"{colors['radius_xs']}px",
        "radius-sm": f"{colors['radius_sm']}px",
        "radius-md": f"{colors['radius_md']}px",
        "radius-lg": f"{colors['radius_lg']}px",
        "radius-xl": f"{colors['radius_xl']}px",
        "user-bg": "#262626" if colors["is_dark"] else "#e8e8e8",
        "user-fg": colors["text"] if colors["is_dark"] else "#1a1a1a",
    }
    return "\n".join(f"  --{key}: {value};" for key, value in mapped.items())


def render_transcript_html(
    session_file: Path,
    *,
    metadata_file: Path | None = None,
    binary_path: str | None = None,
    paths_redacted: bool = False,
) -> str:
    entries = _load_entries(session_file)
    metadata = _load_metadata(metadata_file or session_file)
    items = normalize_session_entries(entries)
    session_title = str(metadata.get("title") or _default_title(metadata_file or session_file, entries))
    binary_label = _binary_label(binary_path, metadata_file or session_file)
    message_count = len(entries)
    started_at = _format_timestamp(entries[0].get("timestamp") if entries else metadata.get("created_at"))
    updated_at = _format_timestamp(entries[-1].get("timestamp") if entries else metadata.get("updated_at"))
    exported_at = _format_timestamp(datetime.now().astimezone().isoformat())
    light = build_ui_colors(False)
    dark = build_ui_colors(True)
    notices = [
        '<div class="notice-banner notice-banner-info"><span class="notice-label">Export</span><span>Single-file IDA Chat transcript</span></div>'
    ]
    if paths_redacted:
        notices.append(
            '<div class="notice-banner notice-banner-success"><span class="notice-label">Privacy</span><span>Local paths and usernames were redacted for sharing.</span></div>'
        )
    if not items:
        notices.append(
            '<div class="notice-banner notice-banner-warning"><span class="notice-label">Empty</span><span>This session does not contain any chat messages yet.</span></div>'
        )
    transcript_html = "\n".join(_render_item(item) for item in items)
    if not transcript_html:
        transcript_html = (
            '<article class="transcript-message transcript-message-system">'
            '<div class="notice-banner notice-banner-warning">'
            '<span class="notice-label">Transcript</span>'
            "<span>No messages were found in this session export.</span>"
            "</div></article>"
        )
    return f"""<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(session_title)} · IDA Chat Export</title>
  <style>
    :root,
    html[data-theme="light"] {{
{_theme_vars(light)}
    }}

    html[data-theme="dark"] {{
{_theme_vars(dark)}
    }}

{build_web_syntax_css("light")}

{build_web_syntax_css("dark")}

    * {{
      box-sizing: border-box;
    }}

    html {{
      color-scheme: light dark;
      scroll-behavior: smooth;
    }}

    body {{
      margin: 0;
      min-height: 100vh;
      background:
        radial-gradient(circle at top left, var(--surface-alt), transparent 34%),
        linear-gradient(180deg, var(--app-bg) 0%, var(--surface-alt) 180%);
      color: var(--text);
      font-family: "Geist", "Segoe UI", "SF Pro Text", -apple-system, BlinkMacSystemFont, sans-serif;
      line-height: 1.6;
    }}

    body::before {{
      content: "";
      position: fixed;
      inset: 0;
      background-image:
        linear-gradient(to right, transparent 0, transparent calc(100% - 1px), rgba(127,127,127,0.08) calc(100% - 1px)),
        linear-gradient(to bottom, transparent 0, transparent calc(100% - 1px), rgba(127,127,127,0.06) calc(100% - 1px));
      background-size: 32px 32px;
      mask-image: linear-gradient(180deg, rgba(0,0,0,0.16), transparent 70%);
      pointer-events: none;
    }}

    a {{
      color: var(--link);
    }}

    .page {{
      position: relative;
      z-index: 1;
      max-width: 1080px;
      margin: 0 auto;
      padding: 32px 20px 56px;
    }}

    .hero {{
      background: color-mix(in srgb, var(--header-bg) 88%, transparent);
      border: 1px solid var(--border);
      border-radius: 26px;
      padding: 24px;
      backdrop-filter: blur(18px);
    }}

    .hero-top {{
      display: flex;
      align-items: flex-start;
      justify-content: space-between;
      gap: 20px;
      flex-wrap: wrap;
    }}

    .eyebrow {{
      color: var(--text-subtle);
      font-size: 11px;
      font-weight: 600;
      letter-spacing: 0.24em;
      text-transform: uppercase;
    }}

    .hero h1 {{
      margin: 10px 0 8px;
      font-size: clamp(30px, 4vw, 44px);
      line-height: 1.05;
      font-weight: 600;
      letter-spacing: -0.04em;
    }}

    .hero-copy {{
      max-width: 720px;
    }}

    .hero-subtitle {{
      margin: 0;
      color: var(--text-muted);
      max-width: 64ch;
      font-size: 14px;
    }}

    .hero-actions {{
      display: flex;
      gap: 10px;
      align-items: center;
    }}

    .theme-toggle {{
      border: 1px solid var(--border);
      border-radius: 999px;
      background: var(--surface);
      color: var(--text);
      padding: 10px 14px;
      font-size: 12px;
      font-weight: 500;
      cursor: pointer;
      transition: background-color 140ms ease, border-color 140ms ease, transform 140ms ease;
    }}

    .theme-toggle:hover {{
      background: var(--surface-alt);
      border-color: var(--ring);
      transform: translateY(-1px);
    }}

    .chip-row {{
      display: flex;
      flex-wrap: wrap;
      gap: 10px;
      margin-top: 18px;
    }}

    .chip,
    .eyebrow-chip,
    .status-chip {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      border-radius: 999px;
      padding: 8px 11px;
      font-size: 12px;
      line-height: 1;
      border: 1px solid var(--border);
      background: var(--surface);
      color: var(--text-muted);
      white-space: nowrap;
    }}

    .eyebrow-chip {{
      padding: 5px 10px;
      text-transform: uppercase;
      letter-spacing: 0.12em;
      font-size: 10px;
      color: var(--text-subtle);
      background: transparent;
    }}

    .status-chip-success {{
      color: var(--success-text);
      background: var(--success-soft);
      border-color: var(--success-border);
    }}

    .status-chip-warning {{
      color: var(--warning-text);
      background: var(--warning-soft);
      border-color: var(--warning-border);
    }}

    .status-chip-danger {{
      color: var(--danger-text);
      background: var(--danger-soft);
      border-color: var(--danger-border);
    }}

    .notice-stack {{
      display: grid;
      gap: 10px;
      margin-top: 18px;
    }}

    .notice-banner {{
      display: flex;
      align-items: flex-start;
      gap: 12px;
      padding: 12px 14px;
      border-radius: var(--radius-lg);
      border: 1px solid var(--border);
      background: var(--surface-alt);
      color: var(--text);
      font-size: 13px;
    }}

    .notice-label {{
      flex: 0 0 auto;
      padding: 5px 8px;
      border-radius: 999px;
      font-size: 10px;
      font-weight: 600;
      letter-spacing: 0.12em;
      text-transform: uppercase;
      border: 1px solid currentColor;
    }}

    .notice-banner-info {{
      background: var(--info-soft);
      border-color: var(--info-border);
      color: var(--info-text);
    }}

    .notice-banner-success {{
      background: var(--success-soft);
      border-color: var(--success-border);
      color: var(--success-text);
    }}

    .notice-banner-warning {{
      background: var(--warning-soft);
      border-color: var(--warning-border);
      color: var(--warning-text);
    }}

    .notice-banner-danger {{
      background: var(--danger-soft);
      border-color: var(--danger-border);
      color: var(--danger-text);
    }}

    .transcript-shell {{
      margin-top: 22px;
      background: color-mix(in srgb, var(--surface) 94%, transparent);
      border: 1px solid var(--border);
      border-radius: 28px;
      overflow: hidden;
      backdrop-filter: blur(14px);
    }}

    .transcript-header {{
      display: flex;
      justify-content: space-between;
      gap: 14px;
      padding: 18px 22px;
      border-bottom: 1px solid var(--border);
      background: color-mix(in srgb, var(--surface) 94%, transparent);
      align-items: center;
      flex-wrap: wrap;
    }}

    .transcript-title {{
      font-size: 18px;
      font-weight: 600;
      letter-spacing: -0.02em;
    }}

    .transcript-meta {{
      color: var(--text-muted);
      font-size: 12px;
      display: flex;
      gap: 10px;
      flex-wrap: wrap;
    }}

    .transcript-stream {{
      padding: 10px 0 20px;
    }}

    .transcript-message {{
      padding: 18px 24px;
    }}

    .transcript-message + .transcript-message {{
      border-top: 1px solid var(--border-light);
    }}

    .transcript-message-user {{
      display: grid;
      justify-items: end;
      gap: 8px;
    }}

    .user-bubble {{
      max-width: min(72ch, 100%);
      padding: 12px 16px;
      border-radius: 18px;
      background: var(--user-bg);
      color: var(--user-fg);
    }}

    .transcript-message-assistant,
    .transcript-message-tool,
    .transcript-message-script,
    .transcript-message-output {{
      display: grid;
      grid-template-columns: 20px minmax(0, 1fr);
      gap: 12px;
    }}

    .assistant-rail {{
      padding-top: 8px;
    }}

    .assistant-dot {{
      color: var(--success-text);
      font-size: 10px;
      line-height: 1;
    }}

    .assistant-dot-info {{
      color: var(--info-text);
    }}

    .assistant-dot-warning {{
      color: var(--warning-text);
    }}

    .assistant-dot-success {{
      color: var(--success-text);
    }}

    .assistant-dot-danger {{
      color: var(--danger-text);
    }}

    .assistant-body,
    .output-shell {{
      min-width: 0;
    }}

    .message-meta {{
      display: flex;
      align-items: center;
      gap: 8px;
      margin-bottom: 8px;
    }}

    .message-prose {{
      color: var(--text);
      font-size: 14px;
    }}

    .message-prose > :first-child {{
      margin-top: 0;
    }}

    .message-prose > :last-child {{
      margin-bottom: 0;
    }}

    .tool-banner {{
      display: inline-flex;
      flex-wrap: wrap;
      gap: 10px;
      align-items: center;
      background: var(--info-soft);
      color: var(--info-text);
      border: 1px solid var(--info-border);
      border-radius: 16px;
      padding: 11px 14px;
      font-size: 13px;
    }}

    .transcript-card {{
      border: 1px solid var(--border);
      border-radius: 18px;
      background: var(--surface-alt);
      overflow: hidden;
    }}

    .transcript-card-header {{
      display: flex;
      justify-content: space-between;
      gap: 12px;
      align-items: center;
      padding: 12px 14px;
      border-bottom: 1px solid var(--border);
      color: var(--text);
      font-size: 12px;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }}

    .code-block,
    .md-code {{
      margin: 0;
      padding: 16px 18px;
      background: var(--code-bg);
      color: var(--code-text);
      font-family: "Geist Mono", "SFMono-Regular", "Consolas", monospace;
      font-size: 12px;
      line-height: 1.65;
      white-space: pre;
      word-break: normal;
      overflow-x: auto;
      tab-size: 2;
    }}

    .md-code-wrap {{
      margin: 12px 0;
      border: 1px solid var(--code-border);
      border-radius: 18px;
      overflow: hidden;
      background: var(--code-bg);
    }}

    .md-code-header {{
      display: flex;
      justify-content: space-between;
      gap: 12px;
      padding: 11px 14px;
      border-bottom: 1px solid var(--code-border);
      background: var(--code-bg-alt);
      color: var(--text-subtle);
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.08em;
      text-transform: uppercase;
    }}

    .md-code-content {{
      display: block;
      min-width: max-content;
    }}

    .md-inline {{
      background: var(--code-bg-alt);
      color: var(--code-text);
      border: 1px solid var(--code-border);
      border-radius: 999px;
      padding: 3px 8px;
      font-family: "Geist Mono", "SFMono-Regular", "Consolas", monospace;
      font-size: 0.92em;
    }}

    .md-inline-api {{
      background: transparent;
      color: var(--info-text);
      border: none;
      padding: 0;
    }}

    .md-link {{
      color: var(--link);
      text-decoration: none;
    }}

    .md-link:hover {{
      color: var(--accent);
    }}

    .md-list {{
      margin: 10px 0 12px;
      padding-left: 22px;
    }}

    .md-list li {{
      padding-left: 4px;
    }}

    .md-list li + li {{
      margin-top: 6px;
    }}

    .md-list li::marker {{
      color: var(--text-muted);
      font-weight: 700;
    }}

    .md-p {{
      margin: 0 0 10px;
    }}

    .md-rule {{
      border: none;
      border-top: 1px solid var(--border);
      margin: 16px 0;
    }}

    .md-h1,
    .md-h2,
    .md-h3 {{
      margin: 14px 0 8px;
      line-height: 1.15;
      letter-spacing: -0.03em;
    }}

    .md-h1 {{
      font-size: 22px;
    }}

    .md-h2 {{
      font-size: 18px;
    }}

    .md-h3 {{
      font-size: 15px;
    }}

    .md-quote {{
      margin: 10px 0;
      padding: 9px 14px;
      border: 1px solid var(--border-light);
      border-radius: 18px;
      background: var(--surface-alt);
      color: var(--text-muted);
    }}

    .md-quote .md-p {{
      margin: 0;
    }}

    .md-quote .md-p + .md-p {{
      margin-top: 6px;
    }}

    .md-api-heading {{
      margin: 8px 0;
      color: var(--info-text);
      font-size: 14px;
      font-weight: 400;
      font-family: "Geist Mono", "SFMono-Regular", "Consolas", monospace;
    }}

    .md-table {{
      width: 100%;
      margin: 12px 0;
      border-collapse: collapse;
      border: 1px solid var(--border);
      border-radius: var(--radius-md);
      overflow: hidden;
    }}

    .md-th,
    .md-td {{
      padding: 10px 12px;
      border: 1px solid var(--border);
      text-align: left;
      vertical-align: top;
    }}

    .md-th {{
      background: var(--surface-alt);
      font-weight: 600;
    }}

    .md-task-list {{
      list-style: none;
      padding-left: 0;
    }}

    .task-list-item {{
      list-style: none;
      margin-left: 0;
    }}

    .task-list-item input {{
      margin-right: 8px;
    }}

    .transcript-disclosure {{
      border: 1px solid var(--border);
      border-radius: 18px;
      background: var(--surface);
      overflow: hidden;
    }}

    .transcript-disclosure summary {{
      cursor: pointer;
      list-style: none;
      padding: 14px 16px;
      font-size: 12px;
      font-weight: 600;
      letter-spacing: 0.08em;
      text-transform: uppercase;
      color: var(--text-muted);
      border-bottom: 1px solid transparent;
    }}

    .transcript-disclosure[open] summary {{
      border-bottom-color: var(--border);
      background: var(--surface-alt);
      color: var(--text);
    }}

    .transcript-disclosure-body {{
      padding: 0;
    }}

    @media (max-width: 720px) {{
      .page {{
        padding: 18px 12px 36px;
      }}

      .hero {{
        padding: 18px;
        border-radius: 22px;
      }}

      .transcript-shell {{
        border-radius: 22px;
      }}

      .transcript-message,
      .transcript-header {{
        padding-left: 16px;
        padding-right: 16px;
      }}

      .transcript-message-assistant,
      .transcript-message-tool,
      .transcript-message-script,
      .transcript-message-output {{
        grid-template-columns: 14px minmax(0, 1fr);
        gap: 10px;
      }}
    }}
  </style>
</head>
<body>
  <main class="page">
    <section class="hero">
      <div class="hero-top">
        <div class="hero-copy">
          <div class="eyebrow">IDA Chat Transcript</div>
          <h1>{html.escape(session_title)}</h1>
          <p class="hero-subtitle">A standalone export rendered with the same visual language as the live IDA Chat panel.</p>
        </div>
        <div class="hero-actions">
          <button id="themeToggle" class="theme-toggle" type="button">Toggle Theme</button>
        </div>
      </div>
      <div class="chip-row">
        <span class="chip">Binary · {html.escape(binary_label)}</span>
        <span class="chip">Session · {html.escape((metadata_file or session_file).stem[:8])}</span>
        <span class="chip">{message_count} entries</span>
        <span class="chip">Started · {html.escape(started_at)}</span>
        <span class="chip">Updated · {html.escape(updated_at)}</span>
        <span class="chip">Exported · {html.escape(exported_at)}</span>
      </div>
      <div class="notice-stack">
        {"".join(notices)}
      </div>
    </section>

    <section class="transcript-shell">
      <div class="transcript-header">
        <div class="transcript-title">Conversation</div>
        <div class="transcript-meta">
          <span>Single file HTML</span>
          <span>Responsive</span>
          <span>{"Paths redacted" if paths_redacted else "Paths preserved"}</span>
        </div>
      </div>
      <div class="transcript-stream">
        {transcript_html}
      </div>
    </section>
  </main>

  <script>
    (() => {{
      const storageKey = "ida-chat-export-theme";
      const root = document.documentElement;
      const button = document.getElementById("themeToggle");

      function applyTheme(theme) {{
        root.dataset.theme = theme;
        button.textContent = theme === "dark" ? "Use Light Theme" : "Use Dark Theme";
        button.setAttribute("aria-pressed", theme === "dark" ? "true" : "false");
      }}

      const stored = window.localStorage.getItem(storageKey);
      const preferred = stored || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
      applyTheme(preferred);

      button.addEventListener("click", () => {{
        const next = root.dataset.theme === "dark" ? "light" : "dark";
        window.localStorage.setItem(storageKey, next);
        applyTheme(next);
      }});
    }})();
  </script>
</body>
</html>
"""
