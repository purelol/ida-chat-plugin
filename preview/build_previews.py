"""Build standalone HTML previews for the IDA Chat UI."""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import webbrowser
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from ida_chat_export import render_transcript_html
from ida_chat_markdown import build_web_syntax_css, render_web_markdown
from ida_chat_theme import build_ui_colors


OUTPUT_DIR = Path(__file__).resolve().parent


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
        "user-bg": colors["user_bubble"],
        "user-fg": colors["user_bubble_text"],
    }
    return "\n".join(f"  --{key}: {value};" for key, value in mapped.items())


def _shared_preview_styles() -> str:
    light = build_ui_colors(False)
    dark = build_ui_colors(True)
    return f"""
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
    }}

    body {{
      margin: 0;
      min-height: 100vh;
      background:
        radial-gradient(circle at top left, var(--surface-alt), transparent 28%),
        linear-gradient(180deg, var(--app-bg) 0%, var(--surface-alt) 160%);
      color: var(--text);
      font-family: "Geist", "Segoe UI", "SF Pro Text", -apple-system, BlinkMacSystemFont, sans-serif;
      line-height: 1.6;
    }}

    a {{
      color: var(--link);
      text-decoration: none;
    }}

    .preview-page {{
      max-width: 1460px;
      margin: 0 auto;
      padding: 24px;
    }}

    .preview-topbar {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 16px;
      margin-bottom: 18px;
    }}

    .preview-meta {{
      display: flex;
      flex-wrap: wrap;
      gap: 12px;
      align-items: center;
    }}

    .preview-title {{
      font-size: 28px;
      line-height: 1.05;
      font-weight: 600;
      letter-spacing: -0.04em;
      margin: 0;
    }}

    .preview-subtitle {{
      margin: 6px 0 0;
      color: var(--text-muted);
      font-size: 14px;
    }}

    .pill {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      border-radius: 999px;
      min-height: 32px;
      padding: 0 14px;
      border: 1px solid var(--border);
      background: color-mix(in srgb, var(--surface) 94%, transparent);
      color: var(--text-muted);
      font-size: 12px;
      font-weight: 600;
      letter-spacing: -0.01em;
      white-space: nowrap;
      box-shadow: inset 0 1px 0 color-mix(in srgb, var(--surface-elevated) 48%, transparent);
    }}

    .theme-toggle,
    .open-link {{
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

    .theme-toggle:hover,
    .open-link:hover {{
      background: var(--surface-alt);
      border-color: var(--ring);
      transform: translateY(-1px);
    }}

    .preview-window {{
      border: 1px solid var(--border);
      border-radius: 28px;
      background: color-mix(in srgb, var(--surface) 96%, transparent);
      overflow: hidden;
      backdrop-filter: blur(18px);
      box-shadow: 0 20px 80px rgba(0, 0, 0, 0.06);
    }}

    .window-chrome {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 14px;
      padding: 14px 18px;
      border-bottom: 1px solid var(--border);
      background: color-mix(in srgb, var(--header-bg) 96%, transparent);
    }}

    .chrome-dots {{
      display: flex;
      gap: 8px;
      align-items: center;
    }}

    .chrome-dot {{
      width: 10px;
      height: 10px;
      border-radius: 999px;
      background: var(--border);
    }}

    .chrome-dot:first-child {{
      background: var(--danger-border);
    }}

    .chrome-dot:nth-child(2) {{
      background: var(--warning-border);
    }}

    .chrome-dot:nth-child(3) {{
      background: var(--success-border);
    }}

    .window-label {{
      font-size: 12px;
      color: var(--text-muted);
      letter-spacing: 0.08em;
      text-transform: uppercase;
      font-weight: 600;
    }}

    .layout-main {{
      display: grid;
      grid-template-columns: 300px minmax(0, 1fr);
      min-height: 840px;
    }}

    .sidebar {{
      border-right: 1px solid var(--border);
      background: color-mix(in srgb, var(--header-bg) 98%, transparent);
      padding: 18px;
      display: flex;
      flex-direction: column;
      gap: 18px;
    }}

    .sidebar-section {{
      display: grid;
      gap: 10px;
    }}

    .sidebar-title {{
      margin: 0;
      font-size: 11px;
      color: var(--text-subtle);
      font-weight: 600;
      letter-spacing: 0.12em;
      text-transform: uppercase;
    }}

    .sidebar-card,
    .session-card,
    .surface-card,
    .settings-card {{
      border: 1px solid var(--border);
      border-radius: 18px;
      background: var(--surface);
    }}

    .sidebar-card {{
      padding: 14px;
      display: grid;
      gap: 8px;
    }}

    .session-card {{
      padding: 14px;
      display: grid;
      gap: 6px;
    }}

    .session-card.active {{
      background: var(--surface-elevated);
      border-color: var(--ring);
    }}

    .session-title {{
      font-size: 14px;
      font-weight: 600;
      letter-spacing: -0.02em;
    }}

    .session-meta {{
      color: var(--text-muted);
      font-size: 12px;
    }}

    .chat-panel {{
      display: flex;
      flex-direction: column;
      min-width: 0;
      background: linear-gradient(180deg, transparent 0%, color-mix(in srgb, var(--surface-alt) 36%, transparent) 100%);
    }}

    .chat-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 14px;
      padding: 18px 22px;
      border-bottom: 1px solid var(--border);
    }}

    .chat-header-copy {{
      display: grid;
      gap: 4px;
    }}

    .chat-header-copy h2 {{
      margin: 0;
      font-size: 24px;
      line-height: 1.05;
      letter-spacing: -0.04em;
    }}

    .chat-header-copy p {{
      margin: 0;
      color: var(--text-muted);
      font-size: 13px;
    }}

    .chat-stream {{
      flex: 1;
      padding: 22px;
      display: grid;
      gap: 16px;
      align-content: start;
      overflow: hidden;
    }}

    .timeline-strip {{
      display: flex;
      align-items: center;
      gap: 8px;
      margin: 18px 22px 0;
      padding: 10px 12px;
      border: 1px solid var(--border);
      border-radius: 18px;
      background: color-mix(in srgb, var(--surface) 96%, transparent);
      flex-wrap: wrap;
    }}

    .timeline-pill {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      min-height: 30px;
      padding: 0 14px;
      border-radius: 999px;
      border: 1px solid var(--border-light);
      background: var(--surface-alt);
      color: var(--text-muted);
      font-size: 12px;
      font-weight: 600;
      letter-spacing: -0.01em;
      white-space: nowrap;
    }}

    .timeline-pill.complete {{
      background: var(--success-soft);
      border-color: var(--success-border);
      color: var(--success-text);
    }}

    .timeline-pill.active {{
      background: var(--warning-soft);
      border-color: var(--warning-border);
      color: var(--warning-text);
    }}

    .timeline-separator {{
      color: var(--text-subtle);
      font-size: 11px;
      font-weight: 700;
    }}

    .chat-message {{
      display: grid;
      gap: 8px;
    }}

    .chat-message.user {{
      justify-items: end;
    }}

    .message-label {{
      font-size: 11px;
      color: var(--text-subtle);
      letter-spacing: 0.12em;
      text-transform: uppercase;
      font-weight: 600;
    }}

    .message-shell {{
      max-width: min(78ch, 100%);
      border: 1px solid var(--border);
      border-radius: 20px;
      background: var(--surface);
      padding: 14px 16px;
    }}

    .chat-message.user .message-shell {{
      background: var(--user-bg);
      border-color: var(--user-bg);
      color: var(--user-fg);
    }}

    .assistant-grid {{
      display: grid;
      grid-template-columns: 18px minmax(0, 1fr);
      gap: 12px;
      align-items: start;
    }}

    .assistant-dot {{
      width: 10px;
      height: 10px;
      border-radius: 999px;
      margin-top: 16px;
      background: var(--success-text);
    }}

    .assistant-dot.info {{
      background: var(--info-text);
    }}

    .assistant-dot.warning {{
      background: var(--warning-text);
    }}

    .message-prose {{
      font-size: 14px;
      color: inherit;
    }}

    .message-prose .md-p {{
      margin: 0 0 10px;
    }}

    .message-prose .md-p:last-child {{
      margin-bottom: 0;
    }}

    .tool-banner {{
      display: inline-flex;
      align-items: center;
      gap: 10px;
      padding: 10px 12px;
      border: 1px solid var(--info-border);
      border-radius: 16px;
      background: var(--info-soft);
      color: var(--info-text);
      font-size: 13px;
    }}

    .composer-shell {{
      padding: 18px 22px 22px;
      border-top: 1px solid var(--border);
      display: grid;
      gap: 12px;
      background: color-mix(in srgb, var(--surface) 96%, transparent);
    }}

    .composer {{
      border: 1px solid var(--border);
      border-radius: 20px;
      background: var(--surface);
      padding: 14px 16px;
      min-height: 126px;
      display: grid;
      gap: 14px;
    }}

    .composer-text {{
      color: var(--text);
      font-size: 14px;
    }}

    .composer-actions {{
      display: flex;
      justify-content: space-between;
      gap: 10px;
      flex-wrap: wrap;
      align-items: center;
    }}

    .button-row {{
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      align-items: center;
    }}

    .button {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      min-height: 34px;
      padding: 0 12px;
      border: 1px solid var(--border);
      border-radius: 999px;
      background: var(--surface);
      color: var(--text);
      font-size: 12px;
      font-weight: 500;
    }}

    .button.primary {{
      background: var(--accent);
      border-color: var(--accent);
      color: var(--accent-text);
    }}

    .statusbar {{
      display: flex;
      justify-content: space-between;
      gap: 10px;
      flex-wrap: wrap;
      color: var(--text-muted);
      font-size: 12px;
    }}

    .settings-layout {{
      display: grid;
      gap: 18px;
      padding: 22px;
    }}

    .settings-hero {{
      display: grid;
      grid-template-columns: minmax(0, 1.3fr) minmax(300px, 0.7fr);
      gap: 18px;
    }}

    .settings-card {{
      padding: 18px;
      display: grid;
      gap: 14px;
    }}

    .settings-card h3,
    .settings-card h4 {{
      margin: 0;
      letter-spacing: -0.02em;
    }}

    .settings-card p {{
      margin: 0;
      color: var(--text-muted);
      font-size: 13px;
    }}

    .settings-grid {{
      display: grid;
      grid-template-columns: repeat(2, minmax(0, 1fr));
      gap: 18px;
    }}

    .option-grid {{
      display: grid;
      gap: 10px;
    }}

    .option-card {{
      border: 1px solid var(--border);
      border-radius: 16px;
      padding: 14px;
      background: var(--surface-alt);
      display: grid;
      gap: 6px;
    }}

    .option-card.active {{
      background: color-mix(in srgb, var(--surface-elevated) 94%, transparent);
      border-color: var(--ring);
    }}

    .toggle-list {{
      display: grid;
      gap: 10px;
    }}

    .toggle-row {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      padding: 12px 14px;
      border: 1px solid var(--border);
      border-radius: 16px;
      background: var(--surface-alt);
    }}

    .toggle-copy {{
      display: grid;
      gap: 4px;
    }}

    .toggle-copy strong {{
      font-size: 14px;
    }}

    .toggle-copy span {{
      color: var(--text-muted);
      font-size: 12px;
    }}

    .toggle {{
      width: 48px;
      height: 28px;
      border-radius: 999px;
      background: var(--border);
      position: relative;
    }}

    .toggle::after {{
      content: "";
      position: absolute;
      top: 3px;
      left: 3px;
      width: 22px;
      height: 22px;
      border-radius: 999px;
      background: #fff;
    }}

    .toggle.on {{
      background: var(--accent);
    }}

    .toggle.on::after {{
      left: 23px;
    }}

    .preview-grid {{
      display: grid;
      gap: 18px;
    }}

    .preview-card {{
      border: 1px solid var(--border);
      border-radius: 26px;
      background: color-mix(in srgb, var(--surface) 96%, transparent);
      overflow: hidden;
    }}

    .preview-card-header {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      padding: 16px 18px;
      border-bottom: 1px solid var(--border);
    }}

    .preview-card-copy {{
      display: grid;
      gap: 4px;
    }}

    .preview-card-copy strong {{
      letter-spacing: -0.02em;
    }}

    .preview-card-copy span {{
      color: var(--text-muted);
      font-size: 13px;
    }}

    .preview-frame {{
      width: 100%;
      height: 720px;
      border: none;
      background: var(--surface);
    }}

    .preview-frame.export {{
      height: 860px;
    }}

    .md-code-wrap {{
      margin: 12px 0;
      border: 1px solid var(--code-border);
      border-radius: 18px;
      overflow: hidden;
      background: var(--code-bg);
      box-shadow: 0 10px 28px rgba(15, 23, 42, 0.08);
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
      text-transform: uppercase;
      letter-spacing: 0.08em;
    }}

    .md-code {{
      margin: 0;
      padding: 16px 18px;
      background: var(--code-bg);
      color: var(--code-text);
      font-family: "Geist Mono", "SFMono-Regular", "Consolas", monospace;
      font-size: 12px;
      line-height: 1.65;
      overflow-x: auto;
      white-space: pre;
      word-break: normal;
      tab-size: 2;
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
      border: none;
      padding: 0;
      color: var(--info-text);
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
      margin: 8px 0 10px;
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

    @media (max-width: 1180px) {{
      .layout-main,
      .settings-hero,
      .settings-grid {{
        grid-template-columns: 1fr;
      }}

      .preview-page {{
        padding: 16px;
      }}
    }}
    """


def _page_shell(title: str, subtitle: str, body: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en" data-theme="light">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{title}</title>
  <style>
{_shared_preview_styles()}
  </style>
</head>
<body>
  <main class="preview-page">
    <section class="preview-topbar">
      <div>
        <h1 class="preview-title">{title}</h1>
        <p class="preview-subtitle">{subtitle}</p>
      </div>
      <div class="preview-meta">
        <span class="pill">Standalone Preview</span>
        <button id="themeToggle" class="theme-toggle" type="button">Use Dark Theme</button>
      </div>
    </section>
    {body}
  </main>
  <script>
    (() => {{
      const storageKey = "ida-chat-preview-theme";
      const root = document.documentElement;
      const button = document.getElementById("themeToggle");
      function applyTheme(theme) {{
        root.dataset.theme = theme;
        button.textContent = theme === "dark" ? "Use Light Theme" : "Use Dark Theme";
      }}
      const stored = window.localStorage.getItem(storageKey);
      applyTheme(stored || "light");
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


def _main_window_markup() -> str:
    assistant_message = render_web_markdown(
        "## Initial read\n\n"
        "> The allocator branch is doing two different size calculations before the copy.\n\n"
        "### What stands out\n\n"
        "- `requested_len` is validated.\n"
        "- `copied_len` is derived later from a signed value.\n"
        "- The final write uses the derived value, not the validated one.\n\n"
        "If you inspect `db.functions.rename()` or `idaapi.get_name()`, they now render as subtle colored references.\n\n"
        "```python\n"
        "def suspicious_copy(dst, src, requested_len, copied_len):\n"
        "    if requested_len <= 0x100:\n"
        "        return memcpy(dst, src, copied_len)\n"
        "```\n\n"
        "| Signal | Why it matters |\n"
        "| --- | --- |\n"
        "| Signed cast | Can wrap into a huge copy |\n"
        "| Mismatched bounds | Validation no longer protects the sink |\n"
    )
    user_message = render_web_markdown(
        "Audit this allocator path and tell me if the signed length can break the guard."
    )
    followup_message = render_web_markdown(
        "Good. Give me a short repro plan and point me to the helper that looks most suspicious."
    )
    return f"""
    <section class="preview-window">
      <div class="window-chrome">
        <div class="chrome-dots">
          <span class="chrome-dot"></span>
          <span class="chrome-dot"></span>
          <span class="chrome-dot"></span>
        </div>
        <span class="window-label">Main Window Preview</span>
        <div class="preview-meta">
          <span class="pill">Light + Dark</span>
          <span class="pill">Sidebar + Chat + Composer</span>
        </div>
      </div>
      <div class="layout-main">
        <aside class="sidebar">
          <div class="sidebar-section">
            <h3 class="sidebar-title">Workspace</h3>
            <div class="sidebar-card">
              <strong>sample.exe</strong>
              <span class="session-meta">3 sessions · Claude Sonnet</span>
            </div>
          </div>
          <div class="sidebar-section">
            <h3 class="sidebar-title">Sessions</h3>
            <div class="session-card active">
              <div class="session-title">Allocator audit</div>
              <div class="session-meta">5 msgs · Updated just now</div>
            </div>
            <div class="session-card">
              <div class="session-title">Decompiler cleanup</div>
              <div class="session-meta">14 msgs · 12 min ago</div>
            </div>
            <div class="session-card">
              <div class="session-title">Import resolver notes</div>
              <div class="session-meta">8 msgs · Yesterday</div>
            </div>
          </div>
          <div class="sidebar-section">
            <h3 class="sidebar-title">Actions</h3>
            <div class="button-row">
              <span class="button primary">New Chat</span>
              <span class="button">Settings</span>
              <span class="button">Export</span>
            </div>
          </div>
        </aside>
        <section class="chat-panel">
          <header class="chat-header">
            <div class="chat-header-copy">
              <h2>IDA Chat</h2>
              <p>Context-aware reverse engineering assistance inside the main docked panel.</p>
            </div>
            <div class="preview-meta">
              <span class="pill">Ready</span>
              <span class="pill">Sonnet</span>
            </div>
          </header>
          <div class="timeline-strip">
            <span class="timeline-pill complete">1. User</span>
            <span class="timeline-separator">→</span>
            <span class="timeline-pill active">2. Thinking</span>
          </div>
          <div class="chat-stream">
            <article class="chat-message user">
              <div class="message-label">User</div>
              <div class="message-shell">
                <div class="message-prose">{user_message}</div>
              </div>
            </article>
            <article class="chat-message">
              <div class="assistant-grid">
                <span class="assistant-dot"></span>
                <div class="message-shell">
                  <div class="message-label">Assistant</div>
                  <div class="message-prose">{assistant_message}</div>
                </div>
              </div>
            </article>
            <article class="chat-message">
              <div class="assistant-grid">
                <span class="assistant-dot info"></span>
                <div class="tool-banner">
                  <strong>IDAPythonExec</strong>
                  <span>Prepared a small inspection helper for the currently selected function.</span>
                </div>
              </div>
            </article>
            <article class="chat-message user">
              <div class="message-label">User</div>
              <div class="message-shell">
                <div class="message-prose">{followup_message}</div>
              </div>
            </article>
          </div>
          <footer class="composer-shell">
            <div class="composer">
              <div class="composer-text">Give me the shortest repro that proves whether the signed-to-unsigned cast can bypass the length check.</div>
              <div class="composer-actions">
                <div class="button-row">
                  <span class="button">Attach context</span>
                  <span class="button">Ask before running scripts</span>
                </div>
                <div class="button-row">
                  <span class="button">Stop</span>
                  <span class="button primary">Send</span>
                </div>
              </div>
            </div>
            <div class="statusbar">
              <span>Enter sends · Shift+Enter newline · Esc stops</span>
              <span>Allocator audit · 5 msgs · $0.08</span>
            </div>
          </footer>
        </section>
      </div>
    </section>
    """


def _settings_markup() -> str:
    return """
    <section class="preview-window">
      <div class="window-chrome">
        <div class="chrome-dots">
          <span class="chrome-dot"></span>
          <span class="chrome-dot"></span>
          <span class="chrome-dot"></span>
        </div>
        <span class="window-label">Settings Preview</span>
        <div class="preview-meta">
          <span class="pill">Authentication</span>
          <span class="pill">Models</span>
          <span class="pill">Execution</span>
        </div>
      </div>
      <div class="settings-layout">
        <div class="settings-hero">
          <article class="settings-card">
            <span class="pill">Connected</span>
            <h3>Configure how the docked chat behaves inside IDA.</h3>
            <p>Previewing the same visual language used by the setup and settings flows, without launching IDA.</p>
            <div class="button-row">
              <span class="button primary">Save Settings</span>
              <span class="button">Test Connection</span>
            </div>
          </article>
          <article class="settings-card">
            <h4>Current profile</h4>
            <div class="option-grid">
              <div class="option-card active">
                <strong>Claude Sonnet</strong>
                <span class="session-meta">Balanced quality and speed for day-to-day reversing.</span>
              </div>
              <div class="option-card">
                <strong>Local login</strong>
                <span class="session-meta">Reuses Claude Code credentials already configured on this machine.</span>
              </div>
            </div>
          </article>
        </div>
        <div class="settings-grid">
          <article class="settings-card">
            <h4>Model selection</h4>
            <div class="option-grid">
              <div class="option-card active">
                <strong>Claude Sonnet</strong>
                <p>Balanced quality and speed for most reverse engineering work.</p>
              </div>
              <div class="option-card">
                <strong>Claude Opus</strong>
                <p>Highest reasoning quality for difficult analysis and reviews.</p>
              </div>
              <div class="option-card">
                <strong>Claude Haiku</strong>
                <p>Fast follow-ups and quick fixes when you do not need the deepest analysis.</p>
              </div>
            </div>
          </article>
          <article class="settings-card">
            <h4>Authentication</h4>
            <div class="option-grid">
              <div class="option-card active">
                <strong>Use Claude on this system</strong>
                <p>No extra setup when Claude Code is already logged in.</p>
              </div>
              <div class="option-card">
                <strong>Sign in with Claude account</strong>
                <p>Browser-based login flow for Claude subscription plans.</p>
              </div>
              <div class="option-card">
                <strong>Anthropic API key</strong>
                <p>Bill usage directly to Anthropic Console with an API key.</p>
              </div>
            </div>
          </article>
          <article class="settings-card">
            <h4>Execution behavior</h4>
            <div class="toggle-list">
              <div class="toggle-row">
                <div class="toggle-copy">
                  <strong>Ask before running generated scripts</strong>
                  <span>Keep generated IDAPython behind an explicit approval step.</span>
                </div>
                <span class="toggle on"></span>
              </div>
              <div class="toggle-row">
                <div class="toggle-copy">
                  <strong>Attach current cursor context automatically</strong>
                  <span>Current address, function, and selection get added to each prompt.</span>
                </div>
                <span class="toggle on"></span>
              </div>
              <div class="toggle-row">
                <div class="toggle-copy">
                  <strong>Redact local paths on export</strong>
                  <span>Hide usernames and absolute binary paths in shared HTML transcripts.</span>
                </div>
                <span class="toggle on"></span>
              </div>
            </div>
          </article>
          <article class="settings-card">
            <h4>Diagnostics and safety</h4>
            <div class="toggle-list">
              <div class="toggle-row">
                <div class="toggle-copy">
                  <strong>Verbose diagnostics</strong>
                  <span>Show detailed errors when connection or tool execution fails.</span>
                </div>
                <span class="toggle"></span>
              </div>
              <div class="toggle-row">
                <div class="toggle-copy">
                  <strong>Reuse last session on open</strong>
                  <span>Return to the latest session instead of creating a new chat each time.</span>
                </div>
                <span class="toggle on"></span>
              </div>
              <div class="toggle-row">
                <div class="toggle-copy">
                  <strong>Connection warmup test</strong>
                  <span>Run a quick Claude health check from the settings panel.</span>
                </div>
                <span class="toggle"></span>
              </div>
            </div>
          </article>
        </div>
      </div>
    </section>
    """


def _index_markup() -> str:
    return """
    <section class="preview-grid">
      <article class="preview-card">
        <div class="preview-card-header">
          <div class="preview-card-copy">
            <strong>Main Window</strong>
            <span>Sidebar, chat stream, tool cards, composer, and status line together.</span>
          </div>
          <a class="open-link" href="./main-window.html" target="_blank" rel="noreferrer">Open standalone</a>
        </div>
        <iframe class="preview-frame" src="./main-window.html" loading="lazy"></iframe>
      </article>
      <article class="preview-card">
        <div class="preview-card-header">
          <div class="preview-card-copy">
            <strong>Settings Window</strong>
            <span>Authentication, model selection, behavior toggles, and save/test actions.</span>
          </div>
          <a class="open-link" href="./settings.html" target="_blank" rel="noreferrer">Open standalone</a>
        </div>
        <iframe class="preview-frame" src="./settings.html" loading="lazy"></iframe>
      </article>
      <article class="preview-card">
        <div class="preview-card-header">
          <div class="preview-card-copy">
            <strong>Exported Chat</strong>
            <span>The actual standalone export page generated from a sample transcript.</span>
          </div>
          <a class="open-link" href="./exported-chat.html" target="_blank" rel="noreferrer">Open standalone</a>
        </div>
        <iframe class="preview-frame export" src="./exported-chat.html" loading="lazy"></iframe>
      </article>
    </section>
    """


def _write_export_preview(output_path: Path) -> None:
    sample_entries = [
        {
            "type": "user",
            "timestamp": "2026-03-07T10:00:00+00:00",
            "message": {
                "role": "user",
                "content": [
                    {
                        "type": "text",
                        "text": "Audit the allocator path and give me the shortest repro plan.",
                    }
                ],
            },
        },
        {
            "type": "assistant",
            "timestamp": "2026-03-07T10:00:05+00:00",
            "message": {
                "role": "assistant",
                "content": [
                    {
                        "type": "text",
                        "text": (
                            "## Initial read\n\n"
                            "> The allocator branch computes the length twice before the sink.\n\n"
                            "- `requested_len` is checked.\n"
                            "- `copied_len` is derived later.\n"
                            "- `db.functions.rename()` is a good place to mark the suspicious helpers.\n\n"
                            "```python\n"
                            "def suspicious_copy(dst, src, requested_len, copied_len):\n"
                            "    if requested_len <= 0x100:\n"
                            "        return memcpy(dst, src, copied_len)\n"
                            "```\n"
                        ),
                    }
                ],
            },
        },
    ]
    with tempfile.TemporaryDirectory(prefix="ida-chat-preview-export-") as tmp_dir:
        tmp_dir_path = Path(tmp_dir)
        session_file = tmp_dir_path / "preview-session.jsonl"
        metadata_file = tmp_dir_path / "preview-session.meta.json"
        session_file.write_text(
            "\n".join(json.dumps(entry, ensure_ascii=False) for entry in sample_entries) + "\n",
            encoding="utf-8",
        )
        metadata_file.write_text(
            json.dumps(
                {
                    "id": "preview",
                    "title": "Export Preview",
                    "created_at": sample_entries[0]["timestamp"],
                    "updated_at": sample_entries[-1]["timestamp"],
                },
                indent=2,
                ensure_ascii=False,
            ),
            encoding="utf-8",
        )
        output_path.write_text(
            render_transcript_html(
                session_file,
                metadata_file=metadata_file,
                binary_path="/tmp/sample-binary.i64",
                paths_redacted=True,
            ),
            encoding="utf-8",
        )


def build_previews(output_dir: Path = OUTPUT_DIR) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)

    main_window_html = _page_shell(
        "IDA Chat Main Window",
        "Preview of the docked chat panel with sessions, messages, and composer.",
        _main_window_markup(),
    )
    settings_html = _page_shell(
        "IDA Chat Settings",
        "Preview of the setup/settings surface with cards and toggles.",
        _settings_markup(),
    )
    index_html = _page_shell(
        "IDA Chat Preview Hub",
        "One place to inspect the main window, settings UI, and exported transcript look.",
        _index_markup(),
    )

    (output_dir / "main-window.html").write_text(main_window_html, encoding="utf-8")
    (output_dir / "settings.html").write_text(settings_html, encoding="utf-8")
    (output_dir / "index.html").write_text(index_html, encoding="utf-8")
    _write_export_preview(output_dir / "exported-chat.html")
    return output_dir / "index.html"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Build standalone HTML previews for the IDA Chat UI.",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=OUTPUT_DIR,
        help="Directory where preview HTML files should be written.",
    )
    parser.add_argument(
        "--no-open",
        action="store_true",
        help="Generate the files but do not open the preview hub in a browser.",
    )
    args = parser.parse_args(argv)

    index_path = build_previews(args.output_dir.resolve())
    print(index_path)
    if not args.no_open:
        webbrowser.open(index_path.as_uri())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
