"""
IDA Chat - LLM Chat Client Plugin for IDA Pro

A dockable chat interface powered by Claude Agent SDK for
AI-assisted reverse engineering within IDA Pro.
"""

# pyright: reportMissingModuleSource=false

import asyncio
import html
import os
import re
import subprocess
import sys
from datetime import datetime
from io import StringIO

# Signal to core that we're running inside IDA Pro (enables UI interaction API)
os.environ["IDA_CHAT_INSIDE_IDA"] = "1"
from pathlib import Path
from typing import Any, Callable, TypedDict, cast

import ida_idaapi
import ida_kernwin
import ida_lines
import ida_settings
from ida_domain import Database
from PySide6.QtWidgets import (
    QVBoxLayout,
    QHBoxLayout,
    QGridLayout,
    QLabel,
    QPushButton,
    QWidget,
    QScrollArea,
    QFrame,
    QSizePolicy,
    QPlainTextEdit,
    QApplication,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QCheckBox,
    QAbstractButton,
    QFileDialog,
    QMessageBox,
    QDialog,
    QSplitter,
)
from PySide6.QtCore import Qt, Signal, QThread, QObject, QTimer
from PySide6.QtGui import QColor, QFont, QFontDatabase, QKeyEvent, QPalette, QPixmap

# Ensure local modules are importable
sys.path.insert(0, str(Path(__file__).parent.resolve()))

from ida_chat_core import (
    IDAChatCore,
    IDAChatRuntimeError,
    ChatCallback,
    test_claude_connection,
    export_transcript,
)
from ida_chat_history import MessageHistory
from ida_chat_support import (
    apply_auth_environment,
    build_progress_timeline_steps,
    can_finalize_settings,
    current_session_message_count,
    DiagnosticReport,
    describe_run_outcome,
    PromptContext,
    RunOutcome,
    ScriptApprovalRequest,
    ScriptDecision,
    ScriptRisk,
    auth_mode_has_credentials,
    find_claude_cli_path,
    VerificationState,
)
from ida_chat_theme import build_ui_colors


# Plugin metadata
PLUGIN_NAME = "IDA Chat"
PLUGIN_COMMENT = "LLM Chat Client for IDA Pro"
PLUGIN_HELP = "A chat interface for interacting with LLMs from within IDA Pro"

# Action configuration
ACTION_ID = "ida_chat:toggle_widget"
ACTION_NAME = "Show IDA Chat"
ACTION_TOOLTIP = "Show or hide the IDA Chat panel"

# Widget form title
WIDGET_TITLE = "IDA Chat"
FONT_DIR = Path(__file__).parent / "assets" / "fonts"
GEIST_SANS_FONT = FONT_DIR / "Geist-Variable.ttf"
GEIST_MONO_FONT = FONT_DIR / "GeistMono-Variable.ttf"
_ui_font_families: dict[str, str] | None = None
_UNSET = cast(object, None)
DEFAULT_MODEL_PROFILE = "sonnet"
_INITIAL_ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY")
_INITIAL_CLAUDE_CODE_OAUTH_TOKEN = os.environ.get("CLAUDE_CODE_OAUTH_TOKEN")


def text_interaction_flags(
    *flags: Qt.TextInteractionFlag,
) -> Qt.TextInteractionFlag:
    """Build PySide6-safe text interaction flags without enum bitwise shims."""
    combined = 0
    for flag in flags:
        combined |= int(flag.value)
    return Qt.TextInteractionFlag(combined)


TEXT_SELECTABLE_FLAGS = text_interaction_flags(
    Qt.TextInteractionFlag.TextSelectableByMouse,
    Qt.TextInteractionFlag.TextSelectableByKeyboard,
)

TEXT_SELECTABLE_LINK_FLAGS = text_interaction_flags(
    Qt.TextInteractionFlag.TextSelectableByMouse,
    Qt.TextInteractionFlag.TextSelectableByKeyboard,
    Qt.TextInteractionFlag.LinksAccessibleByMouse,
)


class ModelPreset(TypedDict):
    label: str
    short_label: str
    description: str
    model: str
    betas: list[str]
    badge: str
    tone: str


MODEL_PRESETS: dict[str, ModelPreset] = {
    "sonnet": {
        "label": "Claude Sonnet",
        "short_label": "Sonnet",
        "description": "Balanced quality and speed for most reverse engineering work.",
        "model": "sonnet",
        "betas": [],
        "badge": "S",
        "tone": "info",
    },
    "opus": {
        "label": "Claude Opus",
        "short_label": "Opus",
        "description": "Highest reasoning quality for difficult analysis, planning, and reviews.",
        "model": "opus",
        "betas": [],
        "badge": "O",
        "tone": "neutral",
    },
    "opus_1m": {
        "label": "Claude Opus 1M",
        "short_label": "Opus 1M",
        "description": "Opus with the 1M context beta for very large projects.",
        "model": "opus",
        "betas": ["context-1m-2025-08-07"],
        "badge": "1M",
        "tone": "success",
    },
    "haiku": {
        "label": "Claude Haiku",
        "short_label": "Haiku",
        "description": "Fastest option for simple questions, quick edits, and follow-ups.",
        "model": "haiku",
        "betas": [],
        "badge": "H",
        "tone": "warning",
    },
}
AUTH_OPTIONS: dict[str, dict[str, str]] = {
    "system": {
        "tab": "Local",
        "title": "Use Claude on this system",
        "description": "Reuses the Claude Code login already configured on this system. No extra setup needed.",
        "tone": "success",
        "breadcrumb": "Local login",
        "placeholder": "Claude Code login will be used from this system.",
    },
    "oauth": {
        "tab": "Claude Account",
        "title": "Sign in with your Claude account",
        "description": "Best for Pro, Max, Team, or Enterprise plans. It opens Claude Code's browser login flow on this machine.",
        "tone": "info",
        "breadcrumb": "Claude account",
        "placeholder": "Optional fallback: paste the generated Claude OAuth token...",
    },
    "api_key": {
        "tab": "API Key",
        "title": "Use an Anthropic Console key",
        "description": "Use an API key when billing should come from Anthropic Console usage instead of your Claude subscription.",
        "tone": "warning",
        "breadcrumb": "API key",
        "placeholder": "Paste your Anthropic API key...",
    },
}


def _qt_app() -> QApplication | None:
    """Return the live QApplication instance when available."""
    app = QApplication.instance()
    return app if isinstance(app, QApplication) else None


def _coerce_int(value: object, default: int = 0) -> int:
    """Best-effort integer coercion for loosely-typed settings/theme values."""
    try:
        return int(cast(int | float | str, value))
    except (TypeError, ValueError):
        return default


def _coerce_str_list(value: object) -> list[str]:
    """Normalize a settings/theme value into a list of strings."""
    if isinstance(value, list):
        return [str(item) for item in value]
    return []


def _coerce_script_risk(value: object) -> ScriptRisk:
    """Normalize persisted script risk values to the supported literal set."""
    normalized = str(value)
    if normalized in {"read-only", "mutating", "unknown"}:
        return cast(ScriptRisk, normalized)
    return "unknown"


def get_ui_fonts() -> dict[str, str]:
    """Load bundled Geist fonts once and return active UI family names."""
    global _ui_font_families
    if _ui_font_families is not None:
        return _ui_font_families

    app = _qt_app()
    families = {
        "font_sans": app.font().family() if app else "sans-serif",
        "font_mono": "monospace",
    }
    if not app:
        _ui_font_families = families
        return families

    for key, font_path in (
        ("font_sans", GEIST_SANS_FONT),
        ("font_mono", GEIST_MONO_FONT),
    ):
        if not font_path.exists():
            continue
        font_id = QFontDatabase.addApplicationFont(str(font_path))
        if font_id == -1:
            continue
        loaded_families = QFontDatabase.applicationFontFamilies(font_id)
        if loaded_families:
            families[key] = loaded_families[0]

    if families["font_sans"]:
        app_font = app.font()
        app_font.setFamily(families["font_sans"])
        app_font.setWeight(QFont.Weight.Normal)
        app.setFont(app_font)

    _ui_font_families = families
    return families


def get_ida_colors():
    """Return semantic UI colors for the current IDA light/dark mode."""
    app = _qt_app()
    palette = app.palette() if app else QPalette()
    window = palette.color(QPalette.ColorRole.Window)
    base = palette.color(QPalette.ColorRole.Base)
    is_dark = ((window.lightnessF() + base.lightnessF()) / 2.0) < 0.58
    colors = build_ui_colors(is_dark)
    colors.update(get_ui_fonts())
    return colors


def apply_selection_palette():
    """Set app-wide text selection to teal, theme-aware (light/dark)."""
    app = _qt_app()
    if not app:
        return
    colors = get_ida_colors()
    is_dark = str(colors.get("app_bg", "#ffffff")).lower() not in ("#ffffff", "#fafafa")
    if is_dark:
        sel_bg = QColor(11, 30, 27)    # teal-900
        sel_fg = QColor(89, 193, 178)  # teal-300
    else:
        sel_bg = QColor(204, 251, 248)  # teal-100
        sel_fg = QColor(52, 119, 110)   # teal-800
    palette = app.palette()
    palette.setColor(QPalette.ColorRole.Highlight, sel_bg)
    palette.setColor(QPalette.ColorRole.HighlightedText, sel_fg)
    app.setPalette(palette)


def button_style(
    colors: dict[str, object], variant: str = "secondary", compact: bool = False
) -> str:
    """Shared button styling for the plugin UI."""
    specs = {
        "primary": {
            "bg": colors["accent"],
            "fg": colors["accent_text"],
            "border": colors["accent"],
            "hover": colors["accent_hover"],
            "pressed": colors["accent_hover"],
        },
        "secondary": {
            "bg": colors["surface"],
            "fg": colors["button_text"],
            "border": colors["border"],
            "hover": colors["surface_hover"],
            "pressed": colors["surface_hover"],
        },
        "ghost": {
            "bg": colors["surface"],
            "fg": colors["text_muted"],
            "border": colors["border"],
            "hover": colors["surface_alt"],
            "pressed": colors["surface_hover"],
        },
        "danger": {
            "bg": colors["danger_soft"],
            "fg": colors["danger_text"],
            "border": colors["danger_border"],
            "hover": colors["danger_border"],
            "pressed": colors["danger_border"],
        },
        "info": {
            "bg": colors["info_soft"],
            "fg": colors["info_text"],
            "border": colors["info_border"],
            "hover": colors["info_border"],
            "pressed": colors["info_border"],
        },
        "success": {
            "bg": colors["success_soft"],
            "fg": colors["success_text"],
            "border": colors["success_border"],
            "hover": colors["success_border"],
            "pressed": colors["success_border"],
        },
    }
    spec = specs[variant]
    padding = "0 8px" if compact else "0 12px"
    radius = f"{colors['radius_sm'] if compact else colors['radius_md']}px"
    min_height = "28px" if compact else "32px"
    border = (
        f"1px solid {spec['border']}"
        if spec["border"] != "transparent"
        else "1px solid transparent"
    )
    hover_fg = (
        colors["accent_text"]
        if variant == "primary"
        else (colors["text"] if variant == "ghost" else spec["fg"])
    )
    return f"""
        QPushButton {{
            background-color: {spec["bg"]};
            color: {spec["fg"]};
            border: {border};
            border-radius: {radius};
            padding: {padding};
            font-weight: 400;
            font-size: 12px;
            letter-spacing: 0.02em;
            min-height: {min_height};
            min-width: 0px;
        }}
        QPushButton:hover {{
            background-color: {spec["hover"]};
            color: {hover_fg};
        }}
        QPushButton:pressed {{
            background-color: {spec["pressed"]};
            color: {hover_fg};
        }}
        QPushButton:disabled {{
            background-color: {colors["surface_alt"]};
            color: {colors["text_subtle"]};
            border-color: {colors["border"]};
        }}
    """


def line_edit_style(colors: dict[str, object], radius: int = 12) -> str:
    """Shared single-line input styling."""
    return f"""
        QLineEdit {{
            background-color: {colors["surface"]};
            color: {colors["text"]};
            border: 1px solid {colors["border"]};
            border-radius: {radius}px;
            padding: 8px 12px;
        }}
        QLineEdit:focus {{
            border-color: {colors["ring"]};
            background-color: {colors["surface"]};
        }}
    """


def status_banner_style(colors: dict[str, object], tone: str = "neutral") -> str:
    """Shared inline status banner styling."""
    palette = {
        "neutral": (colors["text_muted"], colors["surface_alt"], colors["border"]),
        "success": (
            colors["success_text"],
            colors["success_soft"],
            colors["success_border"],
        ),
        "danger": (
            colors["danger_text"],
            colors["danger_soft"],
            colors["danger_border"],
        ),
        "info": (colors["info_text"], colors["info_soft"], colors["info_border"]),
    }
    text_color, bg_color, border_color = palette.get(tone, palette["neutral"])
    return (
        f"QLabel {{ color: {text_color}; background-color: {bg_color}; border: 1px solid "
        f"{border_color}; border-radius: {colors['radius_md']}px; padding: 8px 10px; }}"
    )


def _teal_selection(colors: dict[str, object]) -> tuple[str, str]:
    """Return (sel_bg, sel_fg) teal colors based on dark/light theme."""
    is_dark = str(colors.get("app_bg", "#ffffff")).lower() not in ("#ffffff", "#fafafa")
    if is_dark:
        return "rgb(11,30,27)", "rgb(89,193,178)"
    return "rgb(204,251,248)", "rgb(52,119,110)"


def plain_text_style(colors: dict[str, object]) -> str:
    """Shared multi-line composer styling."""
    sel_bg, _ = _teal_selection(colors)
    return f"""
        QPlainTextEdit {{
            background-color: {colors["surface"]};
            color: {colors["text"]};
            border: 1px solid {colors["border"]};
            border-radius: {colors["radius_lg"]}px;
            padding: 10px 12px;
            selection-background-color: {sel_bg};
        }}
        QPlainTextEdit:focus {{
            border-color: {colors["ring"]};
            background-color: {colors["surface"]};
        }}
    """


def dialog_style(colors: dict[str, object]) -> str:
    """Shared shadcn-inspired dialog styling with no shadow treatment."""
    return f"""
        QDialog, QMessageBox, QFileDialog, QInputDialog {{
            background-color: {colors["surface"]};
            color: {colors["text"]};
        }}
        QLabel {{
            color: {colors["text"]};
        }}
        QListView, QListWidget, QTreeView {{
            background-color: {colors["surface"]};
            color: {colors["text"]};
            border: 1px solid {colors["border"]};
            border-radius: {colors["radius_lg"]}px;
            padding: 4px;
        }}
        QLineEdit, QPlainTextEdit {{
            background-color: {colors["surface"]};
            color: {colors["text"]};
            border: 1px solid {colors["border"]};
            border-radius: {colors["radius_md"]}px;
            padding: 8px 10px;
            selection-background-color: {_teal_selection(colors)[0]};
        }}
        QLineEdit:focus, QPlainTextEdit:focus {{
            border-color: {colors["ring"]};
        }}
        {button_style(colors, "secondary", compact=True)}
    """


def apply_dialog_chrome(dialog: QWidget) -> dict[str, object]:
    """Apply the shared dialog styling and return the active color theme."""
    colors = get_ida_colors()
    dialog.setStyleSheet(dialog_style(colors))
    return colors


def style_dialog_button(
    button: QAbstractButton | None, colors: dict[str, object], variant: str
) -> None:
    """Apply button chrome to a popup action if the widget exists."""
    if button is None:
        return
    button.setCursor(Qt.CursorShape.PointingHandCursor)
    button.setStyleSheet(button_style(colors, variant, compact=True))


def format_timestamp_label(timestamp: object) -> str:
    """Format a session timestamp for sidebar display."""
    if not timestamp:
        return "No activity yet"
    try:
        dt = datetime.fromisoformat(str(timestamp))
    except ValueError:
        return str(timestamp)
    local_dt = dt.astimezone()
    hour = local_dt.strftime("%I").lstrip("0") or "12"
    return f"{local_dt.strftime('%d %b')} · {hour}:{local_dt.strftime('%M')} {local_dt.strftime('%p')}"


def preformatted_html(text: str) -> str:
    """Escape text for use inside a rich text <pre> block."""
    import html

    return (
        "<pre style='margin: 0; white-space: pre-wrap; word-wrap: break-word;'>"
        f"{html.escape(text)}"
        "</pre>"
    )


# -----------------------------------------------------------------------------
# Settings Management (using ida-settings)
# -----------------------------------------------------------------------------


def get_show_wizard() -> bool:
    """Returns whether to show the setup wizard."""
    if ida_settings.has_current_plugin_setting("show_wizard"):
        return bool(ida_settings.get_current_plugin_setting("show_wizard"))
    return True  # Default to true


def set_show_wizard(value: bool) -> None:
    """Set whether to show the setup wizard."""
    ida_settings.set_current_plugin_setting("show_wizard", value)


def get_model_profile() -> str:
    """Return the saved Claude model profile."""
    if ida_settings.has_current_plugin_setting("model_profile"):
        value = str(
            ida_settings.get_current_plugin_setting("model_profile") or ""
        ).strip()
        if value in MODEL_PRESETS:
            return value
    return DEFAULT_MODEL_PROFILE


def set_model_profile(value: str) -> None:
    """Persist the active Claude model profile."""
    ida_settings.set_current_plugin_setting(
        "model_profile",
        value if value in MODEL_PRESETS else DEFAULT_MODEL_PROFILE,
    )


def get_model_config(profile: str | None = None) -> ModelPreset:
    """Resolve a Claude model profile into runtime settings."""
    resolved = profile if profile in MODEL_PRESETS else get_model_profile()
    return MODEL_PRESETS[resolved]


def get_model_display_name(profile: str | None = None) -> str:
    """Return the short label shown in the header and status bar."""
    return str(get_model_config(profile)["short_label"])


def get_auth_type() -> str | None:
    """Returns 'system', 'oauth', or 'api_key', or None if not configured."""
    if ida_settings.has_current_plugin_setting("auth_type"):
        value = ida_settings.get_current_plugin_setting("auth_type")
        return str(value) if value is not None else None
    return None


def get_api_key() -> str | None:
    """Returns the stored API key/token."""
    if ida_settings.has_current_plugin_setting("api_key"):
        value = ida_settings.get_current_plugin_setting("api_key")
        return str(value) if value is not None else None
    return None


def save_auth_settings(auth_type: str, api_key: str | None = None) -> None:
    """Store authentication settings and disable wizard."""
    ida_settings.set_current_plugin_setting("auth_type", auth_type)
    if api_key:
        ida_settings.set_current_plugin_setting("api_key", api_key)
    elif ida_settings.has_current_plugin_setting("api_key"):
        ida_settings.del_current_plugin_setting("api_key")
    # Disable wizard after saving settings
    set_show_wizard(False)


def get_require_script_approval() -> bool:
    """Return whether generated scripts need approval before execution."""
    if ida_settings.has_current_plugin_setting("require_script_approval"):
        return bool(ida_settings.get_current_plugin_setting("require_script_approval"))
    return False


def set_require_script_approval(value: bool) -> None:
    """Persist script approval behavior."""
    ida_settings.set_current_plugin_setting("require_script_approval", value)


def get_auto_context_enabled() -> bool:
    """Return whether prompt context should be attached automatically."""
    if ida_settings.has_current_plugin_setting("auto_context"):
        return bool(ida_settings.get_current_plugin_setting("auto_context"))
    return True


def set_auto_context_enabled(value: bool) -> None:
    """Persist automatic prompt context behavior."""
    ida_settings.set_current_plugin_setting("auto_context", value)


def get_redact_export_paths() -> bool:
    """Return whether transcript exports should redact local paths."""
    if ida_settings.has_current_plugin_setting("redact_export_paths"):
        return bool(ida_settings.get_current_plugin_setting("redact_export_paths"))
    return True


def set_redact_export_paths(value: bool) -> None:
    """Persist transcript export redaction behavior."""
    ida_settings.set_current_plugin_setting("redact_export_paths", value)


def apply_auth_to_environment() -> None:
    """Set environment variables based on stored settings."""
    auth_type = get_auth_type()
    api_key = get_api_key()
    apply_auth_environment(
        os.environ,
        auth_type,
        api_key,
        original_api_key=_INITIAL_ANTHROPIC_API_KEY,
        original_oauth_token=_INITIAL_CLAUDE_CODE_OAUTH_TOKEN,
    )


class CollapsibleSection(QFrame):
    """Expandable/collapsible section for long content."""

    # Threshold for collapsing (lines)
    COLLAPSE_THRESHOLD = 10

    def __init__(
        self,
        title: str,
        content: str,
        collapsed: bool = True,
        parent=None,
        flat: bool = False,
    ):
        super().__init__(parent)
        self._collapsed = collapsed
        self._title = title
        self._content = content
        self._flat = flat
        self._setup_ui()

    def _setup_ui(self):
        colors = get_ida_colors()

        if self._flat:
            self.setStyleSheet("QFrame { background-color: transparent; border: none; }")
        else:
            outer_bg = colors["surface"]
            outer_border = colors["border"]
            self.setStyleSheet(f"""
                QFrame {{
                    background-color: {outer_bg};
                    border: 1px solid {outer_border};
                    border-radius: {colors["radius_lg"]}px;
                }}
            """)

        layout = QVBoxLayout(self)
        if self._flat:
            layout.setContentsMargins(12, 12, 12, 12)
            layout.setSpacing(4)
        else:
            layout.setContentsMargins(6, 6, 6, 6)
            layout.setSpacing(6)

        # Header with toggle button
        self.header = QPushButton()
        self._update_header_text()
        self.header.setCursor(Qt.CursorShape.PointingHandCursor)
        if self._flat:
            self.header.setStyleSheet(f"""
                QPushButton {{
                    background-color: transparent;
                    color: {colors["text_muted"]};
                    border: none;
                    text-align: left;
                    padding: 0 0 4px 0;
                    font-size: 11px;
                    font-weight: 500;
                }}
                QPushButton:hover {{
                    color: {colors["text"]};
                    background-color: transparent;
                }}
            """)
        else:
            self.header.setStyleSheet(f"""
                QPushButton {{
                    background-color: {colors["surface_alt"]};
                    color: {colors["text_muted"]};
                    border: 1px solid {colors["border"]};
                    border-radius: {colors["radius_md"]}px;
                    text-align: left;
                    padding: 8px 10px;
                    font-size: 11px;
                    font-weight: 500;
                }}
                QPushButton:hover {{
                    color: {colors["text"]};
                    background-color: {colors["surface_hover"]};
                }}
            """)
        self.header.clicked.connect(self._toggle)
        layout.addWidget(self.header)

        # Content area
        self.content_label = QLabel()
        self.content_label.setTextFormat(Qt.TextFormat.RichText)
        self.content_label.setWordWrap(True)
        self.content_label.setTextInteractionFlags(TEXT_SELECTABLE_FLAGS)
        self.content_label.setStyleSheet(f"""
            QLabel {{
                background-color: {colors["code_bg"]};
                color: {colors["code_text"]};
                padding: 8px 10px;
                border: none;
                border-radius: {colors["radius_md"]}px;
                font-family: "{colors["font_mono"]}";
                font-size: 11px;
            }}
        """)
        self._update_content()
        layout.addWidget(self.content_label)

    def _update_header_text(self):
        arrow = "▶" if self._collapsed else "▼"
        line_count = len(self._content.strip().split("\n"))
        self.header.setText(f"{arrow} {self._title} ({line_count} lines)")

    def _update_content(self):
        import html

        _pre = "white-space: pre-wrap; word-break: break-all; margin: 0;"
        if self._collapsed:
            lines = self._content.strip().split("\n")
            preview = "\n".join(lines[:3])
            if len(lines) > 3:
                preview += f"\n... ({len(lines) - 3} more lines)"
            self.content_label.setText(f'<pre style="{_pre}">{html.escape(preview)}</pre>')
        else:
            self.content_label.setText(f'<pre style="{_pre}">{html.escape(self._content)}</pre>')

    def _toggle(self):
        self._collapsed = not self._collapsed
        self._update_header_text()
        self._update_content()

    def set_content(self, title: str, content: str, collapsed: bool | None = None):
        """Update the section title/content in place."""
        self._title = title
        self._content = content
        if collapsed is not None:
            self._collapsed = collapsed
        self._update_header_text()
        self._update_content()

    @staticmethod
    def should_collapse(content: str) -> bool:
        """Check if content should be collapsed."""
        return len(content.strip().split("\n")) > CollapsibleSection.COLLAPSE_THRESHOLD


def markdown_to_html(text: str) -> str:
    """Convert markdown to HTML for display in QLabel with rich text."""
    import html

    # Get theme-aware colors
    colors = get_ida_colors()
    code_bg = colors["code_bg"]
    code_fg = colors["code_text"]
    link_color = colors["link"]

    # Extract fenced code blocks first to protect them from other transforms
    code_blocks: list[str] = []

    def stash_code_block(match):
        code = html.escape(match.group(2))
        placeholder = f"\x00CODE{len(code_blocks)}\x00"
        code_blocks.append(
            f'<pre style="background-color: {code_bg}; color: {code_fg}; '
            f'font-family: monospace; font-size: 11px; '
            f"padding: 10px 12px; border-radius: {colors['radius_md']}px; "
            f'margin: 6px 0; white-space: pre-wrap; word-break: break-all;">'
            f"<code>{code}</code></pre>"
        )
        return placeholder

    text = re.sub(r"```(\w*)\n?(.*?)```", stash_code_block, text, flags=re.DOTALL)

    # Escape remaining HTML
    text = html.escape(text)

    # Inline code (`code`) — after escape so backtick content is safe
    text = re.sub(
        r"`([^`]+)`",
        rf'<code style="background-color: {code_bg}; color: {code_fg}; '
        rf'font-family: monospace; padding: 1px 5px; border-radius: {colors["radius_xs"]}px;">\1</code>',
        text,
    )

    # Headers
    text = re.sub(r"^### (.+)$", r'<b style="font-size: 13px;">\1</b>', text, flags=re.MULTILINE)
    text = re.sub(r"^## (.+)$", r'<b style="font-size: 14px;">\1</b>', text, flags=re.MULTILINE)
    text = re.sub(r"^# (.+)$", r'<b style="font-size: 16px;">\1</b>', text, flags=re.MULTILINE)

    # Bold and italic (must run before newline conversion)
    text = re.sub(r"\*\*\*(.+?)\*\*\*", r"<b><i>\1</i></b>", text)
    text = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", text)
    text = re.sub(r"__(.+?)__", r"<b>\1</b>", text)
    text = re.sub(r"(?<!\w)\*([^*\n]+)\*(?!\w)", r"<i>\1</i>", text)
    text = re.sub(r"(?<!\w)_([^_\n]+)_(?!\w)", r"<i>\1</i>", text)

    # Strikethrough
    text = re.sub(r"~~(.+?)~~", r"<s>\1</s>", text)

    # Links [text](url)
    text = re.sub(
        r"\[([^\]]+)\]\(([^)]+)\)",
        rf'<a href="\2" style="color: {link_color}; text-decoration: underline;">\1</a>',
        text,
    )

    # Bullet lists — gather consecutive items into <ul>
    def replace_list_block(match):
        items = re.sub(r"^[ \t]*[-*] (.+)$", r"<li>\1</li>", match.group(0), flags=re.MULTILINE)
        return f"<ul style='margin: 4px 0; padding-left: 20px;'>{items}</ul>"

    text = re.sub(r"(?:^[ \t]*[-*] .+\n?)+", replace_list_block, text, flags=re.MULTILINE)

    # Numbered lists
    def replace_ol_block(match):
        items = re.sub(r"^\d+\. (.+)$", r"<li>\1</li>", match.group(0), flags=re.MULTILINE)
        return f"<ol style='margin: 4px 0; padding-left: 20px;'>{items}</ol>"

    text = re.sub(r"(?:^\d+\. .+\n?)+", replace_ol_block, text, flags=re.MULTILINE)

    # Horizontal rule
    text = re.sub(r"^---+$", "<hr/>", text, flags=re.MULTILINE)

    # Paragraphs: blank lines → paragraph breaks
    text = re.sub(r"\n{2,}", "<br><br>", text)
    text = text.replace("\n", "<br>")

    # Restore code blocks
    for i, block in enumerate(code_blocks):
        text = text.replace(f"\x00CODE{i}\x00", block)

    return text


class MessageType:
    """Message type constants for visual differentiation."""

    TEXT = "text"  # Normal assistant text
    TOOL_USE = "tool_use"  # Tool invocation (muted, italic)
    SCRIPT = "script"  # Script code (monospace, dark bg)
    OUTPUT = "output"  # Script output (monospace, gray bg)
    ERROR = "error"  # Error message (red accent)
    USER = "user"  # User message


class SessionsSidebar(QFrame):
    """Recent sessions panel with search and session actions."""

    new_chat_requested = Signal()
    resume_requested = Signal(str)
    settings_requested = Signal()
    delete_requested = Signal(str)
    export_requested = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._sessions: list[dict[str, object]] = []
        self._suppress_selection_resume = False
        self._sort_mode = "updated_desc"
        self._setup_ui()

    def _setup_ui(self):
        colors = get_ida_colors()
        self.setObjectName("sessionsSidebar")
        self.setStyleSheet(f"""
            QFrame#sessionsSidebar {{
                background-color: {colors["header_bg"]};
                border: 1px solid {colors["border"]};
                border-radius: {colors["radius_xl"]}px;
            }}
            QListWidget {{
                background-color: transparent;
                color: {colors["text"]};
                border: none;
                padding: 0;
                outline: none;
            }}
            QListWidget::item {{
                background-color: transparent;
                border: 1px solid transparent;
                border-radius: {colors["radius_md"]}px;
                padding: 0;
                margin: 4px 0;
            }}
            QListWidget::item:hover {{
                background-color: {colors["surface_alt"]};
                border: 1px solid {colors["border_light"]};
            }}
            QListWidget::item:selected {{
                background-color: {colors["accent_soft"]};
                color: {colors["text"]};
                border: 1px solid {colors["border"]};
            }}
            QListWidget::item:hover:selected {{
                background-color: {colors["accent_soft"]};
                border: 1px solid {colors["border"]};
            }}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        title_row = QHBoxLayout()
        title_row.setContentsMargins(0, 0, 0, 0)
        title_row.setSpacing(8)

        title_block = QVBoxLayout()
        title_block.setContentsMargins(0, 0, 0, 0)
        title_block.setSpacing(2)

        eyebrow = QLabel("History")
        eyebrow.setStyleSheet(
            f"QLabel {{ color: {colors['text_subtle']}; font-size: 10px; letter-spacing: 0.12em; text-transform: uppercase; }}"
        )
        title_block.addWidget(eyebrow)

        title = QLabel("Sessions")
        title.setStyleSheet(
            f"QLabel {{ color: {colors['text']}; font-size: 18px; font-weight: 600; }}"
        )
        title_block.addWidget(title)
        title_row.addLayout(title_block, stretch=1)

        self.settings_btn = QPushButton("‹  Settings")
        self.settings_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.settings_btn.setStyleSheet(button_style(colors, "secondary", compact=True))
        self.settings_btn.clicked.connect(self.settings_requested.emit)
        title_row.addWidget(self.settings_btn)
        layout.addLayout(title_row)

        self.new_btn = QPushButton("New Chat")
        self.new_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.new_btn.setStyleSheet(button_style(colors, "success"))
        self.new_btn.clicked.connect(self.new_chat_requested.emit)
        layout.addWidget(self.new_btn)

        self.current_label = QLabel("Active session: New Chat")
        self.current_label.setStyleSheet(f"""
            QLabel {{
                background-color: {colors["accent_soft"]};
                color: {colors["text"]};
                border: 1px solid {colors["border"]};
                border-radius: {colors["radius_md"]}px;
                padding: 8px 10px;
                font-size: 11px;
                font-weight: 500;
            }}
        """)
        layout.addWidget(self.current_label)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search chats...")
        self.search_input.setStyleSheet(
            line_edit_style(colors, radius=_coerce_int(colors["radius_lg"], 12))
        )
        self.search_input.textChanged.connect(self._apply_filter)

        self.sort_switch = QFrame()
        self.sort_switch.setStyleSheet(f"""
            QFrame {{
                background-color: {colors["surface"]};
                border: 1px solid {colors["border"]};
                border-radius: {colors["radius_lg"]}px;
            }}
        """)
        sort_switch_layout = QHBoxLayout(self.sort_switch)
        sort_switch_layout.setContentsMargins(3, 3, 3, 3)
        sort_switch_layout.setSpacing(0)

        self.sort_latest_btn = QPushButton("Latest")
        self.sort_oldest_btn = QPushButton("Oldest")
        for button in (self.sort_latest_btn, self.sort_oldest_btn):
            button.setCheckable(True)
            button.setCursor(Qt.CursorShape.PointingHandCursor)
            button.setMinimumHeight(28)
            button.setStyleSheet(f"""
                QPushButton {{
                    background-color: transparent;
                    color: {colors["text_muted"]};
                    border: none;
                    border-radius: {colors["radius_md"]}px;
                    padding: 0 10px;
                    font-size: 11px;
                    font-weight: 500;
                }}
                QPushButton:hover {{
                    color: {colors["text"]};
                    background-color: {colors["surface_alt"]};
                }}
                QPushButton:checked {{
                    color: {colors["text"]};
                    background-color: {colors["accent_soft"]};
                }}
            """)
            sort_switch_layout.addWidget(button)

        self.sort_latest_btn.clicked.connect(lambda: self._on_sort_changed("updated_desc"))
        self.sort_oldest_btn.clicked.connect(lambda: self._on_sort_changed("updated_asc"))
        self._update_sort_buttons()

        controls_row = QHBoxLayout()
        controls_row.setContentsMargins(0, 0, 0, 0)
        controls_row.setSpacing(8)
        controls_row.setAlignment(Qt.AlignmentFlag.AlignVCenter)
        controls_row.addWidget(self.search_input, stretch=1)
        controls_row.addWidget(
            self.sort_switch, alignment=Qt.AlignmentFlag.AlignVCenter
        )
        layout.addLayout(controls_row)

        self.list_widget = QListWidget()
        self.list_widget.itemSelectionChanged.connect(self._resume_selected_if_needed)
        self.list_widget.itemActivated.connect(lambda _item: self._resume_selected())
        layout.addWidget(self.list_widget, stretch=1)

        self.setMinimumWidth(280)
        self.setMaximumWidth(360)

    @staticmethod
    def _session_query_blob(session: dict[str, object]) -> str:
        searchable_parts = [
            str(session.get("title") or ""),
            str(session.get("first_message") or ""),
            str(session.get("id") or ""),
            f"{_coerce_int(session.get('message_count'))} msgs",
        ]
        return " ".join(" ".join(searchable_parts).lower().split())

    @staticmethod
    def _session_sort_key(session: dict[str, object], key_name: str) -> str:
        return str(session.get(key_name) or "")

    def _visible_sessions(self) -> list[dict[str, object]]:
        query = " ".join(self.search_input.text().strip().lower().split())
        terms = [term for term in query.split(" ") if term]
        sessions = list(self._sessions)

        if terms:
            filtered: list[dict[str, object]] = []
            for session in sessions:
                haystack = self._session_query_blob(session)
                if all(term in haystack for term in terms):
                    filtered.append(session)
            sessions = filtered

        reverse = self._sort_mode != "updated_asc"
        sessions.sort(
            key=lambda session: self._session_sort_key(session, "updated_at")
            or self._session_sort_key(session, "created_at"),
            reverse=reverse,
        )
        return sessions

    def _update_sort_buttons(self):
        self.sort_latest_btn.setChecked(self._sort_mode == "updated_desc")
        self.sort_oldest_btn.setChecked(self._sort_mode == "updated_asc")

    def _on_sort_changed(self, mode: str):
        self._sort_mode = mode
        self._update_sort_buttons()
        self._apply_filter()

    def _build_session_row(self, session: dict[str, object]) -> QWidget:
        colors = get_ida_colors()
        row = QWidget()
        row.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, False)
        row.setStyleSheet("QWidget { background: transparent; border: none; }")

        layout = QVBoxLayout(row)
        layout.setContentsMargins(12, 9, 12, 9)
        layout.setSpacing(4)

        title = str(session.get("title") or "New Chat").strip() or "New Chat"
        if len(title) > 34:
            title = f"{title[:31]}..."

        title_row = QHBoxLayout()
        title_row.setContentsMargins(0, 0, 0, 0)
        title_row.setSpacing(8)

        title_label = QLabel(title)
        title_label.setStyleSheet(
            f"QLabel {{ color: {colors['text']}; font-size: 12px; font-weight: 500; background: transparent; }}"
        )
        title_row.addWidget(title_label, stretch=1)

        if session.get("is_current"):
            active_pill = QLabel("Active")
            active_pill.setAlignment(Qt.AlignmentFlag.AlignCenter)
            active_pill.setFixedHeight(16)
            active_pill.setStyleSheet(f"""
                QLabel {{
                    color: {colors["success_text"]};
                    background-color: {colors["success_soft"]};
                    border: 1px solid {colors["success_border"]};
                    border-radius: 8px;
                    padding: 0 6px;
                    font-size: 9px;
                    font-weight: 500;
                }}
            """)
            title_row.addWidget(
                active_pill,
                alignment=Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignRight,
            )

        layout.addLayout(title_row)

        meta_row = QHBoxLayout()
        meta_row.setContentsMargins(0, 0, 0, 0)
        meta_row.setSpacing(7)

        count_label = QLabel(f"{_coerce_int(session.get('message_count'))} msgs")
        count_label.setStyleSheet(
            f"QLabel {{ color: {colors['text_muted']}; font-size: 11px; background: transparent; }}"
        )
        meta_row.addWidget(count_label)

        dot_label = QLabel("·")
        dot_label.setStyleSheet(
            f"QLabel {{ color: {colors['text_subtle']}; font-size: 10px; background: transparent; }}"
        )
        meta_row.addWidget(dot_label)

        time_label = QLabel(
            format_timestamp_label(
                session.get("updated_at") or session.get("created_at")
            )
        )
        time_label.setStyleSheet(
            f"QLabel {{ color: {colors['text_muted']}; font-size: 11px; background: transparent; }}"
        )
        meta_row.addWidget(time_label)

        if session.get("last_export_path"):
            export_dot = QLabel("·")
            export_dot.setStyleSheet(
                f"QLabel {{ color: {colors['text_subtle']}; font-size: 10px; background: transparent; }}"
            )
            meta_row.addWidget(export_dot)

            export_label = QLabel("Exported")
            export_label.setStyleSheet(
                f"QLabel {{ color: {colors['info_text']}; font-size: 10px; font-weight: 500; background: transparent; }}"
            )
            meta_row.addWidget(export_label)

        meta_row.addStretch(1)
        layout.addLayout(meta_row)
        return row

    def _apply_filter(self):
        self._suppress_selection_resume = True
        self.list_widget.clear()
        current_item = None
        for session in self._visible_sessions():
            item = QListWidgetItem()
            item.setData(Qt.ItemDataRole.UserRole, session)
            item.setToolTip(str(session.get("first_message") or ""))
            row = self._build_session_row(session)
            item.setSizeHint(row.sizeHint())
            self.list_widget.addItem(item)
            self.list_widget.setItemWidget(item, row)
            if session.get("is_current"):
                current_item = item
        if current_item:
            self.list_widget.setCurrentItem(current_item)
        self._suppress_selection_resume = False

    def set_sessions(self, sessions: list[dict[str, object]]):
        self._sessions = sessions
        current = next((item for item in sessions if item.get("is_current")), None)
        current_title = str((current or {}).get("title") or "New Chat")
        self.current_label.setText(f"Active session: {current_title}")
        self._apply_filter()

    def selected_session_id(self) -> str | None:
        item = self.list_widget.currentItem()
        if not item:
            return None
        session = item.data(Qt.ItemDataRole.UserRole) or {}
        session_id = session.get("id")
        return str(session_id) if session_id else None

    def _resume_selected(self):
        session_id = self.selected_session_id()
        current = next(
            (
                session
                for session in self._sessions
                if str(session.get("id")) == session_id
            ),
            None,
        )
        if session_id and not (current or {}).get("is_current"):
            self.resume_requested.emit(session_id)

    def _resume_selected_if_needed(self):
        if self._suppress_selection_resume:
            return
        self._resume_selected()

class CodeBlock(QFrame):
    """Monospaced code/output panel used across chat cards."""

    def __init__(self, title: str, body: str, tone: str = "script", parent=None):
        super().__init__(parent)
        self.title = title
        self.body = body
        self.tone = tone
        self._setup_ui()

    def _setup_ui(self):
        colors = get_ida_colors()
        palettes = {
            "script": (colors["code_bg"], colors["accent"], colors["code_text"]),
            "output": (
                colors["code_bg_alt"],
                colors["success_text"],
                colors["code_text"],
            ),
            "error": (
                colors["danger_soft"],
                colors["danger_text"],
                colors["danger_text"],
            ),
        }
        background, accent, text_color = palettes.get(
            self.tone,
            (colors["code_bg"], colors["accent"], colors["code_text"]),
        )

        self.setStyleSheet(f"""
            QFrame {{
                background-color: {background};
                border: none;
                border-radius: {colors["radius_md"]}px;
            }}
            QLabel {{
                background-color: transparent;
            }}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)

        heading = QLabel(self.title.upper())
        heading.setStyleSheet(
            f"QLabel {{ color: {accent}; font-size: 10px; letter-spacing: 0.12em; font-weight: 600; }}"
        )
        layout.addWidget(heading)

        body = QLabel(preformatted_html(self.body))
        body.setTextFormat(Qt.TextFormat.RichText)
        body.setWordWrap(True)
        body.setTextInteractionFlags(TEXT_SELECTABLE_FLAGS)
        body.setStyleSheet(
            f'QLabel {{ color: {text_color}; font-family: "{colors["font_mono"]}"; font-size: 11px; line-height: 1.45; }}'
        )
        layout.addWidget(body)


class ScriptReviewCard(QFrame):
    """Script preview widget with optional approval actions."""

    decision_made = Signal(str, str)

    def __init__(self, request: ScriptApprovalRequest, parent=None):
        super().__init__(parent)
        self.request = request
        self._setup_ui()

    def _setup_ui(self):
        colors = get_ida_colors()
        risk_colors = {
            "mutating": colors["danger_text"],
            "read-only": colors["success_text"],
            "unknown": colors["warning_text"],
        }
        self.setObjectName("scriptReviewCard")

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(10)

        self.setStyleSheet(f"""
            QFrame#scriptReviewCard {{
                background-color: transparent;
                border: none;
            }}
            QLabel {{
                color: {colors["text"]};
            }}
        """)

        heading_row = QHBoxLayout()
        heading_row.setContentsMargins(0, 0, 0, 0)
        heading_row.setSpacing(8)

        title_block = QVBoxLayout()
        title_block.setContentsMargins(0, 0, 0, 0)
        title_block.setSpacing(2)

        eyebrow = QLabel("Script review")
        eyebrow.setStyleSheet(
            f"QLabel {{ color: {colors['text_subtle']}; font-size: 10px; letter-spacing: 0.12em; font-weight: 500; }}"
        )
        title_block.addWidget(eyebrow)

        heading = QLabel(
            f"Script {self.request.script_index} of {self.request.total_scripts}"
        )
        heading.setStyleSheet("font-weight: 600; font-size: 16px;")
        title_block.addWidget(heading)
        heading_row.addLayout(title_block, stretch=1)

        _risk_labels = {"mutating": "MUTATING", "read-only": "READ ONLY", "unknown": "UNKNOWN"}
        _risk_border = colors["danger_border"] if self.request.risk == "mutating" else colors["success_border"] if self.request.risk == "read-only" else colors["warning_border"]
        _risk_bg = colors["danger_soft"] if self.request.risk == "mutating" else colors["success_soft"] if self.request.risk == "read-only" else colors["warning_soft"]
        risk = QLabel(_risk_labels.get(self.request.risk, self.request.risk.upper()))
        risk.setAlignment(Qt.AlignmentFlag.AlignCenter)
        risk.setStyleSheet(f"""
            QLabel {{
                background-color: {_risk_bg};
                color: {risk_colors.get(self.request.risk, colors["text"])};
                border: 1px solid {_risk_border};
                border-radius: 8px;
                padding: 1px 7px;
                font-size: 9px;
                font-weight: 600;
                letter-spacing: 0.08em;
            }}
        """)
        heading_row.addWidget(risk)
        layout.addLayout(heading_row)

        summary = QLabel(
            "Review generated IDAPython before it touches the database."
            if self.request.requires_approval
            else "This script was auto-approved by current settings."
        )
        summary.setWordWrap(True)
        summary.setStyleSheet(f"QLabel {{ color: {colors['text_muted']}; }}")
        layout.addWidget(summary)

        layout.addWidget(
            CodeBlock("IDAPython preview", self.request.preview, tone="script")
        )

        self.status_label = QLabel(
            "Waiting for approval..."
            if self.request.requires_approval
            else "Auto-approved"
        )
        self.status_label.setStyleSheet(f"""
            QLabel {{
                color: {colors["text_muted"]};
                font-size: 11px;
            }}
        """)
        layout.addWidget(self.status_label)

        details = CollapsibleSection("Full Script", self.request.code, collapsed=True, flat=True)
        layout.addWidget(details)

        self.buttons_row = QHBoxLayout()
        self.buttons_row.setSpacing(8)
        self.approve_btn = QPushButton("Approve")
        self.skip_btn = QPushButton("Skip")
        self.cancel_btn = QPushButton("Cancel")
        self.approve_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.skip_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.cancel_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.approve_btn.setStyleSheet(button_style(colors, "primary"))
        self.skip_btn.setStyleSheet(button_style(colors, "secondary"))
        self.cancel_btn.setStyleSheet(button_style(colors, "danger"))
        self.approve_btn.clicked.connect(lambda: self._resolve("approve"))
        self.skip_btn.clicked.connect(lambda: self._resolve("skip"))
        self.cancel_btn.clicked.connect(lambda: self._resolve("cancel"))
        self.buttons_row.addWidget(self.approve_btn)
        self.buttons_row.addWidget(self.skip_btn)
        self.buttons_row.addWidget(self.cancel_btn)

        buttons_container = QWidget()
        buttons_container.setLayout(self.buttons_row)
        buttons_container.setVisible(self.request.requires_approval)
        self.buttons_container = buttons_container
        layout.addWidget(buttons_container)

    def _resolve(self, decision: str):
        self.approve_btn.setEnabled(False)
        self.skip_btn.setEnabled(False)
        self.cancel_btn.setEnabled(False)
        self.status_label.setText(f"Decision: {decision}")
        self.decision_made.emit(self.request.request_id, decision)


class ProgressTimeline(QFrame):
    """Compact progress timeline showing agent stages."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._script_count = 0
        self._current_stage = ""
        self._is_complete = False
        self._setup_ui()

    def _setup_ui(self):
        colors = get_ida_colors()
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {colors["surface"]};
                border: 1px solid {colors["border"]};
                border-radius: {colors["radius_lg"]}px;
            }}
        """)

        self._layout = QHBoxLayout(self)
        self._layout.setContentsMargins(12, 8, 12, 8)
        self._layout.setSpacing(6)

        self.timeline_label = QLabel("")
        self.timeline_label.setStyleSheet(
            f"color: {colors['text_muted']}; font-size: 11px;"
        )
        self._layout.addWidget(self.timeline_label)
        self._layout.addStretch()

        self.setVisible(False)

    def reset(self):
        """Reset the timeline for a new conversation."""
        self._script_count = 0
        self._current_stage = "User"
        self._is_complete = False
        self._update_display()
        self.setVisible(True)

    def add_stage(self, name: str):
        """Add a new stage to the timeline."""
        # Track scripts by parsing the number from "Script N"
        if name.startswith("Script "):
            try:
                self._script_count = int(name.split()[1])
            except (IndexError, ValueError):
                pass
        self._current_stage = name
        self._update_display()

    def complete(self):
        """Mark the timeline as complete."""
        self._is_complete = True
        self._current_stage = "Done"
        self._update_display()

    def hide_timeline(self):
        """Hide the timeline."""
        self.setVisible(False)

    def _update_display(self):
        """Update the timeline display with compact summary."""
        colors = get_ida_colors()
        parts = []

        for index, label, state in build_progress_timeline_steps(
            self._script_count,
            self._current_stage,
            self._is_complete,
        ):
            color = (
                colors["success_text"]
                if state == "complete"
                else colors["warning_text"]
            )
            weight = "600" if state != "complete" or index > 1 else "normal"
            parts.append(
                f"<span style='color: {color}; font-weight: {weight};'><b>{index}.</b> {html.escape(label)}</span>"
            )

        self.timeline_label.setText(" → ".join(parts))


class ChatMessage(QFrame):
    """A single chat message bubble with optional status indicator."""

    def __init__(
        self,
        text: str,
        is_user: bool = True,
        is_processing: bool = False,
        msg_type: str = MessageType.TEXT,
        parent=None,
    ):
        super().__init__(parent)
        self.is_user = is_user
        self._is_processing = is_processing
        self._msg_type = msg_type if not is_user else MessageType.USER
        self._blink_visible = True
        self._blink_timer: QTimer | None = None
        self._status_indicator: QLabel | None = None
        self.message_widget: QLabel | CodeBlock
        self._raw_text = text
        self._setup_ui(text)

    def _setup_ui(self, text: str):
        """Set up the message bubble UI."""
        colors = get_ida_colors()
        self.setStyleSheet("QFrame { background: transparent; border: none; }")

        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 3, 12, 3)
        layout.setSpacing(10)

        if self.is_user:
            # User message - right aligned, bubble style
            self.message_widget = QLabel(text)
            self.message_widget.setWordWrap(True)
            self.message_widget.setTextInteractionFlags(TEXT_SELECTABLE_FLAGS)
            self.message_widget.setSizePolicy(
                QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Minimum
            )
            self.message_widget.setMaximumWidth(480)
            layout.addStretch()
            _user_bg = "#262626" if colors["is_dark"] else "#e8e8e8"
            _user_fg = colors["text"] if colors["is_dark"] else "#1a1a1a"
            self.message_widget.setStyleSheet(f"""
                QLabel {{
                    background-color: {_user_bg};
                    color: {_user_fg};
                    border-radius: {colors["radius_lg"]}px;
                    padding: 10px 14px;
                    font-weight: 400;
                }}
            """)
            layout.addWidget(self.message_widget)
        else:
            # Status indicator for assistant messages (small dot)
            self._status_indicator = QLabel("●")
            self._status_indicator.setFixedWidth(16)
            self._status_indicator.setAlignment(
                Qt.AlignmentFlag.AlignCenter | Qt.AlignmentFlag.AlignTop
            )
            self._update_indicator_style()
            layout.addWidget(self._status_indicator)

            # Apply type-specific styling
            if self._msg_type == MessageType.TOOL_USE:
                self.message_widget = QLabel()
                self.message_widget.setTextFormat(Qt.TextFormat.RichText)
                self.message_widget.setWordWrap(True)
                self.message_widget.setTextInteractionFlags(TEXT_SELECTABLE_FLAGS)
                self.message_widget.setText(
                    f"<b style='color: {colors['success_text']};'>{text}</b>"
                )
                self.message_widget.setStyleSheet(f"""
                    QLabel {{
                        background-color: transparent;
                        color: {colors["success_text"]};
                        padding: 2px 0;
                        font-size: 12px;
                    }}
                """)
            elif self._msg_type == MessageType.SCRIPT:
                self.message_widget = CodeBlock("IDAPython", text, tone="script")
            elif self._msg_type == MessageType.OUTPUT:
                self.message_widget = CodeBlock("Output", text, tone="output")
            elif self._msg_type == MessageType.ERROR:
                self.message_widget = QLabel()
                self.message_widget.setTextFormat(Qt.TextFormat.RichText)
                self.message_widget.setWordWrap(True)
                self.message_widget.setOpenExternalLinks(True)
                self.message_widget.setTextInteractionFlags(TEXT_SELECTABLE_LINK_FLAGS)
                self.message_widget.setText(markdown_to_html(text))
                self.message_widget.setStyleSheet(f"""
                    QLabel {{
                        background-color: {colors["danger_soft"]};
                        color: {colors["danger_text"]};
                        border-left: 3px solid {colors["danger_border"]};
                        border-radius: 0;
                        padding: 8px 12px;
                    }}
                """)
            else:
                self.message_widget = QLabel()
                self.message_widget.setTextFormat(Qt.TextFormat.RichText)
                self.message_widget.setWordWrap(True)
                self.message_widget.setOpenExternalLinks(True)
                self.message_widget.setTextInteractionFlags(TEXT_SELECTABLE_LINK_FLAGS)
                self.message_widget.setText(markdown_to_html(text))
                self.message_widget.setStyleSheet(f"""
                    QLabel {{
                        background-color: transparent;
                        color: {colors["text"]};
                        padding: 2px 0;
                        line-height: 1.6;
                    }}
                """)

            self.message_widget.setSizePolicy(
                QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum
            )
            layout.addWidget(self.message_widget)

            # Start blinking if processing
            if self._is_processing:
                self._start_blinking()

    def _update_indicator_style(self):
        """Update the status indicator color."""
        colors = get_ida_colors()
        if not self._status_indicator:
            return
        if self._is_processing:
            # Yellow/orange for processing, blink visibility
            color = colors["warning_text"] if self._blink_visible else "transparent"
        else:
            # Green for complete
            color = colors["success_text"]
        self._status_indicator.setStyleSheet(
            f"QLabel {{ color: {color}; font-size: 10px; }}"
        )

    def _start_blinking(self):
        """Start the blinking animation."""
        if self._blink_timer:
            return
        self._blink_timer = QTimer(self)
        self._blink_timer.timeout.connect(self._toggle_blink)
        self._blink_timer.start(500)  # Blink every 500ms

    def _stop_blinking(self):
        """Stop the blinking animation."""
        if self._blink_timer:
            self._blink_timer.stop()
            self._blink_timer = None
        self._blink_visible = True

    def _toggle_blink(self):
        """Toggle blink visibility."""
        self._blink_visible = not self._blink_visible
        self._update_indicator_style()

    def set_complete(self):
        """Mark this message as complete (green indicator)."""
        self._is_processing = False
        self._stop_blinking()
        self._update_indicator_style()

    def update_text(self, text: str):
        """Update the message text."""
        if self.is_user and isinstance(self.message_widget, QLabel):
            self.message_widget.setText(text)
        elif isinstance(self.message_widget, QLabel):
            self.message_widget.setText(markdown_to_html(text))

    def append_text(self, text: str):
        """Append text to this message (TEXT type only)."""
        if not self.is_user and self._msg_type == MessageType.TEXT and isinstance(self.message_widget, QLabel):
            self._raw_text = self._raw_text + "\n\n" + text
            self.message_widget.setText(markdown_to_html(self._raw_text))


class ChatHistoryWidget(QScrollArea):
    """Scrollable chat history container."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._current_processing_message: ChatMessage | None = None
        self._setup_ui()

    def _setup_ui(self):
        """Set up the chat history UI."""
        self.setWidgetResizable(True)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.setFrameShape(QFrame.Shape.NoFrame)
        colors = get_ida_colors()
        self.setStyleSheet(
            f"QScrollArea {{ background-color: {colors['app_bg']}; border: none; }}"
        )

        # Container widget for messages
        self.container = QWidget()
        self.container.setObjectName("chatHistoryContainer")
        self.container.setStyleSheet(
            f"QWidget#chatHistoryContainer {{ background-color: {colors['app_bg']}; }}"
        )
        self._layout = QVBoxLayout(self.container)
        self._layout.setSpacing(8)
        self._layout.setContentsMargins(12, 12, 12, 12)
        self._layout.addStretch(1)  # Stretch at top pushes messages to bottom

        self.setWidget(self.container)

    def add_message(
        self,
        text: str,
        is_user: bool = True,
        is_processing: bool = False,
        msg_type: str = MessageType.TEXT,
    ) -> ChatMessage:
        """Add a message to the chat history."""
        message = ChatMessage(text, is_user, is_processing, msg_type)
        self._layout.addWidget(message)

        # Track processing message
        if is_processing:
            self._current_processing_message = message

        self.scroll_to_bottom()
        return message

    def mark_current_complete(self):
        """Mark the current processing message as complete."""
        if self._current_processing_message:
            self._current_processing_message.set_complete()
            self._current_processing_message = None

    def scroll_to_bottom(self):
        """Scroll the chat history to the bottom."""
        QTimer.singleShot(
            10,
            lambda: self.verticalScrollBar().setValue(
                self.verticalScrollBar().maximum()
            ),
        )

    def add_collapsible(
        self, title: str, content: str, collapsed: bool = True
    ) -> CollapsibleSection:
        """Add a collapsible section to the chat history."""
        section = CollapsibleSection(title, content, collapsed)
        self._layout.addWidget(section)
        self.scroll_to_bottom()
        return section

    def add_script_review(self, request: ScriptApprovalRequest) -> ScriptReviewCard:
        """Add a script review card to the chat history."""
        card = ScriptReviewCard(request)
        self._layout.addWidget(card)
        self.scroll_to_bottom()
        return card

    def clear_history(self):
        """Clear all messages from the chat history."""
        self._current_processing_message = None
        # Remove all widgets except the stretch at index 0
        while self._layout.count() > 1:
            item = self._layout.takeAt(
                1
            )  # Always take from index 1, leaving stretch at 0
            if item is None:
                continue
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()


class ChatInputWidget(QPlainTextEdit):
    """Multi-line text input with Enter to send and history navigation."""

    message_submitted = Signal(str)
    cancel_requested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._history: list[str] = []
        self._history_index = -1  # -1 means not browsing history
        self._current_input = ""  # Stores current input when browsing history
        self._setup_ui()

    def set_history(self, messages: list[str]):
        """Set the message history for up/down navigation.

        Args:
            messages: List of previous user messages (oldest first).
        """
        self._history = messages
        self._history_index = -1

    def add_to_history(self, message: str):
        """Add a message to the history.

        Args:
            message: The message to add.
        """
        # Don't add duplicates of the last message
        if not self._history or self._history[-1] != message:
            self._history.append(message)
        self._history_index = -1

    def _setup_ui(self):
        """Set up the input widget UI."""
        colors = get_ida_colors()

        self.setPlaceholderText(
            "Ask about the current function, symbol, or selection..."
        )
        self.setMaximumHeight(84)
        self.setMinimumHeight(40)
        self.setStyleSheet(plain_text_style(colors))

    def keyPressEvent(self, event: QKeyEvent):
        """Handle special keys: Enter, Escape, Up/Down for history."""
        if event.key() == Qt.Key.Key_Escape:
            # Escape: cancel current operation
            self.cancel_requested.emit()
        elif event.key() == Qt.Key.Key_Up:
            # Up arrow: navigate to older history
            self._navigate_history(-1)
        elif event.key() == Qt.Key.Key_Down:
            # Down arrow: navigate to newer history
            self._navigate_history(1)
        elif event.key() == Qt.Key.Key_Return or event.key() == Qt.Key.Key_Enter:
            if event.modifiers() & Qt.KeyboardModifier.ShiftModifier:
                # Shift+Enter: insert new line
                super().keyPressEvent(event)
            else:
                # Enter: submit message
                text = self.toPlainText().strip()
                if text:
                    self.submit_current_text()
        else:
            super().keyPressEvent(event)

    def submit_current_text(self):
        """Emit the current composer contents as a message."""
        text = self.toPlainText().strip()
        if not text:
            return
        self.add_to_history(text)
        self.message_submitted.emit(text)
        self.clear()
        self._history_index = -1
        self.setFocus()

    def _navigate_history(self, direction: int):
        """Navigate through message history.

        Args:
            direction: -1 for older (up), +1 for newer (down)
        """
        if not self._history:
            return

        # Save current input when starting to browse
        if self._history_index == -1:
            self._current_input = self.toPlainText()

        # Calculate new index
        if direction < 0:  # Up - go to older
            if self._history_index == -1:
                # Start browsing from the end (most recent)
                new_index = len(self._history) - 1
            else:
                new_index = max(0, self._history_index - 1)
        else:  # Down - go to newer
            if self._history_index == -1:
                # Already at current input, do nothing
                return
            new_index = self._history_index + 1
            if new_index >= len(self._history):
                # Return to current input
                self._history_index = -1
                self.setPlainText(self._current_input)
                # Move cursor to end
                cursor = self.textCursor()
                cursor.movePosition(cursor.MoveOperation.End)
                self.setTextCursor(cursor)
                return

        # Set the history item
        self._history_index = new_index
        self.setPlainText(self._history[self._history_index])
        # Move cursor to end
        cursor = self.textCursor()
        cursor.movePosition(cursor.MoveOperation.End)
        self.setTextCursor(cursor)


class PluginCallback(ChatCallback):
    """Qt widget output implementation of ChatCallback.

    Uses Qt signals to safely update UI from any thread.
    """

    def __init__(self, signals: "AgentSignals"):
        self.signals = signals

    def on_turn_start(self, turn: int, max_turns: int) -> None:
        self.signals.turn_start.emit(turn, max_turns)

    def on_thinking(self) -> None:
        self.signals.thinking.emit()

    def on_thinking_done(self) -> None:
        self.signals.thinking_done.emit()

    def on_tool_use(self, tool_name: str, details: str) -> None:
        self.signals.tool_use.emit(tool_name, details)

    def on_text(self, text: str) -> None:
        self.signals.text.emit(text)

    def on_script_code(self, request: ScriptApprovalRequest) -> None:
        self.signals.script_review.emit(request)

    def on_script_output(self, output: str) -> None:
        self.signals.script_output.emit(output)

    def on_error(self, error: object) -> None:
        self.signals.error.emit(error)

    def on_result(self, num_turns: int, cost: float | None) -> None:
        self.signals.result.emit(num_turns, cost or 0.0)


class AgentSignals(QObject):
    """Qt signals for agent callbacks."""

    turn_start = Signal(int, int)
    thinking = Signal()
    thinking_done = Signal()
    tool_use = Signal(str, str)
    text = Signal(str)
    script_review = Signal(object)
    script_output = Signal(str)
    error = Signal(object)
    result = Signal(int, float)
    finished = Signal()
    connection_ready = Signal(object)
    connection_error = Signal(object)
    session_list_updated = Signal(object)
    session_loaded = Signal(object, object)


class AgentWorker(QThread):
    """Background worker for running async agent calls."""

    def __init__(
        self,
        db: Database,
        script_executor: Callable[[str], str],
        history: MessageHistory,
        model_profile: str = DEFAULT_MODEL_PROFILE,
        parent=None,
    ):
        super().__init__(parent)
        self.db = db
        self.script_executor = script_executor
        self.history = history
        self.model_profile = model_profile
        self.signals = AgentSignals()
        self.callback = PluginCallback(self.signals)
        self.core: IDAChatCore | None = None
        self._pending_message: str | None = None
        self._pending_context: PromptContext | None = None
        self._pending_resume_session: str | None = None
        self._pending_delete_session: str | None = None
        self._should_connect = False
        self._should_disconnect = False
        self._should_cancel = False
        self._should_new_session = False
        self._running = True
        self._loop: asyncio.AbstractEventLoop | None = None
        self._approval_futures: dict[str, asyncio.Future[ScriptDecision]] = {}
        self.require_script_approval = get_require_script_approval()

    def request_connect(self):
        """Request connection to agent."""
        self._should_connect = True
        if not self.isRunning():
            self.start()

    def request_disconnect(self):
        """Request disconnection from agent."""
        self._should_disconnect = True
        self._running = False

    def request_cancel(self):
        """Request cancellation of current operation."""
        self._should_cancel = True
        if self.core:
            self.core.request_cancel()
        if self.core and self._loop and self._loop.is_running():
            asyncio.run_coroutine_threadsafe(self.core.interrupt(), self._loop)

    def request_new_session(self):
        """Request starting a new session for history tracking."""
        self._should_new_session = True

    def request_resume_session(self, session_id: str):
        """Request resuming an existing session."""
        self._pending_resume_session = session_id
        if not self.isRunning():
            self.start()

    def request_delete_session(self, session_id: str):
        """Request deleting an existing session."""
        self._pending_delete_session = session_id
        if not self.isRunning():
            self.start()

    def submit_script_decision(self, request_id: str, decision: ScriptDecision):
        """Resolve a pending script approval future from the UI thread."""
        if not self._loop:
            return
        future = self._approval_futures.get(request_id)
        if not future or future.done():
            return

        def _set_result():
            if not future.done():
                future.set_result(decision)

        self._loop.call_soon_threadsafe(_set_result)

    def send_message(self, message: str, prompt_context: PromptContext | None = None):
        """Queue a message to be sent to the agent."""
        self._pending_message = message
        self._pending_context = prompt_context
        if not self.isRunning():
            self.start()

    def run(self):
        """Run the async event loop in this thread."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop

        try:
            loop.run_until_complete(self._async_run())
        finally:
            self._loop = None
            loop.close()

    async def _await_script_decision(
        self, request: ScriptApprovalRequest
    ) -> ScriptDecision:
        """Wait for a UI decision on a generated script."""
        loop = asyncio.get_running_loop()
        future: asyncio.Future[ScriptDecision] = loop.create_future()
        self._approval_futures[request.request_id] = future
        try:
            return await future
        finally:
            self._approval_futures.pop(request.request_id, None)

    def _emit_sessions(self):
        self.signals.session_list_updated.emit(self.history.list_sessions())

    def _emit_current_session(self):
        session_id = self.history.get_current_session_id()
        if not session_id:
            return
        sessions = self.history.list_sessions()
        summary = next(
            (item for item in sessions if item.get("id") == session_id), None
        )
        items = self.history.get_session_display_items(session_id)
        self.signals.session_loaded.emit(summary or {}, items)

    async def _async_run(self):
        """Main async loop."""
        # Handle connection request
        if self._should_connect:
            self._should_connect = False
            try:
                # Start a session only when there is no active one to resume.
                if not self.history.get_current_session_id():
                    self.history.start_new_session()
                model_config = get_model_config(self.model_profile)

                self.core = IDAChatCore(
                    self.db,
                    self.callback,
                    script_executor=self.script_executor,
                    script_approver=self._await_script_decision,
                    history=self.history,
                    require_script_approval=self.require_script_approval,
                    model=str(model_config["model"]),
                    betas=model_config["betas"],
                )
                await self.core.connect()
                self.signals.connection_ready.emit(
                    {"session_title": self.history.get_current_session_title()}
                )
                self._emit_sessions()
                self._emit_current_session()
            except IDAChatRuntimeError as error:
                self.signals.connection_error.emit(error.diagnostics)
                return
            except Exception as error:
                self.signals.connection_error.emit(str(error))
                return

        # Process messages while running
        while self._running:
            if self._pending_resume_session:
                session_id = self._pending_resume_session
                self._pending_resume_session = None
                if self.history.switch_session(session_id):
                    self._emit_sessions()
                    self._emit_current_session()

            if self._pending_delete_session:
                session_id = self._pending_delete_session
                self._pending_delete_session = None
                current_before = self.history.get_current_session_id()
                if self.history.delete_session(session_id):
                    if (
                        current_before == session_id
                        and not self.history.get_current_session_id()
                    ):
                        self.history.start_new_session()
                    self._emit_sessions()
                    self._emit_current_session()

            # Handle new session request (e.g., after Clear)
            if self._should_new_session:
                self._should_new_session = False
                self.history.start_new_session()
                self._emit_sessions()
                self._emit_current_session()

            if self._pending_message:
                message = self._pending_message
                prompt_context = self._pending_context
                self._pending_message = None
                self._pending_context = None
                try:
                    core = self.core
                    if core is None:
                        raise RuntimeError("Agent core is not initialized.")
                    await core.process_message(message, prompt_context)
                except IDAChatRuntimeError as error:
                    self.signals.error.emit(error.diagnostics)
                except Exception as error:
                    self.signals.error.emit(str(error))
                self.signals.finished.emit()
                self._emit_sessions()

            # Check for disconnect request
            if self._should_disconnect:
                break

            # Small sleep to avoid busy loop
            await asyncio.sleep(0.1)

        # Handle disconnection
        if self.core:
            try:
                await self.core.disconnect()
            except IDAChatRuntimeError as error:
                self.signals.error.emit(error.diagnostics)


class TestConnectionWorker(QThread):
    """Background thread for testing Claude connection."""

    finished = Signal(object)

    def __init__(
        self, model: str | None = None, betas: list[str] | None = None, parent=None
    ):
        super().__init__(parent)
        self.model = model
        self.betas = list(betas or [])

    def run(self):
        """Run the connection test."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(
                test_claude_connection(model=self.model, betas=self.betas)
            )
            self.finished.emit(result)
        except Exception as error:
            self.finished.emit(str(error))
        finally:
            loop.close()


class ModelOptionCard(QFrame):
    """Clickable card used for Claude model selection."""

    clicked = Signal(str)

    def __init__(
        self,
        profile_key: str,
        badge: str,
        title: str,
        description: str,
        tone: str,
        parent=None,
    ):
        super().__init__(parent)
        self.profile_key = profile_key
        self.badge = badge
        self.title = title
        self.description = description
        self.tone = tone
        self._setup_ui()

    def _tone_colors(self, colors: dict[str, object]) -> tuple[str, str, str]:
        if self.tone == "success":
            return (
                str(colors["success_soft"]),
                str(colors["success_border"]),
                str(colors["success_text"]),
            )
        if self.tone == "warning":
            return (
                str(colors["warning_soft"]),
                str(colors["warning_border"]),
                str(colors["warning_text"]),
            )
        if self.tone == "info":
            return (
                str(colors["info_soft"]),
                str(colors["info_border"]),
                str(colors["info_text"]),
            )
        return (
            str(colors["surface_alt"]),
            str(colors["border"]),
            str(colors["text"]),
        )

    def _setup_ui(self):
        self.setObjectName("modelOptionCard")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 14, 14, 14)
        layout.setSpacing(12)

        self.badge_label = QLabel(self.badge)
        self.badge_label.setObjectName("modelOptionBadge")
        self.badge_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.badge_label.setFixedSize(34, 34)
        layout.addWidget(self.badge_label, alignment=Qt.AlignmentFlag.AlignTop)

        copy_layout = QVBoxLayout()
        copy_layout.setContentsMargins(0, 0, 0, 0)
        copy_layout.setSpacing(4)

        self.title_label = QLabel(self.title)
        self.title_label.setObjectName("modelOptionTitle")
        copy_layout.addWidget(self.title_label)

        self.description_label = QLabel(self.description)
        self.description_label.setObjectName("modelOptionDescription")
        self.description_label.setWordWrap(True)
        copy_layout.addWidget(self.description_label)

        layout.addLayout(copy_layout, stretch=1)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

    def set_selected(self, selected: bool):
        """Apply the selected or idle card appearance."""
        colors = get_ida_colors()
        tone_bg, tone_border, tone_text = self._tone_colors(colors)
        card_bg = tone_bg if selected else colors["surface"]
        card_border = tone_border if selected else colors["border"]
        title_color = tone_text if selected else colors["text"]
        desc_color = tone_text if selected else colors["text_muted"]
        self.setStyleSheet(f"""
            QFrame#modelOptionCard {{
                background-color: {card_bg};
                border: 1px solid {card_border};
                border-radius: {colors["radius_lg"]}px;
            }}
            QLabel#modelOptionBadge {{
                background-color: {tone_bg};
                color: {tone_text};
                border: 1px solid {tone_border};
                border-radius: 17px;
                font-size: 11px;
                font-weight: 600;
            }}
            QLabel#modelOptionTitle {{
                color: {title_color};
                background: transparent;
                border: none;
                font-size: 13px;
                font-weight: 500;
            }}
            QLabel#modelOptionDescription {{
                color: {desc_color};
                background: transparent;
                border: none;
                font-size: 11px;
                line-height: 1.45;
            }}
        """)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self.profile_key)
        super().mousePressEvent(event)


class AuthOptionTab(QFrame):
    """Compact joined tab used for auth selection."""

    clicked = Signal(str)

    def __init__(
        self, auth_key: str, step_label: str, title: str, tone: str, parent=None
    ):
        super().__init__(parent)
        self.auth_key = auth_key
        self.step_label = step_label
        self.title = title
        self.tone = tone
        self._setup_ui()

    def _tone_colors(self, colors: dict[str, object]) -> tuple[str, str, str]:
        if self.tone == "success":
            return (
                str(colors["success_soft"]),
                str(colors["success_border"]),
                str(colors["success_text"]),
            )
        if self.tone == "warning":
            return (
                str(colors["warning_soft"]),
                str(colors["warning_border"]),
                str(colors["warning_text"]),
            )
        return (
            str(colors["info_soft"]),
            str(colors["info_border"]),
            str(colors["info_text"]),
        )

    def _setup_ui(self):
        self.setObjectName("authOptionTab")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setMinimumHeight(46)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(10)

        self.badge_label = QLabel(self.step_label)
        self.badge_label.setObjectName("authOptionBadge")
        self.badge_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.badge_label.setFixedSize(22, 22)
        layout.addWidget(self.badge_label, alignment=Qt.AlignmentFlag.AlignVCenter)

        self.title_label = QLabel(self.title)
        self.title_label.setObjectName("authOptionTitle")
        layout.addWidget(self.title_label)
        layout.addStretch(1)

    def set_selected(self, selected: bool, is_first: bool, is_last: bool):
        """Apply active or idle styles with proper corner rounding."""
        colors = get_ida_colors()
        tone_bg, tone_border, tone_text = self._tone_colors(colors)
        r = colors["radius_md"]
        right_border = "none" if is_last else f"1px solid {colors['border']}"
        # Corner radii: only round the outer edges of the tab strip
        tl = f"{r}px" if is_first else "0px"
        bl = f"{r}px" if is_first else "0px"
        tr = f"{r}px" if is_last else "0px"
        br = f"{r}px" if is_last else "0px"
        if selected:
            bg_color = tone_bg
            text_color = tone_text
            hover_bg = tone_bg  # keep selected color on hover
            font_weight = "600"
        else:
            bg_color = "transparent"
            text_color = colors["text_muted"]
            hover_bg = colors["surface_alt"]
            font_weight = "500"
        badge_bg = tone_bg if selected else colors["surface_alt"]
        badge_border = tone_border if selected else colors["border"]
        badge_text = tone_text if selected else colors["text_subtle"]
        self.setStyleSheet(f"""
            QFrame#authOptionTab {{
                background-color: {bg_color};
                border: none;
                border-right: {right_border};
                border-top-left-radius: {tl};
                border-bottom-left-radius: {bl};
                border-top-right-radius: {tr};
                border-bottom-right-radius: {br};
            }}
            QFrame#authOptionTab:hover {{
                background-color: {hover_bg};
            }}
            QLabel#authOptionBadge {{
                background-color: {badge_bg};
                color: {badge_text};
                border: 1px solid {badge_border};
                border-radius: 8px;
                font-size: 11px;
                font-weight: 600;
            }}
            QLabel#authOptionTitle {{
                color: {text_color};
                background: transparent;
                border: none;
                font-size: 13px;
                font-weight: {font_weight};
            }}
        """)

    def mouseReleaseEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton and self.rect().contains(
            event.position().toPoint()
        ):
            self.clicked.emit(self.auth_key)
            event.accept()
            return
        super().mouseReleaseEvent(event)


class PreferenceOption(QWidget):
    """Checkbox row with a short helper description."""

    def __init__(
        self,
        title: str,
        description: str,
        checkbox_style: str,
        description_style: str,
        parent=None,
    ):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(14)

        self.checkbox = QCheckBox(title)
        self.checkbox.setStyleSheet(checkbox_style)
        layout.addWidget(self.checkbox)

        self.description_label = QLabel(description)
        self.description_label.setWordWrap(True)
        self.description_label.setStyleSheet(description_style)
        layout.addWidget(self.description_label)


class OAuthWorker(QThread):
    """Runs `claude setup-token` silently; emits result when done."""

    finished = Signal(bool, str)  # (success, message)

    def __init__(self, cli_path: str, parent=None):
        super().__init__(parent)
        self._cli_path = cli_path

    def run(self):
        try:
            result = subprocess.run(
                [self._cli_path, "setup-token"],
                capture_output=True,
                text=True,
                timeout=120,
            )
            if result.returncode == 0:
                self.finished.emit(True, "Login complete. You can now run a test.")
            else:
                err = (result.stderr or result.stdout or "").strip()
                self.finished.emit(False, err or "Login was cancelled or failed.")
        except subprocess.TimeoutExpired:
            self.finished.emit(False, "Login timed out after 2 minutes.")
        except Exception as exc:
            self.finished.emit(False, str(exc))


class OnboardingPanel(QFrame):
    """Onboarding panel for first-time setup and settings configuration."""

    onboarding_complete = Signal()  # Emitted when user clicks Save & Start
    status_changed = Signal(str)
    back_requested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self._test_worker: TestConnectionWorker | None = None
        self._oauth_worker: OAuthWorker | None = None
        self._selected_model_profile = get_model_profile()
        self._selected_auth_type = get_auth_type() or "system"
        self._model_cards: dict[str, ModelOptionCard] = {}
        self._panel_mode = "setup"
        self._verification_state: VerificationState = "unverified"
        self._controls_busy = False
        self._artwork_pixmap: QPixmap | None = None
        self._auth_buttons: dict[str, AuthOptionTab] = {}
        self._setup_ui()

    def _setup_ui(self):
        colors = get_ida_colors()
        self.setObjectName("onboardingPanel")
        check_style = f"""
            QCheckBox {{
                color: {colors["text"]};
                spacing: 10px;
                font-size: 13px;
                font-weight: 500;
                padding: 0;
            }}
            QCheckBox::indicator {{
                width: 12px;
                height: 12px;
                border-radius: 6px;
                border: 1px solid {colors["border_strong"]};
                background-color: {colors["surface"]};
            }}
            QCheckBox::indicator:checked {{
                background-color: {colors["accent"]};
                border: 1px solid {colors["accent"]};
            }}
        """
        pref_description_style = (
            f"QLabel {{ color: {colors['text_muted']}; font-size: 11px; line-height: 1.45; "
            f"padding-left: 24px; }}"
        )

        self.setStyleSheet(f"""
            QFrame#onboardingPanel {{
                background-color: {colors["app_bg"]};
                border-radius: {colors["radius_xl"]}px;
            }}
        """)

        # Main horizontal layout for two columns
        self._main_layout = QHBoxLayout(self)
        self._main_layout.setContentsMargins(0, 0, 0, 0)
        self._main_layout.setSpacing(0)

        # Left column (30%) - Image
        self.artwork_container = QWidget()
        self.artwork_container.setObjectName("onboardingArtwork")
        self.artwork_container.setStyleSheet(f"""
            QWidget#onboardingArtwork {{
                background-color: {colors["header_bg"]};
                border-top: 1px solid {colors["border"]};
                border-left: 1px solid {colors["border"]};
                border-bottom: 1px solid {colors["border"]};
                border-right: 1px solid {colors["border"]};
                border-top-left-radius: {colors["radius_xl"]}px;
                border-bottom-left-radius: {colors["radius_xl"]}px;
            }}
        """)
        image_layout = QVBoxLayout(self.artwork_container)
        image_layout.setContentsMargins(0, 18, 0, 0)
        image_layout.setSpacing(0)

        image_label = QLabel()
        self.artwork_label = image_label
        splash_path = Path(__file__).parent / "splash.png"
        if splash_path.exists():
            self._artwork_pixmap = QPixmap(str(splash_path))
        image_label.setAlignment(
            Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignBottom
        )
        image_label.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        image_layout.addStretch()
        image_layout.addWidget(
            image_label,
            alignment=Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignBottom,
        )

        self._main_layout.addWidget(self.artwork_container, stretch=30)

        # Right column (70%) - Settings
        settings_container = QWidget()
        settings_container.setObjectName("onboardingSettings")
        settings_container.setStyleSheet("""
            QWidget#onboardingSettings {
                background-color: transparent;
            }
        """)
        self._settings_layout = QVBoxLayout(settings_container)
        self._settings_layout.setContentsMargins(32, 28, 32, 32)
        self._settings_layout.setSpacing(12)

        # Back button row — wrapped in a widget so it collapses when hidden
        self._top_row_widget = QWidget()
        self._top_row_widget.setStyleSheet("QWidget { background: transparent; }")
        self._top_row = QHBoxLayout(self._top_row_widget)
        self._top_row.setContentsMargins(0, 0, 0, 0)
        self._top_row.setSpacing(10)

        self.back_btn = QPushButton("Back")
        self.back_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.back_btn.setStyleSheet(button_style(colors, "ghost", compact=True))
        self.back_btn.clicked.connect(self.back_requested.emit)
        self._top_row.addWidget(
            self.back_btn, alignment=Qt.AlignmentFlag.AlignTop
        )
        self._top_row.addStretch(1)
        self._top_row_widget.hide()
        self._settings_layout.addWidget(self._top_row_widget)

        def _section_header(number: str, text: str) -> QHBoxLayout:
            row = QHBoxLayout()
            row.setContentsMargins(0, 0, 0, 0)
            row.setSpacing(10)
            badge = QLabel(number)
            badge.setFixedSize(22, 22)
            badge.setAlignment(Qt.AlignmentFlag.AlignCenter)
            badge.setStyleSheet(f"""
                QLabel {{
                    background-color: {colors["surface_alt"]};
                    color: {colors["text"]};
                    border: 1px solid {colors["border"]};
                    border-radius: 11px;
                    font-size: 11px;
                    font-weight: 700;
                }}
            """)
            title = QLabel(text)
            title.setStyleSheet(f"""
                QLabel {{
                    color: {colors["text"]};
                    font-size: 14px;
                    font-weight: 500;
                }}
            """)
            row.addWidget(badge)
            row.addWidget(title)
            row.addStretch(1)
            return row

        self._settings_layout.addLayout(_section_header("1", "Authentication"))

        # Joined auth selector
        self.auth_tabs = QFrame()
        self.auth_tabs.setObjectName("authTabs")
        self.auth_tabs.setStyleSheet(f"""
            QFrame#authTabs {{
                background-color: {colors["surface"]};
                border: 1px solid {colors["border"]};
                border-radius: {colors["radius_md"]}px;
            }}
        """)
        auth_tabs_layout = QHBoxLayout(self.auth_tabs)
        auth_tabs_layout.setContentsMargins(0, 0, 0, 0)
        auth_tabs_layout.setSpacing(0)
        for index, (auth_id, config) in enumerate(AUTH_OPTIONS.items(), start=1):
            button = AuthOptionTab(
                auth_key=auth_id,
                step_label=str(index),
                title=str(config["tab"]),
                tone=str(config["tone"]),
            )
            button.clicked.connect(self._on_auth_type_changed)
            self._auth_buttons[auth_id] = button
            auth_tabs_layout.addWidget(button)
        self._settings_layout.addWidget(self.auth_tabs)

        self.auth_description_label = QLabel()
        self.auth_description_label.setWordWrap(True)
        self.auth_description_label.setStyleSheet(
            f"QLabel {{ color: {colors['text_muted']}; font-size: 12px; line-height: 1.45; }}"
        )
        self._settings_layout.addWidget(self.auth_description_label)

        # Key input field (hidden for system option)
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("Paste your key here...")
        self.key_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.key_input.setStyleSheet(line_edit_style(colors))
        self.key_input.hide()  # Hidden by default (system option selected)
        self._settings_layout.addWidget(self.key_input)
        self.key_input.textChanged.connect(self._on_credentials_changed)

        self.oauth_launch_btn = QPushButton("Open Claude Login")
        self.oauth_launch_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.oauth_launch_btn.setAutoDefault(False)
        self.oauth_launch_btn.setDefault(False)
        self.oauth_launch_btn.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.oauth_launch_btn.setStyleSheet(button_style(colors, "info"))
        self.oauth_launch_btn.clicked.connect(self._on_oauth_login_clicked)
        self.oauth_launch_btn.hide()
        self._settings_layout.addWidget(self.oauth_launch_btn)

        self.oauth_launch_hint = QLabel()
        self.oauth_launch_hint.hide()
        self._settings_layout.addWidget(self.oauth_launch_hint)

        self._settings_layout.addSpacing(20)
        self._settings_layout.addLayout(_section_header("2", "Choose Claude model"))

        self._model_grid = QGridLayout()
        self._model_grid.setContentsMargins(0, 0, 0, 0)
        self._model_grid.setHorizontalSpacing(12)
        self._model_grid.setVerticalSpacing(12)

        for index, (profile_key, config) in enumerate(MODEL_PRESETS.items()):
            card = ModelOptionCard(
                profile_key=profile_key,
                badge=str(config["badge"]),
                title=str(config["label"]),
                description=str(config["description"]),
                tone=str(config["tone"]),
            )
            card.clicked.connect(self._on_model_selected)
            self._model_cards[profile_key] = card
            self._model_grid.addWidget(card, index // 2, index % 2)
        self._settings_layout.addLayout(self._model_grid)
        self._apply_model_selection()

        # Preferences section — header at same level as sections 1 & 2
        self.behavior_hint = QLabel()  # kept for compatibility, hidden
        self.behavior_hint.hide()
        self._settings_layout.addSpacing(20)
        self._settings_layout.addLayout(_section_header("3", "Preferences"))

        require_approval_option = PreferenceOption(
            "Ask before running generated scripts",
            "Scripts pause for your approval before executing. Uncheck to let Claude run scripts automatically.",
            check_style,
            pref_description_style,
        )
        self.require_approval_cb = require_approval_option.checkbox
        self.require_approval_cb.setChecked(get_require_script_approval())

        auto_context_option = PreferenceOption(
            "Attach current IDA location automatically",
            "Adds your current address, function, selection, and highlighted token to new prompts whenever that context is available.",
            check_style,
            pref_description_style,
        )
        self.auto_context_cb = auto_context_option.checkbox
        self.auto_context_cb.setChecked(get_auto_context_enabled())

        redact_export_option = PreferenceOption(
            "Redact local paths in transcript exports",
            "Removes usernames and local filesystem paths from transcripts before you share them outside your machine.",
            check_style,
            pref_description_style,
        )
        self.redact_export_cb = redact_export_option.checkbox
        self.redact_export_cb.setChecked(get_redact_export_paths())

        pref_checks = QVBoxLayout()
        pref_checks.setContentsMargins(0, 0, 0, 0)
        pref_checks.setSpacing(14)
        pref_checks.addWidget(require_approval_option)
        pref_checks.addWidget(auto_context_option)
        pref_checks.addWidget(redact_export_option)
        self._settings_layout.addLayout(pref_checks)

        # Buttons row
        self._settings_layout.addSpacing(8)
        buttons_layout = QHBoxLayout()
        buttons_layout.setSpacing(12)

        self.test_btn = QPushButton("Test Connection")
        self.test_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.test_btn.setStyleSheet(button_style(colors, "secondary"))
        self.test_btn.clicked.connect(self._on_test_clicked)
        buttons_layout.addWidget(self.test_btn)

        self.save_btn = QPushButton("Save && Start")
        self.save_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.save_btn.setStyleSheet(button_style(colors, "primary"))
        self.save_btn.clicked.connect(self._on_save_clicked)
        buttons_layout.addWidget(self.save_btn)

        self._settings_layout.addLayout(buttons_layout)

        # Status label
        self.status_label = QLabel("Not configured")
        self.status_label.setStyleSheet(status_banner_style(colors, "neutral"))
        self._settings_layout.addWidget(self.status_label)

        # Response area (for showing joke on successful test)
        self.response_label = QLabel()
        self.response_label.setWordWrap(True)
        self.response_label.setStyleSheet(f"""
            QLabel {{
                color: {colors["text"]};
                background-color: {colors["surface_alt"]};
                border: 1px solid {colors["border"]};
                border-radius: {colors["radius_lg"]}px;
                padding: 12px;
            }}
        """)
        self.response_label.hide()
        self._settings_layout.addWidget(self.response_label)

        self.diagnostics_section = CollapsibleSection(
            "Connection details", "", collapsed=False, flat=True
        )
        self.diagnostics_section.hide()
        self._settings_layout.addWidget(self.diagnostics_section)

        self._settings_layout.addStretch()

        self.settings_scroll = QScrollArea()
        self.settings_scroll.setObjectName("onboardingSettingsScroll")
        self.settings_scroll.setWidgetResizable(True)
        self.settings_scroll.setFrameShape(QFrame.Shape.NoFrame)
        self.settings_scroll.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )
        self.settings_scroll.setVerticalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )
        self.settings_scroll.setStyleSheet(f"""
            QScrollArea#onboardingSettingsScroll {{
                background-color: {colors["surface"]};
                border-top: 1px solid {colors["border"]};
                border-right: 1px solid {colors["border"]};
                border-bottom: 1px solid {colors["border"]};
                border-left: none;
                border-top-right-radius: {colors["radius_xl"]}px;
                border-bottom-right-radius: {colors["radius_xl"]}px;
            }}
            QScrollArea#onboardingSettingsScroll > QWidget > QWidget {{
                background: transparent;
            }}
            QScrollBar:vertical {{
                background: transparent;
                width: 0px;
                margin: 0px;
            }}
            QScrollBar::handle:vertical {{
                background: transparent;
                border-radius: {colors["radius_xs"]}px;
                min-height: 32px;
            }}
            QScrollBar:horizontal {{
                background-color: transparent;
                height: 0px;
                margin: 0px;
            }}
            QScrollBar::handle:horizontal {{
                background-color: transparent;
                border-radius: {colors["radius_xs"]}px;
                min-width: 32px;
            }}
            QScrollBar::add-line:vertical,
            QScrollBar::sub-line:vertical,
            QScrollBar::add-page:vertical,
            QScrollBar::sub-page:vertical,
            QScrollBar::add-line:horizontal,
            QScrollBar::sub-line:horizontal,
            QScrollBar::add-page:horizontal,
            QScrollBar::sub-page:horizontal {{
                background: transparent;
                height: 0px;
            }}
        """)
        self.settings_scroll.setWidget(settings_container)
        self._main_layout.addWidget(self.settings_scroll, stretch=70)
        self._set_auth_type(self._selected_auth_type)
        self._refresh_selection_summary()
        self._refresh_actions()
        self._emit_status()
        self._update_density()
        self._refresh_artwork_pixmap()

    def _on_auth_type_changed(self, auth_type: str):
        """Show/hide key input based on selected auth type."""
        self._selected_auth_type = auth_type if auth_type in AUTH_OPTIONS else "system"
        auth_type = self._selected_auth_type
        self._set_verification_state("unverified")
        if auth_type == "system":
            self.key_input.hide()
            self.oauth_launch_btn.hide()
            self.oauth_launch_hint.hide()
        elif auth_type == "oauth":
            self.key_input.hide()
            self.oauth_launch_btn.show()
            self.oauth_launch_hint.show()
            QTimer.singleShot(0, self._show_oauth_controls_if_needed)
        else:
            self.oauth_launch_btn.hide()
            self.oauth_launch_hint.hide()
            self.key_input.show()
        self.key_input.setPlaceholderText(str(AUTH_OPTIONS[auth_type]["placeholder"]))
        self._clear_connection_feedback(
            "Authentication updated. Run a test to verify it."
        )
        self._apply_auth_button_styles()
        self._refresh_selection_summary()
        self._refresh_actions()
        self._emit_status()

    def _show_oauth_controls_if_needed(self):
        """Show OAuth controls after the current click event fully completes."""
        if self._selected_auth_type != "oauth":
            return
        self.oauth_launch_btn.show()
        self.oauth_launch_hint.show()

    def _set_auth_type(self, auth_type: str):
        """Set the selected auth mode and refresh dependent controls."""
        self._on_auth_type_changed(auth_type if auth_type in AUTH_OPTIONS else "system")

    def _on_oauth_login_clicked(self):
        """Run `claude setup-token` silently — browser opens automatically."""
        cli_path = find_claude_cli_path()
        if not cli_path:
            self._set_status_banner(
                "Claude Code CLI not found. Install it first, then retry.", "danger"
            )
            return
        self._set_verification_state("unverified")
        self.oauth_launch_btn.setText("Waiting for browser login…")
        self._set_controls_busy(True)
        self._set_status_banner(
            "Browser opened for login. Complete it there, then come back.", "neutral"
        )
        self.response_label.hide()
        self.diagnostics_section.hide()
        self._oauth_worker = OAuthWorker(cli_path, parent=self)
        self._oauth_worker.finished.connect(self._on_oauth_finished)
        self._oauth_worker.start()
        self._emit_status()

    def _on_oauth_finished(self, success: bool, message: str):
        """Handle result of background `claude setup-token`."""
        self._oauth_worker = None
        self.oauth_launch_btn.setText("Open Claude Login")
        self._set_controls_busy(False)
        if success:
            self.key_input.blockSignals(True)
            self.key_input.clear()
            self.key_input.blockSignals(False)
            self._set_verification_state("unverified")
            self._clear_connection_feedback(
                "Browser login completed. Run a test to verify this Claude account.",
                force_banner=True,
            )
        else:
            self._set_status_banner(message, "danger")
        self._refresh_actions()
        self._emit_status()

    def _on_credentials_changed(self, _text: str):
        """Reset verification state after credential edits."""
        self._set_verification_state("unverified")
        self._clear_connection_feedback(
            "Credentials updated. Run a test to verify them."
        )
        self._refresh_selection_summary()
        self._refresh_actions()
        self._emit_status()

    def _on_model_selected(self, profile_key: str):
        """Select a Claude model card."""
        self._selected_model_profile = profile_key
        self._set_verification_state("unverified")
        self._clear_connection_feedback(
            "Model updated. Run a test to verify it."
        )
        self._apply_model_selection()
        self._refresh_selection_summary()
        self._refresh_actions()
        self._emit_status()

    def _apply_model_selection(self):
        """Refresh card selection states."""
        for profile_key, card in self._model_cards.items():
            card.set_selected(profile_key == self._selected_model_profile)

    def _current_model_config(self) -> ModelPreset:
        """Return the currently selected Claude model config."""
        return get_model_config(self._selected_model_profile)

    def current_model_display_name(self) -> str:
        """Return the short model label currently selected in the UI."""
        return str(self._current_model_config()["short_label"])

    def _auth_mode_label(self) -> str:
        """Return a compact label for the selected auth mode."""
        return str(self._current_auth_config()["title"])

    def current_auth_display_name(self) -> str:
        """Return the short auth label used in the header breadcrumb."""
        return str(self._current_auth_config()["breadcrumb"])

    def _current_auth_config(self) -> dict[str, str]:
        """Return metadata for the selected auth mode."""
        return AUTH_OPTIONS[self._get_auth_type()]

    def _has_credentials_ready(self) -> bool:
        """Return whether the current auth choice is ready to test/save."""
        return auth_mode_has_credentials(
            self._get_auth_type(),
            self.key_input.text().strip(),
            cli_available=bool(find_claude_cli_path()),
        )

    def _can_save_current_settings(self) -> bool:
        """Allow save/start only after the current settings are verified."""
        return can_finalize_settings(
            self._verification_state,
            self._get_auth_type(),
            self.key_input.text().strip(),
            cli_available=bool(find_claude_cli_path()),
        )

    def _refresh_selection_summary(self):
        """Refresh compact helper copy for the active auth and model choices."""
        model_config = self._current_model_config()
        context_note = " with 1M context beta" if model_config.get("betas") else ""
        auth_config = self._current_auth_config()
        self.auth_description_label.setText(str(auth_config["description"]))
        self.behavior_hint.setText(
            f"{model_config['label']}{context_note} will be used after you save settings."
        )

    def _refresh_actions(self):
        """Update CTA labels based on mode and selection."""
        model_name = str(self._current_model_config()["label"])
        self.test_btn.setText(f"Test {model_name}")
        self.save_btn.setText(
            "Save Settings" if self._panel_mode == "settings" else "Save && Start"
        )
        controls_enabled = not self._controls_busy
        credentials_ready = self._has_credentials_ready()

        for button in self._auth_buttons.values():
            button.setEnabled(controls_enabled)
        for card in self._model_cards.values():
            card.setEnabled(controls_enabled)

        self.key_input.setEnabled(
            controls_enabled and self._selected_auth_type in {"oauth", "api_key"}
        )
        self.require_approval_cb.setEnabled(controls_enabled)
        self.auto_context_cb.setEnabled(controls_enabled)
        self.redact_export_cb.setEnabled(controls_enabled)
        self.back_btn.setEnabled(controls_enabled)

        oauth_login_available = (
            controls_enabled
            and self._selected_auth_type == "oauth"
            and bool(find_claude_cli_path())
        )
        self.oauth_launch_btn.setEnabled(oauth_login_available)
        self.test_btn.setEnabled(controls_enabled and credentials_ready)
        self.save_btn.setEnabled(controls_enabled and self._can_save_current_settings())

    def _update_density(self):
        """Keep the breathable layout while letting the form scroll when needed."""
        show_artwork = self.width() >= 1080
        self.artwork_container.setVisible(show_artwork)
        self._main_layout.setStretch(0, 34 if show_artwork else 0)
        self._main_layout.setStretch(1, 66 if show_artwork else 100)
        self.behavior_hint.setVisible(False)
        self.oauth_launch_hint.setVisible(False)
        self._refresh_artwork_pixmap()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._update_density()

    def current_status_text(self) -> str:
        """Return the breadcrumb status text for the current panel state."""
        if self._verification_state == "verified":
            return "Verified"
        if self._verification_state == "verifying":
            return "Verifying..."
        return "Not Verified"

    def set_mode(self, mode: str):
        """Configure the panel copy for setup or settings mode."""
        self._panel_mode = "settings" if mode == "settings" else "setup"
        self._top_row_widget.setVisible(False)  # Back handled by header chevron
        self._refresh_actions()
        self._update_density()
        self._emit_status()

    def _emit_status(self, override: str | None = None):
        """Broadcast a concise header status for the parent breadcrumb."""
        if override:
            self.status_changed.emit(override)
            return
        self.status_changed.emit(self.current_status_text())

    def _clear_connection_feedback(
        self, message: str | None = None, *, force_banner: bool = False
    ):
        """Remove stale test output when the configuration changes."""
        had_feedback = (
            not self.response_label.isHidden()
            or not self.diagnostics_section.isHidden()
            or self._verification_state == "verified"
        )
        self.response_label.hide()
        self.diagnostics_section.hide()
        if message and (had_feedback or force_banner):
            self._set_status_banner(message, "neutral")

    def _set_controls_busy(self, busy: bool):
        """Temporarily lock settings controls while async work is running."""
        self._controls_busy = busy
        self._refresh_actions()

    def _on_test_clicked(self):
        """Run connection test."""
        model_config = self._current_model_config()
        self._set_verification_state("verifying")
        self._set_controls_busy(True)
        self._set_status_banner(f"Verifying {model_config['label']}...", "neutral")
        self.response_label.hide()
        self.diagnostics_section.hide()
        self._refresh_selection_summary()
        self._emit_status()

        # Apply settings to environment before testing
        self._apply_current_settings()

        # Start test worker
        self._test_worker = TestConnectionWorker(
            model=str(model_config["model"]),
            betas=model_config["betas"],
            parent=self,
        )
        self._test_worker.finished.connect(self._on_test_finished)
        self._test_worker.start()

    def _on_test_finished(self, result: object):
        """Handle test result."""
        self._test_worker = None
        self._set_controls_busy(False)

        if hasattr(result, "success") and getattr(result, "success"):
            self._set_verification_state("verified")
            self._set_status_banner(
                "Verified. Claude responded successfully.", "success"
            )
            self.response_label.setText(getattr(result, "message"))
            self.response_label.show()
            self.diagnostics_section.hide()
            self._refresh_selection_summary()
            self._emit_status()
        else:
            self._set_verification_state("unverified")
            message = getattr(result, "message", str(result))
            self._set_status_banner(f"Verification failed: {message}", "danger")
            self.response_label.setText(message)
            self.response_label.show()
            diagnostics = getattr(result, "diagnostics", None)
            if diagnostics:
                self.diagnostics_section.set_content(
                    "Connection details", diagnostics.to_text(), collapsed=True
                )
                self.diagnostics_section.show()
            else:
                self.diagnostics_section.hide()
            self._refresh_selection_summary()
            self._emit_status()

    def _apply_current_settings(self):
        """Apply current UI settings to environment variables."""
        auth_type = self._get_auth_type()
        api_key = (
            self.key_input.text().strip() if auth_type in {"oauth", "api_key"} else None
        )
        apply_auth_environment(
            os.environ,
            auth_type,
            api_key,
            original_api_key=_INITIAL_ANTHROPIC_API_KEY,
            original_oauth_token=_INITIAL_CLAUDE_CODE_OAUTH_TOKEN,
        )

        set_require_script_approval(self.require_approval_cb.isChecked())
        set_auto_context_enabled(self.auto_context_cb.isChecked())
        set_redact_export_paths(self.redact_export_cb.isChecked())

    def _get_auth_type(self) -> str:
        """Get the selected auth type."""
        return self._selected_auth_type

    def _on_save_clicked(self):
        """Save settings and emit completion signal."""
        auth_type = self._get_auth_type()
        api_key = (
            self.key_input.text().strip() if auth_type in {"oauth", "api_key"} else None
        )

        if not self._can_save_current_settings():
            self._set_status_banner(
                "Run a successful connection test before saving these settings.",
                "danger",
            )
            self._refresh_selection_summary()
            self._emit_status()
            return

        # Validate key input for non-system auth types
        if auth_type == "api_key" and not api_key:
            self._set_verification_state("unverified")
            self._set_status_banner("Please enter your API key.", "danger")
            self._refresh_selection_summary()
            self._emit_status()
            return

        # Save settings
        save_auth_settings(auth_type, api_key)
        set_model_profile(self._selected_model_profile)

        # Apply to environment
        self._apply_current_settings()
        if self._verification_state == "verified":
            self._set_status_banner(
                "Settings saved. Verification is still valid.", "success"
            )
        else:
            self._set_status_banner(
                "Settings saved. Run a test when you want to verify them.", "neutral"
            )
        self._refresh_selection_summary()
        self._emit_status()

        # Emit completion signal
        self.onboarding_complete.emit()

    def load_current_settings(self, verification_state: VerificationState = "unverified"):
        """Load current settings into the UI (for settings mode)."""
        auth_type = get_auth_type()
        api_key = get_api_key()
        self._selected_model_profile = get_model_profile()
        self._apply_model_selection()
        self.key_input.blockSignals(True)
        self.key_input.clear()

        if auth_type == "system":
            self._selected_auth_type = "system"
        elif auth_type == "oauth":
            self._selected_auth_type = "oauth"
            if api_key:
                self.key_input.setText(api_key)
        elif auth_type == "api_key":
            self._selected_auth_type = "api_key"
            if api_key:
                self.key_input.setText(api_key)
        else:
            self._selected_auth_type = "system"
        self.key_input.blockSignals(False)

        self.require_approval_cb.setChecked(get_require_script_approval())
        self.auto_context_cb.setChecked(get_auto_context_enabled())
        self.redact_export_cb.setChecked(get_redact_export_paths())
        self._set_auth_type(self._selected_auth_type)
        self._set_verification_state(verification_state)

        # Reset status
        if verification_state == "verified":
            self._set_status_banner(
                "Current settings are verified and match the active chat session.",
                "success",
            )
        else:
            self._set_status_banner(
                "Saved settings loaded. Run a test to verify them.", "neutral"
            )
        self.response_label.hide()
        self.diagnostics_section.hide()
        self._refresh_selection_summary()
        self._refresh_actions()
        self._emit_status()

    def _apply_auth_button_styles(self):
        """Refresh the joined auth selector styling."""
        items = list(self._auth_buttons.items())
        for index, (auth_id, button) in enumerate(items):
            button.set_selected(
                selected=(auth_id == self._selected_auth_type),
                is_first=(index == 0),
                is_last=(index == len(items) - 1),
            )

    def _set_status_banner(self, text: str, tone: str = "neutral"):
        """Update the inline status banner."""
        colors = get_ida_colors()
        self.status_label.setText(text)
        self.status_label.setStyleSheet(status_banner_style(colors, tone))

    def _set_verification_state(self, state: VerificationState):
        """Track whether settings are verified, unverified, or actively verifying."""
        self._verification_state = state
        if hasattr(self, "save_btn"):
            self._refresh_actions()

    def _refresh_artwork_pixmap(self):
        """Scale the splash artwork to the available left column and anchor it to the bottom."""
        if not self._artwork_pixmap or self._artwork_pixmap.isNull():
            return
        available_width = max(260, self.artwork_container.width() - 2)
        available_height = max(320, self.artwork_container.height() - 18)
        scaled = self._artwork_pixmap.scaled(
            available_width,
            available_height,
            Qt.AspectRatioMode.KeepAspectRatio,
            Qt.TransformationMode.SmoothTransformation,
        )
        self.artwork_label.setPixmap(scaled)


class IDAChatForm(ida_kernwin.PluginForm):
    """Main chat widget form."""

    root_widget: QWidget = cast(QWidget, _UNSET)
    db: Database | None = None
    history: MessageHistory = cast(MessageHistory, _UNSET)
    worker: AgentWorker | None = None

    _is_processing: bool = False
    _current_message: ChatMessage | None = None
    _current_turn: int = 0
    _max_turns: int = 20
    _total_cost: float = 0.0
    _script_count: int = 0
    _last_had_error: bool = False
    _message_count: int = 0
    _model_name: str = ""
    _connection_ready: bool = False
    _run_outcome: RunOutcome = "success"
    _sidebar_expanded: bool = True
    _header_page: str = "Chat"
    _header_detail: str | None = None
    _header_state: str | None = None
    _header_pulse_on: bool = False

    sidebar_toggle_btn: QPushButton = cast(QPushButton, _UNSET)
    header_eyebrow_label: QLabel = cast(QLabel, _UNSET)
    header_title_label: QLabel = cast(QLabel, _UNSET)
    header_meta_label: QLabel = cast(QLabel, _UNSET)
    share_btn: QPushButton = cast(QPushButton, _UNSET)
    delete_chat_btn: QPushButton = cast(QPushButton, _UNSET)
    _header_pulse_timer: QTimer = cast(QTimer, _UNSET)
    onboarding_panel: OnboardingPanel = cast(OnboardingPanel, _UNSET)
    main_body: QSplitter = cast(QSplitter, _UNSET)
    sessions_sidebar: SessionsSidebar = cast(SessionsSidebar, _UNSET)
    progress_timeline: ProgressTimeline = cast(ProgressTimeline, _UNSET)
    chat_history: ChatHistoryWidget = cast(ChatHistoryWidget, _UNSET)
    input_container: QFrame = cast(QFrame, _UNSET)
    input_widget: ChatInputWidget = cast(ChatInputWidget, _UNSET)
    compose_btn: QPushButton = cast(QPushButton, _UNSET)
    status_bar: QFrame = cast(QFrame, _UNSET)
    status_label: QLabel = cast(QLabel, _UNSET)
    status_model_dot: QLabel = cast(QLabel, _UNSET)
    status_session_label: QLabel = cast(QLabel, _UNSET)
    status_session_dot: QLabel = cast(QLabel, _UNSET)
    status_messages_label: QLabel = cast(QLabel, _UNSET)
    status_cost_label: QLabel = cast(QLabel, _UNSET)
    status_hint_btn: QPushButton = cast(QPushButton, _UNSET)

    def OnCreate(self, form):
        """Called when the widget is created."""
        self.root_widget = self.FormToPyQtWidget(form)
        apply_selection_palette()
        self.db: Database | None = None
        self.worker: AgentWorker | None = None
        self._is_processing = False
        self._current_message: ChatMessage | None = None
        self._current_turn = 0
        self._max_turns = 20
        self._total_cost = 0.0
        self._script_count = 0
        self._last_had_error = False
        self._message_count = 0
        self._model_name = get_model_display_name()
        self._connection_ready = False
        self._run_outcome = "success"
        self._sidebar_expanded = True
        self._header_page = "Chat"
        self._header_detail: str | None = None
        self._header_state: str | None = "Connecting"
        self._header_pulse_on = False

        self.root_widget.setMinimumWidth(600)
        self.root_widget.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding
        )
        self._create_ui()
        apply_auth_to_environment()

        if get_show_wizard():
            self._show_onboarding()
        else:
            self._init_agent()

    def _reset_worker(self):
        """Stop any existing worker before rebuilding the agent."""
        if self.worker:
            self.worker.request_disconnect()
            self.worker.wait(5000)
            self.worker = None

    def _create_script_executor(self, db: Database) -> Callable[[str], str]:
        """Create a script executor that runs on the main thread.

        IDA operations must be performed on the main thread. This executor
        uses ida_kernwin.execute_sync() to ensure scripts run safely.
        """

        def execute_on_main_thread(code: str) -> str:
            result = [""]

            def run_script():
                old_stdout = sys.stdout
                sys.stdout = captured = StringIO()
                try:
                    exec(code, {"db": db, "print": print})
                    result[0] = captured.getvalue()
                except Exception as e:
                    result[0] = f"Script error: {e}"
                finally:
                    sys.stdout = old_stdout
                return 1  # Required return for execute_sync

            ida_kernwin.execute_sync(run_script, ida_kernwin.MFF_FAST)
            return result[0]

        return execute_on_main_thread

    def _init_agent(self, resume_session_id: str | None = None):
        """Initialize the agent worker."""
        try:
            self._reset_worker()
            self._model_name = get_model_display_name()
            self._connection_ready = False
            self._set_state_chip("Connecting", "busy")
            self._sync_composer_state()
            self.db = Database.open()
            script_executor = self._create_script_executor(self.db)
            if not self.db.path:
                raise RuntimeError("Database path is unavailable.")
            self.history = MessageHistory(self.db.path)
            if resume_session_id:
                self.history.switch_session(resume_session_id)
            self.worker = AgentWorker(
                self.db,
                script_executor,
                self.history,
                model_profile=get_model_profile(),
            )
            self.worker.signals.connection_ready.connect(self._on_connection_ready)
            self.worker.signals.connection_error.connect(self._on_connection_error)
            self.worker.signals.turn_start.connect(self._on_turn_start)
            self.worker.signals.thinking.connect(self._on_thinking)
            self.worker.signals.thinking_done.connect(self._on_thinking_done)
            self.worker.signals.tool_use.connect(self._on_tool_use)
            self.worker.signals.text.connect(self._on_text)
            self.worker.signals.script_review.connect(self._on_script_review)
            self.worker.signals.script_output.connect(self._on_script_output)
            self.worker.signals.error.connect(self._on_error)
            self.worker.signals.result.connect(self._on_result)
            self.worker.signals.finished.connect(self._on_finished)
            self.worker.signals.session_list_updated.connect(
                self._on_session_list_updated
            )
            self.worker.signals.session_loaded.connect(self._on_session_loaded)
            self.worker.request_connect()
        except Exception as error:
            self._connection_ready = False
            self._set_state_chip("Connection failed", "error")
            self._sync_composer_state()
            self.chat_history.add_message(
                f"Error initializing agent: {error}",
                is_user=False,
                msg_type=MessageType.ERROR,
            )

    def _history_or_none(self) -> MessageHistory | None:
        """Return the live message history object when initialized."""
        history = getattr(self, "history", None)
        return history if isinstance(history, MessageHistory) else None

    def _onboarding_panel_or_none(self) -> OnboardingPanel | None:
        """Return the onboarding/settings panel when initialized."""
        panel = getattr(self, "onboarding_panel", None)
        return panel if isinstance(panel, OnboardingPanel) else None

    def _visible_onboarding_panel(self) -> OnboardingPanel | None:
        """Return the onboarding panel only when currently visible."""
        panel = self._onboarding_panel_or_none()
        if panel is not None and panel.isVisible():
            return panel
        return None

    def _header_pulse_timer_or_none(self) -> QTimer | None:
        """Return the breadcrumb pulse timer when initialized."""
        timer = getattr(self, "_header_pulse_timer", None)
        return timer if isinstance(timer, QTimer) else None

    def _show_onboarding(self):
        """Show onboarding panel, hide chat UI."""
        self.onboarding_panel.set_mode("setup")
        self.onboarding_panel.show()
        self.main_body.hide()
        self.status_bar.hide()
        self._refresh_header_identity()
        self._on_onboarding_status_changed(self.onboarding_panel.current_status_text())

    def _show_settings(self):
        """Show settings panel (re-use onboarding panel)."""
        if self._is_processing:
            return
        self.onboarding_panel.set_mode("settings")
        self.onboarding_panel.load_current_settings(
            verification_state="verified" if self._connection_ready else "unverified"
        )
        self.onboarding_panel.show()
        self.main_body.hide()
        self.status_bar.hide()
        self._refresh_header_identity()
        self._on_onboarding_status_changed(self.onboarding_panel.current_status_text())
        # Hide chat-only header buttons in settings
        self.share_btn.hide()
        self.delete_chat_btn.hide()
        # Chevron becomes a back button while in settings
        self.sidebar_toggle_btn.setText("←")
        self.sidebar_toggle_btn.setToolTip("Back to chat")
        self.sidebar_toggle_btn.clicked.disconnect()
        self.sidebar_toggle_btn.clicked.connect(self._close_settings_panel)

    def _on_onboarding_complete(self):
        """Handle successful onboarding."""
        resume_session_id = None
        history = self._history_or_none()
        if history is not None:
            resume_session_id = history.get_current_session_id()
        panel = self._onboarding_panel_or_none()
        if panel is not None:
            panel.hide()
        self.main_body.show()
        self.status_bar.show()
        self._model_name = get_model_display_name()
        self._refresh_header_identity()
        self._update_status_bar()
        self._restore_chat_header_controls()
        self._init_agent(resume_session_id=resume_session_id)

    def _on_onboarding_status_changed(self, status: str):
        """Keep the header breadcrumb aligned with settings-page state."""
        panel = self._onboarding_panel_or_none()
        if panel is None:
            return
        self._model_name = panel.current_model_display_name()
        if panel.isVisible():
            self._set_header_breadcrumb(
                self._current_onboarding_page_label(),
                panel.current_auth_display_name(),
                status,
            )

    def _close_settings_panel(self):
        """Return from the settings page to the main chat view."""
        panel = self._onboarding_panel_or_none()
        if panel is None:
            return
        panel.hide()
        self.main_body.show()
        self.status_bar.show()
        self._model_name = get_model_display_name()
        self._refresh_header_identity()
        self._update_status_bar()
        self._restore_chat_header_controls()

    def _restore_chat_header_controls(self):
        """Restore the chat-only header buttons and sidebar toggle behavior."""
        # Restore chat-only header buttons
        self.share_btn.show()
        self.delete_chat_btn.show()
        # Restore chevron to sidebar toggle
        self.sidebar_toggle_btn.clicked.disconnect()
        self.sidebar_toggle_btn.clicked.connect(self._toggle_sidebar)
        toggle_text = "<" if self._sidebar_expanded else ">"
        self.sidebar_toggle_btn.setText(toggle_text)
        self.sidebar_toggle_btn.setToolTip(
            "Collapse chat history" if self._sidebar_expanded else "Expand chat history"
        )

    def _format_error(self, error: object) -> tuple[str, str | None]:
        """Split an error object into short and detailed text."""
        if isinstance(error, DiagnosticReport):
            return error.short_message, error.to_text()
        return str(error), None

    def _render_error(self, error: object, prefix: str = "Error"):
        """Render a structured error into the chat stream."""
        short, details = self._format_error(error)
        self.chat_history.add_message(
            f"{prefix}: {short}", is_user=False, msg_type=MessageType.ERROR
        )
        if details:
            self.chat_history.add_collapsible(
                f"{prefix} details", details, collapsed=False
            )

    def _collect_prompt_context(self) -> PromptContext | None:
        """Capture the current UI position and selection for the next prompt."""
        if not get_auto_context_enabled() or not self.db:
            return None

        context = PromptContext()
        try:
            ea = ida_kernwin.get_screen_ea()
            if ea != ida_idaapi.BADADDR:
                context.current_address = f"0x{ea:X}"
                try:
                    func = self.db.functions.get_at(ea)
                    if func:
                        context.current_function = self.db.functions.get_name(func)
                except Exception:
                    pass
        except Exception:
            pass

        try:
            selection = ida_kernwin.read_range_selection(None)
            if selection and selection[0]:
                context.selected_range = f"0x{selection[1]:X}-0x{selection[2]:X}"
        except Exception:
            pass

        try:
            highlight = ida_kernwin.get_highlight(ida_kernwin.get_current_widget())
            if highlight:
                context.highlighted_token = highlight[0]
        except Exception:
            pass

        try:
            current_line = ida_kernwin.get_curline()
            if current_line:
                context.current_line = ida_lines.tag_remove(current_line)
        except Exception:
            pass

        return None if context.is_empty() else context

    def _update_status_bar(self, processing_text: str | None = None):
        """Update the status bar with current stats or processing text.

        Args:
            processing_text: If provided, show this instead of idle stats.
        """
        colors = get_ida_colors()
        if processing_text:
            self.status_label.setText(processing_text)
            self.status_label.setStyleSheet(
                f"color: {colors['text_muted']}; font-size: 11px; font-weight: 500;"
            )
            for widget in (
                self.status_model_dot,
                self.status_session_label,
                self.status_session_dot,
                self.status_messages_label,
                self.status_cost_label,
            ):
                widget.hide()
        else:
            session_title = "New Chat"
            history = self._history_or_none()
            if history is not None:
                session_title = (
                    history.get_current_session_title().strip() or "New Chat"
                )
            if len(session_title) > 32:
                session_title = f"{session_title[:29]}..."

            self.status_label.setText(self._model_name)
            self.status_label.setStyleSheet(
                f"color: {colors['text']}; font-size: 12px; font-weight: 600;"
            )
            self.status_model_dot.show()
            self.status_session_label.setText(session_title)
            self.status_session_label.show()
            self.status_session_dot.show()
            self.status_messages_label.setText(f"{self._message_count} msgs")
            self.status_messages_label.show()
            if self._total_cost > 0:
                self.status_cost_label.setText(f"${self._total_cost:.4f}")
                self.status_cost_label.show()
            else:
                self.status_cost_label.hide()
        self._refresh_status_hint()
        panel = self._visible_onboarding_panel()
        if panel is not None:
            self._set_header_breadcrumb(
                self._current_onboarding_page_label(),
                panel.current_auth_display_name(),
                panel.current_status_text(),
            )
            return
        session_title = None
        history = self._history_or_none()
        if history is not None:
            session_title = (
                history.get_current_session_title().strip() or "New Chat"
            )
        elif self._connection_ready:
            session_title = "New Chat"
        state = processing_text.rstrip(".") if processing_text else None
        self._set_header_breadcrumb("Chat", session_title, state)

    def _set_header_breadcrumb(
        self,
        page: str,
        detail: str | None = None,
        state: str | None = None,
    ):
        """Render the compact header breadcrumb under the main title."""
        self._header_page = page
        self._header_detail = detail
        self._header_state = state
        header_meta_label = getattr(self, "header_meta_label", None)
        if header_meta_label is None:
            return
        colors = get_ida_colors()
        if page in {"Setup", "Settings"}:
            self._sync_header_pulse()
            trail_parts = [
                html.escape(str(part))
                for part in (page, detail)
                if str(part or "").strip()
            ]
            pieces = [" / ".join(trail_parts)]
            if self._model_name:
                pieces.append(
                    f'<span style="color:{colors["text_muted"]};">{html.escape(self._model_name)}</span>'
                )
            if state:
                pieces.append(self._format_onboarding_state_html(state, colors))
            header_meta_label.setText(" · ".join(filter(None, pieces)))
            return
        self._stop_header_pulse()
        parts: list[str] = []
        for part in (page, detail, state):
            normalized = (part or "").strip()
            if normalized and normalized not in parts:
                parts.append(normalized)
        trail = " / ".join(parts) if parts else page
        header_meta_label.setText(f"{trail} · {self._model_name}")

    def _set_state_chip(self, text: str, tone: str = "neutral"):
        """Update the compact breadcrumb state text."""
        panel = self._visible_onboarding_panel()
        if panel is not None:
            self._set_header_breadcrumb(
                self._current_onboarding_page_label(),
                panel.current_auth_display_name(),
                panel.current_status_text(),
            )
            return
        detail = None
        history = self._history_or_none()
        if history is not None:
            detail = history.get_current_session_title().strip() or "New Chat"
        elif self._connection_ready:
            detail = "New Chat"
        state = None if text == "Ready" else text
        self._set_header_breadcrumb("Chat", detail, state)

    def _current_onboarding_page_label(self) -> str:
        """Return the correct header page label for the onboarding panel."""
        panel = self._onboarding_panel_or_none()
        if panel is None:
            return "Settings"
        return "Settings" if panel._panel_mode == "settings" else "Setup"

    def _refresh_header_identity(self):
        """Update the static header title block for chat versus settings surfaces."""
        header_eyebrow_label = getattr(self, "header_eyebrow_label", None)
        if header_eyebrow_label is not None:
            header_eyebrow_label.setText("AI RCE ASSISTANT")
        header_title_label = getattr(self, "header_title_label", None)
        if header_title_label is None:
            return
        if self._visible_onboarding_panel() is not None:
            header_title_label.setText("Settings")
        else:
            header_title_label.setText(PLUGIN_NAME)

    def _format_onboarding_state_html(
        self, state: str, colors: dict[str, object]
    ) -> str:
        """Render settings/setup verification state with a colored status dot."""
        normalized = state.strip().lower()
        if normalized == "verified":
            tone = colors["success_text"]
            dot_color = colors["success"]
        elif normalized in ("unverified", "not verified"):
            tone = colors["danger_text"]
            dot_color = colors["danger"]
        else:
            tone = colors["text_muted"]
            dot_color = (
                colors["text_muted"] if self._header_pulse_on else colors["text_subtle"]
            )
        label = html.escape(state)
        return (
            f'<span style="color:{dot_color}; font-size:12px;">●</span> '
            f'<span style="color:{tone};">{label}</span>'
        )

    def _sync_header_pulse(self):
        """Animate the muted verifying dot while settings/setup is testing."""
        timer = self._header_pulse_timer_or_none()
        if timer is None:
            return
        if self._header_state == "Verifying...":
            if not timer.isActive():
                timer.start()
        else:
            self._stop_header_pulse()

    def _stop_header_pulse(self):
        """Stop the header pulse animation when verification is idle."""
        timer = self._header_pulse_timer_or_none()
        if timer is not None and timer.isActive():
            timer.stop()
        self._header_pulse_on = False

    def _on_header_pulse_tick(self):
        """Re-render the onboarding breadcrumb to animate the verifying dot."""
        self._header_pulse_on = not self._header_pulse_on
        self._set_header_breadcrumb(
            self._header_page, self._header_detail, self._header_state
        )

    def _apply_compose_btn_style(
        self, colors: dict[str, object], processing: bool
    ) -> None:
        """Apply the correct circular style to the inline send/stop button."""
        if processing:
            self.compose_btn.setText("■")
            self.compose_btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {colors["danger"]};
                    color: {colors["danger_text"]};
                    border: none;
                    border-radius: 16px;
                    font-size: 14px;
                    font-weight: 500;
                }}
                QPushButton:hover {{ background-color: {colors["danger_border"]}; }}
                QPushButton:disabled {{ background-color: {colors["surface_alt"]}; color: {colors["text_muted"]}; }}
            """)
        else:
            self.compose_btn.setText("↑")
            self.compose_btn.setStyleSheet(f"""
                QPushButton {{
                    background-color: {colors["accent"]};
                    color: {colors["accent_text"]};
                    border: none;
                    border-radius: 16px;
                    font-size: 16px;
                    font-weight: 400;
                }}
                QPushButton:hover {{ background-color: {colors["accent_hover"]}; }}
                QPushButton:pressed {{ background-color: {colors["accent_hover"]}; }}
                QPushButton:disabled {{ background-color: {colors["surface_alt"]}; color: {colors["text_muted"]}; }}
            """)

    def _refresh_status_hint(self):
        """Refresh the footer toggle text and styling."""
        status_hint_btn = getattr(self, "status_hint_btn", None)
        if status_hint_btn is None:
            return
        colors = get_ida_colors()
        enabled = get_auto_context_enabled()
        status_hint_btn.setText("Auto context on" if enabled else "Auto context off")
        status_hint_btn.setChecked(enabled)
        status_hint_btn.setToolTip(
            "Automatically attach the current cursor, symbol, selection, and related context to new prompts."
            if enabled
            else "Manual mode: prompts will not include current IDA context unless you add it yourself."
        )
        if enabled:
            status_hint_btn.setStyleSheet(f"""
                QPushButton {{
                    color: {colors["success_text"]};
                    background-color: transparent;
                    border: none;
                    padding: 0 2px;
                    min-height: 22px;
                    font-size: 11px;
                    font-weight: 500;
                }}
                QPushButton:hover {{
                    color: {colors["text"]};
                }}
                QPushButton:pressed {{
                    color: {colors["text"]};
                }}
                QPushButton:disabled {{
                    background-color: transparent;
                    color: {colors["text_subtle"]};
                }}
            """)
        else:
            status_hint_btn.setStyleSheet(f"""
                QPushButton {{
                    color: {colors["text_muted"]};
                    background-color: transparent;
                    border: none;
                    padding: 0 2px;
                    min-height: 22px;
                    font-size: 11px;
                    font-weight: 500;
                }}
                QPushButton:hover {{
                    color: {colors["text"]};
                }}
                QPushButton:pressed {{
                    color: {colors["text"]};
                }}
                QPushButton:disabled {{
                    background-color: transparent;
                    color: {colors["text_subtle"]};
                }}
            """)

    def _toggle_auto_context_footer(self):
        """Toggle auto-context from the footer chip."""
        set_auto_context_enabled(not get_auto_context_enabled())
        self._refresh_status_hint()

    def _sync_composer_state(self):
        """Keep composer controls aligned with connection and processing state."""
        input_widget = getattr(self, "input_widget", None)
        compose_btn = getattr(self, "compose_btn", None)
        if input_widget is None or compose_btn is None:
            return
        colors = get_ida_colors()
        history = self._history_or_none()
        has_session = bool(history and history.get_current_session_id())
        ready_for_input = self._connection_ready and not self._is_processing
        input_widget.setEnabled(ready_for_input)
        has_text = bool(input_widget.toPlainText().strip())
        compose_btn.setEnabled(
            self._is_processing or (self._connection_ready and has_text)
        )

        delete_chat_btn = getattr(self, "delete_chat_btn", None)
        if delete_chat_btn is not None:
            delete_chat_btn.setEnabled(has_session and not self._is_processing)
        share_btn = getattr(self, "share_btn", None)
        if share_btn is not None:
            share_btn.setEnabled(has_session and not self._is_processing)
        sessions_sidebar = getattr(self, "sessions_sidebar", None)
        settings_btn = getattr(sessions_sidebar, "settings_btn", None)
        if settings_btn is not None:
            settings_btn.setEnabled(not self._is_processing)
        status_hint_btn = getattr(self, "status_hint_btn", None)
        if status_hint_btn is not None:
            status_hint_btn.setEnabled(not self._is_processing)
        self._apply_compose_btn_style(colors, processing=self._is_processing)

    def _toggle_sidebar(self):
        """Collapse or expand the sessions sidebar."""
        self._sidebar_expanded = not self._sidebar_expanded
        self.sessions_sidebar.setVisible(self._sidebar_expanded)
        toggle_text = "<" if self._sidebar_expanded else ">"
        tooltip = (
            "Collapse chat history" if self._sidebar_expanded else "Expand chat history"
        )
        self.sidebar_toggle_btn.setText(toggle_text)
        self.sidebar_toggle_btn.setToolTip(tooltip)
        if self._sidebar_expanded:
            self.main_body.setSizes([320, max(self.root_widget.width() - 320, 640)])
        else:
            self.main_body.setSizes([0, max(self.root_widget.width(), 900)])

    def _on_connection_ready(self, _payload: object):
        """Called when agent connection is established."""
        self._connection_ready = True
        self.chat_history.add_message("Agent connected and ready!", is_user=False)
        self._set_state_chip("Ready", "ready")
        self._sync_composer_state()
        self.input_widget.setFocus()
        self._update_status_bar()
        self._refresh_status_hint()

        # Sync settings panel verification state — agent connected = verified
        panel = self._onboarding_panel_or_none()
        if panel is not None:
            panel._set_verification_state("verified")
            panel._emit_status()

        # Load message history for up/down arrow navigation
        history = self._history_or_none()
        if history is not None:
            user_messages = history.get_all_user_messages()
            self.input_widget.set_history(user_messages)

    def _on_connection_error(self, error: object):
        """Called when agent connection fails."""
        self._connection_ready = False
        self._render_error(error, prefix="Connection error")
        self._set_state_chip("Connection failed", "error")
        self._sync_composer_state()
        self._update_status_bar("Connection failed")

        # Sync settings panel verification state
        panel = self._onboarding_panel_or_none()
        if panel is not None:
            panel._set_verification_state("unverified")
            panel._emit_status()

    def _on_turn_start(self, turn: int, max_turns: int):
        """Called at the start of each agentic turn."""
        self._current_turn = turn
        self._max_turns = max_turns

    def _on_thinking(self):
        """Called when agent starts processing."""
        self._is_processing = True
        # Mark previous message as complete before starting new turn
        if self._current_message:
            self._current_message.set_complete()
        self._set_state_chip("Thinking", "busy")
        self._sync_composer_state()

        # Check if this is a retry after error
        if self._last_had_error:
            self._last_had_error = False
            # Update timeline
            self.progress_timeline.add_stage("Retrying")
            # Add retry message
            self._current_message = self.chat_history.add_message(
                "Retrying after error...", is_user=False, is_processing=True
            )
        else:
            self.progress_timeline.add_stage("Thinking")
            self._current_message = self.chat_history.add_message(
                "Thinking...", is_user=False, is_processing=True
            )
        self._update_status_bar("Thinking...")

    def _on_thinking_done(self):
        """Called when agent produces first output."""
        if self._current_message:
            self._current_message.deleteLater()
            self._current_message = None

    def _add_processing_message(
        self, text: str, msg_type: str = MessageType.TEXT
    ) -> None:
        """Add a new processing message, marking previous one as complete."""
        if self._current_message:
            self._current_message.set_complete()
            self._current_message = None
        self._current_message = self.chat_history.add_message(
            text, is_user=False, is_processing=True, msg_type=msg_type
        )

    def _on_tool_use(self, tool_name: str, details: str):
        """Called when agent uses a tool."""
        tool_msg = f"{tool_name}"
        if details:
            tool_msg += f" · {details}"
        self._add_processing_message(tool_msg, MessageType.TOOL_USE)

    def _on_text(self, text: str):
        """Called when agent outputs text."""
        if not text.strip():
            return
        # Accumulate consecutive text into one bubble instead of creating many boxes
        if (
            self._current_message
            and not self._current_message.is_user
            and self._current_message._msg_type == MessageType.TEXT
        ):
            self._current_message.append_text(text)
        else:
            self._add_processing_message(text)

    def _on_script_review(self, request: ScriptApprovalRequest):
        """Render a generated script preview and approval controls."""
        self._script_count += 1
        self.progress_timeline.add_stage(f"Script {self._script_count}")
        if self._current_message:
            self._current_message.set_complete()
            self._current_message = None
        card = self.chat_history.add_script_review(request)
        if request.requires_approval and self.worker:
            card.decision_made.connect(self.worker.submit_script_decision)

    def _on_script_output(self, output: str):
        """Called with script output."""
        if output.strip():
            is_error = output.strip().startswith("Script error:")
            if is_error:
                self._last_had_error = True
                self.chat_history.add_message(
                    output, is_user=False, msg_type=MessageType.ERROR
                )
            elif CollapsibleSection.should_collapse(output):
                if self._current_message:
                    self._current_message.set_complete()
                    self._current_message = None
                self.chat_history.add_collapsible(
                    "Script Output", output, collapsed=True
                )
            else:
                self.chat_history.add_message(
                    output, is_user=False, msg_type=MessageType.OUTPUT
                )

    def _on_error(self, error: object):
        """Called when an error occurs."""
        short, details = self._format_error(error)
        if short != "Operation cancelled":
            self._run_outcome = "error"
            self._last_had_error = True
            self._set_state_chip("Needs attention", "error")
        else:
            self._run_outcome = "cancelled"
            self._set_state_chip("Cancelled", "neutral")
        self.chat_history.add_message(
            f"Error: {short}", is_user=False, msg_type=MessageType.ERROR
        )
        if details:
            self.chat_history.add_collapsible("Error details", details, collapsed=False)

    def _on_result(self, _num_turns: int, cost: float):
        """Called when agent returns result with stats."""
        self._total_cost += cost

    def _on_session_list_updated(self, sessions: object):
        """Refresh sidebar contents after session mutations."""
        session_list = sessions if isinstance(sessions, list) else []
        typed_session_list = cast(list[dict[str, object]], session_list)
        self.sessions_sidebar.set_sessions(
            typed_session_list
        )
        history = self._history_or_none()
        message_count = current_session_message_count(
            typed_session_list,
            history.get_current_session_id() if history is not None else None,
        )
        if message_count is not None:
            self._message_count = message_count
        self._sync_composer_state()
        self._update_status_bar()

    def _render_session_items(self, items: list[dict[str, object]]):
        """Rehydrate a session into the chat history area."""
        for item in items:
            kind = item.get("kind")
            if kind == "user":
                self.chat_history.add_message(str(item.get("text", "")), is_user=True)
            elif kind == "assistant":
                self.chat_history.add_message(str(item.get("text", "")), is_user=False)
            elif kind == "tool":
                details = str(item.get("details", ""))
                tool_name = str(item.get("tool_name", "Tool"))
                label = tool_name if not details else f"{tool_name} · {details}"
                self.chat_history.add_message(
                    label, is_user=False, msg_type=MessageType.TOOL_USE
                )
            elif kind == "script":
                request = ScriptApprovalRequest(
                    request_id=f"history_{len(str(item.get('code', '')))}_{self._script_count}",
                    code=str(item.get("code", "")),
                    script_index=1,
                    total_scripts=1,
                    risk=_coerce_script_risk(item.get("risk", "unknown")),
                    preview=str(item.get("code", ""))[:240],
                    requires_approval=False,
                )
                self.chat_history.add_script_review(request)
            elif kind in {"output", "tool_result"}:
                text = str(item.get("text", ""))
                if item.get("is_error"):
                    self.chat_history.add_message(
                        text, is_user=False, msg_type=MessageType.ERROR
                    )
                elif CollapsibleSection.should_collapse(text):
                    self.chat_history.add_collapsible("Output", text, collapsed=True)
                else:
                    self.chat_history.add_message(
                        text, is_user=False, msg_type=MessageType.OUTPUT
                    )
            elif kind == "system":
                msg_type = (
                    MessageType.ERROR
                    if item.get("level") == "error"
                    else MessageType.TEXT
                )
                self.chat_history.add_message(
                    str(item.get("text", "")), is_user=False, msg_type=msg_type
                )

    def _on_session_loaded(self, summary: object, items: object):
        """Render a resumed or newly created session."""
        self.chat_history.clear_history()
        self._script_count = 0
        loaded_items = items if isinstance(items, list) else []
        if loaded_items:
            self._render_session_items(cast(list[dict[str, object]], loaded_items))
        else:
            self.chat_history.add_message(
                "Ready for a new conversation. Try asking about the current function, a highlighted symbol, or your current selection.",
                is_user=False,
            )
        if isinstance(summary, dict):
            self._message_count = _coerce_int(summary.get("message_count"))
        self._update_status_bar()
        self._set_state_chip("Ready", "ready")
        self._sync_composer_state()
        self.input_widget.setFocus()

    def _on_finished(self):
        """Called when agent finishes processing."""
        self._is_processing = False
        status_text, tone, mark_complete = describe_run_outcome(self._run_outcome)
        self._set_state_chip(status_text, tone)
        self._sync_composer_state()
        self.input_widget.setFocus()
        self._update_status_bar()
        if mark_complete:
            self.progress_timeline.complete()
        if self._current_message:
            self._current_message.set_complete()
            self._current_message = None

    def _create_ui(self):
        """Create the chat interface UI."""
        colors = get_ida_colors()
        self.root_widget.setObjectName("idaChatRoot")
        self.root_widget.setStyleSheet(f"""
            QWidget#idaChatRoot {{
                background-color: {colors["app_bg"]};
                color: {colors["text"]};
            }}
            QSplitter#chatMainBody::handle {{
                background-color: transparent;
                width: 12px;
            }}
            QScrollBar:vertical {{
                background-color: transparent;
                width: 0px;
                margin: 0px;
            }}
            QScrollBar::handle:vertical {{
                background-color: transparent;
                border-radius: {colors["radius_xs"]}px;
                min-height: 32px;
            }}
            QScrollBar:horizontal {{
                background-color: transparent;
                height: 0px;
                margin: 0px;
            }}
            QScrollBar::handle:horizontal {{
                background-color: transparent;
                border-radius: {colors["radius_xs"]}px;
                min-width: 32px;
            }}
            QScrollBar::add-line:vertical,
            QScrollBar::sub-line:vertical,
            QScrollBar::add-page:vertical,
            QScrollBar::sub-page:vertical,
            QScrollBar::add-line:horizontal,
            QScrollBar::sub-line:horizontal,
            QScrollBar::add-page:horizontal,
            QScrollBar::sub-page:horizontal {{
                background: transparent;
                height: 0px;
            }}
        """)

        layout = QVBoxLayout()
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(12)

        # Header
        header = QFrame()
        header.setObjectName("chatHeader")
        header.setStyleSheet(f"""
            QFrame#chatHeader {{
                background-color: {colors["header_bg"]};
                border: 1px solid {colors["border"]};
                border-radius: {colors["radius_xl"]}px;
            }}
        """)
        header_layout = QHBoxLayout(header)
        header_layout.setContentsMargins(14, 12, 14, 12)
        header_layout.setSpacing(10)

        self.sidebar_toggle_btn = QPushButton("<")
        self.sidebar_toggle_btn.setFixedSize(32, 32)
        self.sidebar_toggle_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.sidebar_toggle_btn.setToolTip("Collapse chat history")
        self.sidebar_toggle_btn.setStyleSheet(
            button_style(colors, "ghost", compact=True)
        )
        self.sidebar_toggle_btn.clicked.connect(self._toggle_sidebar)
        header_layout.addWidget(self.sidebar_toggle_btn)

        title_block = QVBoxLayout()
        title_block.setContentsMargins(0, 0, 0, 0)
        title_block.setSpacing(2)

        self.header_eyebrow_label = QLabel("AI RCE ASSISTANT")
        self.header_eyebrow_label.setStyleSheet(
            f"QLabel {{ color: {colors['text_subtle']}; font-size: 10px; font-weight: 500; letter-spacing: 1.5px; }}"
        )
        title_block.addWidget(self.header_eyebrow_label)

        self.header_title_label = QLabel(PLUGIN_NAME)
        self.header_title_label.setStyleSheet(
            f"QLabel {{ color: {colors['window_text']}; font-size: 22px; font-weight: 700; }}"
        )
        title_block.addWidget(self.header_title_label)

        self.header_meta_label = QLabel(f"Connecting · {self._model_name}")
        self.header_meta_label.setStyleSheet(
            f"QLabel {{ color: {colors['text_muted']}; font-size: 12px; }}"
        )
        self.header_meta_label.setTextFormat(Qt.TextFormat.RichText)
        title_block.addWidget(self.header_meta_label)
        header_layout.addLayout(title_block, stretch=1)

        self.share_btn = QPushButton("Export")
        self.share_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.share_btn.setStyleSheet(button_style(colors, "info"))
        self.share_btn.clicked.connect(self._on_share)
        header_layout.addWidget(self.share_btn)

        self.delete_chat_btn = QPushButton("Delete")
        self.delete_chat_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.delete_chat_btn.setStyleSheet(button_style(colors, "danger"))
        self.delete_chat_btn.clicked.connect(self._on_delete_current_session)
        header_layout.addWidget(self.delete_chat_btn)

        layout.addWidget(header)
        self._header_pulse_timer = QTimer(self.root_widget)
        self._header_pulse_timer.setInterval(520)
        self._header_pulse_timer.timeout.connect(self._on_header_pulse_tick)
        self._refresh_header_identity()
        self._set_state_chip("Connecting", "busy")

        self.onboarding_panel = OnboardingPanel()
        self.onboarding_panel.onboarding_complete.connect(self._on_onboarding_complete)
        self.onboarding_panel.status_changed.connect(self._on_onboarding_status_changed)
        self.onboarding_panel.back_requested.connect(self._close_settings_panel)
        self.onboarding_panel.hide()
        layout.addWidget(self.onboarding_panel)

        self.main_body = QSplitter(Qt.Orientation.Horizontal)
        self.main_body.setObjectName("chatMainBody")
        self.main_body.setChildrenCollapsible(False)
        self.main_body.setHandleWidth(12)
        self.sessions_sidebar = SessionsSidebar()
        self.sessions_sidebar.new_chat_requested.connect(self._on_clear)
        self.sessions_sidebar.resume_requested.connect(self._on_resume_session)
        self.sessions_sidebar.settings_requested.connect(self._show_settings)
        self.sessions_sidebar.delete_requested.connect(self._on_delete_session)
        self.sessions_sidebar.export_requested.connect(self._export_session)
        self.main_body.addWidget(self.sessions_sidebar)

        conversation = QFrame()
        conversation.setObjectName("conversationShell")
        conversation.setStyleSheet(f"""
            QFrame#conversationShell {{
                background-color: transparent;
                border-radius: {colors["radius_xl"]}px;
            }}
        """)
        conversation_layout = QVBoxLayout(conversation)
        conversation_layout.setContentsMargins(0, 0, 0, 0)
        conversation_layout.setSpacing(10)

        self.progress_timeline = ProgressTimeline()
        conversation_layout.addWidget(self.progress_timeline)

        self.chat_history = ChatHistoryWidget()
        conversation_layout.addWidget(self.chat_history, stretch=1)

        self.input_container = QFrame()
        self.input_container.setObjectName("inputShell")
        self.input_container.setStyleSheet(f"""
            QFrame#inputShell {{
                background-color: {colors["surface"]};
                border: 1px solid {colors["border"]};
                border-radius: {colors["radius_xl"]}px;
            }}
        """)
        input_layout = QVBoxLayout(self.input_container)
        input_layout.setContentsMargins(0, 0, 0, 0)
        input_layout.setSpacing(0)

        self.input_widget = ChatInputWidget()
        self.input_widget.message_submitted.connect(self._on_message_submitted)
        self.input_widget.cancel_requested.connect(self._on_cancel)
        self.input_widget.setStyleSheet(f"""
            QPlainTextEdit {{
                background-color: transparent;
                color: {colors["text"]};
                border: none;
                padding: 8px 12px 4px 12px;
                font-size: 12px;
                selection-background-color: {_teal_selection(colors)[0]};
            }}
            QPlainTextEdit:focus {{ border: none; }}
        """)
        input_layout.addWidget(self.input_widget)

        bottom_row = QHBoxLayout()
        bottom_row.setContentsMargins(8, 0, 8, 6)
        bottom_row.setSpacing(5)
        bottom_row.addStretch(1)

        shortcuts_label = QLabel("Enter sends  ·  Shift+Enter new line  ·  Esc stop")
        shortcuts_label.setStyleSheet(
            f"QLabel {{ color: {colors['text_subtle']}; font-size: 11px; }}"
        )
        bottom_row.addWidget(shortcuts_label)

        self.compose_btn = QPushButton("↑")
        self.compose_btn.setFixedSize(32, 32)
        self.compose_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.compose_btn.clicked.connect(self._on_compose_clicked)
        self.compose_btn.setEnabled(False)
        self._apply_compose_btn_style(colors, processing=False)
        bottom_row.addWidget(self.compose_btn)

        input_layout.addLayout(bottom_row)

        # Enable send button only when there's text
        self.input_widget.textChanged.connect(
            lambda: self.compose_btn.setEnabled(
                bool(self.input_widget.toPlainText().strip()) or self._is_processing
            )
        )

        # Side margins matching the chat area
        input_wrapper_layout = QHBoxLayout()
        input_wrapper_layout.setContentsMargins(12, 6, 12, 0)
        input_wrapper_layout.addWidget(self.input_container)
        conversation_layout.addLayout(input_wrapper_layout)
        self.main_body.addWidget(conversation)
        self.main_body.setStretchFactor(0, 0)
        self.main_body.setStretchFactor(1, 1)
        self.main_body.setSizes([320, 980])
        layout.addWidget(self.main_body, stretch=1)

        self.status_bar = QFrame()
        self.status_bar.setObjectName("chatStatusBar")
        self.status_bar.setStyleSheet(f"""
            QFrame#chatStatusBar {{
                background-color: {colors["surface"]};
                border: 1px solid {colors["border"]};
                border-radius: {colors["radius_lg"]}px;
            }}
        """)
        status_layout = QHBoxLayout(self.status_bar)
        status_layout.setContentsMargins(10, 6, 10, 6)
        status_layout.setSpacing(8)

        self.status_label = QLabel("")
        self.status_label.setStyleSheet(
            f"color: {colors['text']}; font-size: 12px; font-weight: 600;"
        )
        status_layout.addWidget(self.status_label)

        self.status_model_dot = QLabel("·")
        self.status_model_dot.setStyleSheet(
            f"color: {colors['text_subtle']}; font-size: 11px;"
        )
        status_layout.addWidget(self.status_model_dot)

        self.status_session_label = QLabel("New Chat")
        self.status_session_label.setStyleSheet(
            f"color: {colors['text_muted']}; font-size: 11px; font-weight: 500;"
        )
        status_layout.addWidget(self.status_session_label)

        self.status_session_dot = QLabel("·")
        self.status_session_dot.setStyleSheet(
            f"color: {colors['text_subtle']}; font-size: 11px;"
        )
        status_layout.addWidget(self.status_session_dot)

        self.status_messages_label = QLabel("0 msgs")
        self.status_messages_label.setStyleSheet(
            f"color: {colors['text_muted']}; font-size: 11px; font-weight: 500;"
        )
        status_layout.addWidget(self.status_messages_label)

        self.status_cost_label = QLabel("")
        self.status_cost_label.setStyleSheet(f"""
            QLabel {{
                background-color: {colors["info_soft"]};
                color: {colors["info_text"]};
                border: 1px solid {colors["info_border"]};
                border-radius: {colors["radius_md"]}px;
                padding: 2px 8px;
                font-size: 10px;
                font-weight: 500;
            }}
        """)
        self.status_cost_label.hide()
        status_layout.addWidget(self.status_cost_label)

        status_layout.addStretch()
        self.status_hint_btn = QPushButton()
        self.status_hint_btn.setCheckable(True)
        self.status_hint_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.status_hint_btn.clicked.connect(self._toggle_auto_context_footer)
        status_layout.addWidget(self.status_hint_btn)
        self._refresh_status_hint()

        layout.addWidget(self.status_bar)

        self.root_widget.setLayout(layout)
        self._sync_composer_state()

        # Add welcome message
        self._add_welcome_message()

    def _add_welcome_message(self):
        """Add a welcome message to the chat."""
        welcome_text = (
            "IDA Chat is connecting to Claude. Use the sessions drawer to reopen prior investigations, "
            "or start a fresh chat against the current function, cursor, or selection."
        )
        self.chat_history.add_message(welcome_text, is_user=False)
        self._sync_composer_state()

    def _on_message_submitted(self, text: str):
        """Handle message submission from input widget."""
        self._send_message(text)

    def _send_message(self, text: str):
        """Send a message to the agent."""
        if not self.worker or self._is_processing:
            return

        # Reset timeline for new conversation
        self.progress_timeline.reset()
        self._script_count = 0
        self._last_had_error = False
        self._run_outcome = "success"

        # Add user message to chat
        self.chat_history.add_message(text, is_user=True)

        self.worker.send_message(text, self._collect_prompt_context())

    def _on_compose_clicked(self):
        """Submit or cancel from the composer action button."""
        if self._is_processing:
            self._on_cancel()
        else:
            self.input_widget.submit_current_text()

    def _on_cancel(self):
        """Cancel the current agent operation."""
        if self.worker and self._is_processing:
            self.worker.request_cancel()
            self._set_state_chip("Stopping", "busy")

    def _export_session(self, session_id: str):
        """Export a specific session to HTML."""
        history = self._history_or_none()
        if history is None:
            self.chat_history.add_message("No active session to export.", is_user=False)
            return

        session_file = history.session_dir / f"{session_id}.jsonl"
        if not session_file.exists():
            self.chat_history.add_message(
                "No session file found to export.", is_user=False
            )
            return

        idb_path = Path(history.binary_path)
        default_path = str(idb_path.parent / f"{idb_path.stem}_{session_id[:8]}.html")
        dialog = QFileDialog(
            self.root_widget, "Export chat transcript", default_path, "HTML Files (*.html)"
        )
        dialog.setAcceptMode(QFileDialog.AcceptMode.AcceptSave)
        dialog.setFileMode(QFileDialog.FileMode.AnyFile)
        dialog.setOption(QFileDialog.Option.DontUseNativeDialog, True)
        dialog.setDefaultSuffix("html")
        apply_dialog_chrome(dialog)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        selected_files = dialog.selectedFiles()
        html_path = selected_files[0] if selected_files else ""
        if not html_path:
            return

        try:
            export_path = Path(html_path)
            export_transcript(
                session_file,
                export_path,
                redact_paths=get_redact_export_paths(),
                binary_path=history.binary_path,
            )
            history.record_export_path(str(export_path), session_id=session_id)
            file_url = export_path.resolve().as_uri()
            self.chat_history.add_message(
                f"Chat exported to: [{export_path}]({file_url})", is_user=False
            )
            self.sessions_sidebar.set_sessions(history.list_sessions())
        except Exception as error:
            self.chat_history.add_message(
                f"Export failed: {error}", is_user=False, msg_type=MessageType.ERROR
            )

    def _on_share(self):
        """Export the current or selected session."""
        history = self._history_or_none()
        if history is None:
            return
        session_id = (
            self.sessions_sidebar.selected_session_id()
            or history.get_current_session_id()
        )
        if session_id:
            self._export_session(session_id)

    def _on_clear(self):
        """Clear the chat history."""
        if self._is_processing:
            return
        self.chat_history.clear_history()
        self._total_cost = 0.0
        self._script_count = 0
        self._message_count = 0
        self.progress_timeline.hide_timeline()
        self._set_state_chip("Ready", "ready")

        # Start a new session for history tracking
        if self.worker:
            self.worker.request_new_session()

        self._sync_composer_state()
        self.input_widget.setFocus()
        self._update_status_bar()

    def _on_resume_session(self, session_id: str):
        """Resume a selected historical session."""
        if self.worker and not self._is_processing:
            self.worker.request_resume_session(session_id)

    def _on_delete_current_session(self):
        """Delete the currently active chat session."""
        history = self._history_or_none()
        if history is None:
            return
        session_id = history.get_current_session_id()
        if session_id:
            self._on_delete_session(session_id)

    def _on_delete_session(self, session_id: str):
        """Delete a selected session after confirmation."""
        history = self._history_or_none()
        if self._is_processing or not self.worker or history is None:
            return

        current_sessions = history.list_sessions()
        current = next(
            (item for item in current_sessions if item.get("id") == session_id), None
        )
        title = str((current or {}).get("title") or "this chat")
        dialog = QMessageBox(self.root_widget)
        dialog.setWindowTitle("Delete chat")
        dialog.setIcon(QMessageBox.Icon.Warning)
        dialog.setText(f"Delete '{title}' permanently?")
        dialog.setInformativeText("This removes the saved transcript for this session.")
        dialog.setStandardButtons(
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        dialog.setDefaultButton(QMessageBox.StandardButton.No)
        colors = apply_dialog_chrome(dialog)
        style_dialog_button(
            dialog.button(QMessageBox.StandardButton.Yes), colors, "danger"
        )
        style_dialog_button(
            dialog.button(QMessageBox.StandardButton.No), colors, "secondary"
        )
        if dialog.exec() != QMessageBox.StandardButton.Yes:
            return

        if session_id == self.history.get_current_session_id():
            self.chat_history.clear_history()
            self.progress_timeline.hide_timeline()
            self._message_count = 0
            self._total_cost = 0.0
            self._script_count = 0
        self.worker.request_delete_session(session_id)
        self._set_state_chip("Updating", "busy")

    def OnClose(self, form):
        """Called when the widget is closed."""
        self._reset_worker()


class ToggleWidgetHandler(ida_kernwin.action_handler_t):
    """Handler to toggle the dockable widget."""

    plugin: "IDAChatPlugin" = cast("IDAChatPlugin", _UNSET)

    def __new__(cls, *args: object, **kwargs: object) -> "ToggleWidgetHandler":
        return cast(
            "ToggleWidgetHandler",
            super(ToggleWidgetHandler, cls).__new__(cls, *args, **kwargs),
        )

    def __init__(self, *args: object, **kwargs: object) -> None:
        ida_kernwin.action_handler_t.__init__(self)

    def activate(self, ctx):
        """Toggle widget visibility."""
        self.plugin.toggle_widget()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_ALWAYS


class IDAChatPlugin(ida_idaapi.plugin_t):
    """Main plugin class."""

    flags = ida_idaapi.PLUGIN_KEEP
    comment = PLUGIN_COMMENT
    help = PLUGIN_HELP
    wanted_name = PLUGIN_NAME
    wanted_hotkey = ""
    form: IDAChatForm | None = None

    def init(self):
        """Initialize the plugin."""
        self.form = None

        # Register toggle action
        handler = ToggleWidgetHandler()
        handler.plugin = self
        action_desc_factory = cast(Any, ida_kernwin.action_desc_t)
        action_desc = action_desc_factory(
            ACTION_ID,
            ACTION_NAME,
            handler,
            "",
            ACTION_TOOLTIP,
            -1,
        )

        if not ida_kernwin.register_action(action_desc):
            ida_kernwin.msg(f"{PLUGIN_NAME}: Failed to register action\n")
            return ida_idaapi.PLUGIN_SKIP

        ida_kernwin.attach_action_to_menu("View/", ACTION_ID, ida_kernwin.SETMENU_APP)

        ida_kernwin.msg(f"{PLUGIN_NAME}: Loaded (open from View > IDA Chat)\n")
        return ida_idaapi.PLUGIN_KEEP

    def toggle_widget(self):
        """Show or hide the dockable widget."""
        widget = ida_kernwin.find_widget(WIDGET_TITLE)

        if widget:
            ida_kernwin.close_widget(widget, 0)
            self.form = None
        else:
            form_factory = cast(Any, IDAChatForm)
            form = cast(IDAChatForm, form_factory())
            self.form = form
            form.Show(
                WIDGET_TITLE,
                options=(
                    ida_kernwin.PluginForm.WOPN_PERSIST
                    | ida_kernwin.PluginForm.WOPN_DP_RIGHT
                    | ida_kernwin.PluginForm.WOPN_DP_SZHINT
                ),
            )
            # Dock to the right side panel
            ida_kernwin.set_dock_pos(
                WIDGET_TITLE,
                "IDATopLevelDockArea",
                ida_kernwin.DP_RIGHT | ida_kernwin.DP_SZHINT,
            )

    def run(self, arg):
        """Called when plugin is invoked directly."""
        self.toggle_widget()

    def term(self):
        """Clean up when plugin is unloaded."""
        widget = ida_kernwin.find_widget(WIDGET_TITLE)
        if widget:
            ida_kernwin.close_widget(widget, 0)

        ida_kernwin.detach_action_from_menu("View/", ACTION_ID)
        ida_kernwin.unregister_action(ACTION_ID)

        ida_kernwin.msg(f"{PLUGIN_NAME}: Unloaded\n")


def PLUGIN_ENTRY():
    """Plugin entry point."""
    plugin_factory = cast(Any, IDAChatPlugin)
    return plugin_factory()
