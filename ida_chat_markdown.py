"""Shared markdown rendering helpers for the live UI and HTML exports."""

from __future__ import annotations

import html
import re
from typing import Any

from bs4 import BeautifulSoup
from bs4.element import NavigableString, Tag
from markdown_it import MarkdownIt
from pygments import highlight
from pygments.formatters import HtmlFormatter
from pygments.lexers import TextLexer, get_lexer_by_name, guess_lexer
from pygments.util import ClassNotFound


_MARKDOWN_ENGINE = (
    MarkdownIt(
        "commonmark",
        {
            "breaks": True,
            "html": False,
            "linkify": True,
        },
    )
    .enable("strikethrough")
    .enable("table")
    .enable("linkify")
)

_IDA_REFERENCE_RE = re.compile(
    r"(?:\bdb\.[A-Za-z_][A-Za-z0-9_\.]*|\bidaapi\.[A-Za-z_][A-Za-z0-9_\.]*|\bida_[A-Za-z0-9_]+)(?:\([^)]*\))?"
)
_WEB_SYNTAX_STYLE_NAMES = {
    "light": "friendly",
    "dark": "native",
}
_QT_SYNTAX_STYLE_NAMES = {
    "light": "friendly",
    "dark": "native",
}


def merge_markdown_fragments(existing: str, new: str) -> str:
    """Join streamed markdown blocks without forcing extra blank paragraphs."""
    if not existing:
        return new
    if not new:
        return existing

    left = existing.rstrip()
    right = new.lstrip()
    if not left:
        return right
    if not right:
        return left

    if left.endswith(("\n", "\r")) or new.startswith(("\n", "\r")):
        separator = "\n"
    elif right.startswith(("#", ">", "-", "*", "`")) or re.match(r"\d+\.\s", right):
        separator = "\n\n"
    elif left.endswith((".", "!", "?", ":", ";")):
        separator = "\n\n"
    else:
        separator = " "

    return f"{left}{separator}{right}"


def _render_markdown(text: str) -> str:
    return _MARKDOWN_ENGINE.render(text or "")


def _extract_language(classes: Any) -> str:
    if not classes:
        return ""
    if isinstance(classes, str):
        class_names = classes.split()
    else:
        class_names = [str(value) for value in classes]
    for class_name in class_names:
        match = re.search(r"language-([A-Za-z0-9_+-]+)", class_name)
        if match:
            return html.escape(match.group(1))
    return ""


def _replace_code_blocks(
    html_text: str,
    block_renderer,
) -> tuple[str, list[str]]:
    soup = BeautifulSoup(html_text, "html.parser")
    code_blocks: list[str] = []

    for pre_tag in list(soup.find_all("pre")):
        code_tag = pre_tag.find("code", recursive=False)
        if code_tag is None:
            continue

        placeholder = f"\x00CODE{len(code_blocks)}\x00"
        language = _extract_language(code_tag.get("class"))
        code = code_tag.get_text().rstrip("\n")
        code_blocks.append(block_renderer(language, code))
        pre_tag.replace_with(NavigableString(placeholder))

    return _render_fragment(soup), code_blocks


def _restore_code_blocks(html_text: str, code_blocks: list[str]) -> str:
    rendered = html_text
    for index, block in enumerate(code_blocks):
        rendered = rendered.replace(f"\x00CODE{index}\x00", block)
    return rendered


def _render_fragment(soup: BeautifulSoup) -> str:
    return "".join(str(node) for node in soup.contents)


def _is_ida_reference(text: str) -> bool:
    candidate = html.unescape(text).strip()
    return bool(candidate and _IDA_REFERENCE_RE.fullmatch(candidate))


def _read_class_names(tag: Tag) -> list[str]:
    raw_classes = tag.get("class")
    if raw_classes is None:
        return []
    if isinstance(raw_classes, str):
        return [value for value in raw_classes.split() if value]
    return [str(value) for value in raw_classes if str(value)]


def _set_class_names(tag: Tag, *class_names: str) -> None:
    tag["class"] = " ".join(name for name in class_names if name)


def _replace_tag_with_fragment(tag: Tag, html_fragment: str) -> None:
    fragment = BeautifulSoup(html_fragment, "html.parser")
    new_nodes = list(fragment.contents)
    if not new_nodes:
        tag.decompose()
        return

    first = new_nodes.pop(0)
    tag.replace_with(first)
    previous = first
    for node in new_nodes:
        previous.insert_after(node)
        previous = node


def _web_soup_from_markdown(text: str) -> tuple[BeautifulSoup, list[str]]:
    transformed, code_blocks = _replace_code_blocks(
        _render_markdown(text), _render_web_code_block
    )
    return BeautifulSoup(transformed, "html.parser"), code_blocks


def _qt_soup_from_markdown(
    text: str, colors: dict[str, Any]
) -> tuple[BeautifulSoup, list[str]]:
    transformed, code_blocks = _replace_code_blocks(
        _render_markdown(text),
        lambda language, code: _render_qt_code_block(language, code, colors),
    )
    return BeautifulSoup(transformed, "html.parser"), code_blocks


def build_web_syntax_css(theme: str, selector: str = ".md-code") -> str:
    """Return fenced code syntax rules for the requested export theme."""
    style_name = _WEB_SYNTAX_STYLE_NAMES.get(theme, "friendly")
    formatter = HtmlFormatter(style=style_name, classprefix="tok-")
    prefix = f'html[data-theme="{theme}"] {selector}'
    return formatter.get_style_defs(prefix)


def _resolve_lexer(language: str, code: str):
    normalized = language.strip().lower()
    if normalized:
        try:
            return get_lexer_by_name(normalized, stripall=False)
        except ClassNotFound:
            pass
    if code.strip():
        try:
            return guess_lexer(code)
        except ClassNotFound:
            pass
    return TextLexer(stripall=False)


def _highlight_web_code(language: str, code: str) -> str:
    lexer = _resolve_lexer(language, code)
    formatter = HtmlFormatter(nowrap=True, classprefix="tok-", style="friendly")
    return highlight(code, lexer, formatter).rstrip("\n")


def _highlight_qt_code(language: str, code: str, *, dark: bool) -> str:
    lexer = _resolve_lexer(language, code)
    formatter = HtmlFormatter(
        nowrap=True,
        noclasses=True,
        style=_QT_SYNTAX_STYLE_NAMES["dark" if dark else "light"],
    )
    return highlight(code, lexer, formatter).rstrip("\n")


def render_web_markdown(text: str) -> str:
    """Render markdown into HTML fragments used by transcript/export pages."""
    soup, code_blocks = _web_soup_from_markdown(text)

    for code_tag in soup.find_all("code"):
        classes = ["md-inline"]
        if _is_ida_reference(code_tag.get_text()):
            classes.append("md-inline-api")
        _set_class_names(code_tag, *classes)

    heading_classes = {"h1": "md-h1", "h2": "md-h2", "h3": "md-h3"}
    for name, css_class in heading_classes.items():
        for heading in list(soup.find_all(name)):
            if _is_ida_reference(heading.get_text("", strip=True)):
                _replace_tag_with_fragment(
                    heading,
                    f'<p class="md-api-heading">{heading.decode_contents()}</p>',
                )
                continue
            _set_class_names(heading, css_class)

    for anchor in soup.find_all("a"):
        _set_class_names(anchor, "md-link")

    for list_tag in soup.find_all("ul"):
        _set_class_names(list_tag, "md-list")

    for list_tag in soup.find_all("ol"):
        _set_class_names(list_tag, "md-list", "md-list-ordered")

    for blockquote in soup.find_all("blockquote"):
        _set_class_names(blockquote, "md-quote")

    for table in soup.find_all("table"):
        _set_class_names(table, "md-table")

    for cell in soup.find_all("th"):
        _set_class_names(cell, "md-th")

    for cell in soup.find_all("td"):
        _set_class_names(cell, "md-td")

    for paragraph in soup.find_all("p"):
        existing_classes = _read_class_names(paragraph)
        if "md-api-heading" in existing_classes:
            continue
        _set_class_names(paragraph, *existing_classes, "md-p")

    for divider in soup.find_all("hr"):
        _set_class_names(divider, "md-rule")

    return _restore_code_blocks(_render_fragment(soup), code_blocks)


def _render_web_code_block(language: str, code: str) -> str:
    label = language or "code"
    highlighted = _highlight_web_code(language, code)
    header = (
        f'<div class="md-code-header"><span>Code</span><span>{label}</span></div>'
        if language
        else '<div class="md-code-header"><span>Code</span></div>'
    )
    return (
        f'<div class="md-code-wrap">{header}'
        f'<pre class="md-code"><code class="md-code-content">{highlighted}</code></pre></div>'
    )


def render_qt_markdown(text: str, colors: dict[str, Any]) -> str:
    """Render markdown into an inline-styled fragment suitable for QTextBrowser."""
    soup, code_blocks = _qt_soup_from_markdown(text, colors)

    for code_tag in list(soup.find_all("code")):
        _replace_tag_with_fragment(
            code_tag,
            _render_qt_inline_code(code_tag.get_text(), colors),
        )

    heading_sizes = {"h1": 20, "h2": 17, "h3": 14}
    for name, size in heading_sizes.items():
        for heading in list(soup.find_all(name)):
            _replace_tag_with_fragment(
                heading,
                _render_qt_heading(heading.decode_contents(), colors, size),
            )

    for anchor in soup.find_all("a"):
        anchor["style"] = f'color: {colors["link"]}; text-decoration: none;'

    for blockquote in soup.find_all("blockquote"):
        blockquote["style"] = (
            f"margin: 8px 0 10px 0; "
            f"padding: 8px 12px; "
            f"border: 1px solid {colors['border_light']}; "
            f"border-radius: {colors['radius_lg']}px; "
            f"background-color: {colors['surface_alt']}; "
            f"color: {colors['text_muted']};"
        )

    for paragraph in soup.find_all("p"):
        if paragraph.has_attr("style"):
            continue
        paragraph["style"] = "margin: 0 0 10px 0; line-height: 1.65;"

    for blockquote in soup.find_all("blockquote"):
        paragraphs = list(blockquote.find_all("p", recursive=False))
        for index, paragraph in enumerate(paragraphs):
            paragraph["style"] = (
                "margin: 0; line-height: 1.65;"
                if index == 0
                else "margin: 6px 0 0 0; line-height: 1.65;"
            )

    for list_tag in soup.find_all("ul"):
        list_tag["style"] = "margin: 8px 0 12px 18px;"

    for list_tag in soup.find_all("ol"):
        list_tag["style"] = "margin: 8px 0 12px 18px;"

    for table in soup.find_all("table"):
        table["cellspacing"] = "0"
        table["cellpadding"] = "0"
        table["width"] = "100%"
        table["style"] = (
            f"margin: 10px 0; border: 1px solid {colors['border']}; "
            f"background-color: {colors['surface']};"
        )

    for cell in soup.find_all("th"):
        cell["style"] = (
            f"padding: 8px 10px; border: 1px solid {colors['border']}; "
            f"background-color: {colors['surface_alt']}; text-align: left;"
        )

    for cell in soup.find_all("td"):
        cell["style"] = (
            f"padding: 8px 10px; border: 1px solid {colors['border']}; "
            f"background-color: {colors['surface']};"
        )

    for divider in list(soup.find_all("hr")):
        _replace_tag_with_fragment(
            divider,
            f'<p style="margin: 14px 0; color: {colors["border"]};">{"─" * 36}</p>',
        )

    return _restore_code_blocks(_render_fragment(soup), code_blocks)


def _render_qt_inline_code(content: str, colors: dict[str, Any]) -> str:
    font_mono = html.escape(str(colors.get("font_mono", "monospace")))
    if _is_ida_reference(content):
        return (
            f'<span style="font-family: \'{font_mono}\'; '
            f'color: {colors["info_text"]};">'
            f"{content}</span>"
        )
    return (
        f'<span style="font-family: \'{font_mono}\'; '
        f'background-color: {colors["code_bg_alt"]}; color: {colors["code_text"]}; '
        f'border: 1px solid {colors["code_border"]}; border-radius: 999px; '
        f'padding: 2px 7px;">{content}</span>'
    )


def _render_qt_heading(content: str, colors: dict[str, Any], size: int) -> str:
    if _is_ida_reference(BeautifulSoup(content, "html.parser").get_text("", strip=True)):
        font_mono = html.escape(str(colors.get("font_mono", "monospace")))
        return (
            f'<p style="margin: 8px 0; font-size: 13px; font-weight: 400; '
            f'line-height: 1.5; color: {colors["info_text"]}; '
            f'font-family: \'{font_mono}\';">{content}</p>'
        )
    return (
        f'<p style="margin: 12px 0 8px 0; font-size: {size}px; '
        f'font-weight: 600; line-height: 1.2; color: {colors["text"]};">{content}</p>'
    )


def _render_qt_code_block(language: str, code: str, colors: dict[str, Any]) -> str:
    font_mono = html.escape(str(colors.get("font_mono", "monospace")))
    highlighted = _highlight_qt_code(
        language,
        code,
        dark=bool(colors.get("is_dark", False)),
    )
    label = language or "code"
    header_label = f"Code · {html.escape(label)}" if language else "Code"
    return (
        f'<div style="margin: 12px 0; border: 1px solid {colors["code_border"]}; '
        f'border-radius: {colors["radius_lg"]}px; background-color: {colors["code_bg"]};">'
        f'<div style="padding: 10px 14px; background-color: {colors["code_bg_alt"]}; '
        f'border-bottom: 1px solid {colors["code_border"]}; color: {colors["text_subtle"]}; '
        f'font-size: 10px; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase;">'
        f"{header_label}</div>"
        f'<pre style="margin: 0; padding: 14px 16px; background-color: {colors["code_bg"]}; '
        f'color: {colors["code_text"]}; font-family: \'{font_mono}\'; '
        f'font-size: 11px; line-height: 1.65; white-space: pre-wrap; word-break: normal;">{highlighted}</pre>'
        f"</div>"
    )
