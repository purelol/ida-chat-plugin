from ida_chat_markdown import (
    build_web_syntax_css,
    merge_markdown_fragments,
    render_qt_markdown,
    render_web_markdown,
)
from ida_chat_support import normalize_session_entries
from ida_chat_theme import build_ui_colors


def test_render_web_markdown_supports_richer_blocks():
    html = render_web_markdown(
        "# Title\n\n"
        "> quoted\n\n"
        "- item\n\n"
        "| A | B |\n| --- | --- |\n| 1 | 2 |\n\n"
        "Use `inline` and `db.functions.rename()`.\n\n"
        "Docs: https://example.com/docs\n\n"
        "```python\nprint('hi')\n```"
    )

    assert 'class="md-h1"' in html
    assert 'class="md-quote"' in html
    assert 'class="md-list"' in html
    assert 'class="md-table"' in html
    assert 'class="md-inline"' in html
    assert 'class="md-inline md-inline-api"' in html
    assert 'class="md-code-wrap"' in html
    assert 'href="https://example.com/docs"' in html
    assert 'class="tok-k"' in html or 'class="tok-nb"' in html
    assert "python" in html


def test_render_qt_markdown_styles_code_blocks_and_links():
    colors = build_ui_colors(False)
    html = render_qt_markdown(
        "See [docs](https://example.com), call `db.functions.rename()`.\n\n```python\nprint('hi')\n```",
        colors,
    )

    assert 'href="https://example.com"' in html
    assert "text-decoration: none" in html
    assert "background-color" in html
    assert "font-family" in html
    assert "Code</td>" in html
    assert colors["info_text"] in html


def test_render_web_markdown_styles_ordered_lists_and_multiparagraph_quotes():
    html = render_web_markdown(
        "1. first\n2. second\n\n> line one\n>\n> line two"
    )

    assert 'class="md-list md-list-ordered"' in html
    assert '<blockquote class="md-quote">' in html
    assert html.count('class="md-p"') >= 2


def test_render_qt_markdown_compacts_quote_paragraph_spacing():
    colors = build_ui_colors(False)
    html = render_qt_markdown("> alpha\n>\n> beta", colors)

    assert "<blockquote" in html
    assert "margin: 0; line-height: 1.65;" in html
    assert "margin: 6px 0 0 0; line-height: 1.65;" in html


def test_merge_markdown_fragments_preserves_block_spacing():
    merged = merge_markdown_fragments("First paragraph.", "## Second")
    assert merged == "First paragraph.\n\n## Second"


def test_normalize_session_entries_merges_adjacent_assistant_text_blocks():
    entries = [
        {
            "type": "assistant",
            "message": {
                "content": [
                    {"type": "text", "text": "First paragraph."},
                ]
            },
        },
        {
            "type": "assistant",
            "message": {
                "content": [
                    {"type": "text", "text": "Second paragraph."},
                ]
            },
        },
    ]

    items = normalize_session_entries(entries)

    assert items == [
        {
            "kind": "assistant",
            "text": "First paragraph.\n\nSecond paragraph.",
        }
    ]


def test_render_web_markdown_flattens_ida_api_headings():
    html = render_web_markdown("### db.functions.rename()")

    assert 'class="md-api-heading"' in html
    assert 'class="md-h3"' not in html


def test_build_web_syntax_css_contains_theme_scoped_rules():
    css = build_web_syntax_css("dark")

    assert 'html[data-theme="dark"] .md-code' in css
    assert ".tok-" in css
