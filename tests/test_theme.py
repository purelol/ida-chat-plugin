from ida_chat_theme import build_ui_colors


def test_build_ui_colors_light_mode_matches_vercel_tokens():
    colors = build_ui_colors(False)

    assert colors["mode"] == "light"
    assert colors["accent"] == "#0a0a0a"
    assert colors["accent_text"] == "#ffffff"
    assert colors["surface"] == "#ffffff"
    assert colors["assistant_bubble"] == "#ffffff"
    assert colors["user_bubble"] == "#0a0a0a"
    assert colors["link"] == "#1b6aff"
    assert colors["danger"] == "#f43f5e"
    assert colors["danger_text"] == "#9f1239"
    assert colors["radius_md"] == 10


def test_build_ui_colors_dark_mode_matches_vercel_tokens():
    colors = build_ui_colors(True)

    assert colors["mode"] == "dark"
    assert colors["accent"] == "#ededed"
    assert colors["accent_text"] == "#000000"
    assert colors["surface"] == "#111111"
    assert colors["assistant_bubble"] == "#111111"
    assert colors["user_bubble"] == "#ededed"
    assert colors["link"] == "#5b9aff"
    assert colors["danger"] == "#f43f5e"
    assert colors["warning_text"] == "#fbbf24"
    assert colors["radius_xl"] == 16


def test_status_tints_are_softened_versions_of_base_intents():
    light = build_ui_colors(False)
    dark = build_ui_colors(True)

    assert light["danger_soft"] != light["danger"]
    assert light["warning_soft"] != light["warning"]
    assert dark["success_soft"] != dark["success"]
    assert light["success_border"] != light["border"]
