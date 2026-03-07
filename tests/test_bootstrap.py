import ida_chat_bootstrap as bootstrap
import pytest


def test_read_requirements_ignores_comments_and_blank_lines(tmp_path, monkeypatch):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text(
        "\n".join(
            [
                "# comment",
                "markdown-it-py>=3.0.0",
                "",
                "Pygments>=2.18.0  # inline comment",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(bootstrap, "REQUIREMENTS_FILE", requirements)

    assert bootstrap._read_requirements() == [
        "markdown-it-py>=3.0.0",
        "Pygments>=2.18.0",
    ]


def test_missing_requirements_reports_only_unimportable_specs(tmp_path, monkeypatch):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text(
        "\n".join(
            [
                "existing-pkg>=1.0",
                "missing-pkg>=2.0",
            ]
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(bootstrap, "REQUIREMENTS_FILE", requirements)
    monkeypatch.setattr(
        bootstrap,
        "_REQUIREMENT_IMPORTS",
        {
            "existing-pkg": "json",
            "missing-pkg": "__definitely_missing_ida_chat_test__",
        },
    )

    assert bootstrap._missing_requirements() == ["missing-pkg>=2.0"]


def test_bootstrap_runtime_dependencies_noops_when_all_requirements_are_present(monkeypatch):
    monkeypatch.setattr(bootstrap, "_missing_requirements", lambda: [])

    bootstrap.bootstrap_runtime_dependencies()


def test_normalize_requirement_name_strips_version_markers():
    assert bootstrap._normalize_requirement_name("markdown-it-py>=3.0.0") == "markdown-it-py"
    assert bootstrap._normalize_requirement_name("Pygments[foo]==2.18.0") == "Pygments"


def test_project_site_packages_discovers_common_virtualenv_layouts(tmp_path, monkeypatch):
    lib_site = tmp_path / "lib" / "python3.11" / "site-packages"
    lib_site.mkdir(parents=True)
    win_site = tmp_path / "Lib" / "site-packages"
    win_site.mkdir(parents=True)
    monkeypatch.setattr(bootstrap, "VENV_DIR", tmp_path)

    paths = bootstrap._project_site_packages()

    assert lib_site in paths
    assert win_site in paths


def test_bootstrap_runtime_dependencies_raises_actionable_error(monkeypatch):
    monkeypatch.setattr(
        bootstrap,
        "_missing_requirements",
        lambda: ["markdown-it-py>=3.0.0", "Pygments>=2.18.0"],
    )

    with pytest.raises(RuntimeError) as exc_info:
        bootstrap.bootstrap_runtime_dependencies()

    message = str(exc_info.value)
    assert "markdown-it-py" in message
    assert "Pygments" in message
    assert "uv sync" in message
    assert "requirements.txt" in message
