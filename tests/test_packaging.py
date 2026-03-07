from pathlib import Path
import tomllib


def test_wheel_includes_runtime_project_docs():
    pyproject = Path(__file__).resolve().parent.parent / "pyproject.toml"
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))

    only_include = data["tool"]["hatch"]["build"]["targets"]["wheel"]["only-include"]

    assert "project" in only_include


def test_runtime_prompt_files_exist():
    project_dir = Path(__file__).resolve().parent.parent / "project"

    for file_name in ("PROMPT.md", "IDA.md", "USAGE.md", "API_REFERENCE.md"):
        assert (project_dir / file_name).exists(), file_name
