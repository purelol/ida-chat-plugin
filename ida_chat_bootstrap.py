"""Runtime dependency bootstrap for source checkouts loaded directly by IDA."""

from __future__ import annotations

import importlib.util
import site
import sys
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parent
VENV_DIR = ROOT_DIR / ".venv"
REQUIREMENTS_FILE = ROOT_DIR / "requirements.txt"

_REQUIREMENT_IMPORTS = {
    "claude-agent-sdk": "claude_agent_sdk",
    "ida-domain": "ida_domain",
    "ida-settings": "ida_settings",
    "beautifulsoup4": "bs4",
    "linkify-it-py": "linkify_it",
    "markdown-it-py": "markdown_it",
    "pygments": "pygments",
    "rich": "rich",
}


def _normalize_requirement_name(spec: str) -> str:
    spec = spec.strip()
    if not spec:
        return ""
    terminators = "<>=!~;["
    end = len(spec)
    for token in terminators:
        index = spec.find(token)
        if index != -1:
            end = min(end, index)
    return spec[:end].strip()


def _read_requirements() -> list[str]:
    if not REQUIREMENTS_FILE.exists():
        return []
    requirements: list[str] = []
    for raw_line in REQUIREMENTS_FILE.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if line:
            requirements.append(line)
    return requirements


def _add_project_environment() -> None:
    for site_packages in _project_site_packages():
        site.addsitedir(str(site_packages))


def _current_python_tag() -> str:
    return f"python{sys.version_info.major}.{sys.version_info.minor}"


def _project_site_packages() -> list[Path]:
    candidates = [
        VENV_DIR / "Lib" / "site-packages",
        VENV_DIR / "lib" / _current_python_tag() / "site-packages",
        VENV_DIR / "lib64" / _current_python_tag() / "site-packages",
    ]
    return [path for path in candidates if path.exists()]


def _missing_requirements() -> list[str]:
    missing: list[str] = []
    for spec in _read_requirements():
        package_name = _normalize_requirement_name(spec).lower()
        import_name = _REQUIREMENT_IMPORTS.get(
            package_name, package_name.replace("-", "_")
        )
        if import_name in sys.modules:
            continue
        try:
            spec_info = importlib.util.find_spec(import_name)
        except ValueError:
            spec_info = None
        if spec_info is None:
            missing.append(spec)
    return missing


def bootstrap_runtime_dependencies() -> None:
    """Expose the repo virtualenv to IDA and fail fast if runtime deps are missing."""
    _add_project_environment()
    missing = _missing_requirements()
    if not missing:
        return

    missing_list = ", ".join(_normalize_requirement_name(spec) for spec in missing)
    env_hint = (
        f"Create the project environment with the same Python major.minor version as IDA "
        f"using `uv sync --python {sys.version_info.major}.{sys.version_info.minor} --extra dev`, "
        f"or run `python{sys.version_info.major}.{sys.version_info.minor} -m venv {VENV_DIR.name} && "
        f"{VENV_DIR.name}/bin/pip install -r requirements.txt`."
    )
    raise RuntimeError(
        "IDA Chat runtime dependencies are missing: "
        f"{missing_list}. {env_hint}"
    )
