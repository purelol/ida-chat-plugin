"""Runtime bootstrap for the standalone CLI entrypoint."""

from __future__ import annotations

import sys
from pathlib import Path

from ida_chat_bootstrap import bootstrap_runtime_dependencies


ROOT_DIR = Path(__file__).resolve().parent

if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

bootstrap_runtime_dependencies()
