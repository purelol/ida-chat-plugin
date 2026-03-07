"""Shared runtime bootstrap for source checkouts loaded directly by IDA."""

from __future__ import annotations

import os
import sys
from pathlib import Path

from ida_chat_bootstrap import bootstrap_runtime_dependencies


ROOT_DIR = Path(__file__).resolve().parent

# Signal to core that we're running inside IDA Pro (enables UI interaction API)
os.environ["IDA_CHAT_INSIDE_IDA"] = "1"

if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

bootstrap_runtime_dependencies()
