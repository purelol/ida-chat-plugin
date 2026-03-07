from typing import Any

BADADDR: int
PLUGIN_KEEP: int
PLUGIN_SKIP: int


class plugin_t:
    flags: int
    comment: str
    help: str
    wanted_name: str
    wanted_hotkey: str

    def init(self) -> int: ...
    def run(self, arg: int) -> None: ...
    def term(self) -> None: ...


def __getattr__(name: str) -> Any: ...
