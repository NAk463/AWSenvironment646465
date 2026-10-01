"""データプレーンを持たない (状態だけを管理する) ドライバ。"""
from __future__ import annotations

from typing import Any


class SimulatedNetplane:
    enabled = False
    name = "simulated"

    def __init__(self, reason: str = "") -> None:
        self.reason = reason

    def __getattr__(self, name: str) -> Any:
        # linux ドライバと同じメソッド名を呼ばれても何もしない
        def noop(*args: Any, **kwargs: Any) -> None:
            return None
        return noop

    def instance_alive(self, instance_id: str) -> bool:
        return True
