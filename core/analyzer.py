import time
from collections import deque
from typing import Optional, Dict, Any

class BehaviorAnalyzer:
    def __init__(
        self,
        time_window_sec: int = 3,
        burst_write_threshold: int = 20,
        burst_rename_threshold: int = 8,
        enable_rename_rule: bool = True,
    ):
        self.time_window_sec = time_window_sec
        self.burst_write_threshold = burst_write_threshold
        self.burst_rename_threshold = burst_rename_threshold
        self.enable_rename_rule = enable_rename_rule
        self._events = deque()

    def add_event(self, event_type: str) -> None:
        relevant = {"created", "modified", "moved"}
        if event_type not in relevant:
            return

        now = time.time()
        self._events.append((now, event_type))
        self._prune(now)

    def _prune(self, now: Optional[float] = None) -> None:
        if now is None:
            now = time.time()

        while self._events and (now - self._events[0][0]) > self.time_window_sec:
            self._events.popleft()

    def verdict(self) -> Dict[str, Any]:
        now = time.time()
        self._prune(now)

        write_count = sum(1 for (_, et) in self._events if et in ("created", "modified"))
        rename_count = sum(1 for (_, et) in self._events if et == "moved")

        triggers = []
        suspicious = False

        if write_count >= self.burst_write_threshold:
            triggers.append(f"burst_writes={write_count}/{self.burst_write_threshold}")
            suspicious = True

        if self.enable_rename_rule and rename_count >= self.burst_rename_threshold:
            triggers.append(f"burst_renames={rename_count}/{self.burst_rename_threshold}")
            suspicious = True

        return {
            "suspicious": suspicious,
            "time_window_sec": self.time_window_sec,
            "write_count": write_count,
            "rename_count": rename_count,
            "triggers": triggers,
        }

    def reset(self) -> None:
        self._events.clear()
