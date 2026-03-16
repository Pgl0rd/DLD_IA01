# agent/queue_monitor.py
import time
import json
from pathlib import Path

class QueueMonitor:
    def __init__(
        self,
        queue_manager,
        state_dir: Path,
        check_interval_sec: float = 1.0,
        panic_on_threshold: float = 0.8,
        panic_off_threshold: float = 0.5,
    ):
        self.qm = queue_manager
        self.state_dir = state_dir
        self.state_dir.mkdir(parents=True, exist_ok=True)

        self.check_interval_sec = check_interval_sec
        self.panic_on_threshold = panic_on_threshold
        self.panic_off_threshold = panic_off_threshold

        self.panic_mode = False
        self.last_state = None

        self.stats_file = self.state_dir / "sensor_stats.json"

    def loop(self, stop_event):
        while not stop_event.is_set():
            st = self.qm.stats()
            qsize = st["qsize"]
            maxsize = st["maxsize"]
            util = qsize / maxsize if maxsize else 0.0

            # ---- panic mode state machine (hysteresis) ----
            if (not self.panic_mode) and util >= self.panic_on_threshold:
                self.panic_mode = True
            elif self.panic_mode and util <= self.panic_off_threshold:
                self.panic_mode = False

            # ✅ sync panic_mode về QueueManager để enqueue_event() drop ưu tiên
            self.qm.panic_mode = self.panic_mode

            state = {
                "ts": int(time.time()),
                "queue": st,
                "utilization": round(util, 3),
                "panic_mode": self.panic_mode,
            }

            # chỉ ghi file nếu có thay đổi để giảm IO
            if state != self.last_state:
                tmp = self.stats_file.with_suffix(".tmp")
                tmp.write_text(json.dumps(state, ensure_ascii=False), encoding="utf-8")
                tmp.replace(self.stats_file)
                self.last_state = state

            time.sleep(self.check_interval_sec)
