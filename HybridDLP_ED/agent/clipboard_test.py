# agent/sensors/test_clipboard_only.py
from __future__ import annotations

import json
import threading
import time

from agent.sensors.clipboard_sensor import ClipboardSensor
from agent.sensors.context import ContextProvider


class _QM:
    """QueueManager mock: print event to console."""
    panic_mode = False

    def enqueue_event(self, evt):
        # in 1 dòng json cho dễ nhìn
        print(json.dumps(evt, ensure_ascii=False), flush=True)
        return True


def main():
    qm = _QM()
    ctx = ContextProvider(cache_ttl_sec=0.2)

    # bật mode “đọc text” (nếu ClipboardSensor của bạn có tham số này)
    # Nếu constructor của bạn KHÔNG có các tham số bên dưới, cứ xóa bớt cho khớp.
    sensor = ClipboardSensor(
        queue_manager=qm,
        poll_interval_sec=0.08,
        min_len=1,
        preview_len=120,
        cooldown_sec=0.10,
        # các param này tùy version bạn đang có:
        # capture_text_file=True,
        # max_text_file_len=500,
    )

    stop = threading.Event()

    t = threading.Thread(
        target=sensor.run_loop,
        args=(stop, ctx),
        name="clipboard_test",
        daemon=True,
    )
    t.start()

    print("[clipboard-test] Running. Copy something now (Ctrl+C). Ctrl+V to test paste if hook exists.")
    print("[clipboard-test] Press Ctrl+C in this console to stop.\n")

    try:
        while True:
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        stop.set()
        t.join(timeout=1.0)
        print("[clipboard-test] stopped.")


if __name__ == "__main__":
    main()