"""
test_pipeline.py – Inject a fake browser_upload event directly into the TCP sensor.
======================================================================================
Dùng để test toàn bộ pipeline mà không cần extension + native host.

Chạy:
  Terminal 1:  python -m sensor_system.runner --sensor browser_upload_sensor
  Terminal 2:  python test_pipeline.py

Nếu mọi thứ đúng, terminal 1 sẽ in ra JSON event type "browser_upload".
"""
import json
import socket
import sys
import time

HOST = "127.0.0.1"
PORT = 47266

EVENTS = [
    {
        "browser": "chrome",
        "tab_url": "https://drive.google.com/drive/my-drive",
        "destination": "drive.google.com",
        "filename": "ccxccx.xlsx",
        "size": 7191,
        "trigger": "file_input",
        "confidence_score": 0.9,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "host_user": "test_user",
    },
    {
        "browser": "chrome",
        "tab_url": "https://drive.google.com/drive/my-drive",
        "destination": "drive.google.com",
        "filename": "report_secret.pdf",
        "size": 385836,
        "trigger": "xhr",
        "confidence_score": 0.85,
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "host_user": "test_user",
    },
]


def main() -> None:
    print(f"[test_pipeline] Connecting to BrowserUploadSensor at {HOST}:{PORT}...")
    try:
        s = socket.create_connection((HOST, PORT), timeout=5)
    except ConnectionRefusedError:
        print(
            "[test_pipeline] ❌ Connection refused!\n"
            "   Hãy chạy sensor trước:\n"
            "   python -m sensor_system.runner --sensor browser_upload_sensor"
        )
        sys.exit(1)
    except OSError as e:
        print(f"[test_pipeline] ❌ Cannot connect: {e}")
        sys.exit(1)

    print(f"[test_pipeline] ✅ Connected! Sending {len(EVENTS)} test events...\n")
    with s:
        for i, event in enumerate(EVENTS, 1):
            line = (json.dumps(event, ensure_ascii=False) + "\n").encode()
            s.sendall(line)
            print(f"[test_pipeline] Sent event {i}: filename={event['filename']} trigger={event['trigger']}")
            time.sleep(0.3)

    print("\n[test_pipeline] Done. Check sensor terminal for 'browser_upload' JSON output.")


if __name__ == "__main__":
    main()
