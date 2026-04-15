"""
test_enriched_events.py — Gửi test enriched events lên server

Dùng để test hệ thống admin dashboard với chi tiết match information
"""

import requests
import json
from datetime import datetime, timezone, timedelta

# Server config
SERVER_URL = "http://localhost:8000"
API_KEY = "test-key-123"  # Sử dụng API key hiện có

# Timezone UTC+7
TZ_VN = timezone(timedelta(hours=7))

def now_vn():
    return datetime.now(tz=TZ_VN).isoformat()


def send_enriched_event(event):
    """Gửi enriched event lên server"""
    headers = {
        "X-API-Key": API_KEY,
        "Content-Type": "application/json"
    }
    
    try:
        resp = requests.post(
            f"{SERVER_URL}/api/events",
            json=event,
            headers=headers,
            timeout=5
        )
        resp.raise_for_status()
        result = resp.json()
        print(f"✅ Event sent: {result}")
        return True
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


def send_batch_events(events):
    """Gửi batch events"""
    headers = {
        "X-API-Key": API_KEY,
        "Content-Type": "application/json"
    }
    
    try:
        resp = requests.post(
            f"{SERVER_URL}/api/events/batch",
            json=events,
            headers=headers,
            timeout=5
        )
        resp.raise_for_status()
        result = resp.json()
        print(f"✅ Batch sent: {result}")
        return True
    except Exception as e:
        print(f"❌ Error: {e}")
        return False


# ════════════════════════════════════════════════════════
# TEST EVENT 1: Clipboard with Credit Card + API Key
# ════════════════════════════════════════════════════════

event1 = {
    "timestamp": now_vn(),
    "risk_score": 6.5,
    "action": "alert",
    "file_path": "/clipboard",
    "file_name": "clipboard_data",
    "keywords": ["credit card", "visa", "api key"],
    "window_title": "Google Chrome - Gmail",
    "process_name": "chrome.exe",
    "user": "admin",
    "source": "clipboard",
    "is_clipboard": True,
    
    # ═══ Enriched Data ═══
    "yara_matches_count": 2,
    "yara_rules_matched": [
        {
            "rule": "Credit_Card",
            "strings": ["visa1", "mastercard1"],
            "timestamp": now_vn()
        },
        {
            "rule": "API_Key",
            "strings": ["aws_key"],
            "timestamp": now_vn()
        }
    ],
    "behavioral_matches_count": 2,
    "behavioral_rules_matched": [
        {
            "rule": "clipboard_copy_large_data",
            "score": 0.6,
            "reason": "Copied >10KB data in <5 seconds"
        },
        {
            "rule": "rapid_clipboard_access",
            "score": 0.4,
            "reason": "Accessed clipboard 5 times in 10s"
        }
    ],
    "risk_score_breakdown": {
        "keyword_score": 1.5,
        "yara_score": 3.0,
        "behavioral_score": 1.5,
        "application_score": 0.5,
        "final_score": 6.5
    },
    "action_reason": "Credit card (2 patterns) + API key detected | Rapid clipboard access | Large data copy detected",
    "event_type": "clipboard_access",
    "content_size": 15240,
    "check_duration_ms": 245
}

# ════════════════════════════════════════════════════════
# TEST EVENT 2: File Copy with Sensitive Data
# ════════════════════════════════════════════════════════

event2 = {
    "timestamp": now_vn(),
    "risk_score": 7.2,
    "action": "blocked",
    "file_path": "C:\\Users\\admin\\Documents\\financial_report_2026.xlsx",
    "file_name": "financial_report_2026.xlsx",
    "keywords": ["financial", "revenue", "salary", "profit"],
    "window_title": "File Explorer - Copy to USB",
    "process_name": "explorer.exe",
    "user": "admin",
    "source": "file_copy",
    "is_clipboard": False,
    
    # ═══ Enriched Data ═══
    "yara_matches_count": 1,
    "yara_rules_matched": [
        {
            "rule": "Financial_Data",
            "strings": ["revenue", "profit", "salary"],
            "timestamp": now_vn()
        }
    ],
    "behavioral_matches_count": 1,
    "behavioral_rules_matched": [
        {
            "rule": "file_copy_to_removable_media",
            "score": 0.8,
            "reason": "File copied to USB/removable drive"
        }
    ],
    "risk_score_breakdown": {
        "keyword_score": 2.0,
        "yara_score": 2.5,
        "behavioral_score": 2.2,
        "application_score": 0.5,
        "final_score": 7.2
    },
    "action_reason": "Financial data detected (revenue, profit) | Suspicious file copy to USB drive",
    "event_type": "file_copy",
    "content_size": 512000,
    "check_duration_ms": 1250
}

# ════════════════════════════════════════════════════════
# TEST EVENT 3: Process Execution - Suspicious
# ════════════════════════════════════════════════════════

event3 = {
    "timestamp": now_vn(),
    "risk_score": 5.2,
    "action": "alert",
    "file_path": "C:\\Windows\\System32\\cmd.exe",
    "file_name": "cmd.exe",
    "keywords": ["suspicious process", "system"],
    "window_title": "Command Prompt - C:\\Users\\admin",
    "process_name": "cmd.exe",
    "user": "admin",
    "source": "process",
    "is_clipboard": False,
    
    # ═══ Enriched Data ═══
    "yara_matches_count": 0,
    "yara_rules_matched": [],
    "behavioral_matches_count": 2,
    "behavioral_rules_matched": [
        {
            "rule": "suspicious_process_execution",
            "score": 0.5,
            "reason": "cmd.exe started from unusual location"
        },
        {
            "rule": "elevated_privileges",
            "score": 0.6,
            "reason": "Process running with elevated privileges"
        }
    ],
    "risk_score_breakdown": {
        "keyword_score": 0.1,
        "yara_score": 0.0,
        "behavioral_score": 2.1,
        "application_score": 3.0,
        "final_score": 5.2
    },
    "action_reason": "Suspicious process execution (cmd.exe) with elevated privileges from user context",
    "event_type": "process_start",
    "content_size": 0,
    "check_duration_ms": 150
}

# ════════════════════════════════════════════════════════
# TEST EVENT 4: Vietnam ID Card Detection
# ════════════════════════════════════════════════════════

event4 = {
    "timestamp": now_vn(),
    "risk_score": 8.5,
    "action": "blocked",
    "file_path": "/clipboard",
    "file_name": "clipboard_data",
    "keywords": ["CMND", "CCCD", "ID", "identification"],
    "window_title": "Telegram - Chat",
    "process_name": "telegram.exe",
    "user": "admin",
    "source": "clipboard",
    "is_clipboard": True,
    
    # ═══ Enriched Data ═══
    "yara_matches_count": 2,
    "yara_rules_matched": [
        {
            "rule": "Vietnam_ID_Card",
            "strings": ["123456789", "012345678901"],
            "timestamp": now_vn()
        },
        {
            "rule": "Email",
            "strings": ["user@gmail.com"],
            "timestamp": now_vn()
        }
    ],
    "behavioral_matches_count": 1,
    "behavioral_rules_matched": [
        {
            "rule": "sensitive_data_to_messaging",
            "score": 0.9,
            "reason": "Personal ID data sent to messaging app (Telegram)"
        }
    ],
    "risk_score_breakdown": {
        "keyword_score": 2.5,
        "yara_score": 4.0,
        "behavioral_score": 1.5,
        "application_score": 0.5,
        "final_score": 8.5
    },
    "action_reason": "Vietnam ID card (CMND/CCCD) detected + Email | Suspicious transmission to messaging app",
    "event_type": "clipboard_access",
    "content_size": 8200,
    "check_duration_ms": 320
}


if __name__ == "__main__":
    import sys
    
    print("=" * 70)
    print("🧪 TEST ENRICHED EVENTS - Admin Dashboard")
    print("=" * 70)
    print(f"\n📡 Server: {SERVER_URL}")
    print(f"🔑 API Key: {API_KEY}")
    
    # Check server is running
    try:
        resp = requests.get(f"{SERVER_URL}/api/stats", timeout=2)
        if resp.status_code == 200:
            print("✅ Server is running\n")
        else:
            print("❌ Server returned error")
            sys.exit(1)
    except:
        print("❌ Cannot connect to server. Make sure it's running on port 8000")
        print("   python main.py")
        sys.exit(1)
    
    # Send test events
    events = [event1, event2, event3, event4]
    
    print(f"📤 Sending {len(events)} test enriched events...\n")
    
    success_count = 0
    for i, event in enumerate(events, 1):
        print(f"[{i}/{len(events)}] Sending: {event['file_name']} | Risk: {event['risk_score']}")
        if send_enriched_event(event):
            success_count += 1
        print()
    
    print("=" * 70)
    print(f"✅ Results: {success_count}/{len(events)} events sent successfully")
    print("=" * 70)
    
    if success_count == len(events):
        print("\n🎉 All test events sent!")
        print("📊 You can now view them in admin dashboard:")
        print(f"   {SERVER_URL}")
        print("\n🔍 Click event detail to see:")
        print("   ✓ YARA matches")
        print("   ✓ Behavioral matches")
        print("   ✓ Risk score breakdown")
        print("   ✓ Action reason")
        print("   ✓ Processing metadata")
    else:
        print(f"\n⚠️  Only {success_count}/{len(events)} events sent")
        print("Check server logs for errors")
