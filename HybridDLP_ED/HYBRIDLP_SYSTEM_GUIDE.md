# 🎉 HybridDLP Complete System - Full Documentation

## 📋 Overview

Hệ thống HybridDLP đã được xây dựng hoàn chỉnh với:
1. ✅ **Setup wizard lần đầu** - Set password, server URL, API Key
2. ✅ **System Tray icon** - Quản lý từ system tray
3. ✅ **Control Center** - Dashboard để start/stop services, chỉnh config
4. ✅ **Password protection** - Tất cả thao tác yêu cầu mật khẩu
5. ✅ **Service management** - Control Sensor + Worker

---

## 🎯 Architecture

```
┌─────────────────────────────────┐
│    boot.py (Entry Point)        │
└────────┬────────────────────────┘
         │
         ├─► [Lần đầu?] YES ──┐
         │                   │
         │                NO ▼
         │            [Setup Wizard]
         │            ├─ Set Password
         │            ├─ Set Server URL/Key
         │            └─ Start Services
         │
         │                   │
         ▼                   ▼
    [System Tray Icon] ◄────┘
         │
         ├─ Right-click → Menu
         │  ├─ Control Center
         │  ├─ Sensor Status
         │  ├─ Worker Status
         │  └─ Exit
         │
         └─ Double-click → Control Center
              └─ Request Password
                 ├─ Start/Stop Sensor
                 ├─ Start/Stop Worker
                 ├─ Edit Server Settings
                 └─ Logout
```

---

## 📦 Files (Tất cả đã tạo)

| File | Mô Tả |
|------|-------|
| `agent/password_manager.py` | Quản lý mật khẩu (hash, verify) |
| `agent/config.py` | Quản lý Server URL + API Key |
| `agent/service_manager.py` | Start/Stop Sensor + Worker |
| `agent/setup_wizard.py` | 3-step wizard (password, config, services) |
| `agent/main_window.py` | Control Center giao diện |
| `agent/system_tray_app.py` | System Tray icon + menu |
| `agent/boot.py` | Entry point chính |
| `agent/agent_sender.py` | **Updated** để sử dụng config |
| `start_hybridlp.bat` | Windows launcher |
| `agent/test_system.py` | Comprehensive test suite |

---

## 🚀 Cách Sử Dụng

### **Cách 1: Chạy Desktop App (Recommended)**

```bash
# Lần đầu tiên:
# 1. Popup set password
# 2. Popup set server URL + API Key
# 3. Chọn nào start sensor/worker

# Lần tiếp theo:
# System tray icon hiện -> click để mở Control Center

# Windows:
double-click start_hybridlp.bat

# Hoặc terminal:
python agent/boot.py
```

### **Cách 2: Chạy Setup Wizard (Reset)**

```bash
python agent/setup_wizard.py
```

Popup 3 bước sẽ hiện.

### **Cách 3: Chạy Control Center Trực Tiếp**

```bash
python agent/main_window.py
```

Sẽ yêu cầu password trước.

---

## 🔐 Security Flow

### Lần Đầu Khởi Động:

```
┌─────────────────┐
│  boot.py runs   │
└────────┬────────┘
         │
         ▼
    Has password?
         │
    ┌────┴────┐
    │ YES  NO │
    │         ▼
    │      [Set Password]
    │      (≥ 4 chars)
    │         │
    │         ▼
    │      [Set Server URL]
    │      [Set API Key]
    │         │
    │         ▼
    │      [Start Services?]
    │      ☐ Sensor
    │      ☐ Worker
    │         │
    ▼         ▼
[System Tray] ◄─┘
      │
[User clicks]
      │
      ▼
[Request Password]
      │
  ┌───┴───┐
  │ PASS? │
  │       ├─ NO ──► Reject
  │       │
  │       └─ YES ──► [Control Center]
  │                       │
  │                       ├─ Start/Stop Sensor
  │                       ├─ Start/Stop Worker
  │                       ├─ Edit Server Settings
  │                       └─ Logout
  │
  └──────────────────────┘
```

### Password Hashing:
- Dùng PBKDF2 SHA256 + 32-byte salt
- 100,000 iterations
- Không lưu plain text
- File: `agent/runtime/config/password.json`

---

## 📝 Configuration Files

### 1. Password File
**Location**: `agent/runtime/config/password.json`
```json
{
  "password_hash": "salt$hash..."
}
```

### 2. Config File
**Location**: `agent/runtime/config/config.json`
```json
{
  "server_url": "http://100.91.22.25:8000",
  "api_key": "dlp-key-may-ketoan-01"
}
```

---

## 🎮 Control Center Features

### Sensor Section
- **Status**: 🟢 Running / 🔴 Stopped
- **Buttons**: Start | Stop | Refresh

### Worker Section
- **Status**: 🟢 Running / 🔴 Stopped  
- **Buttons**: Start | Stop | Refresh

### Configuration
- **Edit Server Settings**: Chỉnh URL + API Key
- Auto-update running services

### Account
- **Logout**: Quay lại login screen
- **Exit**: Tắt ứng dụng

---

## 🔧 System Tray Menu

```
🎛️  Control Center
─────────────────────
Sensor
  └─ 🟢 Running / 🔴 Stopped
Worker
  └─ 🟢 Running / 🔴 Stopped
─────────────────────
Exit
```

- **Click Control Center**: Mở Control Center
- **Right-click**: Show menu
- **Double-click**: Open Control Center

---

## ✅ Installation

### 1. Required Dependencies

```bash
# Core
pip install -r agent/requirements.txt

# For System Tray (optional but recommended)
pip install pystray pillow

# Development/Testing  
pip install pytest
```

### 2. Test Installation

```bash
python agent/test_system.py
```

Kết quả mong đợi:
```
✅ ALL TESTS PASSED!
```

### 3. First Start

```bash
# Windows
start_hybridlp.bat

# Linux/Mac
python agent/boot.py
```

---

## 🐛 Troubleshooting

### System Tray không hiện
- Kiểm tra: `pip install pystray pillow`
- Windows: Kiểm tra system tray settings

### Password wizard không hiện
- Xoá: `agent/runtime/config/password.json`
- Lần kế tiếp sẽ show setup wizard

### Cannot import agent
- Chắc chắn chạy từ HybridDLP_ED root
- Hoặc: `python -m agent.boot` từ parent folder

### Service không start
- Kiểm tra logs: `agent/runtime/events.jsonl`
- Sensor: Kiểm tra Python executable
- Worker: Kiểm trap Docker Desktop running

---

## 🏗️ Architecture Details

### boot.py
- Entry point chính
- Checks lần đầu setup
- Khởi động system tray

### password_manager.py
- PBKDF2 SHA256 hashing
- Persist to JSON
- Singleton pattern

### config.py
- Manage server URL + API key
- Load/save JSON
- Support env vars override

### service_manager.py
- Start/stop operations
- Status checking
- Error handling

### setup_wizard.py
- 3-step wizard
- Step 1: Password
- Step 2: Server settings
- Step 3: Start services

### main_window.py
- Login screen
- Control center
- Service management
- Config dialog

### system_tray_app.py
- Tray icon + menu
- Click handling
- Background thread

---

## 📊 Data Flows

### Setup Flow
```
User Start
    ↓
Has Password?
    ├─ NO → Setup Wizard (Password)
    │           ↓
    │       Setup Wizard (Config)
    │           ↓
    │       Setup Wizard (Services)
    │           ↓
    └─→ System Tray
```

### Control Flow
```
User Clicks Tray Icon
    ↓
Show Control Center
    ↓
Request Password
    ├─ FAIL → Reject
    └─ PASS → Show Dashboard
         ├─ Service Management
         ├─ Config Editing
         └─ Logout
```

---

## 🔄 Environment Variables (Optional Override)

```bash
set DLP_SERVER_URL=http://custom-server:8000
set DLP_API_KEY=custom-api-key
python agent/boot.py
```

---

## 📱 User Experience

### First Run (5-10 minutes)
1. Run `start_hybridlp.bat`
2. Set password (e.g., "MySecurePass123")
3. Enter Server URL & API Key
4. Choose to start Sensor/Worker
5. System Tray icon appears

### Normal Operation
1. Click System Tray icon
2. Enter password
3. View services status
4. Start/stop as needed
5. Edit settings if needed

### Leaving Application
- Click "Exit" in Control Center
- Or close System Tray

---

## ✨ Key Features

✅ **Secure**: Password-protected access
✅ **User-Friendly**: Wizard-based setup
✅ **Background Operation**: System Tray
✅ **Easy Management**: One-click start/stop
✅ **Configurable**: Edit server settings anytime
✅ **Portable**: Single batch file to start
✅ **Non-intrusive**: Runs in background

---

## 🎓 Development Notes

### Adding New Services

1. Update `service_manager.py`:
```python
def start_new_service(self):
    # Implementation
```

2. Add to Control Center in `main_window.py`:
```python
ttk.Button(frame, text="Service", command=self._start_new)
```

3. Add to System Tray menu in `system_tray_app.py`

### Custom Setup Steps

Extend `setup_wizard.py` with new steps:
```python
def _show_step_4(self):
    # Custom setup
    self._update_buttons("Next", self._step_4_next, self._show_step_3)
```

---

## 📞 Support

- Check logs: `agent/runtime/events.jsonl`
- Config check: `agent/runtime/config/config.json`
- Test: `python agent/test_system.py`
- Reset: Delete `agent/runtime/config/` and restart

---

## ✅ Checklist

- [x] Password manager (PBKDF2 hash)
- [x] Config manager (Server URL + API Key)
- [x] Service manager (Start/Stop)
- [x] 3-step setup wizard
- [x] Control center GUI
- [x] System tray application
- [x] Boot entry point
- [x] Agent sender integration
- [x] Windows batch launcher
- [x] Comprehensive test suite
- [x] Full documentation

## 🎉 Ready to Use!

```bash
# Start HybridDLP
start_hybridlp.bat
```

Enjoy! 🚀
