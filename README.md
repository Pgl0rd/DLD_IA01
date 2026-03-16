## 🎯 Overview

# HybridDLP Endpoint Agent

**HybridDLP Endpoint Agent** is a Windows-based Data Loss Prevention (DLP) sensor designed to monitor, detect, and prevent unauthorized data exfiltration.

The agent operates with a robust **Supervisor/Worker architecture**, ensuring high availability through a custom Watchdog service that manages the sensor lifecycle.

![System Architecture](docs/architecture_diagram.png)
*(Note: Please move your `image_f5103b.png` to a `docs` folder and rename it, or update this link)*

## 🚀 Key Features

* **L1 Sensor Layer:** Captures system events (File System, USB, Clipboard, Screenshot) - *In Progress*.
* **High Availability Watchdog:**
    * **Auto-Healing:** Automatically restarts the Sensor process if it crashes or hangs.
    * **Heartbeat Monitoring:** Detects "zombie" processes using timestamp-based heartbeats.
    * **Process Tree Killing:** Ensures clean restarts by terminating the entire process tree.
* **Windows Service Integration:** Runs silently in the background as a system service.
* **Atomic State Management:** Uses atomic file writes for thread-safe state communication.

## 📂 Project Structure

```text
HybridDLP_ED/
├── agent/
│   ├── sensor.py             # Main Data Collector (Worker)
│   ├── watchdog_core.py      # Supervisor Logic & Process Management
│   ├── service.py            # Windows Service Wrapper (Entry point)
│   └── watchdog_service.py   # (Alternative Service entry)
├── runtime/                  # Generated at runtime
│   ├── logs/                 # Stdout/Stderr and Watchdog logs
│   └── state/                # Heartbeats (.json) and control flags
└── README.md

```

## 🧩 Architecture Details
The Watchdog Mechanism
The system uses a Supervisor class that performs:

Spawning: Launches sensor.py using the correct Python executable.

Monitoring: Checks for process exit codes and stale heartbeats (default timeout: 10s).

Backoff Strategy: Implements exponential backoff (0s, 2s, 5s...) if the sensor crashes repeatedly to prevent CPU exhaustion.

Logging
Logs are stored in runtime/logs/:

watchdog.log: Supervisor events (starts, stops, restarts).

sensor.stdout.log & sensor.stderr.log: Captured output from the sensor process.

## 🛠️ Installation & Requirements
Windows 10/11 or Windows Server.

Python 3.10+

Administrator privileges.

Dependencies
Install the required Python packages (mainly pywin32 for service management):

Bash
pip install pywin32 wmi watchdog

## ⚙️ Usage
1. Development Mode (Foreground)
To test the Watchdog and Sensor logic without installing the Windows Service, run the watchdog core directly:

Bash
python agent/watchdog_core.py
This will spawn sensor.py as a subprocess and print logs to the console.

2. Production Mode (Windows Service)
To install and run the agent as a background Windows Service:

Install the Service:

Bash
python agent/service.py install
(Make sure to run Command Prompt as Administrator)

Start the Service:

Bash
python agent/service.py start
Or start it via services.msc (Look for "HybridDLP Watchdog Service").

Stop/Remove:

Bash
python agent/service.py stop
python agent/service.py remove

