from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, FrozenSet, List, Tuple

# Named pipe used by BrowserUploadSensor to receive events from Native Host
DEFAULT_BROWSER_UPLOAD_PIPE = r"\\.\pipe\dlp_browser_upload"


@dataclass
class NetworkSensorConfig:
    """Settings for honest host-level outbound candidate emission (L1)."""

    host_bytes_delta_threshold: float = 100 * 1024
    min_emit_interval_seconds: float = 8.0
    quiet_period_resend_seconds: float = 45.0
    relevance_score_threshold: int = 4
    max_dedup_state_entries: int = 5000
    poll_interval_seconds: float = 1.0

    denied_process_names: FrozenSet[str] = field(
        default_factory=lambda: frozenset(
            {
                "cursor.exe",
                "language_server_windows_x64.exe",
                "supportassistagent.exe",
                "parsecd.exe",
                "svchost.exe",
                "searchhost.exe",
                "runtimebroker.exe",
            }
        )
    )
    denied_path_tokens: Tuple[str, ...] = field(
        default_factory=lambda: (
            "\\cache\\",
            "\\code cache\\",
            "\\gpucache\\",
            "\\network\\",
            "\\logs\\",
            "\\appdata\\roaming\\cursor\\",
            "\\appdata\\roaming\\zalodata\\cache\\",
            "\\appdata\\local\\google\\chrome\\user data\\",
            "\\appdata\\local\\microsoft\\edge\\user data\\",
            "\\programdata\\",
            "\\windows\\",
            "\\temp\\",
            "\\tmp\\",
            "journal",
            "leveldb",
            "cookies",
            "history",
        )
    )
    allowed_user_path_roots: Tuple[str, ...] = field(
        default_factory=lambda: (
            "\\desktop\\",
            "\\documents\\",
            "\\downloads\\",
            "\\pictures\\",
            "\\onedrive\\",
        )
    )
    denied_file_extensions: FrozenSet[str] = field(
        default_factory=lambda: frozenset(
            {".log", ".pf", ".tmp", ".journal", ".sqlite", ".ldb", ".old", ".bak"}
        )
    )
    infrastructure_domain_tokens: Tuple[str, ...] = field(
        default_factory=lambda: (
            "cloudfront.net",
            "amazonaws.com",
            "compute.amazonaws",
            "1e100.net",
            "akamai",
            "edgesuite.net",
            "fastly",
            "cloudflare",
        )
    )


@dataclass
class QueueConfig:
    retry_count: int = 3
    retry_backoff_seconds: float = 0.5
    local_buffer_path: Path = Path("buffer") / "events.buffer"
    local_buffer_key_path: Path = Path("buffer") / "key.bin"


@dataclass
class BrowserUploadSensorConfig:
    """Config for BrowserUploadSensor (TCP server)."""
    tcp_host: str = "127.0.0.1"
    tcp_port: int = 47266           # BrowserUploadSensor listens here
    reconnect_delay_sec: float = 2.0

    # Legacy compat aliases (kept so existing code using pipe_name doesn't crash)
    @property
    def pipe_name(self) -> str:
        return self.tcp_host

    @property
    def poll_timeout_ms(self) -> int:
        return 200


@dataclass
class SensorConfig:
    enabled: bool = True
    watch_paths: List[str] = field(default_factory=list)


@dataclass
class AppConfig:
    queue: QueueConfig = field(default_factory=QueueConfig)
    network_sensor_config: NetworkSensorConfig = field(default_factory=NetworkSensorConfig)
    browser_upload_sensor_config: BrowserUploadSensorConfig = field(
        default_factory=BrowserUploadSensorConfig
    )
    sensors: Dict[str, SensorConfig] = field(
        default_factory=lambda: {
            "file_sensor": SensorConfig(),
            "clipboard_sensor": SensorConfig(),
            "process_sensor": SensorConfig(),
            "network_sensor": SensorConfig(),
            "usb_sensor": SensorConfig(),
            "print_sensor": SensorConfig(),
            "browser_upload_sensor": SensorConfig(),  # L1 Browser Upload via Native Host
        }
    )

