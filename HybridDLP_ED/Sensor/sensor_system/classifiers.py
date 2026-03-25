from __future__ import annotations

from typing import Dict, Optional

BROWSERS = {"chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe"}
DESKTOP_UPLOAD_APPS = {
    "slack.exe",
    "discord.exe",
    "outlook.exe",
    "zalo.exe",
    "dropbox.exe",
    "onedrive.exe",
    "telegram.exe",
}
CLI_UPLOAD_TOOLS = {"curl.exe", "powershell.exe", "scp.exe", "winscp.exe", "filezilla.exe", "certutil.exe"}

SENSITIVE_DOMAINS = {
    "chatgpt.com",
    "gmail.com",
    "drive.google.com",
    "dropbox.com",
    "slack.com",
    "discord.com",
    "chat.zalo.me",
    "onedrive.live.com",
    "pastebin.com",
}

SENSITIVE_EXTENSIONS = {".xlsx", ".xls", ".csv", ".docx", ".doc", ".pdf", ".sql", ".zip", ".7z", ".env"}


def classify_upload_tool(process_name: str) -> Dict[str, object]:
    process = (process_name or "").lower()
    is_browser = process in BROWSERS
    is_desktop_upload_app = process in DESKTOP_UPLOAD_APPS
    is_cli_upload_tool = process in CLI_UPLOAD_TOOLS
    tool_family = "unknown"
    if is_browser:
        tool_family = "browser"
    elif is_desktop_upload_app:
        tool_family = "desktop_upload_app"
    elif is_cli_upload_tool:
        tool_family = "cli_upload_tool"
    return {
        "is_browser": is_browser,
        "is_desktop_upload_app": is_desktop_upload_app,
        "is_cli_upload_tool": is_cli_upload_tool,
        "tool_family": tool_family,
    }


def classify_domain(domain: Optional[str]) -> Dict[str, object]:
    d = (domain or "").lower()
    if not d:
        return {"has_destination": False, "is_sensitive_domain": False, "category": "unknown"}
    if d in SENSITIVE_DOMAINS:
        return {"has_destination": True, "is_sensitive_domain": True, "category": "sensitive_service"}
    if "drive" in d or "dropbox" in d or "onedrive" in d:
        return {"has_destination": True, "is_sensitive_domain": False, "category": "cloud_storage"}
    if "slack" in d or "discord" in d or "zalo" in d or "telegram" in d:
        return {"has_destination": True, "is_sensitive_domain": False, "category": "messaging"}
    return {"has_destination": True, "is_sensitive_domain": False, "category": "external"}

