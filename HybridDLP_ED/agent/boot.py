"""
boot.py — Entry point chính cho HybridDLP

Flow:
1. Nếu lần đầu -> run setup wizard (password + config + services)
2. Nếu đã setup -> hiển thị system tray icon
   - Click icon -> yêu cầu password -> control center
"""

import sys
import time
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from agent.password_manager import is_password_set
from agent.setup_wizard import run_setup_wizard
from agent.system_tray_app import show_system_tray


def main():
    """Main entry point."""
    print("\n" + "=" * 60)
    print("  🚀 HybridDLP - Startup")
    print("=" * 60 + "\n")
    
    # Check lần đầu setup
    if not is_password_set():
        print("[Boot] First-time setup detected...")
        print("[Boot] Running Setup Wizard...\n")
        
        try:
            if not run_setup_wizard():
                print("\n❌ Setup was canceled")
                sys.exit(1)
            
            print("\n✅ Setup completed successfully!")
        except Exception as e:
            print(f"\n❌ Setup error: {e}")
            import traceback
            traceback.print_exc()
            sys.exit(1)
    else:
        print("[Boot] Configuration already set")
    
    # Run system tray
    print("\n[Boot] Starting System Tray Application...")
    
    try:
        tray_app = show_system_tray()
        
        if tray_app:
            print("✅ System Tray running")
            print("\nℹ️  Click the DLP icon in system tray to:")
            print("   - Access Control Center (yêu cầu password)")
            print("   - Start/Stop Sensor")
            print("   - Start/Stop Worker")
            print("   - Edit Server Settings\n")
            
            # Keep running
            try:
                tray_app.wait()
            except KeyboardInterrupt:
                print("\n\nShutting down...")
                tray_app.stop()
                sys.exit(0)
        else:
            print("❌ Failed to start System Tray")
            sys.exit(1)
    except Exception as e:
        print(f"❌ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
