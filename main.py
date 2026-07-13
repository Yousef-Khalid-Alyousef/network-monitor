import logging
import os
import sys

# Mute logging to console so the Rich UI doesn't get corrupted
logging.basicConfig(
    level=logging.ERROR, # Only log errors so they don't break the UI
    filename="monitor_errors.log",
    filemode="a",
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)

import config
import db
import geolocation
import blocker
import monitor_engine
import cli

def main():
    # Init subsystems
    db.init_db()
    geolocation.init_geolocation()
    blocker.clear_all_blocks()
    
    # Start background threads
    monitor_engine.start_background_tasks()
    
    # Render CLI blocking (until KeyboardInterrupt)
    cli.render_cli()
    
    # Cleanup
    monitor_engine.stop_background_tasks()
    blocker.clear_all_blocks()
    print("\n[network-monitor] Shutdown complete.")

if __name__ == "__main__":
    main()
