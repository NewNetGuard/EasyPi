import sys
# ruff: noqa: E402

from pathlib import Path
BASE_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(BASE_DIR))
import os
os.chdir(str(BASE_DIR))

from app.services.picloud_service import pi_cloud_service
import time
import signal

running = True

def stop_handler(sig, frame):
    global running
    print('Stopping bot...')
    pi_cloud_service.stop_telegram_bot()
    running = False

signal.signal(signal.SIGTERM, stop_handler)
signal.signal(signal.SIGINT, stop_handler)

print('Starting Telegram bot...')
pi_cloud_service.start_telegram_bot()

# Wait for bot thread to start and keep process alive
while running:
    # Check if bot thread is still alive
    if pi_cloud_service._bot_thread and pi_cloud_service._bot_thread.is_alive():
        # Bot is running, wait for it
        try:
            pi_cloud_service._bot_thread.join(timeout=1.0)
        except Exception:
            pass
    else:
        # Bot thread died or never started, sleep and check again
        time.sleep(1)

print('Bot stopped')
