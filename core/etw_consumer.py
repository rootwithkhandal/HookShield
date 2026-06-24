"""
ETW Consumer for real-time kernel events.
Replaces psutil polling with event-driven hooks.
"""
import asyncio
import logging
import threading
import queue
import ctypes
import os

logger = logging.getLogger(__name__)

# Cross-thread sync queue to ferry events from ETW C-thread to Python async loop
sync_queue = queue.Queue()

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False

def etw_callback(event):
    """
    Called by the ETW C-extension thread for every event.
    Push it to the sync queue.
    """
    sync_queue.put(event)

def start_etw_listeners():
    """Start the ETW listener in a background thread."""
    if not is_admin():
        logger.error("Administrator privileges required for ETW Kernel tracing. Please restart as Admin.")
        # We don't exit entirely to let other legacy non-ETW scans run, 
        # but ETW won't work.
        return False

    try:
        import etw
    except ImportError:
        logger.error("Failed to import `etw` package. Did you run `mise run install`?")
        return False

    def _run():
        try:
            logger.info("Binding to ETW Kernel Providers...")
            job = etw.ETW(
                providers=[
                    'Microsoft-Windows-Kernel-Process',
                    'Microsoft-Windows-Kernel-File',
                    'Microsoft-Windows-Kernel-Registry'
                ],
                event_callback=etw_callback
            )
            job.start()
        except Exception as e:
            logger.error("ETW listener failed: %s", e)

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    logger.info("ETW Kernel listeners running in background.")
    return True

async def get_next_etw_event():
    """Async generator to consume ETW events from the sync queue without blocking the loop."""
    while True:
        try:
            event = sync_queue.get_nowait()
            yield event
        except queue.Empty:
            await asyncio.sleep(0.05)
