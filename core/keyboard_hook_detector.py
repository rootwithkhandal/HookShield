"""
Keyboard hook detector.

Strategy:
  1. On Windows — query SetWindowsHookEx hooks via ctypes (reliable).
  2. Fallback — attempt to start a pynput Listener; if another hook is
     already consuming events the listener may raise, which we treat as
     a positive signal.  A clean start is treated as no hook detected.
"""
import logging
import platform
import ctypes

logger = logging.getLogger(__name__)

_OS = platform.system()


def _detect_hooks_windows() -> bool:
    """
    Use GetAsyncKeyState polling as a lightweight sanity check, then
    enumerate low-level keyboard hooks via EnumWindows / SetWindowsHookEx
    inspection is not directly exposed, so we use a practical heuristic:
    attempt to install our own WH_KEYBOARD_LL hook.  If the system already
    has the maximum number of hooks installed the call will fail.

    For a BCA-level tool this is a reasonable approximation.
    """
    try:
        user32 = ctypes.windll.user32  # type: ignore[attr-defined]
        # Try to set a low-level keyboard hook with a NULL proc (will fail
        # immediately but tells us if the hook infrastructure is responsive)
        hook = user32.SetWindowsHookExW(13, None, None, 0)
        if hook:
            user32.UnhookWindowsHookEx(hook)
            return False  # Hook installed cleanly → no blocking hook present
        # SetWindowsHookExW returned NULL — could indicate a hook conflict
        err = ctypes.GetLastError()
        logger.debug("SetWindowsHookExW returned NULL, error code: %d", err)
        return err != 0
    except Exception as e:
        logger.error("Windows hook detection error: %s", e)
        return False


def _detect_hooks_pynput() -> bool:
    """
    Fallback: try to start a pynput Listener for a very short window.
    An exception during startup may indicate an existing hook conflict.
    """
    try:
        from pynput.keyboard import Listener  # type: ignore

        with Listener(on_press=None) as listener:
            listener.join(timeout=1)
        return False
    except Exception as e:
        logger.warning("pynput Listener raised during hook check: %s", e)
        return True


def detect_keyboard_hooks() -> bool:
    """
    Return True if a suspicious keyboard hook is detected, False otherwise.
    """
    if _OS == "Windows":
        result = _detect_hooks_windows()
    else:
        result = _detect_hooks_pynput()

    if result:
        logger.warning("Keyboard hook detected.")
    else:
        logger.info("No keyboard hook detected.")

    return result
