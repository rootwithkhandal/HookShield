"""
Memory scanner for DLL injection detection.
Scans for MEM_PRIVATE + PAGE_EXECUTE_READWRITE memory regions.
"""
import ctypes
from ctypes import wintypes
import psutil
import logging

logger = logging.getLogger(__name__)

PAGE_EXECUTE_READWRITE = 0x40
MEM_PRIVATE = 0x20000
PROCESS_QUERY_INFORMATION = 0x0400
PROCESS_VM_READ = 0x0010

# ponytail: Handle 32/64-bit struct padding without external deps
if ctypes.sizeof(ctypes.c_void_p) == 8:
    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", wintypes.DWORD),
            ("__alignment1", wintypes.DWORD),
            ("RegionSize", ctypes.c_size_t),
            ("State", wintypes.DWORD),
            ("Protect", wintypes.DWORD),
            ("Type", wintypes.DWORD),
            ("__alignment2", wintypes.DWORD),
        ]
else:
    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", wintypes.DWORD),
            ("RegionSize", ctypes.c_size_t),
            ("State", wintypes.DWORD),
            ("Protect", wintypes.DWORD),
            ("Type", wintypes.DWORD),
        ]

kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

def scan_process_memory(pid: int, name: str) -> list[dict]:
    # ponytail: pure ctypes, no third-party memory library required.
    h_process = kernel32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, False, pid)
    if not h_process: 
        return []
    
    hits = []
    address = 0
    mbi = MEMORY_BASIC_INFORMATION()
    
    while kernel32.VirtualQueryEx(h_process, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi)):
        if mbi.Type == MEM_PRIVATE and mbi.Protect == PAGE_EXECUTE_READWRITE:
            hits.append({
                "pid": pid, 
                "name": name, 
                "address": hex(mbi.BaseAddress or 0), 
                "size": mbi.RegionSize
            })
        address += mbi.RegionSize
        
    kernel32.CloseHandle(h_process)
    return hits

def detect_dll_injection(targets=("explorer.exe", "winlogon.exe")) -> list[dict]:
    hits = []
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            name = proc.info['name']
            if name and name.lower() in targets:
                hits.extend(scan_process_memory(proc.info['pid'], name))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass
            
    if hits:
        logger.warning("Suspicious memory regions (RWX) found: %s", hits)
    else:
        logger.info("No suspicious memory regions found in targets.")
    return hits
