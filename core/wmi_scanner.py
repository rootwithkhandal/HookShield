"""
WMI Event Consumer Scanner.
Detects advanced persistence mechanisms stored within the WMI repository.
This complements the startup scanner by catching fileless persistence
(e.g., PowerShell scripts stored directly in WMI namespaces).
"""
import subprocess
import logging
import json
import platform

logger = logging.getLogger(__name__)

def detect_wmi_persistence() -> list[dict]:
    """
    Scans the WMI repository for suspicious CommandLineEventConsumers.
    Returns a list of detected suspicious WMI configurations.
    """
    if platform.system() != "Windows":
        return []

    detected = []
    
    try:
        # We use powershell to query the WMI namespace for event consumers
        cmd = [
            "powershell", "-NoProfile", "-Command",
            "Get-WmiObject -Namespace root\\subscription -Class CommandLineEventConsumer | Select-Object Name, CommandLineTemplate | ConvertTo-Json -Compress"
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        
        if result.returncode == 0 and result.stdout.strip():
            output = result.stdout.strip()
            try:
                consumers = json.loads(output)
                if isinstance(consumers, dict):
                    consumers = [consumers]
                    
                for c in consumers:
                    name = c.get("Name", "")
                    cmd_template = c.get("CommandLineTemplate", "") or ""
                    cmd_lower = cmd_template.lower()
                    
                    # Check for suspicious patterns in the command line template
                    suspicious_patterns = [
                        "powershell", "cmd.exe", "wscript", "cscript", 
                        "mshta", "regsvr32", "bitsadmin", "certutil", 
                        "bypass", "hidden", "invoke-", "downloadstring"
                    ]
                    
                    if any(pat in cmd_lower for pat in suspicious_patterns):
                        detected.append({
                            "name": name,
                            "command": cmd_template,
                            "type": "WMI_CommandLineEventConsumer"
                        })
            except json.JSONDecodeError:
                pass
                
    except Exception as e:
        logger.error("WMI scanner failed: %s", e)
        
    if detected:
        logger.warning("Suspicious WMI Event Consumers detected: %s", detected)
    else:
        logger.info("No suspicious WMI Event Consumers found.")
        
    return detected
