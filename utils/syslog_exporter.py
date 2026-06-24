"""
Syslog Exporter
Implements RFC 5424 formatted UDP Syslog to forward events to SIEMs like Wazuh.
"""
import socket
import json
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

class SyslogSender:
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # RFC 5424 Facility 16 = local0
        self.facility = 16

    def _get_severity(self, level: str) -> int:
        level_map = {
            "CRITICAL": 2, # Critical
            "ERROR": 3,    # Error
            "WARN": 4,     # Warning
            "INFO": 6,     # Informational
            "DEBUG": 7     # Debug
        }
        return level_map.get(level.upper(), 6)

    def _format_rfc5424(self, level: str, msgid: str, payload_dict: dict) -> bytes:
        severity = self._get_severity(level)
        prival = (self.facility * 8) + severity
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        hostname = socket.gethostname()
        app_name = "HookShield"
        procid = "-"
        
        # Convert dictionary payload to JSON string
        msg = json.dumps(payload_dict)
        
        # <PRIVAL>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
        syslog_str = f"<{prival}>1 {timestamp} {hostname} {app_name} {procid} {msgid} - {msg}"
        return syslog_str.encode('utf-8')

    def send(self, level: str, msgid: str, payload: dict):
        try:
            data = self._format_rfc5424(level, msgid, payload)
            self.sock.sendto(data, (self.host, self.port))
            logger.debug("Syslog event sent to %s:%d", self.host, self.port)
        except Exception as e:
            logger.error("Failed to send syslog: %s", e)
