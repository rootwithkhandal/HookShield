"""
Behavioral Scoring Engine
Aggregates threat points per-PID to reduce alert fatigue.
"""
import time
import logging

logger = logging.getLogger(__name__)

class BehavioralScorer:
    def __init__(self, threshold=80, window_seconds=300):
        self.threshold = threshold
        self.window_seconds = window_seconds
        # { pid: {"score": 0, "name": "", "events": [], "last_seen": timestamp, "alerted": False} }
        self.scores = {}

    def _cleanup_stale(self):
        """Remove scores that haven't seen activity within the window."""
        now = time.time()
        stale_pids = [
            pid for pid, data in self.scores.items()
            if now - data["last_seen"] > self.window_seconds
        ]
        for pid in stale_pids:
            del self.scores[pid]

    def add_event(self, pid: int, process_name: str, event_type: str, points: int) -> bool:
        """
        Add an event to the PID's aggregate score.
        Returns True if the threshold is newly breached.
        """
        self._cleanup_stale()

        if pid not in self.scores:
            self.scores[pid] = {
                "score": 0,
                "name": process_name,
                "events": [],
                "last_seen": time.time(),
                "alerted": False
            }

        data = self.scores[pid]
        data["last_seen"] = time.time()
        data["events"].append(event_type)
        data["score"] += points

        logger.debug(f"PID {pid} ({process_name}) scored +{points} for {event_type}. Total: {data['score']}")

        if data["score"] >= self.threshold and not data["alerted"]:
            data["alerted"] = True
            return True

        return False

    def get_summary(self, pid: int) -> dict:
        return self.scores.get(pid, {})
