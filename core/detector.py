import os
import yaml
import time
from collections import defaultdict, deque
from typing import List, Dict, Any

class RuleDetector:
    """
    Loads security detection rules from YAML files and evaluates parsed log events
    against thresholds and timeframes (sliding window).
    """

    def __init__(self, rules_dir: str = "rules"):
        self.rules_dir = rules_dir
        self.rules = []
        self.event_windows = defaultdict(lambda: defaultdict(deque))
        self.load_rules()

    def load_rules(self):
        self.rules = []
        if not os.path.exists(self.rules_dir):
            os.makedirs(self.rules_dir, exist_ok=True)
            return

        for filename in os.listdir(self.rules_dir):
            if filename.endswith(".yaml") or filename.endswith(".yml"):
                filepath = os.path.join(self.rules_dir, filename)
                try:
                    with open(filepath, "r", encoding="utf-8") as f:
                        rule_data = yaml.safe_load(f)
                        if rule_data and "title" in rule_data:
                            self.rules.append(rule_data)
                except Exception as e:
                    print(f"Error loading rule {filename}: {e}")

    def evaluate(self, parsed_event: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Evaluates a parsed event against all loaded rules.
        Returns a list of triggered alerts.
        """
        if not parsed_event:
            return []

        triggered_alerts = []
        current_time = time.time()
        source_ip = parsed_event.get("source_ip")
        raw_log = parsed_event.get("raw_log", "").lower()

        for rule in self.rules:
            # Check if log matches rule pattern
            pattern = rule.get("pattern", "").lower()
            if pattern and pattern in raw_log:
                rule_id = rule.get("id", rule.get("title"))
                threshold = rule.get("threshold", 1)
                timeframe = rule.get("timeframe", 60) # seconds

                if source_ip:
                    # Track events for this IP and rule
                    window = self.event_windows[rule_id][source_ip]
                    window.append(current_time)

                    # Remove events outside timeframe
                    while window and current_time - window[0] > timeframe:
                        window.popleft()

                    if len(window) >= threshold:
                        # Trigger alert
                        alert = {
                            "rule_title": rule.get("title"),
                            "severity": rule.get("severity", "MEDIUM"),
                            "source_ip": source_ip,
                            "username": parsed_event.get("username"),
                            "description": rule.get("description", ""),
                            "count": len(window),
                            "timestamp": parsed_event.get("timestamp"),
                            "raw_log": parsed_event.get("raw_log")
                        }
                        triggered_alerts.append(alert)
                        # Reset window after alert to prevent alert flooding
                        window.clear()
                else:
                    # If no IP, trigger immediately if threshold is 1
                    if threshold <= 1:
                        alert = {
                            "rule_title": rule.get("title"),
                            "severity": rule.get("severity", "LOW"),
                            "source_ip": "N/A",
                            "username": parsed_event.get("username"),
                            "description": rule.get("description", ""),
                            "count": 1,
                            "timestamp": parsed_event.get("timestamp"),
                            "raw_log": parsed_event.get("raw_log")
                        }
                        triggered_alerts.append(alert)

        return triggered_alerts
