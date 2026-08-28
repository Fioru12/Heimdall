import yaml
from typing import Any, Dict

DEFAULT_CONFIG: Dict[str, Any] = {
    "responder": {"dry_run": True, "allowed_os": ["Linux", "Windows"], "block_ttl_hours": None},
    "telegram": {"enabled": False, "bot_token": "", "chat_id": ""},
    "database": {"path": "heimdall.db"},
}


def load_config(path: str = "config.yaml") -> Dict[str, Any]:
    """Loads config.yaml, falling back to safe defaults if the file is
    missing or malformed. Never raises."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
            if not isinstance(data, dict):
                raise ValueError("config.yaml must contain a mapping at the top level")
            return data
    except FileNotFoundError:
        print(f"[CONFIG] {path} not found, using default configuration.")
    except (yaml.YAMLError, ValueError) as e:
        print(f"[CONFIG] Failed to parse {path} ({e}), using default configuration.")
    return DEFAULT_CONFIG
