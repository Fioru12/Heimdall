import os
import yaml
from typing import Any, Dict

DEFAULT_CONFIG: Dict[str, Any] = {
    "responder": {"dry_run": True, "allowed_os": ["Linux", "Windows"], "block_ttl_hours": None},
    "telegram": {"enabled": False, "bot_token": "", "chat_id": ""},
    "database": {"path": "heimdall.db"},
}


def _apply_env_overrides(config: Dict[str, Any]) -> Dict[str, Any]:
    """TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID env vars override config.yaml and,
    if both are present, enable Telegram even when config.yaml doesn't -
    this lets a wrapper (e.g. Ragnarok's setup wizard) configure Heimdall
    without ever touching its config.yaml file."""
    telegram = dict(config.get("telegram", {}))
    env_token = os.environ.get("TELEGRAM_BOT_TOKEN")
    env_chat_id = os.environ.get("TELEGRAM_CHAT_ID")
    if env_token:
        telegram["bot_token"] = env_token
    if env_chat_id:
        telegram["chat_id"] = env_chat_id
    if env_token and env_chat_id:
        telegram["enabled"] = True
    config = dict(config)
    config["telegram"] = telegram
    return config


def load_config(path: str = "config.yaml") -> Dict[str, Any]:
    """Loads config.yaml, falling back to safe defaults if the file is
    missing or malformed. Never raises. Environment variables (see
    _apply_env_overrides) always take precedence over the file."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
            if not isinstance(data, dict):
                raise ValueError("config.yaml must contain a mapping at the top level")
            return _apply_env_overrides(data)
    except FileNotFoundError:
        print(f"[CONFIG] {path} not found, using default configuration.")
    except (yaml.YAMLError, ValueError) as e:
        print(f"[CONFIG] Failed to parse {path} ({e}), using default configuration.")
    return _apply_env_overrides(DEFAULT_CONFIG)
