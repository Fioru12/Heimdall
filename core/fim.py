"""Heimdall FIM lite — File Integrity Monitoring a baseline hash.

Disegno volutamente piccolo: niente demone, niente dipendenze nuove
(hashlib/json/os dalla stdlib). Due comandi espliciti:

  python main.py fim-baseline --paths C:\\Windows\\System32\\drivers\\etc[,..]
  python main.py fim-scan

La baseline e' un JSON {abspath: sha256}. Lo scan ritorna eventi
{path, status: NEW|MODIFIED|DELETED, ...} e li persiste in SQLite
(tabella fim_events). Fallisce in modo rumoroso su path inesistenti o
illeggibili invece di fingere un "tutto ok".
"""
import fnmatch
import hashlib
import json
import os
from typing import Any, Dict, List


def hash_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _iter_files(paths: List[str], exclude: List[str]):
    for base in paths:
        base = os.path.abspath(base)
        if os.path.isfile(base):
            yield base
        elif os.path.isdir(base):
            for root, _dirs, names in os.walk(base):
                for name in names:
                    full = os.path.join(root, name)
                    rel = os.path.relpath(full, base)
                    if any(fnmatch.fnmatch(rel, pat) for pat in (exclude or [])):
                        continue
                    yield full
        else:
            raise FileNotFoundError(f"FIM path non trovato: {base}")


def build_baseline(paths: List[str], exclude: List[str] = None) -> Dict[str, str]:
    """Legge tutti i file sotto `paths` e ritorna {abspath: sha256}."""
    if not paths:
        raise ValueError("FIM: nessuna path da monitorare (fim.paths vuoto).")
    baseline: Dict[str, str] = {}
    for full in _iter_files(paths, exclude or []):
        try:
            baseline[os.path.abspath(full)] = hash_file(full)
        except (OSError, PermissionError) as exc:
            raise RuntimeError(f"FIM: impossibile leggere {full}: {exc}") from exc
    return baseline


def save_baseline(baseline: Dict[str, str], baseline_file: str) -> str:
    out_dir = os.path.dirname(os.path.abspath(baseline_file))
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(baseline_file, "w", encoding="utf-8") as fh:
        json.dump(baseline, fh, indent=2, sort_keys=True)
    return baseline_file


def load_baseline(baseline_file: str) -> Dict[str, str]:
    if not os.path.isfile(baseline_file):
        raise FileNotFoundError(
            f"FIM baseline non trovata: {baseline_file} "
            "(creala con `python main.py fim-baseline`)."
        )
    with open(baseline_file, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"FIM baseline malformata in {baseline_file}: atteso oggetto JSON.")
    return {str(k): str(v) for k, v in data.items()}


def scan(paths: List[str], baseline: Dict[str, str], exclude: List[str] = None) -> List[Dict[str, Any]]:
    """Confronta lo stato corrente con la baseline. Ritorna eventi NEW/MODIFIED/DELETED."""
    current = build_baseline(paths, exclude)
    events: List[Dict[str, Any]] = []
    for path, digest in sorted(current.items()):
        if path not in baseline:
            events.append({"path": path, "status": "NEW", "detail": "File non in baseline"})
        elif baseline[path] != digest:
            events.append({
                "path": path, "status": "MODIFIED",
                "detail": f"sha256 {baseline[path][:12]}... -> {digest[:12]}...",
            })
    for path in sorted(set(baseline) - set(current)):
        events.append({"path": path, "status": "DELETED", "detail": "File in baseline ma assente su disco"})
    return events
