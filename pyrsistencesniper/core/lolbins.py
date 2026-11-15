"""LOLBin data access: bundled snapshot, user-level cache, and HTTP download."""

from __future__ import annotations

import importlib.resources
import json
import logging
import random
import time
import urllib.request
from pathlib import Path

import platformdirs

logger = logging.getLogger(__name__)

LOLBAS_URL = "https://lolbas-project.github.io/api/lolbas.json"

_CACHE_DIR = Path(platformdirs.user_cache_dir("pyrsistencesniper"))
_CACHE_FILE = _CACHE_DIR / "lolbins.json"

_TIMEOUT_S = 30.0
_MAX_ATTEMPTS = 4
_BACKOFF_BASE_S = 0.5
_BACKOFF_CAP_S = 8.0
_JITTER_S = 0.25

_MAX_PAYLOAD_BYTES = 16 << 20


def _load_bundled() -> frozenset[str]:
    """Load LOLBin names from the bundled data file."""
    resource = importlib.resources.files("pyrsistencesniper.data").joinpath(
        "lolbins.json"
    )
    data = json.loads(resource.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("Bundled lolbins.json has unexpected format")
    return frozenset(name.lower() for name in data if isinstance(name, str) and name)


def _load_cache() -> frozenset[str] | None:
    """Load LOLBin names from the user-level cache file, or None if absent."""
    if not _CACHE_FILE.is_file():
        return None
    try:
        data = json.loads(_CACHE_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        logger.debug("Cache file unreadable, ignoring", exc_info=True)
        return None
    if not isinstance(data, list) or not all(isinstance(name, str) for name in data):
        return None
    return frozenset(name.lower() for name in data if name)


def _fetch_payload() -> object:
    """Fetch the LOLBAS list and decode it, raising on any failure."""
    with urllib.request.urlopen(LOLBAS_URL, timeout=_TIMEOUT_S) as response:
        body = response.read(_MAX_PAYLOAD_BYTES + 1)
    if len(body) > _MAX_PAYLOAD_BYTES:
        raise ValueError(f"LOLBAS payload exceeds {_MAX_PAYLOAD_BYTES} bytes")
    return json.loads(body)


def download_lolbins() -> set[str]:
    """Download LOLBin names from the LOLBAS API and persist to the user cache."""
    for attempt in range(1, _MAX_ATTEMPTS + 1):
        try:
            payload = _fetch_payload()
            break
        # urllib reports HTTP status, network and timeout failures as OSError.
        except (OSError, ValueError):
            if attempt == _MAX_ATTEMPTS:
                raise
            backoff = min(_BACKOFF_CAP_S, _BACKOFF_BASE_S * (2 ** (attempt - 1)))
            sleep_s = backoff + random.uniform(0.0, _JITTER_S)  # noqa: S311
            logger.warning(
                "LOLBAS fetch failed (attempt %d/%d); retrying in %.2fs",
                attempt,
                _MAX_ATTEMPTS,
                sleep_s,
                exc_info=True,
            )
            time.sleep(sleep_s)

    if not isinstance(payload, list):
        raise ValueError(
            f"Unexpected LOLBAS payload type: {type(payload)!r} (expected list)"
        )

    names = {
        name.strip().lower()
        for entry in payload
        if isinstance(entry, dict)
        and isinstance((name := entry.get("Name")), str)
        and name.strip()
    }
    if not names:
        raise ValueError("LOLBAS payload contained no usable 'Name' entries")

    _CACHE_DIR.mkdir(parents=True, exist_ok=True)
    _CACHE_FILE.write_text(json.dumps(sorted(names)), encoding="utf-8")
    logger.info("Downloaded %d LOLBin names to %s", len(names), _CACHE_FILE)
    return names


def load_lolbin_names() -> frozenset[str]:
    """Return LOLBin names, preferring the user cache over bundled data."""
    cached = _load_cache()
    if cached is not None:
        return cached
    return _load_bundled()
