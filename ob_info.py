"""Fetch latest OB release info from star-auto-update.vercel.app."""

import os
import threading
import time

import httpx

OB_INFO_URL = "https://star-auto-update.vercel.app/"
CACHE_TTL   = int(os.environ.get("OB_CACHE_TTL", "15"))
FALLBACK_OB = "OB55"

_cache = {"data": None, "ts": 0.0}
_lock  = threading.Lock()


def fetch_ob_info(force: bool = False) -> dict:
    with _lock:
        now = time.time()
        if not force and _cache["data"] and now - _cache["ts"] < CACHE_TTL:
            return _cache["data"]
        try:
            r = httpx.get(
                OB_INFO_URL,
                headers={"Cache-Control": "no-cache", "Pragma": "no-cache"},
                timeout=10,
            )
            r.raise_for_status()
            data = r.json()
            if "latest_release_version" not in data:
                raise ValueError("missing latest_release_version")
            _cache["data"] = data
            _cache["ts"]   = now
            print(f"[ob_info] fetched OB={data['latest_release_version']} "
                  f"client={data.get('current_version')}", flush=True)
            return data
        except Exception as e:
            print(f"[ob_info] fetch failed: {e}", flush=True)
            if _cache["data"]:
                return _cache["data"]
            return {
                "latest_release_version": FALLBACK_OB,
                "current_version": "unknown",
                "error": str(e),
            }


def get_release_version(force: bool = False) -> str:
    return fetch_ob_info(force=force).get("latest_release_version", FALLBACK_OB)


def get_ob_info(force: bool = False) -> dict:
    return fetch_ob_info(force=force)