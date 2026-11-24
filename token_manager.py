"""Persistent JWT token manager.

- Refreshes ALL regions every REFRESH_INTERVAL (10 min)
- Rotates guest index each cycle (different guest per region)
- Persists to tokens.json (atomic write)
- Thread-safe access from Flask request handlers
"""

import asyncio
import json
import os
import time
import threading
from collections import defaultdict

TOKENS_FILE      = "tokens.json"
REFRESH_INTERVAL = 120      # 10 minutes
TOKEN_LIFETIME   = 25200    # 7 hours


class TokenManager:
    def __init__(self, regions, guest_credentials, jwt_builder, release_getter):
        self.regions    = list(regions)
        self.guests     = guest_credentials
        self.build_jwt  = jwt_builder
        self.get_ob     = release_getter
        self.tokens     = {}                    # region -> dict
        self.guest_idx  = defaultdict(int)      # region -> next guest idx
        self.lock       = threading.Lock()
        self._thread    = None
        self._stop      = threading.Event()
        self._refreshing = False
        self._load_from_disk()

    # ── disk persistence ──
    def _load_from_disk(self):
        try:
            with open(TOKENS_FILE) as f:
                data = json.load(f)
            now = time.time()
            loaded = 0
            for r, info in data.items():
                if isinstance(info, dict) and info.get('expires_at', 0) > now:
                    self.tokens[r] = info
                    loaded += 1
            print(f"[token_mgr] Loaded {loaded} valid tokens from disk")
        except FileNotFoundError:
            print("[token_mgr] tokens.json not found — starting fresh")
        except Exception as e:
            print(f"[token_mgr] load error: {e}")

    def _save_to_disk(self):
        try:
            tmp = TOKENS_FILE + ".tmp"
            with open(tmp, 'w') as f:
                json.dump(self.tokens, f, indent=2)
            os.replace(tmp, TOKENS_FILE)
        except Exception as e:
            print(f"[token_mgr] save error: {e}")

    # ── access ──
    def get(self, region):
        with self.lock:
            return self.tokens.get(region)

    def set(self, region, info):
        with self.lock:
            self.tokens[region] = info
            self._save_to_disk()

    def all(self):
        with self.lock:
            return dict(self.tokens)

    def valid_for_ob(self, region, ob):
        with self.lock:
            info = self.tokens.get(region)
            return (info is not None
                    and time.time() < info.get('expires_at', 0)
                    and info.get('ob_version') == ob)

    def update_guests(self, new_guests):
        with self.lock:
            self.guests = new_guests

    # ── refresh ──
    async def _refresh_one(self, region, ob):
        guest_list = self.guests.get(region, [])
        if not guest_list:
            print(f"[token_mgr] {region}: no guests configured")
            return False

        n = len(guest_list)
        start = self.guest_idx[region]

        for attempt in range(n):
            idx = (start + attempt) % n
            guest = guest_list[idx]
            try:
                tok = await self.build_jwt(region, guest, ob)
                if tok and tok.get('token'):
                    tok['ob_version'] = ob
                    tok['expires_at'] = time.time() + TOKEN_LIFETIME
                    tok['guest_idx']  = idx
                    with self.lock:
                        self.tokens[region] = tok
                        self._save_to_disk()
                    # rotate for NEXT cycle
                    self.guest_idx[region] = (idx + 1) % n
                    print(f"✅ [token_mgr] {region} OK (guest {idx}/{n}, OB={ob})")
                    return True
                else:
                    print(f"⚠️  [token_mgr] {region} guest {idx}: empty token")
            except Exception as e:
                print(f"⚠️  [token_mgr] {region} guest {idx}: {e}")
        print(f"❌ [token_mgr] {region}: ALL {n} guests failed")
        return False

    async def refresh_all(self):
        if self._refreshing:
            print("[token_mgr] refresh already in progress, skipping")
            return
        self._refreshing = True
        try:
            ob = self.get_ob(force=True)          # force fresh OB
            active = [r for r in self.regions if self.guests.get(r)]
            print(f"\n[token_mgr] ═══ Refreshing {len(active)} regions | OB={ob} ═══")
            results = await asyncio.gather(
                *[self._refresh_one(r, ob) for r in active],
                return_exceptions=True,
            )
            ok = sum(1 for r in results if r is True)
            print(f"[token_mgr] ═══ Cycle done: {ok}/{len(active)} OK ═══\n")
        finally:
            self._refreshing = False

    # ── background thread ──
    def _run_loop(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            print("[token_mgr] Running initial refresh...")
            try:
                loop.run_until_complete(self.refresh_all())
            except Exception as e:
                print(f"[token_mgr] initial refresh error: {e}")

            while not self._stop.is_set():
                if self._stop.wait(REFRESH_INTERVAL):
                    break
                try:
                    loop.run_until_complete(self.refresh_all())
                except Exception as e:
                    print(f"[token_mgr] cycle error: {e}")
        finally:
            loop.close()

    def start(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._run_loop, daemon=True, name="TokenManager")
        self._thread.start()
        print(f"[token_mgr] Background refresh started "
              f"(every {REFRESH_INTERVAL}s)")

    def stop(self):
        self._stop.set()