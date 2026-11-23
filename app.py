# INFO API SRC BYY
# POWERED BY : @STAR_GMR
# CHANNEL : @STAR_METHODE
import asyncio
import time
import httpx
import json
import os
from collections import defaultdict
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
from cachetools import TTLCache
from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2
from google.protobuf import json_format, message
from google.protobuf.message import Message
from Crypto.Cipher import AES
import base64

from ob_info import get_release_version, get_ob_info, fetch_ob_info
from token_manager import TokenManager

# ---------- Config ----------
MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV  = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
USERAGENT = "UnityPlayer/2018.4.12f1 (UnityWebRequest/1.0, libcurl/8.5.0-DEV)"
SUPPORTED_REGIONS = [
    "IND", "SG", "ID", "BR", "VN", "US", "SAC", "NA",
    "RU", "TH", "TW", "BD", "PK", "ME", "CIS", "EUROPE"
]
API_KEY = "STARGMR"

app = Flask(__name__)
CORS(app)
response_cache = TTLCache(maxsize=1000, ttl=30)
uid_region_cache = {}

# ---------- Guests ----------
GUEST_CREDENTIALS = {}

def load_guests_from_file():
    global GUEST_CREDENTIALS
    try:
        with open('guests.json', 'r', encoding='utf-8') as f:
            data = json.load(f)
        for r in SUPPORTED_REGIONS:
            if r not in data or not isinstance(data[r], list):
                data[r] = []
        GUEST_CREDENTIALS = data
        counts = {r: len(v) for r, v in data.items() if v}
        print(f"✅ Guests loaded: {counts}")
    except Exception as e:
        print(f"❌ guests.json: {e}")
        GUEST_CREDENTIALS = {}

load_guests_from_file()

# ---------- Crypto helpers ----------
def pad(text: bytes) -> bytes:
    n = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([n] * n)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    return AES.new(key, AES.MODE_CBC, iv).encrypt(pad(plaintext))

def decode_protobuf(encoded_data: bytes, message_type: message.Message) -> message.Message:
    inst = message_type()
    inst.ParseFromString(encoded_data)
    return inst

async def json_to_proto(json_data: str, proto_message: Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

def find_protobuf_start(data: bytes) -> int:
    idx = data.find(b'\x12\x03IND')
    if idx != -1:
        for i in range(idx - 1, max(idx - 20, -1), -1):
            if data[i] == 0x08:
                return i
    jwt_marker = data.find(b'B\xe7\x05eyJ')
    if jwt_marker != -1:
        for i in range(jwt_marker - 1, max(jwt_marker - 200, -1), -1):
            if data[i] == 0x08:
                return i
    return data.find(b'\x08')

# ---------- JWT builder for ONE guest ----------
async def _get_access_token(account: str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = account + "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/x-www-form-urlencoded"
    }
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(url, data=payload, headers=headers)
        try:
            data = resp.json()
        except Exception:
            return "0", "0"
        return data.get("access_token", "0"), data.get("open_id", "0")


async def _build_jwt_for_guest(region: str, guest: str, ob: str):
    token_val, open_id = await _get_access_token(guest)
    if token_val == "0" or open_id == "0":
        return None

    body = json.dumps({
        "open_id": open_id,
        "open_id_type": "4",
        "login_token": token_val,
        "orign_platform_type": "4"
    })
    proto_bytes = await json_to_proto(body, FreeFire_pb2.LoginReq())
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)

    url = "https://loginbp.ppmainecoonghj.com/MajorLogin"
    headers = {
        'User-Agent': USERAGENT,
        'Accept': "*/*",
        'Accept-Encoding': "deflate, gzip",
        'X-Ga-Sv': "1789534056",
        'Authorization': "Bearer",
        'X-Ga': "v1 1",
        'Releaseversion': ob,
        'Content-Type': "application/x-www-form-urlencoded",
        'X-Unity-Version': "2018.4.12f1",
        'PlAy_VeR': "1.132.1",
        'Ob_VeR': ob
    }

    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(url, data=payload, headers=headers)
        start_idx = find_protobuf_start(resp.content)
        if start_idx == -1:
            return None
        try:
            msg = json.loads(json_format.MessageToJson(
                decode_protobuf(resp.content[start_idx:], FreeFire_pb2.LoginRes)
            ))
        except Exception:
            return None
        token_str = msg.get("token", "")
        if not token_str:
            return None
        return {
            'token': f"Bearer {token_str}",
            'region': msg.get('lockRegion', region) or region,
            'server_url': msg.get('serverUrl', '0'),
        }


token_manager = TokenManager(
    regions=SUPPORTED_REGIONS,
    guest_credentials=GUEST_CREDENTIALS,
    jwt_builder=_build_jwt_for_guest,
    release_getter=get_release_version,
)

# ---------- Personal show fetch ----------
async def _call_personal_show(uid, token_info, ob):
    payload = await json_to_proto(
        json.dumps({'a': uid, 'b': "7"}),
        main_pb2.GetPlayerPersonalShow()
    )
    data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)

    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'Expect': "100-continue",
        'Authorization': token_info['token'],
        'X-Unity-Version': "2018.4.12f1",
        'X-GA': "v1 1",
        'ReleaseVersion': ob,
    }

    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(token_info['server_url'] + "/GetPlayerPersonalShow",
                                 data=data_enc, headers=headers)
        return json.loads(
            json_format.MessageToJson(
                decode_protobuf(resp.content,
                                AccountPersonalShow_pb2.AccountPersonalShowInfo)
            )
        )


# ═══════════════════════════════════════════════════════════════════
#  FRESHNESS SCORE — reads response body, not request
#  Higher score = newer / more recent OB data
# ═══════════════════════════════════════════════════════════════════

# Fields that appear ONLY in newer OB responses
_NEW_BASICINFO_FIELDS = [
    'hasElitePass', 'title', 'badgeCnt', 'pinId',
    'csRankingPoints', 'showBrRank', 'showCsRank',
    'socialHighLightsWithBasicInfo', 'releaseVersion',
]

def _freshness_score(data, current_ob):
    """
    Score a PersonalShow response — higher = newer data.
    Priority order:
      1. basicInfo.releaseVersion == current OB  (+10000)  ← STRONGEST
      2. basicInfo.lastLoginAt (newer timestamp)  (+0..5000)
      3. Number of NEW fields present             (+0..900)
      4. Richness (profileInfo, socialInfo, etc.) (+0..200)
      5. seasonId (last resort, weak signal)      (+0..100)
    """
    if not isinstance(data, dict):
        return 0
    bi = data.get('basicInfo') or {}
    score = 0

    # ── 1. releaseVersion match (BIGGEST signal) ──
    rv = (bi.get('releaseVersion') or '').strip().upper()
    if rv:
        if rv == current_ob:
            score += 10000          # ✅ exact OB match
            print(f"[score] releaseVersion={rv} MATCHES current → +10000")
        else:
            score += 2000           # has version but different
            print(f"[score] releaseVersion={rv} (≠{current_ob}) → +2000")

    # ── 2. lastLoginAt (newer = fresher) ──
    try:
        ll = int(bi.get('lastLoginAt') or 0)
        if ll > 0:
            # Normalize: 2019 ≈ 1.56B, 2026 ≈ 1.79B
            # Anything after 2024-01-01 (> 1704067200) = recent
            if ll > 1704067200:
                score += 5000
            elif ll > 1600000000:   # 2020+
                score += 2000
            elif ll > 1500000000:   # 2017-2020
                score += 500
            else:
                score += 100
    except Exception:
        pass

    # ── 3. New-field count ──
    present = [f for f in _NEW_BASICINFO_FIELDS if f in bi]
    score += len(present) * 100

    # ── 4. Richness checks ──
    pi = data.get('profileInfo') or {}
    if pi.get('clothes'):       score += 50
    if pi.get('equipedSkills'): score += 30
    if pi.get('isSelected'):    score += 20

    si = data.get('socialInfo') or {}
    if si.get('signature'):     score += 50
    if si.get('gender'):        score += 20

    ci = data.get('creditScoreInfo') or {}
    if ci.get('creditScore'):   score += 30

    pbi = data.get('primeInfo') or {}
    if (bi.get('primeInfo') or {}).get('primeLevel'):
        score += 50

    # ── 5. seasonId (weak fallback) ──
    try:
        season = int(bi.get('seasonId') or 0)
        score += min(season, 100)
    except Exception:
        pass

    return score


def _ob_from_response(data):
    """Extract OB version literally from response body (if present)."""
    try:
        return (data.get('basicInfo') or {}).get('releaseVersion') or None
    except Exception:
        return None


# ---------- Single-region try ----------
async def _try_one_region(uid, region, ob):
    tok = token_manager.get(region)
    if not tok:
        return None
    if tok.get('ob_version') != ob:
        return None
    if time.time() >= tok.get('expires_at', 0):
        return None
    try:
        data = await _call_personal_show(uid, tok, ob)
        if not isinstance(data, dict):
            return None
        if not (data.get('basicInfo') or {}).get('accountId'):
            print(f"[accinfo] {region} → empty basicInfo, skipping")
            return None
        return (region, data)
    except Exception as e:
        print(f"[accinfo] {region} failed: {e}")
        return None


# ---------- Auto lookup: parallel, freshness-scored ----------
async def _accinfo_lookup(uid, ob, region_hint=None):
    # Mode 1: region pinned → trust it, no comparison
    if region_hint:
        print(f"[accinfo] 🎯 {uid} pinned → {region_hint}")
        return await _try_one_region(uid, region_hint, ob)

    # Mode 2: auto → parallel all regions, best freshness wins
    targets = [r for r in SUPPORTED_REGIONS if token_manager.valid_for_ob(r, ob)]
    if not targets:
        print(f"[accinfo] ⚠️  no valid tokens for OB={ob}")
        return None

    print(f"[accinfo] ⚡ {uid} scan across {len(targets)} regions (OB={ob})")
    tasks = {asyncio.create_task(_try_one_region(uid, r, ob)): r for r in targets}
    successes = []
    deadline = time.time() + 12.0

    try:
        while tasks and time.time() < deadline:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            done, _ = await asyncio.wait(
                tasks.keys(),
                timeout=remaining,
                return_when=asyncio.FIRST_COMPLETED,
            )
            if not done:
                break
            for t in done:
                name = tasks.pop(t)
                try:
                    res = t.result()
                    if isinstance(res, tuple) and res[1]:
                        score = _freshness_score(res[1], ob)
                        resp_ob = _ob_from_response(res[1])
                        successes.append((res[0], res[1], score, resp_ob))
                        print(f"[accinfo]   ✓ {name:<8} score={score:<6} "
                              f"resp_ob={resp_ob or '-'}")
                    else:
                        print(f"[accinfo]   · {name:<8} no result")
                except Exception as e:
                    print(f"[accinfo]   ✗ {name:<8} err: {e}")
    finally:
        for t in tasks:
            t.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    if not successes:
        print(f"[accinfo] ❌ no region returned data for {uid}")
        return None

    # Sort by freshness score → best wins
    successes.sort(key=lambda x: x[2], reverse=True)
    best = successes[0]

    if len(successes) > 1:
        rejected = [(s[0], s[2], s[3] or '-') for s in successes[1:]]
        print(f"[accinfo] ✅ PICKED {best[0]} "
              f"(score={best[2]}, ob={best[3] or '-'})")
        print(f"[accinfo]    rejected: {rejected}")

    return (best[0], best[1])


# ---------- API key decorator ----------
def require_api_key(fn):
    @wraps(fn)
    def wrapper(*a, **k):
        key = request.args.get('key')
        if not key and request.is_json:
            key = (request.get_json(silent=True) or {}).get('key')
        if not key:
            key = request.form.get('key')
        if key != API_KEY:
            return jsonify({"error": "Invalid or missing API key",
                            "hint": "Add ?key=STARGMR"}), 401
        return fn(*a, **k)
    return wrapper


def cached_endpoint():
    def decorator(fn):
        @wraps(fn)
        def wrapper(*a, **k):
            if request.args.get('fresh') == '1' or request.args.get('nocache') == '1':
                return fn(*a, **k)
            current_ob = get_release_version()
            key = (request.path, tuple(request.args.items()), current_ob)
            if key in response_cache:
                return response_cache[key]
            res = fn(*a, **k)
            if isinstance(res, tuple) and len(res) == 3 and res[1] == 200:
                response_cache[key] = res
            return res
        return wrapper
    return decorator


# ---------- Routes ----------

@app.route('/accinfo')
@require_api_key
@cached_endpoint()
def get_account_info():
    uid = request.args.get('uid')
    if not uid:
        return jsonify({"error": "Please provide UID"}), 400

    region_param = (request.args.get('region') or '').strip().upper()
    if region_param and region_param not in SUPPORTED_REGIONS:
        return jsonify({"error": f"Invalid region '{region_param}'",
                        "supported_regions": SUPPORTED_REGIONS}), 400

    if region_param and not GUEST_CREDENTIALS.get(region_param):
        avail = [r for r in SUPPORTED_REGIONS if GUEST_CREDENTIALS.get(r)]
        return jsonify({"error": f"No guests for region {region_param}",
                        "available_regions": avail}), 503

    force = request.args.get('fresh') == '1'
    current_ob = get_release_version(force=force)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        if not any(token_manager.valid_for_ob(r, current_ob)
                   for r in SUPPORTED_REGIONS):
            print(f"[accinfo] No valid tokens for OB={current_ob} — refreshing...")
            try:
                loop.run_until_complete(asyncio.wait_for(
                    token_manager.refresh_all(), timeout=30))
            except asyncio.TimeoutError:
                print("[accinfo] refresh timeout")

        result = loop.run_until_complete(
            _accinfo_lookup(uid, current_ob, region_param or None))
    finally:
        loop.close()

    if not result:
        return jsonify({
            "error": "UID not found in any region or no fresh tokens",
            "ob": current_ob,
            "tokens_available": list(token_manager.all().keys()),
        }), 404

    region, data = result
    uid_region_cache[uid] = region

    resp_ob = _ob_from_response(data)            # OB from response body
    score   = _freshness_score(data, current_ob)

    return json.dumps(data, indent=2), 200, {
        'Content-Type': 'application/json',
        'X-OB-Request':  current_ob,             # OB sent in request
        'X-OB-Response': resp_ob or 'unknown',   # OB parsed from response
        'X-Freshness':   str(score),
        'X-Region-Used': region,
    }


@app.route('/tokens')
@require_api_key
def get_tokens():
    current_ob = get_release_version()
    tm = token_manager.all()
    out = {}
    for r, info in tm.items():
        out[r] = {
            'ob': info.get('ob_version'),
            'match_current_ob': info.get('ob_version') == current_ob,
            'expires_in_sec': max(0, int(info.get('expires_at', 0) - time.time())),
            'guest_idx': info.get('guest_idx'),
            'server_url': info.get('server_url'),
            'token_preview': (info.get('token', '')[:35] + '...')
                             if info.get('token') else None,
        }
    return jsonify({
        "current_ob": current_ob,
        "regions_with_tokens": list(tm.keys()),
        "regions_missing": [r for r in SUPPORTED_REGIONS if r not in tm],
        "tokens": out,
    })


@app.route('/info', methods=['GET'])
@require_api_key
def ob_info_endpoint():
    try:
        use_cache = request.args.get('cache') == '1'
        data = fetch_ob_info(force=not use_cache)
        return jsonify({
            "latest_release_version": data.get("latest_release_version"),
            "current_version":        data.get("current_version"),
            "play_version":           data.get("play_version"),
            "host":                   data.get("host"),
            "server_url":             data.get("server_url"),
            "next_update":            data.get("next_update"),
            "client_url":             data.get("client_url"),
            "owner":                  data.get("owner"),
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/reload-version', methods=['GET', 'POST'])
@require_api_key
def reload_version():
    try:
        data = fetch_ob_info(force=True)
        import threading
        threading.Thread(
            target=lambda: asyncio.run(token_manager.refresh_all()),
            daemon=True,
        ).start()
        return jsonify({
            "message": "OB refreshed + tokens regenerating",
            "latest_release_version": data.get("latest_release_version"),
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/ref-token', methods=['GET', 'POST'])
@require_api_key
def refresh_tokens_endpoint():
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(token_manager.refresh_all())
        loop.close()
        return jsonify({
            'message': 'All region tokens refreshed',
            'ob_version': get_release_version(force=True),
            'regions_with_tokens': list(token_manager.all().keys()),
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/reload-guests', methods=['GET', 'POST'])
@require_api_key
def reload_guests():
    try:
        load_guests_from_file()
        token_manager.update_guests(GUEST_CREDENTIALS)
        return jsonify({
            'message': 'Guests reloaded',
            'regions': {r: len(v) for r, v in GUEST_CREDENTIALS.items() if v},
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/status', methods=['GET'])
@require_api_key
def status():
    current_ob = get_release_version()
    tm = token_manager.all()
    summary = {}
    for r in SUPPORTED_REGIONS:
        info = tm.get(r)
        if info:
            summary[r] = {
                'ob': info.get('ob_version'),
                'match': info.get('ob_version') == current_ob,
                'expires_in': max(0, int(info.get('expires_at', 0) - time.time())),
                'guest_idx': info.get('guest_idx'),
            }
        else:
            summary[r] = None
    return jsonify({
        "release_version": current_ob,
        "regions_configured": {r: len(GUEST_CREDENTIALS.get(r, []))
                               for r in SUPPORTED_REGIONS
                               if GUEST_CREDENTIALS.get(r)},
        "tokens": summary,
        "response_cache_size": len(response_cache),
    })


if __name__ == '__main__':
    print(f"[startup] OB → {get_release_version(force=True)}")
    token_manager.start()
    app.run(host='0.0.0.0', port=5001, debug=False)