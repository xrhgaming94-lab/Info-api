# INFO API SRC BYY 
# POWERED BY : @STAR_GMR
# CHANNEL : @STAR_METHODE
import asyncio
import time
import httpx
import json
import random
import threading
from collections import defaultdict
from functools import wraps
from flask import Flask, request, jsonify
from flask_cors import CORS
from cachetools import TTLCache
from typing import Tuple
from proto import FreeFire_pb2, main_pb2, AccountPersonalShow_pb2
from google.protobuf import json_format, message
from google.protobuf.message import Message
from Crypto.Cipher import AES
import base64

# ---------- Config ----------

MAIN_KEY = base64.b64decode('WWcmdGMlREV1aDYlWmNeOA==')
MAIN_IV = base64.b64decode('Nm95WkRyMjJFM3ljaGpNJQ==')
RELEASEVERSION = "OB53"
USERAGENT = "Dalvik/2.1.0 (Linux; U; Android 13; CPH2095 Build/RKQ1.211119.001)"
SUPPORTED_REGIONS = [
    "IND", "SG", "ID", "BR", "VN", "US", "SAC", "NA",
    "RU", "TH", "TW", "BD", "PK", "ME", "CIS", "EUROPE"
]

# ---------- App Setup ----------

app = Flask(__name__)
CORS(app)
cache = TTLCache(maxsize=100, ttl=300)
cached_tokens = defaultdict(dict)
uid_region_cache = {}

# ----------- Helper Functions ------------

def pad(text: bytes) -> bytes:
    padding_length = AES.block_size - (len(text) % AES.block_size)
    return text + bytes([padding_length] * padding_length)

def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_CBC, iv)
    return aes.encrypt(pad(plaintext))

def decode_protobuf(encoded_data: bytes, message_type: message.Message) -> message.Message:
    instance = message_type()
    instance.ParseFromString(encoded_data)
    return instance

async def json_to_proto(json_data: str, proto_message: Message) -> bytes:
    json_format.ParseDict(json.loads(json_data), proto_message)
    return proto_message.SerializeToString()

# ---------- Guest IDS --------------

def get_account_credentials(region: str) -> str:
    r = region.upper()

    if r == "IND":
        return "uid=4569404695&password=RAGHAVLIKESBOT_RAGHAV_2THCG"

    elif r in {"BR", "US", "SAC", "NA"}:
        return "uid=4438226807&password=10007207D207D6FE0D61FD0AF71047F51466E747B6F10928DB13E9F2F25446B7"

    elif r == "VN":
        return "uid=4331389599&password=Sumon523022_BREXX_4KQT9"

    elif r == "SG":
        return "uid=4708244360&password=IDOY-QSKOPFJYU-SG"

    elif r == "ID":
        return "uid=4708244360&password=IDOY-QSKOPFJYU-SG"

    elif r == "TH":
        return "uid=4708244360&password=Sumon523022_BREXX_4KQT9"

    elif r == "TW":
        return "uid=4708244360&password=Sumon523022_BREXX_4KQT9"

    elif r == "BD":
        return "uid=4331389599&password=Sumon523022_BREXX_4KQT9"

    elif r == "PK":
        return "uid=4680926895&password=gamer-07G3N3MND-X64"

    elif r == "ME":
        return "uid=4275417742&password=CCBD38AAC5A1FA5807FD683B6DD0EE6C5F4F7447DD51C6D30062CD425B10E493"

    elif r == "RU":
        return "uid=4331389599&password=Sumon523022_BREXX_4KQT9"

    elif r == "CIS":
        return "uid=4331389599&password=Sumon523022_BREXX_4KQT9"

    elif r == "EUROPE":  #  ME SERVER ID GIVEN
        return "uid=3981271926&password=7D7BB07D77A209812A04A9B5DCA874A8B4927DAE7F67211639DF1B0902A14B6B"

    else:
        # fallback to ucguest.txt
        try:
            with open("star.txt", "r") as f:
                lines = [line.strip() for line in f if line.strip()]
                if not lines:
                    raise ValueError("star.txt is empty")

                uid, password = random.choice(lines).split()
                return f"uid={uid}&password={password}"

        except Exception as e:
            return f"ERROR: {e}"

# -------------- Token Generation --------------

async def get_access_token(account: str):
    url = "https://ffmconnect.live.gop.garenanow.com/oauth/guest/token/grant"
    payload = account + "&response_type=token&client_type=2&client_secret=2ee44819e9b4598845141067b281621874d0d5d7af9d8f7e00c1e54715b7d1e3&client_id=100067"
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/x-www-form-urlencoded"
    }
    async with httpx.AsyncClient() as client:
        resp = await client.post(url, data=payload, headers=headers)
        data = resp.json()
        return data.get("access_token", "0"), data.get("open_id", "0")


async def create_jwt(region: str):
    account = get_account_credentials(region)
    token_val, open_id = await get_access_token(account)

    body = json.dumps({
        "open_id": open_id,
        "open_id_type": "4",
        "login_token": token_val,
        "orign_platform_type": "4"
    })

    proto_bytes = await json_to_proto(body, FreeFire_pb2.LoginReq())
    payload = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, proto_bytes)

    url = "https://loginbp.ggpolarbear.com/MajorLogin"  # ✅ more stable
    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'Expect': "100-continue",
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': RELEASEVERSION
    }

    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(url, data=payload, headers=headers)

        # ✅ SKIP BAD RESPONSES
        if resp.status_code != 200 or resp.headers.get("content-type") != "application/octet-stream":
            print(f"❌ TOKEN FAIL [{region}]: {resp.content}")
            return

        try:
            decoded = decode_protobuf(resp.content, FreeFire_pb2.LoginRes)
            msg = json.loads(json_format.MessageToJson(decoded))
        except Exception as e:
            print(f"❌ PROTO FAIL [{region}]:", e)
            return

        cached_tokens[region] = {
            'token': f"Bearer {msg.get('token','0')}",
            'region': msg.get('lockRegion','0'),
            'server_url': msg.get('serverUrl','0'),
            'expires_at': time.time() + 25200
        }

        print(f"✅ TOKEN OK [{region}]")


async def initialize_tokens():
    await asyncio.gather(*[create_jwt(r) for r in SUPPORTED_REGIONS])

async def refresh_tokens_periodically():
    while True:
        await asyncio.sleep(25200)
        await initialize_tokens()

async def get_token_info(region: str) -> Tuple[str,str,str]:
    info = cached_tokens.get(region)

    if info and time.time() < info['expires_at']:
        return info['token'], info['region'], info['server_url']

    await create_jwt(region)
    info = cached_tokens[region]
    return info['token'], info['region'], info['server_url']

async def GetAccountInformation(uid, unk, region, endpoint):
    payload = await json_to_proto(
        json.dumps({'a': uid, 'b': unk}),
        main_pb2.GetPlayerPersonalShow()
    )

    data_enc = aes_cbc_encrypt(MAIN_KEY, MAIN_IV, payload)
    token, lock, server = await get_token_info(region)

    headers = {
        'User-Agent': USERAGENT,
        'Connection': "Keep-Alive",
        'Accept-Encoding': "gzip",
        'Content-Type': "application/octet-stream",
        'Expect': "100-continue",
        'Authorization': token,
        'X-Unity-Version': "2018.4.11f1",
        'X-GA': "v1 1",
        'ReleaseVersion': RELEASEVERSION
    }

    async with httpx.AsyncClient() as client:
        resp = await client.post(server + endpoint, data=data_enc, headers=headers)

        return json.loads(
            json_format.MessageToJson(
                decode_protobuf(resp.content, AccountPersonalShow_pb2.AccountPersonalShowInfo)
            )
        )

# -------------- Cache Decorator --------------

def cached_endpoint(ttl=300):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*a, **k):
            key = (request.path, tuple(request.args.items()))
            if key in cache:
                return cache[key]

            res = fn(*a, **k)
            cache[key] = res
            return res

        return wrapper
    return decorator

# -------------- Routes Endpoints --------------

@app.route('/accinfo')
@cached_endpoint()
def get_account_info():
    uid = request.args.get('uid')

    if not uid:
        return jsonify({"error": "Please provide UID Else try correct endpoint."}), 400

    # Create event loop safely
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    # 🔁 If UID already cached with region
    if uid in uid_region_cache:
        try:
            data = loop.run_until_complete(
                GetAccountInformation(uid, "7", uid_region_cache[uid], "/GetPlayerPersonalShow")
            )
            return json.dumps(data, indent=2), 200, {'Content-Type': 'application/json'}
        except:
            pass  # fallback to scanning all regions

    # 🔍 Try all regions
    for region in SUPPORTED_REGIONS:
        try:
            data = loop.run_until_complete(
                GetAccountInformation(uid, "7", region, "/GetPlayerPersonalShow")
            )

            # Save detected region
            uid_region_cache[uid] = region

            return json.dumps(data, indent=2), 200, {'Content-Type': 'application/json'}

        except:
            continue

    return jsonify({"error": "UID not found"}), 404


@app.route('/ref-token', methods=['GET', 'POST'])
def refresh_tokens_endpoint():
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(initialize_tokens())

        return jsonify({'message': 'Tokens refreshed'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# === Startup ===

async def startup():
    await initialize_tokens()
    asyncio.create_task(refresh_tokens_periodically())

if __name__ == '__main__':
    asyncio.run(startup())
    app.run(host='0.0.0.0', port=5001, debug=True)
# INFO API SRC BYY 
# POWERED BY : @STAR_GMR
# CHANNEL : @STAR_METHODE
