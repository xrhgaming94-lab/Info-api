from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import binascii
import requests
from flask import Flask, jsonify, request
from data_pb2 import AccountPersonalShowInfo
from google.protobuf.json_format import MessageToDict
import uid_generator_pb2
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

app = Flask(__name__)
jwt_tokens = {}  # Store tokens per region
jwt_locks = {region: threading.Lock() for region in ["IND", "BR", "US", "SAC", "BD", "PK", "VN", "ME", "TH", "ID"]}
jwt_tokens["default"] = None
default_lock = threading.Lock()

# ---------------- JWT HANDLING ----------------
def extract_token_from_response(data, region):
    if not isinstance(data, dict):
        return None

    if "token" in data and data.get("status") in ["live", "success"]:
        return data["token"]

    if data.get("success") is True and "token" in data:
        return data["token"]

    if region == "IND":
        if data.get("status") in ["success", "live"]:
            return data.get("token")

    elif region in ["BR", "US", "SAC", "BD", "PK", "VN", "ME", "TH", "TW", "ID"]:
        return data.get("token")

    return data.get("token")

def get_jwt_token_sync(region):
    """Fetch JWT token synchronously for a region."""
    endpoints = {
        "IND": "https://star-jwt-api1.lovable.app/api/public/token?uid=5523153630&password=STAR_BYSTARGMR_G37WxzYO",
        "BR": "https://star-jwt-api1.lovable.app/api/public/token?uid=4652831470&password=CG28C3MCWVJKQS7L5CPJHYL9SZ6U4MMTOKLHWY1DKXAN1EAKO5PGHBKDQUPAA4LK",
        "US": "https://star-jwt-api1.lovable.app/api/public/token?uid=4652831470&password=CG28C3MCWVJKQS7L5CPJHYL9SZ6U4MMTOKLHWY1DKXAN1EAKO5PGHBKDQUPAA4LK",
        "SAC": "https://star-jwt-api1.lovable.app/api/public/token?uid=4652831470&password=CG28C3MCWVJKQS7L5CPJHYL9SZ6U4MMTOKLHWY1DKXAN1EAKO5PGHBKDQUPAA4LK",
        "BD": "https://star-jwt-api1.lovable.app/api/public/token?uid=5526987100&password=STAR_BYSTARGMR_kIQcaaLn",
        "ID": "https://star-jwt-api1.lovable.app/api/public/token??uid=5523319335&password=STARR_BYSTARGMR_bC1hULKj",
        "PK": "https://star-jwt-api1.lovable.app/api/public/token??uid=5527675687&password=STAR_BYSTARGMR_7ka41Sdn",
        "VN": "https://star-jwt-api1.lovable.app/api/public/token??uid=5523319335&password=STARR_BYSTARGMR_bC1hULKj",
        "ME": "https://star-jwt-api1.lovable.app/api/public/token??uid=5523319335&password=STARR_BYSTARGMR_bC1hULKj",
        "TH": "https://star-jwt-api1.lovable.app/api/public/token??uid=5523319335&password=STARR_BYSTARGMR_bC1hULKj",
        "TW": "https://star-jwt-api1.lovable.app/api/public/token??uid=5523319335&password=STARR_BYSTARGMR_bC1hULKj",
        "default": "https://star-jwt-api1.lovable.app/api/public/token?uid=5523319335&password=STARR_BYSTARGMR_bC1hULKj"
    }
    url = endpoints.get(region, endpoints["default"])
    
    lock = jwt_locks.get(region, default_lock)
    with lock:
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            data = response.json()
            token = extract_token_from_response(data, region)
            if token:
                jwt_tokens[region] = token
                print(f"[JWT] Token for {region} updated: {token[:50]}...")
                return jwt_tokens[region]
            else:
                print(f"[JWT] Failed to extract token from response for {region}")
        except Exception as e:
            print(f"[JWT] Request error for {region}: {e}")
    return None

def ensure_jwt_token_sync(region):
    """Ensure JWT token is available; fetch if missing."""
    if region not in jwt_tokens or not jwt_tokens.get(region):
        print(f"[JWT] Token missing for {region}. Fetching...")
        return get_jwt_token_sync(region)
    return jwt_tokens.get(region)

# ---------------- API ENDPOINTS ----------------
def get_api_endpoint(region):
    endpoints = {
        "IND": "https://client.ind.freefiremobile.com/GetPlayerPersonalShow",
        "BR": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
        "US": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
        "SAC": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
        "BD": "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
        "ID": "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
        "PK": "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
        "VN": "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
        "ME": "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
        "TH": "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
        "TW": "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow",
        "default": "https://clientbp.ggpolarbear.com/GetPlayerPersonalShow"
    }
    return endpoints.get(region, endpoints["default"])

# ---------------- AES ENCRYPTION ----------------
default_key = "Yg&tc%DEuh6%Zc^8"
default_iv = "6oyZDr22E3ychjM%"

def encrypt_aes(hex_data, key, iv):
    key = key.encode()[:16]
    iv = iv.encode()[:16]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padded_data = pad(bytes.fromhex(hex_data), AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return binascii.hexlify(encrypted_data).decode()

# ---------------- API CALL ----------------
def apis(idd, region, encrypted_hex):
    token = ensure_jwt_token_sync(region)
    if not token:
        raise Exception(f"Failed to get JWT token for region {region}")
    
    endpoint = get_api_endpoint(region)
    headers = {
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)',
        'Connection': 'Keep-Alive',
        'Expect': '100-continue',
        'Authorization': f'Bearer {token}',
        'X-Unity-Version': '2018.4.11f1',
        'X-GA': 'v1 1',
        'ReleaseVersion': 'OB54',
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    
    try:
        data = bytes.fromhex(encrypted_hex)
        response = requests.post(endpoint, headers=headers, data=data, timeout=10)
        response.raise_for_status()
        return response.content.hex()
    except requests.exceptions.RequestException as e:
        print(f"[API] Request to {endpoint} for region {region} failed: {e}")
        raise

# ---------------- FLASK ROUTES ----------------
@app.route('/accinfo', methods=['GET'])
def get_player_info():
    try:
        uid = request.args.get('uid')
        region = request.args.get('region', '').upper()
        custom_key = request.args.get('key', default_key)
        custom_iv = request.args.get('iv', default_iv)
        
        if not uid:
            return jsonify({"error": "UID parameter is required"}), 400
        
        # Generate protobuf (same for all regions)
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        protobuf_data = message.SerializeToString()
        hex_data = binascii.hexlify(protobuf_data).decode()
        
        # Encrypt once
        encrypted_hex = encrypt_aes(hex_data, custom_key, custom_iv)
        
        # If region is specified, try only that region
        if region and region in get_api_endpoint(region):
            try:
                api_response = apis(None, region, encrypted_hex)
                if api_response:
                    message = AccountPersonalShowInfo()
                    message.ParseFromString(bytes.fromhex(api_response))
                    result = MessageToDict(message)
                    result['Owners'] = ['𝗦𝗧𝗔𝗥 𝗚𝗔𝗠𝗘𝗥']
                    result['Used_acc_region'] = region
                    return jsonify(result)
            except Exception as e:
                return jsonify({"error": f"Failed for region {region}: {str(e)}"}), 500
        
        # Try all regions in parallel
        all_regions = ["IND", "BR", "US", "SAC", "BD", "PK", "VN", "ME", "TH", "TW", "ID"]
        results = []
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            future_to_region = {
                executor.submit(try_region, region_name, encrypted_hex, uid, custom_key, custom_iv): region_name 
                for region_name in all_regions
            }
            
            for future in as_completed(future_to_region):
                region_name = future_to_region[future]
                try:
                    result = future.result(timeout=15)
                    if result:
                        # Return first successful response
                        return jsonify(result)
                except Exception as e:
                    print(f"[ERROR] Region {region_name} failed: {e}")
                    results.append({"region": region_name, "error": str(e)})
        
        # If no region succeeded
        return jsonify({
            "error": "All regions failed",
            "details": results
        }), 404
        
    except ValueError:
        return jsonify({"error": "Invalid UID format"}), 400
    except Exception as e:
        print(f"[ERROR] Processing request: {e}")
        return jsonify({"error": f"Failure to process the data: {str(e)}"}), 500

def try_region(region, encrypted_hex, uid, custom_key, custom_iv):
    """Try to get player info from a specific region"""
    try:
        # Ensure JWT token for this region
        token = ensure_jwt_token_sync(region)
        if not token:
            return None
        
        endpoint = get_api_endpoint(region)
        headers = {
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)',
            'Connection': 'Keep-Alive',
            'Expect': '100-continue',
            'Authorization': f'Bearer {token}',
            'X-Unity-Version': '2018.4.11f1',
            'X-GA': 'v1 1',
            'ReleaseVersion': 'OB54',
            'Content-Type': 'application/x-www-form-urlencoded',
        }
        
        data = bytes.fromhex(encrypted_hex)
        response = requests.post(endpoint, headers=headers, data=data, timeout=10)
        response.raise_for_status()
        
        api_response = response.content.hex()
        if api_response:
            message = AccountPersonalShowInfo()
            message.ParseFromString(bytes.fromhex(api_response))
            result = MessageToDict(message)
            print(f"[SUCCESS] Found player in region: {region}")
            return result
        
    except Exception as e:
        print(f"[DEBUG] Region {region} failed: {e}")
        return None
    
    return None

@app.route('/favicon.ico')
def favicon():
    return '', 404

# ---------------- MAIN ----------------
if __name__ == "__main__":
    # Pre-fetch tokens for all regions in background
    def preload_tokens():
        regions = ["IND", "BR", "US", "SAC", "BD", "PK", "VN", "ME", "TH", "ID", "default"]
        for region in regions:
            get_jwt_token_sync(region)
    
    threading.Thread(target=preload_tokens, daemon=True).start()
    app.run(host="0.0.0.0", port=5552)