"""Offline test suite for otf_export.py.

Runs entirely against a local mock server: no network access, no Orangetheory account, and nothing
to install. Your real ~/.otf_export folder is never touched.

    python tests/test_otf_export.py        (Windows: py tests\test_otf_export.py)

If pycognito happens to be installed, the SRP login maths is also cross-checked against it.
Exits non-zero on the first failure.
"""
import base64, hashlib, hmac, json, os, secrets, shutil, sys, threading, datetime as dt, tempfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse, parse_qs

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import otf_export as m
m.RETRY_DELAYS = [0, 0]
for var in ("OTF_EMAIL", "OTF_PASSWORD"):
    os.environ.pop(var, None)

# ---------- 1. SRP maths ----------
now = dt.datetime(2026, 11, 4, 9, 5, 7, tzinfo=dt.timezone.utc)
assert m.cognito_timestamp(now) == "Wed Nov 4 09:05:07 UTC 2026", m.cognito_timestamp(now)
try:
    from pycognito import aws_srp as ref
except ImportError:
    ref = None
    print("pycognito not installed: skipping the reference cross-check (the mock server below still verifies SRP)")
user_id = "abc-123-user"
if ref:
  small_a = int.from_bytes(secrets.token_bytes(128), "big")
  pw = "hunter2!"
  salt = secrets.token_hex(16)
  secret_block = base64.b64encode(secrets.token_bytes(64)).decode()
  B = pow(2, 77777, m.BIG_N)
  r = ref.AWSSRP(username="a@b.c", password=pw, pool_id=m.USER_POOL_ID, client_id=m.CLIENT_ID, client=object())
  r.small_a_value = small_a; r.large_a_value = r.calculate_a()
  ref_key = r.get_password_authentication_key(user_id, pw, B, salt)
  mine = m.SrpClient(pw, small_a=small_a)
  assert mine.srp_a == ref.long_to_hex(r.large_a_value)
  now = dt.datetime(2026, 11, 4, 9, 5, 7, tzinfo=dt.timezone.utc)
  claim = mine.password_claim({"USER_ID_FOR_SRP": user_id, "SRP_B": f"{B:x}", "SALT": salt, "SECRET_BLOCK": secret_block}, now=now)
  ts = ref.AWSSRP.get_cognito_formatted_timestamp(now)
  assert claim["TIMESTAMP"] == ts == "Wed Nov 4 09:05:07 UTC 2026", claim["TIMESTAMP"]
  msg = m.USER_POOL_ID.split("_")[1].encode() + user_id.encode() + base64.b64decode(secret_block) + ts.encode()
  assert claim["PASSWORD_CLAIM_SIGNATURE"] == base64.b64encode(hmac.new(ref_key, msg, hashlib.sha256).digest()).decode()
  print("SRP matches pycognito: OK")

# ---------- 2. mock server doing real server-side SRP ----------
EMAIL, PASSWORD, POOL = "me@example.com", "s3cret-pass", m.USER_POOL_ID.split("_")[1]
SALT = secrets.token_hex(16)
x = int(m._hex_hash(m._pad_hex(SALT) + m._sha256_hex(f"{POOL}{user_id}:{PASSWORD}".encode())), 16)
V = pow(m.G, x, m.BIG_N)
state = {}

def jwt(claims):
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{enc({'alg':'none'})}.{enc(claims)}.sig"

START = "2026-11-10T13:00:00Z"
BOOKINGS = {"items": [
    {"id": "bk1", "canceled": False, "class": {"name": "Orange 60", "starts_at_local": "2026-11-10T08:00:00",
     "coach": {"first_name": "Zoë Łukasz 🏃"}, "studio": {"name": "Ağrı Šibenik"}},
     "workout": {"id": "ps-1", "calories_burned": 612, "splat_points": 14, "step_count": 5000, "active_time_seconds": 3480}},
    {"id": "bk2", "canceled": False, "class": {"name": "Tread 50", "starts_at_local": "2026-11-12T18:00:00",
     "coach": {"first_name": "Lee"}, "studio": {"name": "Downtown"}},
     "workout": {"id": "ps-2", "calories_burned": 500, "splat_points": 9, "step_count": 7000, "active_time_seconds": 3000}},
    {"id": "bk3", "canceled": True, "class": {"name": "Cancelled"}, "workout": None},
]}
ZONES = {"gray": {"startBpm": 0, "endBpm": 110}, "blue": {"startBpm": 111, "endBpm": 130},
         "green": {"startBpm": 131, "endBpm": 150}, "orange": {"startBpm": 151, "endBpm": 170},
         "red": {"startBpm": 171, "endBpm": 190}}
def telemetry(n):
    pts = []
    for i in range(n):
        t = i * 3600 // n
        p = {"relativeTimestamp": t, "hr": 100 + (i * 7) % 85, "aggSplats": i // 10, "aggCalories": i * 4}
        if 600 < t < 1800:
            # real telemetry is SI: m/s and metres (4.02 m/s = 9.0 mph), whatever the display units
            p["treadData"] = {"treadSpeed": 2.24 + 0.447 * (i % 5), "treadIncline": 1.0, "aggTreadDistance": t}
        if 2000 < t < 2400:
            # rowSpeed m/s, rowPps watts, rowPace seconds per 500 m
            p["rowData"] = {"rowSpeed": 4.6, "rowPps": 200, "rowSpm": 24, "aggRowDistance": t - 2000, "rowPace": 109}
        pts.append(p)
    return {"memberUuid": "member-1", "classHistoryUuid": "ps-1", "classStartTime": START, "maxHr": 190,
            "zones": ZONES, "windowSize": 5, "telemetry": pts}
SUMMARY = {"id": "ps-1", "class": {"starts_at_local": "2026-11-10T08:00:00", "name": "Orange 60"}, "details": {"calories_burned": 612, "splat_points": 14,
    "heart_rate": {"avg_hr": 145, "peak_hr": 184}, "zone_time_minutes": {"gray": 2, "blue": 10, "green": 20, "orange": 12, "red": 2},
    "equipment_data": {"treadmill": {"total_distance": {"display_value": "2.1", "display_unit": "mi"},
        "avg_speed": {"display_value": "5.8", "display_unit": "mph"}, "max_speed": {"display_value": "9.0", "display_unit": "mph"}}}}}
seen = []

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def send(self, code, obj):
        b = json.dumps(obj).encode(); self.send_response(code)
        self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        target = self.headers["X-Amz-Target"].split(".")[-1]
        if target == "InitiateAuth":
            p = body["AuthParameters"]
            if p["USERNAME"] != EMAIL: return self.send(400, {"__type": "NotAuthorizedException", "message": "Incorrect username or password."})
            A = int(p["SRP_A"], 16); b = secrets.randbelow(m.BIG_N)
            Bv = (m.K * V + pow(m.G, b, m.BIG_N)) % m.BIG_N
            sb = base64.b64encode(secrets.token_bytes(64)).decode()
            state.update(A=A, b=b, B=Bv, sb=sb)
            return self.send(200, {"ChallengeName": "PASSWORD_VERIFIER", "ChallengeParameters": {
                "USER_ID_FOR_SRP": user_id, "SALT": SALT, "SRP_B": f"{Bv:x}", "SECRET_BLOCK": sb, "USERNAME": user_id}})
        if target == "RespondToAuthChallenge":
            c = body["ChallengeResponses"]
            A, b, Bv = state["A"], state["b"], state["B"]
            u = int(m._hex_hash(m._pad_hex(A) + m._pad_hex(Bv)), 16)
            S = pow(A * pow(V, u, m.BIG_N), b, m.BIG_N)
            key = m._hkdf(bytes.fromhex(m._pad_hex(S)), bytes.fromhex(m._pad_hex(f"{u:x}")))
            msg = POOL.encode() + user_id.encode() + base64.b64decode(state["sb"]) + c["TIMESTAMP"].encode()
            exp = base64.b64encode(hmac.new(key, msg, hashlib.sha256).digest()).decode()
            if c["PASSWORD_CLAIM_SIGNATURE"] != exp:
                return self.send(400, {"__type": "NotAuthorizedException", "message": "Incorrect username or password."})
            exp_t = int(dt.datetime.now().timestamp()) + 3600
            return self.send(200, {"AuthenticationResult": {"IdToken": jwt({"cognito:username": "member-1", "exp": exp_t}),
                                                           "AccessToken": "x", "RefreshToken": "y"}})
    def do_GET(self):
        u = urlparse(self.path); q = parse_qs(u.query); seen.append(self.path)
        if not self.headers.get("Authorization", "").startswith("Bearer "): return self.send(401, {})
        if u.path == "/io/v1/bookings/me":
            assert q["include_canceled"] == ["false"] and "starts_after" in q
            return self.send(200, BOOKINGS)
        if u.path.startswith("/io/v1/performance-summaries/"):
            return self.send(200, SUMMARY)
        if u.path == "/yuzu/v1/performance/summary":
            if q["classHistoryUuid"] == ["ps-2"]:
                return self.send(200, {"classHistoryUuid": "ps-2", "telemetry": []})
            return self.send(200, telemetry(int(q["maxDataPoints"][0])))
        self.send(404, {})

srv = ThreadingHTTPServer(("127.0.0.1", 0), H); port = srv.server_port
threading.Thread(target=srv.serve_forever, daemon=True).start()
base = f"http://127.0.0.1:{port}"
m.COGNITO_URL = base + "/"; m.API_IO = base + "/io"; m.API_TELEMETRY = base + "/yuzu"
home = tempfile.mkdtemp(); m.STATE_DIR = m.Path(home); m.TOKEN_FILE = m.STATE_DIR / "token.json"; m.LAST_LIST_FILE = m.STATE_DIR / "last_list.json"

# wrong password -> clean error
os.environ["OTF_EMAIL"] = EMAIL; os.environ["OTF_PASSWORD"] = "wrong"
assert m.main(["list"]) == 1 and not m.TOKEN_FILE.exists()
print("Wrong password rejected by mock SRP server: OK")

os.environ["OTF_PASSWORD"] = PASSWORD
assert m.main(["list"]) == 0 and m.TOKEN_FILE.exists()
rows = json.loads(m.LAST_LIST_FILE.read_text())
assert [r["id"] for r in rows] == ["ps-2", "ps-1"], rows   # newest first, cancelled dropped

del os.environ["OTF_PASSWORD"]  # cached token must be reused now
out = os.path.join(home, "exp")
assert m.main(["export", "2", "1", "--points", "300", "--out", out]) == 0
files = sorted(os.listdir(out)); print(files)
csvf = [f for f in files if f.startswith("2026-11-10") and f.endswith(".csv")][0]
lines = open(os.path.join(out, csvf), encoding="utf-8").read().splitlines()
assert len(lines) == 301 and lines[0] == (
    "seconds,time,hr,hr_zone,tread_speed_mps,tread_incline_pct,tread_distance_m,"
    "row_speed_mps,row_spm,row_watts,row_pace_s_per_500m,row_distance_m,calories,splats"), lines[:2]
print(lines[0]); print(lines[60]); print(lines[170])
assert any("maxDataPoints=300" in s for s in seen)
html_f = os.path.join(out, csvf.replace(".csv", ".html"))
html_s = open(html_f, encoding="utf-8").read()
# chart speed is converted to the summary's display unit (mph): ticks go past the m/s maximum (~4)
assert "Treadmill speed (mph, right)" in html_s and 'class="ax sp">7<' in html_s, "speed axis not in mph"
# the mock class has a rowing block: it gets its own line and legend entry
assert 'class="rowl"' in html_s and "Rower speed (mph, right)" in html_s, "rower not charted"
assert "Rower power (watts, left) and heart rate (bpm, right)" in html_s and 'class="pwr"' in html_s \
    and "200 W</text>" in html_s and 'class="hrl thin"' in html_s, "power chart (with HR) missing"
# splat goal (14 >= 12), zone bar, and one table row per treadmill / rower block
assert "<b>14 / 12</b> splat points (goal reached)" in html_s and 'class="zbar"' in html_s, "zones section missing"
assert "<h2>Blocks</h2>" in html_s and "1. Treadmill" in html_s and "2. Rower" in html_s, "blocks table missing"
assert "/500m</td>" in html_s and " mph</td>" in html_s, "block effort columns missing"
print("HTML at", html_f)
print("BASIC TESTS PASSED")

# combined export
out2 = os.path.join(home, "exp2")
assert m.main(["export", "all", "--days", "30", "--format", "csv", "--out", out2]) == 0
import csv as _c
s = list(_c.DictReader(open(os.path.join(out2, "classes_summary.csv"), encoding="utf-8")))
assert [r["class"] for r in s] == ["Orange 60", "Tread 50"], s
assert s[0]["avg_hr"] == "145" and s[0]["tread_total_distance"] == "2.1" and s[0]["tread_total_distance_unit"] == "mi" and s[0]["orange_min"] == "12"
t = list(_c.DictReader(open(os.path.join(out2, "all_telemetry.csv"), encoding="utf-8")))
assert len(t) == 600 and t[0]["class"] == "Orange 60"
print(sorted(os.listdir(out2))); print(open(os.path.join(out2, "classes_summary.csv"), encoding="utf-8").read())
assert m.main(["export", "1", "--out", os.path.join(home, "exp3")]) == 0
assert "classes_summary.csv" not in os.listdir(os.path.join(home, "exp3"))
print("COMBINED TESTS PASSED")

# ---- full-history features ----
BOOKINGS["items"].append(dict(BOOKINGS["items"][0], id="bk1-dup"))       # rebooked duplicate of ps-1
BOOKINGS["items"].append({"id": "bk4", "canceled": False, "class": {"name": "Strength 50", "starts_at_local": "2023-03-15T07:00:00"},
                          "workout": {"id": "ps-bad"}})
_orig_get = H.do_GET
def do_GET(self):
    q = parse_qs(urlparse(self.path).query)
    if q.get("classHistoryUuid") == ["ps-bad"]:
        return self.send(500, {"error": "boom"})
    if urlparse(self.path).path == "/io/v1/bookings/me":
        assert q["starts_after"] == ["2023-03-01T00:00:00Z"], q
    return _orig_get(self)
H.do_GET = do_GET

# expired cached token + creds in env -> must transparently re-login
m.TOKEN_FILE.write_text(json.dumps({"id_token": jwt({"cognito:username": "member-1", "exp": 1})}))
os.environ["OTF_PASSWORD"] = PASSWORD
out4 = os.path.join(home, "exp4")
rc = m.main(["export", "all", "--since", "2023-03-01", "--points", "150", "--format", "csv", "--out", out4])
assert rc == 0
rows = json.loads(m.LAST_LIST_FILE.read_text())
assert [r["id"] for r in rows] == ["ps-2", "ps-1", "ps-bad"], [r["id"] for r in rows]   # deduped, oldest last
s = list(_c.DictReader(open(os.path.join(out4, "classes_summary.csv"), encoding="utf-8")))
assert len(s) == 2, len(s)
assert m.main(["list", "--since", "2023-3-1"]) == 1   # bad date -> clean error
print("FULL HISTORY TESTS PASSED")

# ---- resume after network failure ----
calls = {"tel": 0, "drop": True}
_g2 = H.do_GET
def do_GET3(self):
    if "/yuzu/" in self.path:
        calls["tel"] += 1
        if calls["drop"] and "ps-1" in self.path:
            self.connection.close(); return          # simulate dropped connection (every attempt)
    return _g2(self)
H.do_GET = do_GET3
out5 = os.path.join(home, "exp5")
args5 = ["export", "all", "--since", "2023-03-01", "--points", "150", "--format", "csv", "--out", out5]
assert m.main(args5) == 0
s = list(_c.DictReader(open(os.path.join(out5, "classes_summary.csv"), encoding="utf-8")))
assert [r["class_id"] for r in s] == ["ps-2"], s           # ps-1 failed after retries, ps-bad failed
# network back: re-run should reuse ps-2 and only fetch ps-1 + ps-bad
calls.update(tel=0, drop=False)
assert m.main(args5) == 0
s = list(_c.DictReader(open(os.path.join(out5, "classes_summary.csv"), encoding="utf-8")))
assert sorted(r["class_id"] for r in s) == ["ps-1", "ps-2"], s
assert calls["tel"] == 1 + 3, calls   # ps-1 once, ps-bad 3 attempts (500s); ps-2 reused from cache
# transient drop that recovers on retry
calls.update(tel=0)
flaky = {"n": 0}
def do_GET4(self):
    if "/yuzu/" in self.path and "ps-1" in self.path:
        flaky["n"] += 1
        if flaky["n"] == 1:
            self.connection.close(); return
    return _g2(self)
H.do_GET = do_GET4
assert m.main(["export", "2", "--refresh", "--format", "csv", "--out", os.path.join(home, "exp6")]) == 0
assert flaky["n"] == 2
# a raw performance-summary ID that isn't in the last list: name and local start come from the summary
out8 = os.path.join(home, "exp8")
assert m.main(["export", "ps-not-listed", "--format", "csv,html", "--out", out8]) == 0
assert "2026-11-10_0800_orange-60.html" in os.listdir(out8), os.listdir(out8)
print("RESUME TESTS PASSED")

# ---- benchmarks ----
BENCH = {"Dto": [
  {"ChallengeCategoryId": 19, "ChallengeSubCategoryId": 0, "EquipmentId": 2, "EquipmentName": "Treadmill",
   "ChallengeName": "1 Mile", "BestRecord": 452.0, "LastRecord": 470.0, "PreviousRecord": 480.0, "Unit": "Seconds",
   "MetricEntry": {"Title": "Time", "EntryType": "Time"},
   "ChallengeHistories": [{"StudioName": "Downtown", "StartDate": "2023-04-01T00:00:00",
       "BenchmarkHistories": [{"ClassTime": "2023-04-02T08:00:00", "Result": 480.0, "ClassName": "Orange 60", "CoachName": "Sam", "StudioName": "Downtown", "WeightLBS": 0},
                              {"ClassTime": "2024-05-02T08:00:00", "Result": 452.0, "ClassName": "Orange 60", "CoachName": "Lee", "StudioName": "Downtown"}]},
     {"StudioName": "Downtown", "BenchmarkHistories": [{"ClassTime": "2025-06-01T08:00:00", "Result": 470.0}]}]},
  {"ChallengeCategoryId": 17, "EquipmentId": 4, "ChallengeName": "2000m Row", "BestRecord": None, "LastRecord": None,
   "Unit": "Seconds", "ChallengeHistories": []},
]}
_g5 = H.do_GET
def do_GET5(self):
    pth = urlparse(self.path).path
    if pth == "/co/challenges/v3/member/member-1/benchmarks":
        assert parse_qs(urlparse(self.path).query)["challengeTypeId"] == ["0"]
        return self.send(200, BENCH)
    if pth == "/co/challenges/v3.1/member/member-1":
        return self.send(200, {"Dto": {"Benchmarks": []}})
    return _g5(self)
H.do_GET = do_GET5
m.API_CO = base + "/co"
out7 = os.path.join(home, "bench")
assert m.main(["benchmarks", "--out", out7]) == 0
s = list(_c.DictReader(open(os.path.join(out7, "benchmarks_summary.csv"), encoding="utf-8")))
h = list(_c.DictReader(open(os.path.join(out7, "benchmarks_history.csv"), encoding="utf-8")))
assert len(s) == 2 and len(h) == 3, (s, h)
mile = [r for r in s if r["benchmark"] == "1 Mile"][0]
assert mile["best"] == "452.0" and mile["attempts"] == "3" and mile["last_attempt"].startswith("2025-06-01")
assert h[0]["seconds"] == "" and mile["best_seconds"] == ""  # mock uses floats, not mm:ss
assert [r["date"][:4] for r in h] == ["2023", "2024", "2025"] and h[2]["studio"] == "Downtown"
assert [r for r in s if r["benchmark"] == "2000m Row"][0]["equipment"] == "Rower"
print("BENCHMARK TESTS PASSED")

srv.shutdown()
shutil.rmtree(home, ignore_errors=True)
print("\nALL TESTS PASSED")
