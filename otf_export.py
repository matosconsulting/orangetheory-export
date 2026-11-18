#!/usr/bin/env python3
"""otf_export - list your Orangetheory classes and export per-class performance data.

Standard library only, so it runs anywhere Python 3.9+ runs (including Termux on Android).

Unofficial; not affiliated with or endorsed by Orangetheory Fitness. Uses your own account to access
your own data. Endpoint and authentication details were learned from the otf-api project by Jessica
Smith (https://github.com/NodeJSmith/otf-api, MIT licence).

Usage:
  python otf_export.py list [--days 60]
  python otf_export.py export 1 3 5          # numbers from the most recent `list`
  python otf_export.py export latest --points 600
  python otf_export.py export all --days 30

Credentials come from OTF_EMAIL / OTF_PASSWORD, or you are prompted. Only the short-lived
ID token is cached (in ~/.otf_export/), never your password.
"""

from __future__ import annotations

import argparse
import base64
import csv
import datetime as dt
import getpass
import hashlib
import hmac
import http.client
import html
import json
import os
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

# --------------------------------------------------------------------------------------
# Constants (as published by the otf-api project)
# --------------------------------------------------------------------------------------
REGION = "us-east-1"
USER_POOL_ID = "us-east-1_dYDxUeyL1"
CLIENT_ID = "1457d19r0pcjgmp5agooi0rb1b"
COGNITO_URL = f"https://cognito-idp.{REGION}.amazonaws.com/"

API_IO = "https://api.orangetheory.io"
API_CO = "https://api.orangetheory.co"
API_TELEMETRY = "https://api.yuzu.orangetheory.com"
USER_AGENT = "okhttp/4.12.0"

STATE_DIR = Path(os.environ.get("OTF_EXPORT_HOME", Path.home() / ".otf_export"))
TOKEN_FILE = STATE_DIR / "token.json"
LAST_LIST_FILE = STATE_DIR / "last_list.json"


class OtfError(Exception):
    pass


# Waits (seconds) between attempts when the network drops or the server hiccups (HTTP 429/5xx).
RETRY_DELAYS = [2, 5, 15, 30, 60]
TRANSIENT_ERRORS = (urllib.error.URLError, http.client.HTTPException, ConnectionError, TimeoutError, OSError)


def _open_with_retry(req: urllib.request.Request, timeout: int) -> bytes:
    """urlopen + read, retrying dropped connections and 429/5xx with backoff. HTTPError 4xx is raised as-is."""
    for attempt, delay in enumerate([0] + RETRY_DELAYS):
        if delay:
            print(f"    network problem, retrying in {delay}s (attempt {attempt + 1}/{len(RETRY_DELAYS) + 1})...",
                  file=sys.stderr)
            time.sleep(delay)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.read()
        except urllib.error.HTTPError as e:
            if e.code != 429 and e.code < 500:
                raise
            last: Exception = e
        except TRANSIENT_ERRORS as e:
            last = e
    if isinstance(last, urllib.error.HTTPError):
        raise last
    raise OtfError(f"network error after {len(RETRY_DELAYS) + 1} attempts: {last}")


# --------------------------------------------------------------------------------------
# Cognito SRP
#
# Adapted from pycognito's aws_srp.py (https://github.com/pvizeli/pycognito), which derives
# from warrant (https://github.com/capless/warrant). Both are licensed under the Apache License
# 2.0; see THIRD_PARTY_NOTICES.md. Changes: condensed into a single class, no boto3 dependency,
# HTTP calls made directly with urllib, and the device-SRP flow removed.
# --------------------------------------------------------------------------------------
N_HEX = (
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
    "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
    "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
    "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"
)
G_HEX = "2"
BIG_N = int(N_HEX, 16)
G = int(G_HEX, 16)
WEEKDAYS = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().rjust(64, "0")


def _hex_hash(hex_string: str) -> str:
    return _sha256_hex(bytes.fromhex(hex_string))


def _pad_hex(value: int | str) -> str:
    h = value if isinstance(value, str) else f"{value:x}"
    if len(h) % 2 == 1:
        return "0" + h
    if h[0] in "89ABCDEFabcdef":
        return "00" + h
    return h


K = int(_hex_hash("00" + N_HEX + "0" + G_HEX), 16)


def _hkdf(ikm: bytes, salt: bytes) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    return hmac.new(prk, b"Caldera Derived Key\x01", hashlib.sha256).digest()[:16]


def cognito_timestamp(now: dt.datetime) -> str:
    return (
        f"{WEEKDAYS[now.weekday()]} {MONTHS[now.month - 1]} {now.day:d} "
        f"{now.hour:02d}:{now.minute:02d}:{now.second:02d} UTC {now.year:d}"
    )


class SrpClient:
    def __init__(self, password: str, pool_id: str = USER_POOL_ID, small_a: int | None = None):
        self.password = password
        self.pool_name = pool_id.split("_", 1)[1]
        self.small_a = small_a if small_a is not None else int.from_bytes(secrets.token_bytes(128), "big") % BIG_N
        self.large_a = pow(G, self.small_a, BIG_N)
        if self.large_a % BIG_N == 0:
            raise OtfError("Safety check for A failed")

    @property
    def srp_a(self) -> str:
        return f"{self.large_a:x}"

    def password_claim(self, params: dict[str, str], now: dt.datetime | None = None) -> dict[str, str]:
        user_id = params["USER_ID_FOR_SRP"]
        big_b = int(params["SRP_B"], 16)
        salt_hex = params["SALT"]
        secret_block = params["SECRET_BLOCK"]

        u = int(_hex_hash(_pad_hex(self.large_a) + _pad_hex(big_b)), 16)
        if u == 0:
            raise OtfError("SRP U value cannot be zero")
        up_hash = _sha256_hex(f"{self.pool_name}{user_id}:{self.password}".encode())
        x = int(_hex_hash(_pad_hex(salt_hex) + up_hash), 16)
        s = pow(big_b - K * pow(G, x, BIG_N), self.small_a + u * x, BIG_N)
        key = _hkdf(bytes.fromhex(_pad_hex(s)), bytes.fromhex(_pad_hex(f"{u:x}")))

        timestamp = cognito_timestamp(now or dt.datetime.now(dt.timezone.utc))
        msg = (
            self.pool_name.encode()
            + user_id.encode()
            + base64.standard_b64decode(secret_block)
            + timestamp.encode()
        )
        sig = base64.standard_b64encode(hmac.new(key, msg, hashlib.sha256).digest()).decode()
        return {
            "TIMESTAMP": timestamp,
            "USERNAME": params.get("USERNAME", user_id),
            "PASSWORD_CLAIM_SECRET_BLOCK": secret_block,
            "PASSWORD_CLAIM_SIGNATURE": sig,
        }


def _cognito_call(target: str, body: dict[str, Any]) -> dict[str, Any]:
    req = urllib.request.Request(
        COGNITO_URL,
        data=json.dumps(body).encode(),
        method="POST",
        headers={
            "Content-Type": "application/x-amz-json-1.1",
            "X-Amz-Target": f"AWSCognitoIdentityProviderService.{target}",
        },
    )
    try:
        return json.loads(_open_with_retry(req, timeout=30))
    except urllib.error.HTTPError as e:
        try:
            err = json.loads(e.read())
            msg = f"{err.get('__type', e.code)}: {err.get('message', '')}"
        except Exception:
            msg = str(e)
        raise OtfError(f"Cognito {target} failed - {msg}") from None


def cognito_login(email: str, password: str) -> dict[str, Any]:
    srp = SrpClient(password)
    init = _cognito_call(
        "InitiateAuth",
        {
            "AuthFlow": "USER_SRP_AUTH",
            "ClientId": CLIENT_ID,
            "AuthParameters": {"USERNAME": email, "SRP_A": srp.srp_a},
        },
    )
    if init.get("ChallengeName") != "PASSWORD_VERIFIER":
        raise OtfError(f"Unexpected Cognito challenge: {init.get('ChallengeName')}")
    params = dict(init["ChallengeParameters"])
    params.setdefault("USERNAME", email)
    resp = _cognito_call(
        "RespondToAuthChallenge",
        {
            "ClientId": CLIENT_ID,
            "ChallengeName": "PASSWORD_VERIFIER",
            "ChallengeResponses": srp.password_claim(params),
        },
    )
    if "AuthenticationResult" not in resp:
        raise OtfError(f"Login needs an unsupported step: {resp.get('ChallengeName')}")
    return resp["AuthenticationResult"]


def _jwt_claims(token: str) -> dict[str, Any]:
    payload = token.split(".")[1]
    payload += "=" * (-len(payload) % 4)
    return json.loads(base64.urlsafe_b64decode(payload))


# --------------------------------------------------------------------------------------
# Session / HTTP
# --------------------------------------------------------------------------------------
class Otf:
    def __init__(self, debug_dir: Path | None = None):
        self.debug_dir = debug_dir
        self._creds: tuple[str, str] | None = None
        self.id_token = self._load_or_login()
        claims = _jwt_claims(self.id_token)
        self.member_uuid = claims.get("cognito:username")

    def _load_or_login(self, force: bool = False) -> str:
        if not force:
            try:
                cached = json.loads(TOKEN_FILE.read_text(encoding="utf-8"))
                if _jwt_claims(cached["id_token"])["exp"] > dt.datetime.now().timestamp() + 300:
                    return cached["id_token"]
            except Exception:
                pass

        if self._creds is None:
            email = os.environ.get("OTF_EMAIL") or input("Orangetheory email: ").strip()
            password = os.environ.get("OTF_PASSWORD") or getpass.getpass("Orangetheory password: ")
            self._creds = (email, password)  # kept in memory only, for re-login during long exports
        email, password = self._creds
        print("Logging in...", file=sys.stderr)
        result = cognito_login(email, password)
        token = result["IdToken"]
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        TOKEN_FILE.write_text(json.dumps({"id_token": token}), encoding="utf-8")
        try:
            TOKEN_FILE.chmod(0o600)
        except OSError:
            pass
        return token

    def get(self, base: str, path: str, params: dict[str, Any] | None = None, _retry: bool = True) -> Any:
        # ID tokens last ~1 hour; long exports re-login before it runs out.
        if _jwt_claims(self.id_token)["exp"] < dt.datetime.now().timestamp() + 60:
            self.id_token = self._load_or_login(force=True)
        url = base + path
        if params:
            url += "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {self.id_token}",
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": USER_AGENT,
            },
        )
        try:
            data = json.loads(_open_with_retry(req, timeout=60) or b"null")
        except urllib.error.HTTPError as e:
            body = e.read()[:500].decode(errors="replace")
            if e.code == 401 and _retry:
                self.id_token = self._load_or_login(force=True)
                return self.get(base, path, params, _retry=False)
            if e.code in (401, 403):
                TOKEN_FILE.unlink(missing_ok=True)
                raise OtfError(f"{e.code} from {url} - token cleared, run again to log in. {body}") from None
            raise OtfError(f"HTTP {e.code} from {url}: {body}") from None
        if self.debug_dir:
            self.debug_dir.mkdir(parents=True, exist_ok=True)
            name = (path.strip("/").replace("/", "_") or "root")[:80]
            (self.debug_dir / f"{name}.json").write_text(json.dumps(data, indent=2), encoding="utf-8")
        return data

    # ---- endpoints --------------------------------------------------------------------
    def bookings(self, start: dt.datetime) -> list[dict[str, Any]]:
        now = dt.datetime.now(dt.timezone.utc)
        data = self.get(
            API_IO,
            "/v1/bookings/me",
            {
                "starts_after": start.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "ends_before": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
                "include_canceled": "false",
                "expand": "false",
            },
        )
        return data.get("items", []) if isinstance(data, dict) else data

    def performance_summary(self, summary_id: str) -> dict[str, Any]:
        return self.get(API_IO, f"/v1/performance-summaries/{urllib.parse.quote(summary_id)}")

    def benchmarks(self) -> list[dict[str, Any]]:
        """All benchmarks (1-mile tread, 2k row, DriTri, ...) with best/last results and full history.

        Category/equipment/sub-category 0 means "all", as used by the otf-api project.
        """
        data = self.get(
            API_CO,
            f"/challenges/v3/member/{self.member_uuid}/benchmarks",
            {"equipmentId": 0, "challengeTypeId": 0, "challengeSubTypeId": 0},
        )
        return (data or {}).get("Dto") or []

    def challenge_tracker(self) -> dict[str, Any]:
        """Which programs/challenges/benchmarks you took part in, by year."""
        return (self.get(API_CO, f"/challenges/v3.1/member/{self.member_uuid}") or {}).get("Dto") or {}

    def telemetry(self, summary_id: str, points: int) -> dict[str, Any]:
        return self.get(
            API_TELEMETRY,
            "/v1/performance/summary",
            {"classHistoryUuid": summary_id, "maxDataPoints": points},
        )


# --------------------------------------------------------------------------------------
# Data shaping
# --------------------------------------------------------------------------------------
def class_rows(bookings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Flatten bookings that have a recorded workout, newest first."""
    rows = []
    seen: set[str] = set()
    for b in bookings:
        workout = b.get("workout") or {}
        if not workout.get("id") or b.get("canceled") or workout["id"] in seen:
            continue
        seen.add(workout["id"])
        cls = b.get("class") or {}
        coach = cls.get("coach") or {}
        studio = cls.get("studio") or {}
        rows.append(
            {
                "id": workout["id"],
                "starts_at": cls.get("starts_at_local") or cls.get("starts_at") or "",
                "name": cls.get("name") or "",
                "coach": coach.get("first_name", "") if isinstance(coach, dict) else str(coach),
                "studio": studio.get("name") or "",
                "calories": workout.get("calories_burned"),
                "splats": workout.get("splat_points"),
                "steps": workout.get("step_count"),
                "active_min": round(workout["active_time_seconds"] / 60) if workout.get("active_time_seconds") else None,
            }
        )
    rows.sort(key=lambda r: r["starts_at"], reverse=True)
    for i, r in enumerate(rows, 1):
        r["n"] = i
    return rows


def _fmt(v: Any) -> str:
    return "" if v is None else str(v)


def _fmt_num(v: Any) -> str:
    """Like _fmt, but floats are shown with at most 2 decimals (3498.0 -> 3498, 2.78416512 -> 2.78)."""
    if isinstance(v, float):
        return f"{v:.2f}".rstrip("0").rstrip(".")
    return _fmt(v)


def print_table(rows: list[dict[str, Any]]) -> None:
    cols = [("n", "#"), ("starts_at", "When"), ("name", "Class"), ("coach", "Coach"),
            ("studio", "Studio"), ("calories", "Cal"), ("splats", "Splat"), ("active_min", "Min")]
    data = [[_fmt(r[k])[:16] if k == "starts_at" else _fmt(r[k]) for k, _ in cols] for r in rows]
    print_cols([h for _, h in cols], data)


def print_cols(headers: list[str], data: list[list[str]]) -> None:
    """Print an aligned text table. Lines are right-stripped so a row that exactly fills the
    terminal width doesn't wrap into a blank line (seen in Windows terminals)."""
    widths = [max([len(h)] + [len(d[i]) for d in data]) for i, h in enumerate(headers)]
    print("  ".join(h.ljust(w) for h, w in zip(headers, widths)).rstrip())
    print("  ".join("-" * w for w in widths))
    for d in data:
        print("  ".join(c.ljust(w) for c, w in zip(d, widths)).rstrip())


# Telemetry comes in SI units whatever the account's display units (checked against the
# performance summary): speeds in m/s, distances in metres, rower pace in seconds per 500 m and
# rower "pps" in watts. The column names say so.
TELEMETRY_COLUMNS = [
    "seconds", "time", "hr", "hr_zone", "tread_speed_mps", "tread_incline_pct", "tread_distance_m",
    "row_speed_mps", "row_spm", "row_watts", "row_pace_s_per_500m", "row_distance_m", "calories", "splats",
]
SPEED_FROM_MPS = {"mph": 2.236936, "km/h": 3.6, "kph": 3.6}


def hr_zone(hr: int | None, zones: dict[str, Any] | None) -> str:
    if hr is None or not zones:
        return ""
    for name in ("red", "orange", "green", "blue", "gray"):
        z = zones.get(name) or {}
        if z.get("startBpm") is not None and hr >= z["startBpm"]:
            return name
    return "gray"


def telemetry_rows(tel: dict[str, Any]) -> list[dict[str, Any]]:
    start = None
    if tel.get("classStartTime"):
        try:
            start = dt.datetime.fromisoformat(tel["classStartTime"].replace("Z", "+00:00"))
        except ValueError:
            start = None
    zones = tel.get("zones")
    out = []
    for p in tel.get("telemetry") or []:
        tread = p.get("treadData") or {}
        row = p.get("rowData") or {}
        secs = p.get("relativeTimestamp")
        out.append(
            {
                "seconds": secs,
                "time": (start + dt.timedelta(seconds=secs)).isoformat() if start and secs is not None else "",
                "hr": p.get("hr"),
                "hr_zone": hr_zone(p.get("hr"), zones),
                "tread_speed_mps": tread.get("treadSpeed"),
                "tread_incline_pct": tread.get("treadIncline"),
                "tread_distance_m": tread.get("aggTreadDistance"),
                "row_speed_mps": row.get("rowSpeed"),
                "row_spm": row.get("rowSpm"),
                "row_watts": row.get("rowPps"),
                "row_pace_s_per_500m": row.get("rowPace"),
                "row_distance_m": row.get("aggRowDistance"),
                "calories": p.get("aggCalories"),
                "splats": p.get("aggSplats"),
            }
        )
    return out


# --------------------------------------------------------------------------------------
# HTML chart (self-contained inline SVG - works offline in the phone's browser)
# --------------------------------------------------------------------------------------
ZONE_COLORS = {"gray": "#9aa0a6", "blue": "#4a90d9", "green": "#3fae5a", "orange": "#f28c28", "red": "#e5484d"}


def _polyline(points: list[tuple[float, float]]) -> str:
    return " ".join(f"{x:.1f},{y:.1f}" for x, y in points)


def _power_chart(rows: list[dict[str, Any]], x: Any, W: int, L: int, R: int, hr_lo: float, hr_hi: float) -> str:
    """Small chart of rower power (W, left axis) with heart rate (bpm, right axis) under the main
    one, on the same time axis. Empty if no rowing."""
    pts = [(r["seconds"], r["row_watts"]) for r in rows]
    watts = [w for s, w in pts if s is not None and w is not None]
    if not watts:
        return ""
    H, T, B = 170, 28, 34
    ph = H - T - B
    w_hi = max(watts) * 1.15
    step = next((s for s in (25, 50, 100, 200, 250, 500) if w_hi / s <= 4), 1000)

    def y(v: float) -> float:
        return T + ph * (1 - v / w_hi)

    tmax_px = W - R
    def y_hr(v: float) -> float:
        return T + ph * (1 - (v - hr_lo) / (hr_hi - hr_lo))

    parts = [f'<svg viewBox="0 0 {W} {H}" role="img" aria-label="Rower power in watts and heart rate over time">']
    secs = [s for s, _ in pts if s is not None]
    for i in range(0, int(max(secs) // 60) + 1, 10):
        parts.append(f'<line x1="{x(i * 60):.1f}" x2="{x(i * 60):.1f}" y1="{T}" y2="{T + ph}" class="grid"/>')
        parts.append(f'<text x="{x(i * 60):.1f}" y="{H - 8}" text-anchor="middle" class="ax">{i}m</text>')
    for v in range(step, int(w_hi) + 1, step):
        parts.append(f'<line x1="{L}" x2="{tmax_px}" y1="{y(v):.1f}" y2="{y(v):.1f}" class="grid"/>')
        parts.append(f'<text x="{L - 6}" y="{y(v) + 6:.1f}" text-anchor="end" class="ax pw">{v}</text>')
    for v in range(int(hr_lo // 40 * 40 + 40), int(hr_hi), 40):
        parts.append(f'<text x="{W - R + 6}" y="{y_hr(v) + 6:.1f}" class="ax hr">{v}</text>')
    hr_pts = [(x(r["seconds"]), y_hr(r["hr"])) for r in rows if r["hr"] is not None and r["seconds"] is not None]
    if hr_pts:
        parts.append(f'<polyline points="{_polyline(hr_pts)}" class="hrl thin"/>')
    # one filled line per rowing block, with its peak labelled
    seg: list[tuple[float, float]] = []
    last_label_x = -1e9
    for s, w in pts + [(None, None)]:  # trailing None flushes the last block
        if s is not None and w is not None:
            seg.append((s, w))
            continue
        if len(seg) > 1:
            line = [(x(a), y(b)) for a, b in seg]
            area = [(line[0][0], y(0))] + line + [(line[-1][0], y(0))]
            parts.append(f'<polygon points="{_polyline(area)}" class="pwrfill"/>')
            parts.append(f'<polyline points="{_polyline(line)}" class="pwr"/>')
            ps, pw_ = max(seg, key=lambda p: p[1])
            if x(ps) - last_label_x > 60:  # skip labels that would overlap
                parts.append(f'<text x="{x(ps):.1f}" y="{y(pw_) - 8:.1f}" text-anchor="middle" class="pk">{pw_:g} W</text>')
                last_label_x = x(ps)
        seg = []
    parts.append("</svg>")
    return "\n".join(parts)


SPLAT_GOAL = 12  # Orangetheory's usual target: 12 minutes in the orange + red zones


def _num(v: Any) -> float | None:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _zones_html(splats: Any, zt: dict[str, Any], zones: dict[str, Any]) -> str:
    """Splat-goal progress bar, a stacked bar of minutes per zone, and each zone's bpm range."""
    out = []
    sp = _num(splats)
    if sp is not None:
        pct = min(sp / SPLAT_GOAL, 1) * 100
        note = "goal reached" if sp >= SPLAT_GOAL else f"{SPLAT_GOAL - sp:g} to goal"
        out.append(f'<div class="splat"><div class="bar"><span style="width:{pct:.0f}%"></span></div>'
                   f'<div class="lbl"><b>{sp:g} / {SPLAT_GOAL}</b> splat points ({note}). '
                   f'1 splat point = 1 minute in the orange or red zone.</div></div>')
    mins = {z: _num(zt.get(z)) or 0 for z in ZONE_COLORS if z in zt}
    total = sum(mins.values())
    if total:
        segs = "".join(
            f'<span style="width:{m / total * 100:.2f}%;background:{ZONE_COLORS[z]}" title="{z} {m:g} min">'
            f'{f"{m:g}m" if m / total >= 0.08 else ""}</span>'
            for z, m in mins.items() if m
        )
        out.append(f'<div class="zbar">{segs}</div>')
        legend = []
        for z, m in mins.items():
            rng = zones.get(z) or {}
            bpm = f' · {rng["startBpm"]}–{rng["endBpm"]} bpm' if "startBpm" in rng and "endBpm" in rng else ""
            legend.append(f'<span class="zone"><i style="background:{ZONE_COLORS[z]}"></i>'
                          f'{z} {m:g} min ({m / total * 100:.0f}%){bpm}</span>')
        out.append(f'<div class="zones">{"".join(legend)}</div>')
    return "".join(out)


def _blocks(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Split the class into treadmill and rower blocks: consecutive samples on the same machine,
    allowing gaps of up to 90 s. Blocks shorter than 5 samples (~30 s) are dropped."""
    blocks: list[dict[str, Any]] = []
    for r in rows:
        if r["seconds"] is None:
            continue
        m = "tread" if r["tread_speed_mps"] is not None else "row" if r["row_speed_mps"] is not None else None
        if m is None:
            continue
        b = blocks[-1] if blocks else None
        if b and b["machine"] == m and r["seconds"] - b["rows"][-1]["seconds"] <= 90:
            b["rows"].append(r)
        else:
            blocks.append({"machine": m, "rows": [r]})
    return [b for b in blocks if len(b["rows"]) >= 5]


def _blocks_html(rows: list[dict[str, Any]], sp_unit: str, sp_factor: float) -> str:
    """Table with one row per treadmill/rower block: time, distance, speed or power, heart rate."""
    blocks = _blocks(rows)
    if not blocks:
        return ""
    dist_unit, per_m = {"mph": ("mi", 1 / 1609.344), "km/h": ("km", 1 / 1000), "kph": ("km", 1 / 1000)}.get(
        sp_unit, ("m", 1))
    last_agg = {"tread": 0, "row": 0}  # cumulative distance (from 0 at class start) at the previous block's end
    trs = []
    for n, b in enumerate(blocks, 1):
        rs, m = b["rows"], b["machine"]
        dkey = "tread_distance_m" if m == "tread" else "row_distance_m"
        aggs = [r[dkey] for r in rs if r[dkey] is not None]
        dist = None
        if aggs:
            dist = max(aggs[-1] - last_agg[m], 0)
            last_agg[m] = aggs[-1]
        hrs = [r["hr"] for r in rs if r["hr"] is not None]
        t0, t1 = rs[0]["seconds"], rs[-1]["seconds"]
        when = f"{t0 // 60}:{t0 % 60:02d}–{t1 // 60}:{t1 % 60:02d}"
        if m == "tread":
            sp = [r["tread_speed_mps"] * sp_factor for r in rs if r["tread_speed_mps"] is not None]
            dist_s = f"{dist * per_m:.2f} {dist_unit}" if dist is not None and dist_unit != "m" else (
                f"{dist:g} m" if dist is not None else "")
            effort = f"avg {sum(sp) / len(sp):.1f} · max {max(sp):.1f} {sp_unit}"
        else:
            w = [r["row_watts"] for r in rs if r["row_watts"] is not None]
            mps = [r["row_speed_mps"] for r in rs if r["row_speed_mps"]]
            pace = 500 / (sum(mps) / len(mps)) if mps else None
            dist_s = f"{dist:g} m" if dist is not None else ""
            effort = (f"avg {sum(w) / len(w):.0f} · max {max(w):g} W" if w else "") + (
                f" · {int(pace // 60)}:{int(pace % 60):02d}/500m" if pace else "")
        hr_s = f"{sum(hrs) / len(hrs):.0f} / {max(hrs)}" if hrs else ""
        name = "Treadmill" if m == "tread" else "Rower"
        trs.append(f'<tr><td><i class="dot {m}"></i>{n}. {name}</td><td>{when}</td><td>{dist_s}</td>'
                   f'<td>{effort}</td><td>{hr_s}</td></tr>')
    return ('<h2>Blocks</h2><div class="tblwrap"><table class="blocks"><thead><tr><th>Block</th><th>Time</th>'
            '<th>Distance</th><th>Speed / power</th><th>HR avg / max</th></tr></thead><tbody>'
            + "".join(trs) + "</tbody></table></div>")


def render_html(meta: dict[str, Any], summary: dict[str, Any], tel: dict[str, Any], rows: list[dict[str, Any]]) -> str:
    W, H, L, R, T, B = 900, 460, 56, 48, 16, 40
    pw, ph = W - L - R, H - T - B
    secs = [r["seconds"] for r in rows if r["seconds"] is not None]
    tmax = max(secs) if secs else 1
    hrs = [r["hr"] for r in rows if r["hr"] is not None]
    zones = tel.get("zones") or {}
    hr_lo = (min(hrs) // 10) * 10 - 10 if hrs else 60
    hr_hi = max(hrs) + 10 if hrs else 200
    # Chart speed in the same unit the stat cards use (the account's display unit, e.g. mph).
    tread_sum = (((summary or {}).get("details") or {}).get("equipment_data") or {}).get("treadmill") or {}
    sp_unit = str((tread_sum.get("avg_speed") or {}).get("display_unit") or "").lower()
    if sp_unit not in SPEED_FROM_MPS:
        sp_unit = "m/s"
    sp_factor = SPEED_FROM_MPS.get(sp_unit, 1.0)

    def speed(r: dict[str, Any], key: str = "tread_speed_mps") -> float | None:
        v = r[key]
        return None if v is None else v * sp_factor

    # Rower speed shares the speed axis (same unit), drawn in its own colour.
    has_row = any(r["row_speed_mps"] is not None for r in rows)
    speeds = [s for k in ("tread_speed_mps", "row_speed_mps") for s in (speed(r, k) for r in rows) if s is not None]
    sp_hi = max(speeds + [1]) * 1.15

    def x(t: float) -> float:
        return L + pw * t / tmax

    def y_hr(v: float) -> float:
        return T + ph * (1 - (v - hr_lo) / (hr_hi - hr_lo))

    def y_sp(v: float) -> float:
        return T + ph * (1 - v / sp_hi)

    what = "treadmill and rower speed" if has_row else "treadmill speed"
    parts = [f'<svg viewBox="0 0 {W} {H}" role="img" aria-label="Heart rate and {what} over time">']
    # zone bands
    for name in ("gray", "blue", "green", "orange", "red"):
        z = zones.get(name)
        if not z:
            continue
        lo, hi = max(z.get("startBpm", hr_lo), hr_lo), min(z.get("endBpm", hr_hi), hr_hi)
        if hi <= lo:
            continue
        parts.append(
            f'<rect x="{L}" y="{y_hr(hi):.1f}" width="{pw}" height="{y_hr(lo) - y_hr(hi):.1f}" '
            f'fill="{ZONE_COLORS[name]}" opacity="0.10"/>'
        )
    # grid + axes labels
    for i in range(0, int(tmax // 60) + 1, 10):
        parts.append(f'<line x1="{x(i * 60):.1f}" x2="{x(i * 60):.1f}" y1="{T}" y2="{T + ph}" class="grid"/>')
        parts.append(f'<text x="{x(i * 60):.1f}" y="{H - 12}" text-anchor="middle" class="ax">{i}m</text>')
    step = 20
    for v in range(int(hr_lo // step * step + step), int(hr_hi), step):
        parts.append(f'<text x="{L - 6}" y="{y_hr(v) + 4:.1f}" text-anchor="end" class="ax hr">{v}</text>')
    if speeds:
        for v in range(1, int(sp_hi) + 1, 2):
            parts.append(f'<text x="{W - R + 6}" y="{y_sp(v) + 4:.1f}" class="ax sp">{v}</text>')
    # speed lines (gaps when off that machine)
    for key, css in (("tread_speed_mps", "speed"), ("row_speed_mps", "rowl")):
        seg: list[tuple[float, float]] = []
        for r in rows + [None]:  # trailing None flushes the last segment
            sp = speed(r, key) if r is not None and r["seconds"] is not None else None
            if sp is None:
                if len(seg) > 1:
                    parts.append(f'<polyline points="{_polyline(seg)}" class="{css}"/>')
                seg = []
                continue
            seg.append((x(r["seconds"]), y_sp(sp)))
    # heart rate
    hr_pts = [(x(r["seconds"]), y_hr(r["hr"])) for r in rows if r["hr"] is not None and r["seconds"] is not None]
    if hr_pts:
        parts.append(f'<polyline points="{_polyline(hr_pts)}" class="hrl"/>')
    parts.append("</svg>")
    svg = "\n".join(parts)
    power_svg = _power_chart(rows, x, W, L, R, hr_lo, hr_hi)

    details = (summary or {}).get("details") or {}
    hrd = details.get("heart_rate") or {}
    tread = (details.get("equipment_data") or {}).get("treadmill") or {}
    zt = details.get("zone_time_minutes") or {}

    def metric(m: Any) -> str:
        return f"{m.get('display_value')} {m.get('display_unit', '')}".strip() if isinstance(m, dict) else ""

    def with_pct(label: str, v: Any, pct: Any) -> tuple[str, Any]:
        return (f"{label} · % of max", f"{v} · {pct}%") if v is not None and pct else (label, v)

    elev = tread.get("elevation_gained")
    if isinstance(elev, dict) and _num(elev.get("display_value")) is not None:
        elev = dict(elev, display_value=round(_num(elev["display_value"])))
    splats = details.get("splat_points", meta.get("splats"))
    steps = details.get("step_count", meta.get("steps"))
    stats = [
        ("Calories", details.get("calories_burned", meta.get("calories"))),
        ("Splat points", splats),
        with_pct("Avg HR", hrd.get("avg_hr"), hrd.get("avg_hr_percent")),
        with_pct("Peak HR", hrd.get("peak_hr"), hrd.get("peak_hr_percent")),
        ("Steps", steps or None),
        ("Tread distance", metric(tread.get("total_distance"))),
        ("Avg speed", metric(tread.get("avg_speed"))),
        ("Max speed", metric(tread.get("max_speed"))),
        ("Avg pace", metric(tread.get("avg_pace"))),
        ("Elevation", metric(elev)),
    ]
    if has_row:
        rower = (details.get("equipment_data") or {}).get("rower") or {}
        stats += [
            ("Row distance", metric(rower.get("total_distance"))),
            ("Row avg power", metric(rower.get("avg_power"))),
            ("Row avg pace", metric(rower.get("avg_pace"))),
        ]
    row_legend = (f'<span><b style="background:var(--row)"></b>Rower speed ({sp_unit}, right)</span>'
                  if has_row else "")
    stat_html = "".join(
        f'<div class="stat"><div class="v">{html.escape(_fmt(v))}</div><div class="k">{k}</div></div>'
        for k, v in stats if v not in (None, "")
    )
    zone_html = _zones_html(splats, zt, zones)
    blocks_html = _blocks_html(rows, sp_unit, sp_factor)
    title = f"{meta.get('name') or 'Orangetheory class'} - {_fmt(meta.get('starts_at'))[:16].replace('T', ' ')}"
    sub = " · ".join(s for s in (meta.get("studio"), meta.get("coach") and f"Coach {meta['coach']}") if s)

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)}</title>
<style>
:root {{ --bg:#fff; --fg:#1b1d21; --muted:#6b7280; --grid:#e5e7eb; --card:#f6f7f9; --hr:#e5484d; --sp:#2563eb; --row:#8b5cf6; }}
@media (prefers-color-scheme: dark) {{ :root {{ --bg:#111317; --fg:#e8eaed; --muted:#9aa0a6; --grid:#2a2e35; --card:#1b1e24; --hr:#ff6b6f; --sp:#6ea8ff; --row:#b69cff; }} }}
body {{ margin:0; padding:16px; background:var(--bg); color:var(--fg); font:15px/1.4 system-ui, sans-serif; }}
h1 {{ font-size:1.2rem; margin:0 0 4px; }} .sub {{ color:var(--muted); margin-bottom:16px; }}
.stats {{ display:grid; grid-template-columns:repeat(auto-fill,minmax(130px,1fr)); gap:8px; margin-bottom:16px; }}
.stat {{ background:var(--card); border-radius:10px; padding:10px 12px; }} .stat .v {{ font-size:1.25rem; font-weight:600; }}
.stat .k {{ color:var(--muted); font-size:.8rem; }}
svg {{ width:100%; height:auto; display:block; }} .grid {{ stroke:var(--grid); stroke-width:1; }}
.ax {{ fill:var(--muted); font-size:20px; }} .ax.hr {{ fill:var(--hr); }} .ax.sp {{ fill:var(--sp); }}
.hrl {{ fill:none; stroke:var(--hr); stroke-width:2; stroke-linejoin:round; }}
.speed {{ fill:none; stroke:var(--sp); stroke-width:2; stroke-linejoin:round; }}
.rowl {{ fill:none; stroke:var(--row); stroke-width:2; stroke-linejoin:round; }}
.pwr {{ fill:none; stroke:var(--row); stroke-width:2; stroke-linejoin:round; }} .pwrfill {{ fill:var(--row); opacity:.15; }}
.ax.pw {{ fill:var(--row); }} .hrl.thin {{ stroke-width:1.5; opacity:.7; }} .pk {{ fill:var(--fg); font-size:18px; font-weight:600; }}
h2 {{ font-size:.95rem; font-weight:600; margin:18px 0 4px; }}
.legend, .zones {{ display:flex; flex-wrap:wrap; gap:14px; color:var(--muted); font-size:.85rem; margin:8px 0; }}
.legend b {{ display:inline-block; width:14px; height:3px; vertical-align:middle; margin-right:6px; }}
.zone i {{ display:inline-block; width:10px; height:10px; border-radius:2px; margin-right:5px; vertical-align:-1px; }}
.splat .bar {{ height:10px; background:var(--card); border-radius:5px; overflow:hidden; }}
.splat .bar span {{ display:block; height:100%; background:linear-gradient(90deg,#f28c28,#e5484d); }}
.splat .lbl {{ font-size:.85rem; color:var(--muted); margin:4px 0 10px; }} .splat b {{ color:var(--fg); }}
.zbar {{ display:flex; height:22px; border-radius:6px; overflow:hidden; }}
.zbar span {{ display:flex; align-items:center; justify-content:center; color:#fff; font-size:.75rem; font-weight:600; }}
.tblwrap {{ overflow-x:auto; }} table.blocks {{ border-collapse:collapse; width:100%; font-size:.85rem; }}
.blocks th, .blocks td {{ text-align:left; padding:6px 10px 6px 0; border-bottom:1px solid var(--grid); white-space:nowrap; }}
.blocks th {{ color:var(--muted); font-weight:500; }}
.dot {{ display:inline-block; width:8px; height:8px; border-radius:50%; margin-right:6px; }}
.dot.tread {{ background:var(--sp); }} .dot.row {{ background:var(--row); }}
</style></head><body>
<h1>{html.escape(title)}</h1><div class="sub">{html.escape(sub)}</div>
<div class="stats">{stat_html}</div>
{'<h2>Zones</h2>' + zone_html if zone_html else ''}
<h2>Heart rate and speed</h2>
<div class="legend"><span><b style="background:var(--hr)"></b>Heart rate (bpm, left)</span><span><b style="background:var(--sp)"></b>Treadmill speed ({sp_unit}, right)</span>{row_legend}</div>
{svg}
{'<h2>Rower power (watts, left) and heart rate (bpm, right)</h2>' + power_svg if power_svg else ''}
{blocks_html}
</body></html>
"""


# --------------------------------------------------------------------------------------
# Commands
# --------------------------------------------------------------------------------------
def _slug(s: str) -> str:
    return "".join(c if c.isalnum() else "-" for c in s).strip("-").lower()[:40] or "class"


def _start(args: argparse.Namespace) -> dt.datetime:
    if getattr(args, "since", None):
        try:
            d = dt.date.fromisoformat(args.since)
        except ValueError:
            raise OtfError(f"--since must look like 2023-03-01, got {args.since!r}") from None
        return dt.datetime(d.year, d.month, d.day, tzinfo=dt.timezone.utc)
    return dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=args.days)


def cmd_list(otf: Otf, args: argparse.Namespace) -> list[dict[str, Any]]:
    rows = class_rows(otf.bookings(_start(args)))
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    LAST_LIST_FILE.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    if not rows:
        print("No completed classes with workout data in that date range.")
    else:
        print_table(rows)
        print(f"\n{len(rows)} classes. Export with e.g.: python {Path(sys.argv[0]).name} export 1")
    return rows


def _resolve_targets(otf: Otf, args: argparse.Namespace) -> list[dict[str, Any]]:
    want = args.which
    if want == ["all"] or want == ["latest"] or not LAST_LIST_FILE.exists():
        rows = class_rows(otf.bookings(_start(args)))
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        LAST_LIST_FILE.write_text(json.dumps(rows, indent=2), encoding="utf-8")
    else:
        rows = json.loads(LAST_LIST_FILE.read_text(encoding="utf-8"))
    if want == ["all"]:
        return rows
    if want == ["latest"]:
        return rows[:1]
    by_n = {str(r["n"]): r for r in rows}
    by_id = {r["id"]: r for r in rows}
    out = []
    for w in want:
        if w in by_n:
            out.append(by_n[w])
        elif w in by_id:
            out.append(by_id[w])
        else:  # treat as a raw performance summary id
            out.append({"id": w, "n": None, "name": "", "starts_at": "", "coach": "", "studio": ""})
    return out


def summary_row(meta: dict[str, Any], summary: dict[str, Any], rows: list[dict[str, Any]], tel: dict[str, Any]) -> dict[str, Any]:
    """One flat row of headline stats per class, for the combined classes_summary.csv."""
    d = (summary or {}).get("details") or {}
    hrd = d.get("heart_rate") or {}
    zt = d.get("zone_time_minutes") or {}
    eq = d.get("equipment_data") or {}
    out: dict[str, Any] = {
        "class_id": meta.get("id"),
        "starts_at": meta.get("starts_at"),
        "class": meta.get("name"),
        "coach": meta.get("coach"),
        "studio": meta.get("studio"),
        "active_min": meta.get("active_min"),
        "calories": d.get("calories_burned", meta.get("calories")),
        "splats": d.get("splat_points", meta.get("splats")),
        "steps": d.get("step_count", meta.get("steps")),
        "avg_hr": hrd.get("avg_hr"),
        "peak_hr": hrd.get("peak_hr"),
        "max_hr": hrd.get("max_hr", tel.get("maxHr")),
        "avg_hr_pct": hrd.get("avg_hr_percent"),
    }
    for z in ("gray", "blue", "green", "orange", "red"):
        out[f"{z}_min"] = zt.get(z)
    for machine, keys in (
        ("tread", ("total_distance", "avg_speed", "max_speed", "avg_pace", "avg_incline", "max_incline", "elevation_gained")),
        ("row", ("total_distance", "avg_speed", "avg_pace", "avg_power", "avg_cadence")),
    ):
        data = eq.get("treadmill" if machine == "tread" else "rower") or {}
        for k in keys:
            mval = data.get(k)
            out[f"{machine}_{k}"] = mval.get("display_value") if isinstance(mval, dict) else None
            out[f"{machine}_{k}_unit"] = mval.get("display_unit") if isinstance(mval, dict) else None
    out["telemetry_points"] = len(rows)
    return out


def _has_telemetry(tel: Any) -> bool:
    return isinstance(tel, dict) and bool(tel.get("telemetry"))


def cmd_export(otf: Otf, args: argparse.Namespace) -> None:
    targets = _resolve_targets(otf, args)
    if not targets:
        print("Nothing to export.")
        return
    out_dir = Path(args.out).expanduser()
    out_dir.mkdir(parents=True, exist_ok=True)
    formats = set(args.format.split(","))
    combined = args.combined if args.combined is not None else len(targets) > 1
    summaries: list[dict[str, Any]] = []
    all_points: list[dict[str, Any]] = []
    failed: list[str] = []
    no_telemetry = 0
    cache_dir = out_dir / ".otf_cache"
    cache_dir.mkdir(exist_ok=True)
    reused = 0
    for i, meta in enumerate(targets, 1):
        sid = meta["id"]
        if len(targets) > 1:
            print(f"[{i}/{len(targets)}] ", end="", flush=True)
        cache_file = cache_dir / f"{_slug(sid)}.json"
        cached = None
        if not args.refresh and cache_file.exists():
            try:
                cached = json.loads(cache_file.read_text(encoding="utf-8"))
                # Re-fetch classes cached without telemetry: OTF may have processed them since.
                if cached.get("points") != args.points or not _has_telemetry(cached.get("telemetry")):
                    cached = None
            except (OSError, ValueError):
                cached = None
        if cached:
            summary, tel = cached["summary"], cached["telemetry"]
            reused += 1
        else:
            try:
                try:
                    summary = otf.performance_summary(sid)
                except OtfError as e:
                    print(f"  ! summary for {sid}: {e}", file=sys.stderr)
                    summary = {}
                tel = otf.telemetry(sid, args.points)
            except (OtfError, OSError, ValueError) as e:
                print(f"{meta.get('starts_at', '')[:16]} {meta.get('name', '')}: FAILED - {e}")
                failed.append(sid)
                continue
            # Only cache complete results, so a missing summary or telemetry is retried next run.
            # Telemetry can show up a while after class: OTF processes it after the HR monitor syncs.
            if summary and _has_telemetry(tel):
                tmp = cache_file.with_suffix(".tmp")
                tmp.write_text(json.dumps({"points": args.points, "summary": summary, "telemetry": tel}), encoding="utf-8")
                tmp.replace(cache_file)
        if not meta.get("starts_at") or not meta.get("name"):
            # exported by raw ID (not in the last list): take name and local start from the summary
            cls = (summary or {}).get("class") or {}
            meta = dict(meta, starts_at=meta.get("starts_at") or cls.get("starts_at_local") or "",
                        name=meta.get("name") or cls.get("name") or "")
        rows = telemetry_rows(tel)
        stamp =(meta.get("starts_at") or tel.get("classStartTime") or "")[:16].replace(":", "").replace("T", "_")
        base = out_dir / f"{stamp or sid[:8]}_{_slug(meta.get('name') or 'class')}"
        written = []
        if "csv" in formats:
            with open(f"{base}.csv", "w", newline="", encoding="utf-8") as f:
                w = csv.DictWriter(f, fieldnames=TELEMETRY_COLUMNS)
                w.writeheader()
                w.writerows(rows)
            written.append(f"{base}.csv")
        if "json" in formats:
            Path(f"{base}.json").write_text(
                json.dumps({"class": meta, "performance_summary": summary, "telemetry": tel}, indent=2),
                encoding="utf-8",
            )
            written.append(f"{base}.json")
        if "html" in formats:
            Path(f"{base}.html").write_text(render_html(meta, summary, tel, rows), encoding="utf-8")
            written.append(f"{base}.html")
        if combined:
            summaries.append(summary_row(meta, summary, rows, tel))
            label = {"class_id": sid, "class_start": meta.get("starts_at"), "class": meta.get("name")}
            all_points.extend({**label, **r} for r in rows)
        if not rows:
            no_telemetry += 1
        note = "" if rows else "  (no telemetry yet - see note below)"
        note += "  [already downloaded]" if cached else ""
        print(f"{meta.get('starts_at', '')[:16]} {meta.get('name', '')}: {len(rows)} points{note}")
        for p in written:
            print(f"    {p}")

    if reused:
        print(f"\nReused {reused} already-downloaded classes (use --refresh to fetch them again).")
    if no_telemetry:
        print(f"\n{no_telemetry} class(es) had no heart-rate/equipment data. For a recent class, OTF may still be "
              "processing it: run the same command again later and those classes will be fetched again. "
              "If it stays empty, the HR monitor probably wasn't connected.")
    if failed:
        print(f"\n{len(failed)} classes failed; re-run just those with: export {' '.join(failed)}")

    if combined and summaries:
        summaries.sort(key=lambda r: r["starts_at"] or "")
        all_points.sort(key=lambda r: (r["class_start"] or "", r["seconds"] or 0))
        sum_path = out_dir / "classes_summary.csv"
        with open(sum_path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(summaries[0].keys()))
            w.writeheader()
            w.writerows(summaries)
        tel_path = out_dir / "all_telemetry.csv"
        with open(tel_path, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=["class_id", "class_start", "class"] + TELEMETRY_COLUMNS)
            w.writeheader()
            w.writerows(all_points)
        print(f"\nCombined files ({len(summaries)} classes, {len(all_points)} telemetry rows):")
        print(f"    {sum_path}\n    {tel_path}")


EQUIPMENT = {2: "Treadmill", 3: "Strider", 4: "Rower", 5: "Bike", 6: "Weight floor", 7: "Power walker"}


KM_PER_MILE = 1.609344


def _time_to_seconds(v: Any) -> float | None:
    """'06:15', '01:24.64' or '00:07:27.15' -> seconds."""
    if not isinstance(v, str) or ":" not in v:
        return None
    try:
        secs = 0.0
        for part in v.strip().split(":"):
            secs = secs * 60 + float(part)
        return round(secs, 2)
    except ValueError:
        return None


def _normalize(value: Any, metric: str | None, unit: str | None) -> dict[str, Any]:
    """Add analysis-friendly columns: seconds for times, km+miles for distances, a 'kind' flag."""
    kind = "attendance" if (metric or "").lower() == "attendance" else (metric or "").lower() or None
    out: dict[str, Any] = {"kind": kind, "seconds": None, "km": None, "miles": None, "meters": None}
    if kind == "time":
        out["seconds"] = _time_to_seconds(value)
    elif kind == "distance" and value not in (None, ""):
        try:
            v = float(value)
        except (TypeError, ValueError):
            return out
        if (unit or "").lower() == "km":
            out["km"], out["miles"] = round(v, 3), round(v / KM_PER_MILE, 2)
        elif (unit or "").lower() == "m":
            out["meters"] = round(v, 1)
    return out


def benchmark_rows(
    benchmarks: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[dict[str, Any]]]:
    """Flatten the benchmarks response into (one row per benchmark, one row per attempt, one row per
    challenge run - e.g. a Marathon Month total)."""
    summary, history, runs = [], [], []
    for b in benchmarks:
        metric = b.get("MetricEntry") or {}
        equip = b.get("EquipmentName") or EQUIPMENT.get(b.get("EquipmentId"), b.get("EquipmentId"))
        name = b.get("ChallengeName") or metric.get("Title")
        mtype = metric.get("EntryType")
        unit = b.get("Unit") if (mtype or "").lower() != "attendance" else None  # attendance reports a bogus "lb"
        attempts = []
        for ch in b.get("ChallengeHistories") or []:
            hist = ch.get("BenchmarkHistories") or []
            if len(hist) > 1:  # multi-session challenge (Marathon Month, Hell Week...): keep its total
                total = ch.get("TotalResult")
                runs.append(
                    {
                        "challenge": name,
                        "start": ch.get("StartDate"),
                        "end": ch.get("EndDate"),
                        "sessions": len(hist),
                        "total": total,
                        "unit": unit,
                        **_normalize(total, mtype, unit),
                        "finished": ch.get("IsFinished"),
                        "goal_sessions": (b.get("Goals") or {}).get("OverallGoal"),
                    }
                )
            for h in hist:
                attempts.append(
                    {
                        "benchmark": name,
                        "equipment": equip,
                        "date": h.get("ClassTime") or h.get("DateCreated") or ch.get("StartDate"),
                        "result": h.get("Result"),
                        "unit": unit,
                        "metric": mtype,
                        **_normalize(h.get("Result"), mtype, unit),
                        "class": h.get("ClassName"),
                        "coach": h.get("CoachName"),
                        "studio": h.get("StudioName") or ch.get("StudioName"),
                        "weight_lbs": h.get("WeightLBS"),
                        "challenge_category_id": b.get("ChallengeCategoryId"),
                        "challenge_sub_category_id": h.get("ChallengeSubCategoryId", b.get("ChallengeSubCategoryId")),
                    }
                )
        attempts.sort(key=lambda r: r["date"] or "")
        history.extend(attempts)
        summary.append(
            {
                "benchmark": name,
                "equipment": equip,
                "unit": unit,
                "metric": mtype,
                "kind": _normalize(None, mtype, unit)["kind"],
                "best": b.get("BestRecord"),
                "last": b.get("LastRecord"),
                "previous": b.get("PreviousRecord"),
                **{f"best_{k}": v for k, v in _normalize(b.get("BestRecord"), mtype, unit).items() if k != "kind"},
                **{f"last_{k}": v for k, v in _normalize(b.get("LastRecord"), mtype, unit).items() if k != "kind"},
                "attempts": len(attempts),
                "first_attempt": attempts[0]["date"] if attempts else None,
                "last_attempt": attempts[-1]["date"] if attempts else None,
                "challenge_category_id": b.get("ChallengeCategoryId"),
                "challenge_sub_category_id": b.get("ChallengeSubCategoryId"),
            }
        )
    summary.sort(key=lambda r: (str(r["equipment"]), str(r["benchmark"])))
    history.sort(key=lambda r: (r["date"] or ""))
    runs.sort(key=lambda r: (r["start"] or ""))
    return summary, history, runs


def _write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else ["empty"])
        w.writeheader()
        w.writerows(rows)


def cmd_benchmarks(otf: Otf, args: argparse.Namespace) -> None:
    out_dir = Path(args.out).expanduser()
    out_dir.mkdir(parents=True, exist_ok=True)
    raw = otf.benchmarks()
    try:
        tracker = otf.challenge_tracker()
    except OtfError as e:
        print(f"  ! challenge tracker: {e}", file=sys.stderr)
        tracker = {}
    summary, history, runs = benchmark_rows(raw)
    taken = [r for r in summary if r["kind"] != "attendance" and (r["attempts"] or r["best"] not in (None, "", 0))]

    _write_csv(out_dir / "benchmarks_summary.csv", summary)
    _write_csv(out_dir / "benchmarks_history.csv", history)
    _write_csv(out_dir / "challenge_totals.csv", runs)
    (out_dir / "benchmarks_raw.json").write_text(json.dumps({"benchmarks": raw, "challenge_tracker": tracker}, indent=2), encoding="utf-8")

    if taken:
        cols = [("benchmark", "Benchmark"), ("equipment", "Equipment"), ("best", "Best"), ("last", "Last"),
                ("unit", "Unit"), ("attempts", "Tries")]
        # On screen only: round floats (e.g. 4.586630400000001 km -> 4.59). CSVs keep full precision.
        data = [[_fmt_num(r[k]) for k, _ in cols] for r in taken]
        print_cols([h for _, h in cols], data)
    else:
        print("No benchmark results found.")
    print(f"\n{len(taken)} benchmarks with results, {len(history)} attempts/sessions in total, "
          f"{len(runs)} multi-day challenges.")
    for name in ("benchmarks_summary.csv", "benchmarks_history.csv", "challenge_totals.csv", "benchmarks_raw.json"):
        print(f"    {out_dir / name}")


def main(argv: list[str] | None = None) -> int:
    # When output is piped/redirected on Windows, stdout uses the ANSI code page (e.g. cp1252),
    # and printing a coach/studio name like "Łukasz" would crash. Replace unencodable characters
    # instead. No effect on UTF-8 terminals (Linux, macOS, Termux, Windows console).
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")
    ap = argparse.ArgumentParser(description="List Orangetheory classes and export performance data.")
    ap.add_argument("--debug", action="store_true", help="save raw API responses to ~/.otf_export/raw/")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_list = sub.add_parser("list", help="list recent classes that have workout data")
    p_list.add_argument("--days", type=int, default=60, help="how far back to look (default 60)")
    p_list.add_argument("--since", help="start date YYYY-MM-DD (overrides --days), e.g. 2023-03-01")

    p_exp = sub.add_parser("export", help="export telemetry + stats for one or more classes")
    p_exp.add_argument("which", nargs="+", help="numbers from `list`, performance summary IDs, 'latest', or 'all'")
    p_exp.add_argument("--days", type=int, default=60, help="window used for 'all'/'latest' (default 60)")
    p_exp.add_argument("--since", help="start date YYYY-MM-DD for 'all'/'latest' (overrides --days)")
    p_exp.add_argument("--points", type=int, default=600,
                       help="max telemetry points (app uses 150; higher = finer detail, default 600)")
    p_exp.add_argument("--format", default="csv,json,html", help="comma list of csv,json,html")
    p_exp.add_argument("--out", default="otf_exports", help="output directory (default ./otf_exports)")
    p_exp.add_argument("--combined", dest="combined", action="store_true", default=None,
                       help="also write classes_summary.csv + all_telemetry.csv (default when exporting >1 class)")
    p_exp.add_argument("--no-combined", dest="combined", action="store_false")
    p_exp.add_argument("--refresh", action="store_true",
                       help="ignore already-downloaded classes in <out>/.otf_cache and fetch everything again")

    p_bench = sub.add_parser("benchmarks", help="export benchmark results (1-mile, 2k row, DriTri, ...) and history")
    p_bench.add_argument("--out", default="otf_exports", help="output directory (default ./otf_exports)")

    sub.add_parser("logout", help="delete the cached login token")

    args = ap.parse_args(argv)
    if args.cmd == "logout":
        TOKEN_FILE.unlink(missing_ok=True)
        print("Logged out.")
        return 0
    try:
        otf = Otf(debug_dir=STATE_DIR / "raw" if args.debug else None)
        if args.cmd == "list":
            cmd_list(otf, args)
        elif args.cmd == "benchmarks":
            cmd_benchmarks(otf, args)
        else:
            cmd_export(otf, args)
    except OtfError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
