#!/usr/bin/env python3
"""
YourMembership → OIDC bridge for Pretix.

Exposes a minimal OIDC Authorization Code provider backed by YM's 3-step
OAuth2 API.  Pretix (or any OIDC client) points at this service; users are
redirected to the YM member portal to log in.

Flow:
  Pretix → GET /oidc/auth
         → browser redirect → members.caves.org/lock.aspx (YM login)
         → browser redirect → GET /oidc/callback?code=<ym_code>
         → [exchange ym_code for access token]
         → [authenticate to get SessionId + MemberId]
         → [fetch BasicMemberProfile to get email]
         → issue OIDC auth code, redirect to Pretix callback
  Pretix → POST /oidc/token (exchange OIDC code for signed RS256 ID token)
  Pretix → GET  /oidc/userinfo (optional, for extra claims)
"""

import os
import json
import time
import datetime as dt
import html
import hmac
import secrets
import logging
from urllib.parse import urlparse, quote

import redis
import requests
from flask import Flask, abort, jsonify, make_response, redirect, request, session
from authlib.jose import JsonWebKey, jwt

logging.basicConfig(level=logging.INFO)
log = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]

# ── Configuration ──────────────────────────────────────────────────────────

YM_SITE_URL   = os.environ["YM_SITE_URL"].rstrip("/")   # e.g. https://members.caves.org
YM_APP_ID     = os.environ["YM_APP_ID"]
YM_APP_SECRET = os.environ["YM_APP_SECRET"]
YM_CLIENT_ID  = int(os.environ["YM_CLIENT_ID"])

ISSUER          = os.environ["OIDC_ISSUER"].rstrip("/")  # e.g. https://tickets.caves.org/oidc
CLIENT_ID       = os.environ["OIDC_CLIENT_ID"]
CLIENT_SECRET   = os.environ["OIDC_CLIENT_SECRET"]
# Our own callback URL, registered with YM admin as the OAuth redirect URI.
# This is *different* from Pretix's callback — it's where YM sends the browser.
MY_CALLBACK     = os.environ["REDIRECT_URI"]             # e.g. https://tickets.caves.org/oidc/callback

URL_PREFIX      = os.environ.get("URL_PREFIX", "/oidc").rstrip("/")

# Allowed redirect_uri origins — defaults to the same origin as OIDC_ISSUER.
# Set ALLOWED_REDIRECT_ORIGINS to a comma-separated list to override.
_issuer_origin = "{0.scheme}://{0.netloc}".format(urlparse(os.environ.get("OIDC_ISSUER", "")))
ALLOWED_REDIRECT_ORIGINS = [
    o.strip()
    for o in os.environ.get("ALLOWED_REDIRECT_ORIGINS", _issuer_origin).split(",")
    if o.strip()
]

def _validate_redirect_uri(uri: str) -> bool:
    """Return True only if the redirect_uri is on an allowed origin."""
    if not uri:
        return False
    parsed = urlparse(uri)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    return parsed.scheme == "https" and origin in ALLOWED_REDIRECT_ORIGINS

def _safe_next(path: str) -> str:
    """Return path if it's a same-site relative path, else "/".

    Rejects absolute URLs and scheme-relative ones (//host, /\\host), which
    browsers would follow off-site.
    """
    if not path or not path.startswith("/") or path[1:2] in ("/", "\\"):
        return "/"
    return path

# ── Current-membership check ──────────────────────────────────────────────
# Same rules as cavesdotorg/nss-shop-member-sync (Shopify member pricing), so a
# member gets the same answer in the shop and on tickets.caves.org.
#   MEMBER_CHECK = off | log | enforce   (log: decide + log, never block)
MEMBER_CHECK      = os.environ.get("MEMBER_CHECK", "log").strip().lower()
MEMBER_GRACE_DAYS = int(os.environ.get("MEMBER_GRACE_DAYS", "0"))
RENEW_URL         = os.environ.get("RENEW_URL", "https://caves.org/join-us/")
ELIGIBLE_TYPES = {
    "Regular", "Life", "FamilyRegular", "FamilyLife", "ConservationRegular",
    "ConservationLife", "IntroRegular", "Landowner",
}
LIFE_TYPES = {"Life", "FamilyLife", "ConservationLife"}


def _parse_date(v) -> dt.date | None:
    """YM dates: ISO, /Date(ms)/ or M/D/YYYY. 0001-01-01 means unset."""
    if not v:
        return None
    v = str(v).strip()
    d = None
    if v.startswith("/Date("):
        try:
            ms = int(v[6:].split(")")[0].split("-")[0].split("+")[0])
            d = dt.datetime.fromtimestamp(ms / 1000, dt.timezone.utc).date()
        except ValueError:
            return None
    else:
        try:
            d = dt.date.fromisoformat(v[:10])
        except ValueError:
            try:
                d = dt.datetime.strptime(v.split(" ")[0], "%m/%d/%Y").date()
            except ValueError:
                return None
    return None if d.year < 1900 else d


def _membership_status(full_profile: dict, custom_exp_raw: str,
                       today: dt.date | None = None) -> tuple[bool, str, dict]:
    """Return (is_current, reason, detail). detail holds no personal data."""
    today  = today or dt.datetime.now(dt.timezone.utc).date()
    acct   = full_profile.get("AccountInformation") or {}
    admin  = full_profile.get("Administration") or {}
    mtype  = acct.get("MemberTypeCode") or ""
    exp    = _parse_date(acct.get("MembershipExpiresDate"))
    custom = _parse_date(custom_exp_raw)
    detail = {
        "type": mtype or "-",
        "expires_flag": acct.get("MembershipExpires"),
        "custom_vs_account": ("missing" if custom is None or exp is None
                              else "same" if custom == exp else "differ"),
    }
    if not full_profile:
        return False, "no_profile", detail
    if admin.get("Suspended"):
        return False, "suspended", detail
    if mtype not in ELIGIBLE_TYPES:
        return False, "type_not_eligible", detail
    if mtype in LIFE_TYPES:
        return True, "life", detail
    if exp is None:
        return True, "no_expiry_date", detail          # as shop-sync: not lapsed
    if exp < today - dt.timedelta(days=MEMBER_GRACE_DAYS):
        return False, "expired", detail
    return True, "current", detail


_NOT_CURRENT_HTML = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>NSS membership not current</title>
<style>body{{font-family:system-ui,sans-serif;max-width:36em;margin:4em auto;padding:0 1em;line-height:1.5}}
a.b{{display:inline-block;padding:.5em 1em;border-radius:3px;background:#1d4f91;color:#fff;text-decoration:none}}</style>
</head><body><h1>{title}</h1><p>{body}</p>
<p><a class="b" href="{renew}">Join or renew</a> &nbsp; <a href="{back}">Back to tickets</a></p>
</body></html>"""


def _not_current_response(reason: str):
    if reason == "no_profile":
        title = "We couldn't check your membership"
        body  = ("YourMembership didn't return your membership details. "
                 "Please try again in a few minutes.")
    else:
        title = "Your NSS membership isn't current"
        body  = ("Signing in with your NSS account is for current NSS members. "
                 "Renew your membership, then sign in again. If you think this "
                 "is wrong, contact the NSS Office.")
    page = _NOT_CURRENT_HTML.format(
        title=html.escape(title), body=html.escape(body),
        renew=html.escape(RENEW_URL), back=html.escape(_issuer_origin + "/"))
    resp = make_response(page, 403)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    resp.headers["Cache-Control"] = "no-store"
    resp.delete_cookie("ym_session")
    return resp


# Max time between starting a login (/auth or /login) and the YM callback.
_FLOW_TTL = 600

# ── Redis (Valkey) ─────────────────────────────────────────────────────────

_redis = redis.Redis.from_url(
    os.environ.get("REDIS_URL", "redis://valkey:6379/3"),
    decode_responses=True,
)

# ── RSA key pair (RS256) ───────────────────────────────────────────────────

_KEY_PATH = os.environ.get("KEY_PATH", "/secrets/oidc.key")
_PUB_PATH = os.environ.get("PUB_PATH", "/secrets/oidc.pub")
_KID      = "ym-oidc-1"

with open(_KEY_PATH, "rb") as _f:
    _private_key = JsonWebKey.import_key(_f.read(), {"kty": "RSA"})

with open(_PUB_PATH, "rb") as _f:
    _public_key = JsonWebKey.import_key(_f.read(), {"kty": "RSA"})

# ── Redis-backed stores ────────────────────────────────────────────────────

def _store(prefix: str, key: str, value: dict, ttl: int) -> None:
    _redis.setex(f"{prefix}:{key}", ttl, json.dumps(value))

def _pop(prefix: str, key: str) -> dict | None:
    raw = _redis.getdel(f"{prefix}:{key}")  # atomic
    return json.loads(raw) if raw else None

def _get(prefix: str, key: str) -> dict | None:
    raw = _redis.get(f"{prefix}:{key}")
    return json.loads(raw) if raw else None

# ── Browser session (for Caddy forward_auth gate) ─────────────────────────

_SESSION_TTL = int(os.environ.get("SESSION_TTL", 28800))  # 8 hours

def _set_browser_session(identity: dict, response) -> None:
    """Attach a Redis-backed session cookie to response."""
    token = secrets.token_urlsafe(32)
    _store("session", token, identity, ttl=_SESSION_TTL)
    response.set_cookie(
        "ym_session", token,
        max_age=_SESSION_TTL,
        httponly=True,
        secure=True,
        samesite="Lax",
    )

def _get_browser_session() -> dict | None:
    token = request.cookies.get("ym_session")
    return _get("session", token) if token else None


def _ym_exchange_code(code: str) -> dict:
    """
    Run YM's 3-step flow: code → access token → session → profile.
    Returns (identity, (is_current, reason)); identity has keys sub, email, name.
    """
    # Step 1: exchange authorization code for YM access token
    r = requests.post(
        "https://ws.yourmembership.com/OAuth/GetAccessToken",
        json={
            "AppId":     YM_APP_ID,
            "AppSecert": YM_APP_SECRET,  # sic — YM API typo
            "GrantType": "Code",
            "Code":      code,
        },
        timeout=15,
    )
    r.raise_for_status()
    ym_token = r.json().get("AccessToken")
    if not ym_token:
        log.error("YM GetAccessToken response: %s", r.text)
        raise ValueError("No AccessToken in YM response")

    # Step 2: authenticate to get a SessionId and MemberId
    r = requests.post(
        "https://ws.yourmembership.com/Ams/Authenticate",
        json={
            "ConsumerKey":    YM_APP_ID,
            "ConsumerSecret": YM_APP_SECRET,
            "AccessToken":    ym_token,
            "ClientID":       YM_CLIENT_ID,
            "UserType":       "Member",
        },
        timeout=15,
    )
    r.raise_for_status()
    auth_data  = r.json()
    session_id = auth_data.get("SessionId")
    member_id  = auth_data.get("MemberID") or auth_data.get("MemberId")
    if not session_id or not member_id:
        log.error("YM Authenticate response: %s", r.text)
        raise ValueError("Missing SessionId or MemberId in YM response")

    # Step 3: fetch basic profile (email, name)
    r = requests.get(
        f"https://ws.yourmembership.com/Ams/{YM_CLIENT_ID}/Member/{member_id}/BasicMemberProfile",
        headers={"X-SS-ID": session_id, "Accept": "application/json"},
        timeout=15,
    )
    r.raise_for_status()
    profile = r.json()
    log.info("YM BasicMemberProfile for member %s fetched", member_id)

    # Step 4: fetch full profile to discover extra fields (e.g. member number)
    r2 = requests.get(
        f"https://ws.yourmembership.com/Ams/{YM_CLIENT_ID}/Member/{member_id}/MemberProfile",
        headers={"X-SS-ID": session_id, "Accept": "application/json"},
        timeout=15,
    )
    full_profile = r2.json() if r2.ok else {}
    log.info("YM MemberProfile for member %s fetched (ok=%s)", member_id, r2.ok)

    # YM field names vary — try the most common ones
    email = (
        profile.get("EmailAddress")
        or profile.get("Email")
        or profile.get("PrimaryEmail")
        or ""
    )
    first = profile.get("FirstName") or profile.get("First") or ""
    last  = profile.get("LastName")  or profile.get("Last")  or ""
    name  = f"{first} {last}".strip() or f"Member {member_id}"

    # Helper: pull a value from any CustomFieldValues list by FieldCode
    def _custom_field(field_code):
        for section in (
            full_profile.get("ReadOnlyProperties") or {},
            full_profile.get("PersonalInformation") or {},
            full_profile.get("ProfessionalInformation") or {},
        ):
            for field in section.get("CustomFieldValues") or []:
                if field.get("FieldCode") == field_code:
                    values = field.get("Values") or []
                    return values[0].get("Value", "") if values else ""
        return ""

    # Is the membership current? (decided here, enforced in callback())
    is_current, reason, detail = _membership_status(
        full_profile, _custom_field("nssmemberexpiration"))
    log.info("member_check mode=%s result=%s reason=%s type=%s expires_flag=%s "
             "custom_vs_account=%s", MEMBER_CHECK,
             "allow" if is_current else "deny", reason, detail["type"],
             detail["expires_flag"], detail["custom_vs_account"])
    identity = {"sub": str(member_id), "email": email, "name": name}
    if MEMBER_CHECK == "enforce" and not is_current:
        return identity, (False, reason)   # don't cache a lapsed member's profile

    # Extract structured profile data and cache for checkout plugin
    acct    = full_profile.get("AccountInformation") or {}
    personal = full_profile.get("PersonalInformation") or {}

    nss_number = acct.get("ConstituentID") or _custom_field("nssnumber") or ""
    grotto     = _custom_field("GrottoAffiliation")

    # Expiration: prefer the custom field date string; fall back to AccountInformation
    exp_raw    = _custom_field("nssmemberexpiration") or acct.get("MembershipExpiresDate") or ""
    expiration = exp_raw[:10] if exp_raw else ""  # trim to YYYY-MM-DD if ISO datetime

    # Home address from PersonalInformation
    addr_parts = []
    line1 = personal.get("HomeAddressLine1", "")
    line2 = personal.get("HomeAddressLine2", "")
    city    = personal.get("HomeAddressCity", "")
    state   = personal.get("HomeAddressLocation", "")
    zipcode = personal.get("HomeAddressPostalCode", "")
    country = personal.get("HomeAddressCountry", "")
    if line1:
        addr_parts.append(line1)
    if line2:
        addr_parts.append(line2)
    city_state_zip = ", ".join(filter(None, [city, state, zipcode]))
    if city_state_zip:
        addr_parts.append(city_state_zip)
    if country and country != "United States":
        addr_parts.append(country)
    address = "\n".join(addr_parts)

    _store("ym_profile", str(member_id), {
        "nss_number":    str(nss_number),
        "nss_name":      name,
        "nss_grotto":    str(grotto),
        "nss_expiration": str(expiration),
        "nss_address":   address,
    }, ttl=86400)
    log.info("Cached YM profile for member %s (nss=%s)", member_id, nss_number)

    return identity, (is_current, reason)


# ── OIDC Discovery ─────────────────────────────────────────────────────────

@app.route(f"{URL_PREFIX}/.well-known/openid-configuration")
def discovery():
    p = URL_PREFIX
    return jsonify({
        "issuer":                                ISSUER,
        "authorization_endpoint":               f"{ISSUER}/auth",
        "token_endpoint":                        f"{ISSUER}/token",
        "userinfo_endpoint":                     f"{ISSUER}/userinfo",
        "jwks_uri":                              f"{ISSUER}/jwks",
        "response_types_supported":             ["code"],
        "subject_types_supported":              ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported":                     ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_post",
            "client_secret_basic",
        ],
        "claims_supported": ["sub", "iss", "aud", "iat", "exp", "email", "name"],
    })


@app.route(f"{URL_PREFIX}/jwks")
def jwks():
    pub = dict(_public_key.as_dict())
    pub["use"] = "sig"
    pub["kid"] = _KID
    return jsonify({"keys": [pub]})


# ── Authorization endpoint ─────────────────────────────────────────────────

@app.route(f"{URL_PREFIX}/auth")
def auth():
    if request.args.get("client_id") != CLIENT_ID:
        abort(400, "unknown client_id")
    if request.args.get("response_type") != "code":
        abort(400, "only response_type=code is supported")

    redirect_uri = request.args.get("redirect_uri", "")
    if not _validate_redirect_uri(redirect_uri):
        abort(400, "redirect_uri not allowed")

    # Stash Pretix's redirect_uri / state / nonce in the signed session cookie
    session["oidc_redirect_uri"] = redirect_uri
    session["oidc_state"]        = request.args.get("state", "")
    session["oidc_nonce"]        = request.args.get("nonce", "")
    session["oidc_flow_started"] = int(time.time())

    ym_auth_url = (
        f"{YM_SITE_URL}/lock.aspx"
        f"?app_id={YM_APP_ID}"
        f"&redirect_uri={MY_CALLBACK}"
        f"&scope=basic_profile,full_profile"
    )
    return redirect(ym_auth_url)


# ── YM callback ────────────────────────────────────────────────────────────

@app.route(f"{URL_PREFIX}/callback")
def callback():
    ym_code = request.args.get("code")
    if not ym_code:
        log.error("YM callback missing code param; args=%s", dict(request.args))
        abort(400, "missing code")

    # Only accept a code in a browser that started a login flow here, and
    # only once. Without this, an attacker can hand a victim a callback URL
    # carrying the attacker's own YM code and log the victim in as them.
    flow_started = session.pop("oidc_flow_started", None)
    if not flow_started or time.time() - flow_started > _FLOW_TTL:
        log.warning("YM callback with no pending login flow; rejecting")
        abort(400, "no login in progress")

    try:
        identity, (is_current, reason) = _ym_exchange_code(ym_code)
    except Exception as exc:
        log.exception("YM auth exchange failed: %s", exc)
        abort(502, "upstream authentication error")

    if MEMBER_CHECK == "enforce" and not is_current:
        for k in ("oidc_redirect_uri", "oidc_next", "oidc_nonce", "oidc_state"):
            session.pop(k, None)
        return _not_current_response(reason)

    pretix_redirect_uri = session.pop("oidc_redirect_uri", "")
    next_url            = session.pop("oidc_next", "")

    if pretix_redirect_uri:
        # OIDC flow (Pretix login button) — issue auth code and redirect back
        oidc_code = secrets.token_urlsafe(32)
        _store("code", oidc_code, {
            **identity,
            "nonce":        session.pop("oidc_nonce", ""),
            "redirect_uri": pretix_redirect_uri,
        }, ttl=300)
        state = session.pop("oidc_state", "")
        sep   = "&" if "?" in pretix_redirect_uri else "?"
        resp  = make_response(redirect(f"{pretix_redirect_uri}{sep}code={oidc_code}&state={state}"))
    else:
        # Direct access flow (Caddy gate) — redirect to original URL
        session.pop("oidc_nonce", None)
        session.pop("oidc_state", None)
        resp = make_response(redirect(_safe_next(next_url)))

    _set_browser_session(identity, resp)
    return resp


# ── Token endpoint ─────────────────────────────────────────────────────────

@app.route(f"{URL_PREFIX}/token", methods=["POST"])
def token():
    # Accept credentials from both HTTP Basic auth and POST body
    client_id, client_secret = None, None
    if request.authorization:
        client_id     = request.authorization.username
        client_secret = request.authorization.password
    else:
        client_id     = request.form.get("client_id")
        client_secret = request.form.get("client_secret")

    if client_id != CLIENT_ID or not hmac.compare_digest(client_secret or "", CLIENT_SECRET):
        return jsonify({"error": "invalid_client"}), 401

    grant_type = request.form.get("grant_type")
    if grant_type != "authorization_code":
        return jsonify({"error": "unsupported_grant_type"}), 400

    code  = request.form.get("code", "")
    entry = _pop("code", code)
    if entry is None:
        return jsonify({"error": "invalid_grant"}), 400

    # RFC 6749 §4.1.3: redirect_uri must match the one used at authorization
    if entry.get("redirect_uri") and request.form.get("redirect_uri") != entry["redirect_uri"]:
        return jsonify({"error": "invalid_grant", "error_description": "redirect_uri mismatch"}), 400

    now = int(time.time())
    claims: dict = {
        "iss":   ISSUER,
        "sub":   entry["sub"],
        "aud":   CLIENT_ID,
        "iat":   now,
        "exp":   now + 3600,
        "email": entry["email"],
        "name":  entry["name"],
    }
    if entry.get("nonce"):
        claims["nonce"] = entry["nonce"]

    header   = {"alg": "RS256", "kid": _KID}
    id_token = jwt.encode(header, claims, _private_key)
    # authlib returns bytes in some versions, str in others
    if isinstance(id_token, bytes):
        id_token = id_token.decode()

    access_token = secrets.token_urlsafe(32)
    _store("token", access_token, {
        "sub":   entry["sub"],
        "email": entry["email"],
        "name":  entry["name"],
    }, ttl=3600)

    return jsonify({
        "access_token": access_token,
        "token_type":   "Bearer",
        "expires_in":   3600,
        "id_token":     id_token,
    })


# ── UserInfo endpoint ──────────────────────────────────────────────────────

@app.route(f"{URL_PREFIX}/userinfo")
def userinfo():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        abort(401)
    bearer = auth_header[7:]
    entry  = _get("token", bearer)
    if entry is None:
        abort(401)
    return jsonify({
        "sub":   entry["sub"],
        "email": entry["email"],
        "name":  entry["name"],
    })


# ── Caddy forward_auth gate ────────────────────────────────────────────────

@app.route(f"{URL_PREFIX}/check")
def check():
    """
    Called by Caddy forward_auth on every gated request.
    200 → let through. 302 → send browser to YM login first.
    """
    identity = _get_browser_session()
    if identity:
        resp = make_response("", 200)
        resp.headers["X-YM-Sub"]   = identity.get("sub", "")
        resp.headers["X-YM-Email"] = identity.get("email", "")
        return resp

    # Preserve the original URL so we can return after login
    next_url = request.headers.get("X-Forwarded-Uri", "/")
    return redirect(f"{URL_PREFIX}/login?next={quote(next_url, safe='')}", 302)


@app.route(f"{URL_PREFIX}/login")
def login():
    """Initiate YM auth for direct access (not the OIDC code flow)."""
    session["oidc_next"]         = _safe_next(request.args.get("next", "/"))
    session["oidc_redirect_uri"] = ""  # signals direct-access flow to /callback
    session["oidc_nonce"]        = ""
    session["oidc_state"]        = ""
    session["oidc_flow_started"] = int(time.time())

    ym_auth_url = (
        f"{YM_SITE_URL}/lock.aspx"
        f"?app_id={YM_APP_ID}"
        f"&redirect_uri={MY_CALLBACK}"
        f"&scope=basic_profile,full_profile"
    )
    return redirect(ym_auth_url)


# ── Health check ───────────────────────────────────────────────────────────

@app.route("/health")
def health():
    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5557, debug=False)
