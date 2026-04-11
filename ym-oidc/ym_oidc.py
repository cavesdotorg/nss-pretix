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
import hmac
import secrets
import logging
from urllib.parse import urlparse

import redis
import requests
from flask import Flask, abort, jsonify, redirect, request, session
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


def _ym_exchange_code(code: str) -> dict:
    """
    Run YM's 3-step flow: code → access token → session → profile.
    Returns a dict with keys: sub, email, name.
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

    # Step 3: fetch the member's basic profile
    r = requests.get(
        f"https://ws.yourmembership.com/Ams/{YM_CLIENT_ID}/Member/{member_id}/BasicMemberProfile",
        headers={"X-SS-ID": session_id, "Accept": "application/json"},
        timeout=15,
    )
    r.raise_for_status()
    profile = r.json()

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

    return {"sub": str(member_id), "email": email, "name": name}


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

    ym_auth_url = (
        f"{YM_SITE_URL}/lock.aspx"
        f"?app_id={YM_APP_ID}"
        f"&redirect_uri={MY_CALLBACK}"
        f"&scope=basic_profile"
    )
    return redirect(ym_auth_url)


# ── YM callback ────────────────────────────────────────────────────────────

@app.route(f"{URL_PREFIX}/callback")
def callback():
    ym_code = request.args.get("code")
    if not ym_code:
        log.error("YM callback missing code param; args=%s", dict(request.args))
        abort(400, "missing code")

    try:
        identity = _ym_exchange_code(ym_code)
    except Exception as exc:
        log.exception("YM auth exchange failed: %s", exc)
        abort(502, "upstream authentication error")

    oidc_code = secrets.token_urlsafe(32)
    _store("code", oidc_code, {
        **identity,
        "nonce":        session.pop("oidc_nonce", ""),
        "redirect_uri": session.get("oidc_redirect_uri", ""),  # bound for token validation
    }, ttl=300)

    pretix_redirect_uri = session.pop("oidc_redirect_uri", "")
    state               = session.pop("oidc_state", "")

    sep = "&" if "?" in pretix_redirect_uri else "?"
    return redirect(f"{pretix_redirect_uri}{sep}code={oidc_code}&state={state}")


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


# ── Health check ───────────────────────────────────────────────────────────

@app.route("/health")
def health():
    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5557, debug=False)
