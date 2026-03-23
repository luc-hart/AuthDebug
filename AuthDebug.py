import base64
import hashlib
import json
import os
import urllib.parse
from http import HTTPStatus
from datetime import datetime, timezone
import uuid
import xml.etree.ElementTree as ET
from flask import Flask, request, redirect, url_for, render_template_string, session
import requests
from collections import defaultdict

app = Flask(__name__)
app.secret_key = os.environ.get("DEBUGTOOLS_SECRET_KEY", "dev-secret-change-me")

# In-memory debug storage (not suitable for production, but useful for local debugging)
DEBUG_STORE = {
    "oauth2_auth_flows": {},      # flow_id -> dict
    "oauth2_token_flows": {},     # flow_id -> dict
    "saml_authn_flows": {},       # flow_id -> dict
}

# =======================
# Base HTML template
# =======================
BASE_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Auth Debug Tools</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1, h2, h3 { color: #333; }
        label { display: block; margin-top: 8px; }
        input[type=text], input[type=password] { width: 100%%; padding: 6px; box-sizing: border-box; }
        select { padding: 4px; }
        .section { border: 1px solid #ccc; padding: 15px; margin-bottom: 20px; border-radius: 4px; }
        .btn { margin-top: 10px; padding: 6px 12px; }
        .small { font-size: 12px; color: #666; }
        .debug-box { background: #f7f7f7; padding: 10px; border-radius: 4px; border: 1px solid #ddd; }
        .error { color: #b30000; }
        .success { color: #006600; }
        .nav { margin-bottom: 20px; }
        .nav a { margin-right: 15px; }
        pre { white-space: pre-wrap; word-break: break-all; }
        textarea { width: 100%%; height: 200px; font-family: monospace; font-size: 12px; }
    </style>
</head>
<body>
<div class="nav">
    <strong>Debug Tools</strong>:
    <a href="{{ url_for('index') }}">Home</a>
    <a href="{{ url_for('oauth2_tool') }}">OAuth2 / OIDC Debugger</a>
    <a href="{{ url_for('saml_tool') }}">SAML Debugger</a>
</div>
%s
</body>
</html>
"""

INDEX_CONTENT = r"""
<h1>Auth Debug Tools</h1>
<ul>
    <li><a href="{{ url_for('oauth2_tool') }}">OAuth2 / OIDC Debugger</a></li>
    <li><a href="{{ url_for('saml_tool') }}">SAML Debugger</a></li>
</ul>
"""

# =======================
# OAuth2 / OIDC UI
# =======================
OAUTH2_CONTENT = r"""
<h1>OAuth2 / OIDC Debugger</h1>
<div class="section">
  <h2>1. Profiles & Configuration</h2>
  <form method="post" action="{{ url_for('oauth2_tool') }}">
    <h3>Select profile</h3>
    <label>Current profile:
      <select name="load_profile_name">
        <option value="">-- (none / ad-hoc config) --</option>
        {% for pname in profile_names %}
          <option value="{{ pname }}" {% if pname == current_profile_name %}selected{% endif %}>{{ pname }}</option>
        {% endfor %}
      </select>
    </label>
    <button type="submit" name="action" value="load_profile" class="btn">Load profile</button>
    {% if current_profile_name %}
      <p class="small">Active profile: <strong>{{ current_profile_name }}</strong></p>
    {% else %}
      <p class="small"><em>No profile selected (ad-hoc config).</em></p>
    {% endif %}
  </form>
  <hr>
  <h3>OAuth2 / OIDC parameters</h3>
  <form method="post" action="{{ url_for('oauth2_tool') }}">
    <label>Authorization endpoint URL
      <input type="text" name="authorization_endpoint" value="{{ config.authorization_endpoint or '' }}" required>
    </label>
    <label>Token endpoint URL
      <input type="text" name="token_endpoint" value="{{ config.token_endpoint or '' }}" required>
    </label>
    <label>Client ID
      <input type="text" name="client_id" value="{{ config.client_id or '' }}" required>
    </label>
    <label>Client Secret (optional)
      <input type="password" name="client_secret" value="{{ config.client_secret or '' }}">
    </label>
    <label>Redirect URI
      <input type="text" name="redirect_uri" value="{{ config.redirect_uri or '' }}" required>
    </label>
    <label>Scopes (space-separated)
      <input type="text" name="scopes" value="{{ ' '.join(config.scopes) if config.scopes else '' }}">
    </label>
    <label>
      <input type="checkbox" name="use_pkce" value="1" {% if config.use_pkce %}checked{% endif %}>
      Use PKCE (S256)
    </label>
    <button type="submit" name="action" value="save_config" class="btn">Save config (active, not as profile)</button>
    <h4>Save current config as profile</h4>
    <label>Profile name
      <input type="text" name="profile_name" value="{{ current_profile_name or '' }}" placeholder="e.g. Azure-Dev, Azure-Prod">
    </label>
    <button type="submit" name="action" value="save_profile" class="btn">Save / overwrite profile</button>
  </form>
  <p class="small">
    Profiles are stored in the browser session. For a new session you must recreate them,
    unless you add a server-side store.
  </p>
</div>
<div class="section">
  <h2>2. Authorization Code step</h2>
  {% if not config.client_id or not config.authorization_endpoint or not config.redirect_uri %}
    <p class="error">Configure Authorization endpoint, Client ID and Redirect URI first.</p>
  {% else %}
    <form method="post" action="{{ url_for('start_oauth2_flow') }}">
      <button type="submit" class="btn">Start Authorization Request</button>
    </form>
    {% if last_auth_flow %}
      <h3>Authorization Request</h3>
      <div class="debug-box">
        <strong>Request URL:</strong>
        <pre>{{ last_auth_flow.request_url }}</pre>
        <strong>Request parameters:</strong>
        <pre>{{ last_auth_flow.request_params_pretty }}</pre>
        {% if last_auth_flow.state %}
          <strong>STATE:</strong> {{ last_auth_flow.state }}<br>
        {% endif %}
        {% if last_auth_flow.code_verifier %}
          <strong>CODE_VERIFIER (PKCE):</strong> {{ last_auth_flow.code_verifier }}<br>
        {% endif %}
      </div>
      {% if last_auth_flow.response_query_pretty %}
        <h3>Authorization Response (callback)</h3>
        <div class="debug-box">
          <strong>Callback query parameters (response):</strong>
          <pre>{{ last_auth_flow.response_query_pretty }}</pre>
        </div>
      {% endif %}
    {% endif %}
  {% endif %}
</div>
<div class="section">
  <h2>3. Token Request / Response</h2>
  {% if last_token_exchange %}
    {% if last_token_exchange.error %}
      <p class="error"><strong>Token request failed.</strong></p>
    {% else %}
      <p class="success"><strong>Token request succeeded.</strong></p>
    {% endif %}
    <div class="debug-box">
      <h3>Token Request</h3>
      <pre>{{ last_token_exchange.request_pretty }}</pre>
      <h3>Token Response</h3>
      <pre>{{ last_token_exchange.response_pretty }}</pre>
      {% if last_token_exchange.id_token_raw %}
        <h3>Decoded ID Token</h3>
        <p class="small">No signature validation, for inspection only.</p>
        <strong>ID Token:</strong>
        <pre>{{ last_token_exchange.id_token_raw }}</pre>
        {% if last_token_exchange.id_token_header_pretty %}
          <strong>Header:</strong>
          <pre>{{ last_token_exchange.id_token_header_pretty }}</pre>
        {% endif %}
        {% if last_token_exchange.id_token_payload_pretty %}
          <strong>Payload (claims):</strong>
          <pre>{{ last_token_exchange.id_token_payload_pretty }}</pre>
        {% endif %}
        {% if last_token_exchange.id_token_error %}
          <p class="error">Error decoding ID Token: {{ last_token_exchange.id_token_error }}</p>
        {% endif %}
      {% endif %}
      {% if last_token_exchange.access_token_preview %}
        <h3>Access Token</h3>
        <p class="small">Full access token (note: sensitive data!).</p>
        <pre>{{ last_token_exchange.access_token_preview }}</pre>
      {% endif %}
    </div>
  {% else %}
    <p class="small">No token request executed yet in this session.</p>
  {% endif %}
</div>
"""

# =======================
# SAML UI
# =======================
SAML_CONTENT = r"""
<h1>SAML Debugger</h1>
<div class="section">
  <h2>1. Profiles & Configuration</h2>
  <form method="post" action="{{ url_for('saml_tool') }}">
    <h3>Select profile</h3>
    <label>Current SAML profile:
      <select name="load_profile_name">
        <option value="">-- (none / ad-hoc config) --</option>
        {% for pname in profile_names %}
          <option value="{{ pname }}" {% if pname == current_profile_name %}selected{% endif %}>{{ pname }}</option>
        {% endfor %}
      </select>
    </label>
    <button type="submit" name="action" value="load_profile" class="btn">Load profile</button>
    {% if current_profile_name %}
      <p class="small">Active profile: <strong>{{ current_profile_name }}</strong></p>
    {% else %}
      <p class="small"><em>No profile selected (ad-hoc config).</em></p>
    {% endif %}
  </form>
  <hr>
  <h3>SAML parameters</h3>
  <form method="post" action="{{ url_for('saml_tool') }}">
    <label>IdP SSO URL (HTTP-Redirect)
      <input type="text" name="idp_sso_url" value="{{ config.idp_sso_url or '' }}" required>
    </label>
    <label>SP EntityID (Issuer)
      <input type="text" name="sp_entity_id" value="{{ config.sp_entity_id or '' }}" required>
    </label>
    <label>Assertion Consumer Service (ACS) URL
      <input type="text" name="acs_url" value="{{ config.acs_url or '' }}" required>
    </label>
    <label>Requested NameID Format (optional)
      <input type="text" name="nameid_format" value="{{ config.nameid_format or '' }}" placeholder="e.g. urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
    </label>
    <button type="submit" name="action" value="save_config" class="btn">Save config (active, not as profile)</button>
    <h4>Save current config as SAML profile</h4>
    <label>Profile name
      <input type="text" name="profile_name" value="{{ current_profile_name or '' }}" placeholder="e.g. ADFS-Test, AzureAD-SAML">
    </label>
    <button type="submit" name="action" value="save_profile" class="btn">Save / overwrite profile</button>
  </form>
  <p class="small">
    Profiles are stored in the browser session. For a new session you must recreate them,
    unless you add a server-side store.
  </p>
</div>
<div class="section">
  <h2>2. AuthnRequest step</h2>
  {% if not config.idp_sso_url or not config.sp_entity_id or not config.acs_url %}
    <p class="error">Configure IdP SSO URL, SP EntityID and ACS URL first.</p>
  {% else %}
    <form method="post" action="{{ url_for('start_saml_flow') }}">
      <button type="submit" class="btn">Start SAML AuthnRequest (HTTP-Redirect)</button>
    </form>
    {% if last_authn_flow %}
      <h3>SAML AuthnRequest (request)</h3>
      <div class="debug-box">
        <strong>AuthnRequest XML:</strong>
        <pre>{{ last_authn_flow.authn_request_xml }}</pre>
        <strong>AuthnRequest (DEFLATE + Base64, SAMLRequest parameter):</strong>
        <pre>{{ last_authn_flow.saml_request_param }}</pre>
        <strong>Redirect URL:</strong>
        <pre>{{ last_authn_flow.redirect_url }}</pre>
      </div>
      {% if last_authn_flow.response_present %}
        <h3>SAML Response (callback)</h3>
        <div class="debug-box">
          <strong>Raw POST fields (response):</strong>
          <pre>{{ last_authn_flow.response_form_pretty }}</pre>
          {% if last_authn_flow.saml_response_xml %}
            <strong>Decoded SAMLResponse (XML):</strong>
            <pre>{{ last_authn_flow.saml_response_xml }}</pre>
          {% endif %}
          {% if last_authn_flow.saml_response_summary_pretty %}
            <strong>Main elements (parsed):</strong>
            <pre>{{ last_authn_flow.saml_response_summary_pretty }}</pre>
          {% endif %}
        </div>
      {% endif %}
    {% endif %}
  {% endif %}
</div>
"""

# =======================
# Generic helpers
# =======================
def _new_flow_id() -> str:
    return str(uuid.uuid4())

# ---------- OAuth2 helpers ----------
def _get_profiles():
    """Return dict of OAuth profile name -> config dict."""
    return session.get("oauth2_profiles", {})

def _save_profiles(profiles: dict):
    session["oauth2_profiles"] = profiles
    session.modified = True

def get_oauth_config():
    cfg = session.get("oauth2_config", {})
    return type("Cfg", (), {
        "authorization_endpoint": cfg.get("authorization_endpoint", ""),
        "token_endpoint": cfg.get("token_endpoint", ""),
        "client_id": cfg.get("client_id", ""),
        "client_secret": cfg.get("client_secret", ""),
        "redirect_uri": cfg.get("redirect_uri", "http://localhost:5000/callback"),
        "scopes": cfg.get("scopes", ["openid", "profile"]),
        "use_pkce": cfg.get("use_pkce", True),
    })

def _raw_config_from_form(form):
    scopes_str = form.get("scopes", "").strip()
    scopes = scopes_str.split() if scopes_str else []
    return {
        "authorization_endpoint": form.get("authorization_endpoint", "").strip(),
        "token_endpoint": form.get("token_endpoint", "").strip(),
        "client_id": form.get("client_id", "").strip(),
        "client_secret": form.get("client_secret", "").strip(),
        "redirect_uri": form.get("redirect_uri", "").strip(),
        "scopes": scopes or ["openid", "profile"],
        "use_pkce": bool(form.get("use_pkce")),
    }

def save_oauth_config(cfg_dict: dict):
    session["oauth2_config"] = cfg_dict
    session.modified = True

def load_profile_to_active_config(profile_name: str):
    profiles = _get_profiles()
    cfg = profiles.get(profile_name)
    if cfg:
        save_oauth_config(cfg)
        session["oauth2_current_profile_name"] = profile_name
        session.modified = True

def save_profile_from_active_config(profile_name: str):
    if not profile_name:
        return
    profiles = _get_profiles()
    cfg = session.get("oauth2_config", {})
    profiles[profile_name] = cfg
    _save_profiles(profiles)
    session["oauth2_current_profile_name"] = profile_name
    session.modified = True

def generate_code_verifier():
    return base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("ascii")

def generate_code_challenge(verifier):
    import hashlib as _hashlib
    digest = _hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")

def _base64url_decode(input_str):
    rem = len(input_str) % 4
    if rem:
        input_str += "=" * (4 - rem)
    return base64.urlsafe_b64decode(input_str.encode("ascii"))

def decode_id_token(id_token):
    try:
        parts = id_token.split(".")
        if len(parts) != 3:
            return None, None, "JWT does not have 3 parts (header.payload.signature)"
        header_b64, payload_b64, _ = parts
        header_json = _base64url_decode(header_b64).decode("utf-8")
        payload_json = _base64url_decode(payload_b64).decode("utf-8")
        return json.loads(header_json), json.loads(payload_json), None
    except Exception as e:
        return None, None, str(e)

def build_authorization_url(cfg):
    oauth_state = base64.urlsafe_b64encode(os.urandom(16)).decode("ascii")
    params = {
        "response_type": "code",
        "client_id": cfg.client_id,
        "redirect_uri": cfg.redirect_uri,
        "scope": " ".join(cfg.scopes),
        "state": oauth_state,
    }
    code_verifier = None
    if cfg.use_pkce:
        code_verifier = generate_code_verifier()
        code_challenge = generate_code_challenge(code_verifier)
        params["code_challenge"] = code_challenge
        params["code_challenge_method"] = "S256"
    query = urllib.parse.urlencode(params)
    url = f"{cfg.authorization_endpoint}?{query}"
    # Generate new flow_id and only store id in session
    flow_id = _new_flow_id()
    session["oauth2_state"] = oauth_state
    session["oauth2_code_verifier"] = code_verifier
    session["oauth2_last_auth_flow_id"] = flow_id
    DEBUG_STORE["oauth2_auth_flows"][flow_id] = {
        "request_url": url,
        "request_params": params,   # full params
        "state": oauth_state,
        "code_verifier": code_verifier,
        "response_query": None,
    }
    session.modified = True
    return url

def exchange_code_for_token(cfg, code, received_state):
    expected_state = session.get("oauth2_state")
    code_verifier = session.get("oauth2_code_verifier")
    state_debug = {
        "received_code": code,
        "received_state": received_state,
        "expected_state": expected_state,
    }
    token_flow_id = _new_flow_id()
    session["oauth2_last_token_flow_id"] = token_flow_id
    if received_state != expected_state:
        state_debug["state_mismatch"] = True
        DEBUG_STORE["oauth2_token_flows"][token_flow_id] = {
            "error": True,
            "request": {"state_debug": state_debug},
            "response": {"error": "state_mismatch", "description": "State does not match"},
            "id_token_raw": None,
            "id_token_header": None,
            "id_token_payload": None,
            "id_token_error": None,
            "access_token_preview": None,
        }
        session.modified = True
        return None
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": cfg.redirect_uri,
        "client_id": cfg.client_id,
    }
    if cfg.use_pkce and code_verifier:
        data["code_verifier"] = code_verifier
    headers = {"Content-Type": "application/x-www-form-urlencoded"}
    auth = (cfg.client_id, cfg.client_secret) if cfg.client_secret else None
    resp = requests.post(cfg.token_endpoint, data=data, auth=auth, headers=headers)
    try:
        body_json = resp.json()
    except Exception:
        body_json = {"raw_text": resp.text}
    request_dump = {
        "token_endpoint": cfg.token_endpoint,
        "auth_type": "client_secret_basic" if cfg.client_secret else "public_client",
        "form_params": data,       # full params
        "state_debug": state_debug,
    }
    response_dump = {
        "http_status": resp.status_code,
        "body": body_json,         # full body
    }
    id_token_raw_full = body_json.get("id_token") if isinstance(body_json, dict) else None
    id_header, id_payload, id_error = (None, None, None)
    if id_token_raw_full:
        id_header, id_payload, id_error = decode_id_token(id_token_raw_full)
    DEBUG_STORE["oauth2_token_flows"][token_flow_id] = {
        "error": resp.status_code != HTTPStatus.OK,
        "request": request_dump,
        "response": response_dump,
        "id_token_raw": id_token_raw_full,   # full
        "id_token_header": id_header,
        "id_token_payload": id_payload,
        "id_token_error": id_error,
        "access_token_preview": body_json.get("access_token") if isinstance(body_json, dict) else None,
    }
    session.modified = True
    return body_json if resp.status_code == HTTPStatus.OK else None

# ---------- SAML helpers ----------
def _get_saml_profiles():
    """Return dict of SAML profile name -> config dict."""
    return session.get("saml_profiles", {})

def _save_saml_profiles(profiles: dict):
    session["saml_profiles"] = profiles
    session.modified = True

def get_saml_config():
    cfg = session.get("saml_config", {})
    return type("SamlCfg", (), {
        "idp_sso_url": cfg.get("idp_sso_url", ""),
        "sp_entity_id": cfg.get("sp_entity_id", ""),
        "acs_url": cfg.get("acs_url", "http://localhost:5000/saml/acs"),
        "nameid_format": cfg.get("nameid_format", ""),
    })

def _raw_saml_config_from_form(form):
    return {
        "idp_sso_url": form.get("idp_sso_url", "").strip(),
        "sp_entity_id": form.get("sp_entity_id", "").strip(),
        "acs_url": form.get("acs_url", "").strip(),
        "nameid_format": form.get("nameid_format", "").strip(),
    }

def save_saml_config(cfg_dict: dict):
    session["saml_config"] = cfg_dict
    session.modified = True

def load_saml_profile_to_active_config(profile_name: str):
    profiles = _get_saml_profiles()
    cfg = profiles.get(profile_name)
    if cfg:
        save_saml_config(cfg)
        session["saml_current_profile_name"] = profile_name
        session.modified = True

def save_saml_profile_from_active_config(profile_name: str):
    if not profile_name:
        return
    profiles = _get_saml_profiles()
    cfg = session.get("saml_config", {})
    profiles[profile_name] = cfg
    _save_saml_profiles(profiles)
    session["saml_current_profile_name"] = profile_name
    session.modified = True

def build_saml_authn_request_xml(cfg):
    issue_instant = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    request_id = "_" + str(uuid.uuid4())
    # Simple, unsigned AuthnRequest
    root = ET.Element(
        "{urn:oasis:names:tc:SAML:2.0:protocol}AuthnRequest",
        {
            "ID": request_id,
            "Version": "2.0",
            "IssueInstant": issue_instant,
            "Destination": cfg.idp_sso_url,
            "ProtocolBinding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            "AssertionConsumerServiceURL": cfg.acs_url,
        },
    )
    issuer = ET.SubElement(root, "{urn:oasis:names:tc:SAML:2.0:assertion}Issuer")
    issuer.text = cfg.sp_entity_id
    if cfg.nameid_format:
        ET.SubElement(
            root, "{urn:oasis:names:tc:SAML:2.0:protocol}NameIDPolicy",
            {
                "Format": cfg.nameid_format,
                "AllowCreate": "true",
            },
        )
    requested_context = ET.SubElement(
        root,
        "{urn:oasis:names:tc:SAML:2.0:protocol}RequestedAuthnContext",
        {"Comparison": "exact"},
    )
    class_ref = ET.SubElement(
        requested_context,
        "{urn:oasis:names:tc:SAML:2.0:assertion}AuthnContextClassRef",
    )
    class_ref.text = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
    xml_bytes = ET.tostring(root, encoding="utf-8", xml_declaration=True)
    return xml_bytes.decode("utf-8"), request_id

def deflate_and_base64_encode(data: bytes) -> str:
    import zlib
    # HTTP-Redirect binding: DEFLATE + base64
    compressed = zlib.compress(data)[2:-4]  # raw DEFLATE (without zlib header/footer)
    return base64.b64encode(compressed).decode("ascii")

def decode_samlresponse(b64_data: str) -> str:
    """Decode Base64 SAMLResponse to XML string (without verification)."""
    try:
        decoded = base64.b64decode(b64_data)
        return decoded.decode("utf-8", errors="replace")
    except Exception as e:
        return f"Error during Base64 decoding: {e}"

def parse_saml_response_xml(xml_str: str) -> dict:
    """Very simple parser for some core fields from a SAMLResponse."""
    summary = {}
    try:
        ns = {
            "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
            "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
        }
        root = ET.fromstring(xml_str)
        issuer = root.find(".//saml:Issuer", ns)
        if issuer is not None:
            summary["Issuer"] = issuer.text
        subject = root.find(".//saml:Subject/saml:NameID", ns)
        if subject is not None:
            summary["Subject.NameID"] = subject.text
            fmt = subject.attrib.get("Format")
            if fmt:
                summary["Subject.NameID.Format"] = fmt
        # Attributes
        attrs = {}
        for attr in root.findall(".//saml:Attribute", ns):
            name = attr.attrib.get("Name")
            values = [v.text for v in attr.findall("saml:AttributeValue", ns)]
            attrs[name] = values
        if attrs:
            summary["Attributes"] = attrs
    except Exception as e:
        summary["parse_error"] = str(e)
    return summary

# =======================
# Routes: general index
# =======================
@app.route("/")
def index():
    return render_template_string(BASE_TEMPLATE % INDEX_CONTENT)

# =======================
# OAuth2 routes
# =======================
@app.route("/oauth2", methods=["GET", "POST"])
def oauth2_tool():
    if request.method == "POST":
        action = request.form.get("action")
        if action == "save_config":
            cfg_dict = _raw_config_from_form(request.form)
            save_oauth_config(cfg_dict)
        elif action == "save_profile":
            cfg_dict = _raw_config_from_form(request.form)
            save_oauth_config(cfg_dict)
            profile_name = request.form.get("profile_name", "").strip()
            if profile_name:
                save_profile_from_active_config(profile_name)
        elif action == "load_profile":
            profile_name = request.form.get("load_profile_name", "").strip()
            if profile_name:
                load_profile_to_active_config(profile_name)
            else:
                session.pop("oauth2_current_profile_name", None)
                session.modified = True
    cfg = get_oauth_config()
    profiles = _get_profiles()
    profile_names = sorted(profiles.keys())
    current_profile_name = session.get("oauth2_current_profile_name")
    auth_flow_id = session.get("oauth2_last_auth_flow_id")
    token_flow_id = session.get("oauth2_last_token_flow_id")
    last_auth_flow_raw = DEBUG_STORE["oauth2_auth_flows"].get(auth_flow_id)
    last_token_exchange_raw = DEBUG_STORE["oauth2_token_flows"].get(token_flow_id)
    last_auth_flow = None
    if last_auth_flow_raw:
        class AuthFlowObj:
            request_url = last_auth_flow_raw.get("request_url")
            request_params_pretty = json.dumps(
                last_auth_flow_raw.get("request_params", {}), indent=2, sort_keys=True
            )
            state = last_auth_flow_raw.get("state")
            code_verifier = last_auth_flow_raw.get("code_verifier")
            response_query_pretty = (
                json.dumps(last_auth_flow_raw.get("response_query", {}), indent=2, sort_keys=True)
                if last_auth_flow_raw.get("response_query")
                else None
            )
        last_auth_flow = AuthFlowObj
    last_token_exchange = None
    if last_token_exchange_raw:
        class TokenExObj:
            error = last_token_exchange_raw.get("error")
            request_pretty = json.dumps(
                last_token_exchange_raw.get("request", {}), indent=2, sort_keys=True
            )
            response_pretty = json.dumps(
                last_token_exchange_raw.get("response", {}), indent=2, sort_keys=True
            )
            id_token_raw = last_token_exchange_raw.get("id_token_raw")
            id_token_error = last_token_exchange_raw.get("id_token_error")
            access_token_preview = last_token_exchange_raw.get("access_token_preview")
            id_token_header_pretty = (
                json.dumps(last_token_exchange_raw.get("id_token_header"), indent=2, sort_keys=True)
                if last_token_exchange_raw.get("id_token_header") is not None
                else None
            )
            id_token_payload_pretty = (
                json.dumps(last_token_exchange_raw.get("id_token_payload"), indent=2, sort_keys=True)
                if last_token_exchange_raw.get("id_token_payload") is not None
                else None
            )
        last_token_exchange = TokenExObj
    content = render_template_string(
        OAUTH2_CONTENT,
        config=cfg,
        profile_names=profile_names,
        current_profile_name=current_profile_name,
        last_auth_flow=last_auth_flow,
        last_token_exchange=last_token_exchange,
    )
    return render_template_string(BASE_TEMPLATE % content)

@app.route("/oauth2/start", methods=["POST"])
def start_oauth2_flow():
    cfg = get_oauth_config()
    if not cfg.authorization_endpoint or not cfg.client_id or not cfg.redirect_uri:
        return redirect(url_for("oauth2_tool"))
    auth_url = build_authorization_url(cfg)
    return redirect(auth_url)

@app.route("/callback")
def callback():
    cfg = get_oauth_config()
    error = request.args.get("error")
    flow_id = session.get("oauth2_last_auth_flow_id")
    if flow_id and flow_id in DEBUG_STORE["oauth2_auth_flows"]:
        auth_flow = DEBUG_STORE["oauth2_auth_flows"][flow_id]
    else:
        auth_flow = {}
    # Store full query
    auth_flow["response_query"] = dict(request.args)
    if flow_id:
        DEBUG_STORE["oauth2_auth_flows"][flow_id] = auth_flow
    session.modified = True
    if error:
        error_description = request.args.get("error_description")
        token_flow_id = _new_flow_id()
        session["oauth2_last_token_flow_id"] = token_flow_id
        DEBUG_STORE["oauth2_token_flows"][token_flow_id] = {
            "error": True,
            "request": {
                "error": error,
                "error_description": error_description,
                "auth_response_query": dict(request.args),
            },
            "response": {"error": "authorization_error"},
            "id_token_raw": None,
            "id_token_header": None,
            "id_token_payload": None,
            "id_token_error": None,
            "access_token_preview": None,
        }
        session.modified = True
        return redirect(url_for("oauth2_tool"))
    code = request.args.get("code")
    state = request.args.get("state")
    if not code:
        return "<h1>No code received</h1>", 400
    _ = exchange_code_for_token(cfg, code, state)
    return redirect(url_for("oauth2_tool"))

# =======================
# SAML routes
# =======================
@app.route("/saml", methods=["GET", "POST"])
def saml_tool():
    if request.method == "POST":
        action = request.form.get("action")
        if action == "save_config":
            cfg_dict = _raw_saml_config_from_form(request.form)
            save_saml_config(cfg_dict)
        elif action == "save_profile":
            cfg_dict = _raw_saml_config_from_form(request.form)
            save_saml_config(cfg_dict)
            profile_name = request.form.get("profile_name", "").strip()
            if profile_name:
                save_saml_profile_from_active_config(profile_name)
        elif action == "load_profile":
            profile_name = request.form.get("load_profile_name", "").strip()
            if profile_name:
                load_saml_profile_to_active_config(profile_name)
            else:
                session.pop("saml_current_profile_name", None)
                session.modified = True
    cfg = get_saml_config()
    profiles = _get_saml_profiles()
    profile_names = sorted(profiles.keys())
    current_profile_name = session.get("saml_current_profile_name")
    flow_id = session.get("saml_last_authn_flow_id")
    last_authn_flow_raw = DEBUG_STORE["saml_authn_flows"].get(flow_id)
    last_authn_flow = None
    if last_authn_flow_raw:
        class AuthnFlowObj:
            authn_request_xml = last_authn_flow_raw.get("authn_request_xml")
            saml_request_param = last_authn_flow_raw.get("saml_request_param")
            redirect_url = last_authn_flow_raw.get("redirect_url")
            response_form_pretty = (
                json.dumps(last_authn_flow_raw.get("response_form", {}), indent=2, sort_keys=True)
                if last_authn_flow_raw.get("response_form") else None
            )
            saml_response_xml = last_authn_flow_raw.get("saml_response_xml")
            saml_response_summary_pretty = (
                json.dumps(last_authn_flow_raw.get("saml_response_summary", {}), indent=2, sort_keys=True)
                if last_authn_flow_raw.get("saml_response_summary") else None
            )
            response_present = bool(last_authn_flow_raw.get("response_form"))
        last_authn_flow = AuthnFlowObj
    content = render_template_string(
        SAML_CONTENT,
        config=cfg,
        profile_names=profile_names,
        current_profile_name=current_profile_name,
        last_authn_flow=last_authn_flow,
    )
    return render_template_string(BASE_TEMPLATE % content)

@app.route("/saml/start", methods=["POST"])
def start_saml_flow():
    cfg = get_saml_config()
    if not cfg.idp_sso_url or not cfg.sp_entity_id or not cfg.acs_url:
        return redirect(url_for("saml_tool"))
    # Build AuthnRequest
    authn_xml, req_id = build_saml_authn_request_xml(cfg)
    saml_request = deflate_and_base64_encode(authn_xml.encode("utf-8"))
    params = {
        "SAMLRequest": saml_request,
        # RelayState optional, for debug we can set something simple
        "RelayState": "debugtool",
    }
    query = urllib.parse.urlencode(params)
    redirect_url = f"{cfg.idp_sso_url}?{query}"
    flow_id = _new_flow_id()
    session["saml_last_authn_flow_id"] = flow_id
    DEBUG_STORE["saml_authn_flows"][flow_id] = {
        "authn_request_xml": authn_xml,
        "saml_request_param": saml_request,  # full
        "redirect_url": redirect_url,
        "response_form": None,
        "saml_response_xml": None,
        "saml_response_summary": None,
        "relay_state": None,
    }
    session.modified = True
    return redirect(redirect_url)

@app.route("/saml/acs", methods=["POST"])
def saml_acs():
    """Assertion Consumer Service endpoint for SAMLResponse."""
    form_data = dict(request.form)
    saml_response_b64 = form_data.get("SAMLResponse")
    relay_state = form_data.get("RelayState")
    saml_response_xml_full = None
    summary_full = None
    if saml_response_b64:
        saml_response_xml_full = decode_samlresponse(saml_response_b64)
        summary_full = parse_saml_response_xml(saml_response_xml_full)
    flow_id = session.get("saml_last_authn_flow_id")
    flow = DEBUG_STORE["saml_authn_flows"].get(flow_id, {}) if flow_id else {}
    flow.update(
        {
            "response_form": form_data,                 # full form data
            "saml_response_xml": saml_response_xml_full,
            "saml_response_summary": summary_full,
            "relay_state": relay_state,
        }
    )
    if flow_id:
        DEBUG_STORE["saml_authn_flows"][flow_id] = flow
    session.modified = True
    return redirect(url_for("saml_tool"))

# =======================
# main
# =======================
if __name__ == "__main__":
    # OAuth2 redirect_uri: http://localhost:5000/callback
    # SAML ACS URL:       http://localhost:5000/saml/acs
    app.run(host="localhost", port=5000, debug=True)