# Auth Debug Tools

Flask web app to inspect and debug **OAuth2/OIDC Authorization Code flows (with PKCE)** and **SAML 2.0** flows locally.

## What it does

- **OAuth2 / OIDC**
\ \ - Configure auth endpoint, token endpoint, client ID/secret, redirect URI, scopes, PKCE.
\ \ - Start authorization code flow and inspect:
\ \ \ \ - Authorization URL and parameters
\ \ \ \ - Callback query (`code`, `state`, `error`, …)
\ \ \ \ - Token request and response (JSON)
\ \ \ \ - Decoded ID token header/payload (no signature validation)
\ \ \ \ - Access token value

- **SAML 2.0**
\ \ - Configure IdP SSO URL, SP EntityID, ACS URL, NameID format.
\ \ - Generate unsigned AuthnRequest (XML), encode as `SAMLRequest`, and redirect.
\ \ - Inspect:
\ \ \ \ - AuthnRequest XML and encoded value
\ \ \ \ - Raw POST with `SAMLResponse`
\ \ \ \ - Base64-decoded SAMLResponse XML
\ \ \ \ - Simple parsed summary (issuer, subject, attributes)

Profiles for both protocols are stored in the browser session.

## Requirements

- Python 3.8+
- `flask`
- `requests`

Install:

```bash
pip install flask requests
```

## Run

Assuming the code is in `AuthDebug.py`:

```bash
export DEBUGTOOLS_SECRET_KEY="change-me" # optional but recommended
python AuthDebug.py
```

The app listens on:

- `http://localhost:5000/\`
- OAuth2 redirect URI: `http://localhost:5000/callback\`
- SAML ACS: `http://localhost:5000/saml/acs\`

Open in your browser:

```text
http://localhost:5000/
```

## Security

- Shows full tokens and assertions in the UI.
- No signature or schema validation.
- **For local debugging only**; do not use in production.
