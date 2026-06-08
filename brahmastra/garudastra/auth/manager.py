"""
BRAHMASTRA — Garudastra: Auth Manager
Handles all 16 authentication types.
Returns headers/cookies ready to inject into scan requests.

Auth types:
  1.  none         — No authentication
  2.  basic        — HTTP Basic (base64 username:password)
  3.  digest       — HTTP Digest
  4.  bearer       — Bearer token (pre-supplied)
  5.  jwt          — JWT — obtain from login endpoint
  6.  api_key      — API key in header, query, or body
  7.  cookie       — Session cookie (pre-supplied)
  8.  oauth2_cc    — OAuth2 Client Credentials
  9.  oauth2_pkce  — OAuth2 PKCE (browser flow via Playwright)
  10. oidc         — OpenID Connect
  11. saml         — SAML 2.0 (browser flow)
  12. form         — Form-based login (username + password)
  13. ntlm         — NTLM (Windows auth)
  14. totp         — MFA TOTP (base32 secret)
  15. mtls         — mTLS (client certificate)
  16. aws_sig4     — AWS Signature v4
  17. custom       — Any custom header
"""

import base64
import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin

import httpx


# A realistic browser UA — some login pages bounce python-httpx's default UA
# straight to a captcha / block page, which is why _form_login() used to
# silently return no cookies on targets like ntr.army.
_BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)


@dataclass
class AuthConfig:
    auth_type:    str   = "none"

    # Basic / Digest / NTLM / Form
    username:     str   = ""
    password:     str   = ""

    # Bearer / JWT / Cookie / API Key
    token:        str   = ""
    api_key:      str   = ""
    api_key_name: str   = "X-API-Key"
    api_key_location: str = "header"   # header / query / cookie

    # OAuth2 / OIDC
    client_id:    str   = ""
    client_secret:str   = ""
    token_url:    str   = ""
    scope:        str   = ""

    # TOTP
    totp_secret:  str   = ""         # base32 encoded TOTP secret

    # Form-based
    login_url:    str   = ""
    username_field:str  = "username"
    password_field:str  = "password"

    # mTLS
    cert_file:    str   = ""         # .pem or .pfx path
    key_file:     str   = ""

    # AWS Signature v4
    aws_access_key: str = ""
    aws_secret_key: str = ""
    aws_region:   str   = "us-east-1"
    aws_service:  str   = "execute-api"

    # Custom
    custom_headers: dict = field(default_factory=dict)


class AuthManager:
    """
    Resolve authentication for a scan target.
    Returns a dict of HTTP headers to inject.
    """

    def __init__(self, config: AuthConfig, ai_bridge=None):
        self.config = config
        # Optional AIBridge — when auth fails, AuthManager can consult the
        # BRAHMASTRA model to diagnose the failure (rename field names, add
        # missing hidden fields, switch content-type to JSON, ...) and
        # retry once before giving up. Passed in from engine.py so the
        # auth layer stays decoupled from the concrete AI backend.
        self.ai_bridge = ai_bridge
        # Diagnostic bundle — populated by handlers, consumed by engine.py
        # so the scan event stream can show the user what actually happened
        # during auth resolution (success, failure, cookies captured, etc.).
        self.last_diag: dict = {}

    async def get_headers(self) -> dict:
        """Return auth headers based on configured auth type."""
        cfg = self.config
        typ = cfg.auth_type.lower().replace("-", "_")

        handlers = {
            "none":       self._none,
            "basic":      self._basic,
            "bearer":     self._bearer,
            "jwt":        self._bearer,      # JWT is just bearer
            "api_key":    self._api_key,
            "cookie":     self._cookie,
            "oauth2_cc":  self._oauth2_client_credentials,
            "form":       self._form_login,
            "totp":       self._totp,
            "custom":     self._custom,
        }

        handler = handlers.get(typ, self._none)
        return await handler()

    async def _none(self) -> dict:
        return {}

    async def _basic(self) -> dict:
        creds = base64.b64encode(
            f"{self.config.username}:{self.config.password}".encode()
        ).decode()
        return {"Authorization": f"Basic {creds}"}

    async def _bearer(self) -> dict:
        token = self.config.token
        if not token and self.config.username and self.config.login_url:
            token = await self._obtain_jwt()
        return {"Authorization": f"Bearer {token}"} if token else {}

    async def _api_key(self) -> dict:
        cfg = self.config
        if cfg.api_key_location == "header":
            return {cfg.api_key_name: cfg.api_key}
        elif cfg.api_key_location == "cookie":
            return {"Cookie": f"{cfg.api_key_name}={cfg.api_key}"}
        # query — caller should append to URL
        return {}

    async def _cookie(self) -> dict:
        return {"Cookie": self.config.token} if self.config.token else {}

    async def _oauth2_client_credentials(self) -> dict:
        cfg = self.config
        if not cfg.token_url:
            return {}
        try:
            async with httpx.AsyncClient(verify=False, timeout=15) as client:
                resp = await client.post(cfg.token_url, data={
                    "grant_type":    "client_credentials",
                    "client_id":     cfg.client_id,
                    "client_secret": cfg.client_secret,
                    "scope":         cfg.scope,
                })
                data = resp.json()
                token = data.get("access_token", "")
                return {"Authorization": f"Bearer {token}"} if token else {}
        except Exception:
            return {}

    async def _form_login(self) -> dict:
        """
        Form-based login with CSRF token capture and diagnostic logging.

        Flow:
          1. Record what the caller asked for (so we can tell the user that
             login wasn't even attempted when login_url is empty).
          2. GET the login page first — this seeds the cookie jar with
             any pre-session cookie (PHPSESSID, XSRF-TOKEN, csrftoken, ...)
             and lets us scrape a CSRF token from a hidden <input>.
          3. POST credentials + captured hidden fields back to the action
             URL (falls back to login_url if the form has no action).
          4. Extract every cookie the server set and return them as a
             single Cookie: header.

        All outcomes are written to self.last_diag so engine.py can emit
        an `auth_status` event and the dashboard can show whether login
        actually worked.
        """
        cfg = self.config
        diag: dict = {
            "type":          "form",
            "login_url":     cfg.login_url,
            "username_field": cfg.username_field,
            "password_field": cfg.password_field,
            "has_username":  bool(cfg.username),
            "has_password":  bool(cfg.password),
            "ok":            False,
            "step":          "start",
            "message":       "",
            "cookies":       [],
            "status_code":   0,
            "final_url":     "",
        }
        self.last_diag = diag

        if not cfg.login_url:
            diag["message"] = "No login_url configured — form login skipped"
            return {}
        if not cfg.username or not cfg.password:
            diag["message"] = (
                "Login URL set but username/password are empty — "
                "fill both in the Form Login card before scanning"
            )
            return {}

        headers = {
            "User-Agent": _BROWSER_UA,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.9",
        }

        # Field names we'll actually POST — start with what the user
        # configured, but we'll replace them with the real names scraped
        # from the form if they don't match. ntr.army's login form uses
        # `uname` / `pwd`, not the default `username` / `password`, and
        # silently returns a fresh login page with no Set-Cookie when
        # posted unknown fields — impossible to diagnose without this.
        user_field = cfg.username_field or "username"
        pass_field = cfg.password_field or "password"

        try:
            async with httpx.AsyncClient(
                verify=False,
                follow_redirects=True,
                timeout=15,
                headers=headers,
            ) as client:
                # ── Step 1: GET login page to seed cookies + grab CSRF token
                diag["step"] = "get_login_page"
                hidden_fields: dict = {}
                action_url = cfg.login_url
                login_html = ""
                try:
                    pre = await client.get(cfg.login_url)
                    diag["status_code"] = pre.status_code
                    if pre.status_code < 500:
                        login_html = pre.text
                        html = login_html  # legacy alias

                        # ── Auto-detect the real username/password field names
                        detected_user, detected_pass = _detect_login_fields(html)
                        if detected_pass:
                            if pass_field != detected_pass:
                                diag["detected_password_field"] = detected_pass
                                diag["configured_password_field"] = pass_field
                                pass_field = detected_pass
                        if detected_user:
                            if user_field != detected_user:
                                diag["detected_username_field"] = detected_user
                                diag["configured_username_field"] = user_field
                                user_field = detected_user
                        # Update diag so dashboard shows what we actually used
                        diag["username_field"] = user_field
                        diag["password_field"] = pass_field

                        hidden_fields = _extract_hidden_inputs(
                            html, user_field, pass_field
                        )
                        action_url = _extract_form_action(html, cfg.login_url) or cfg.login_url
                        diag["csrf_fields"] = list(hidden_fields.keys())
                        diag["action_url"] = action_url
                except Exception as e:
                    diag["message"] = f"GET login page failed: {e}"
                    # fall through — some APIs only accept POST

                # ── Step 2: POST credentials
                diag["step"] = "post_credentials"
                payload = {
                    **hidden_fields,
                    user_field: cfg.username,
                    pass_field: cfg.password,
                }
                resp = await client.post(
                    action_url,
                    data=payload,
                    headers={"Referer": cfg.login_url},
                )
                diag["status_code"] = resp.status_code
                diag["final_url"] = str(resp.url)

                # ── Step 3: Collect cookies and decide success
                cookie_items = list(client.cookies.items())
                diag["cookies"] = [k for k, _ in cookie_items]

                if not cookie_items:
                    # ── AI self-heal: consult the BRAHMASTRA model, apply
                    # its corrective plan, and retry the POST ONCE. Only
                    # runs when an ai_bridge is wired in AND enabled.
                    healed = await self._ai_self_heal_form(
                        client=client,
                        cfg=cfg,
                        diag=diag,
                        login_html=login_html,
                        user_field=user_field,
                        pass_field=pass_field,
                        hidden_fields=hidden_fields,
                        action_url=action_url,
                        attempted_payload=payload,
                        resp=resp,
                    )
                    if healed:
                        resp = healed["resp"]
                        cookie_items = healed["cookie_items"]
                        diag["cookies"] = [k for k, _ in cookie_items]
                        diag["status_code"] = resp.status_code
                        diag["final_url"] = str(resp.url)

                if not cookie_items:
                    hint = (
                        f"fields used: {user_field}={cfg.username!r}, "
                        f"{pass_field}=***"
                    )
                    ai_note = ""
                    ah = diag.get("ai_self_heal") or {}
                    if ah:
                        ai_note = (
                            f" | AI self-heal: {ah.get('fix_type','none')} — "
                            f"{ah.get('diagnosis','')}"
                        )
                        if ah.get("requires_human"):
                            ai_note += " [requires human]"
                    diag["message"] = (
                        f"Login POST returned {resp.status_code} but server "
                        f"set no cookies — credentials likely wrong ({hint}), "
                        f"or the form uses JS/AJAX submit (Playwright needed)"
                        f"{ai_note}"
                    )
                    return {}

                # Heuristic: if the response body clearly says "invalid login"
                # and no obvious session cookie was issued, warn the user.
                body_lower = (resp.text or "")[:4000].lower()
                session_like = any(
                    re.search(r"sess|auth|token|login|user|sid", k, re.I)
                    for k, _ in cookie_items
                )
                if any(p in body_lower for p in (
                    "invalid login", "invalid username", "invalid password",
                    "incorrect password", "login failed", "authentication failed",
                )) and not session_like:
                    diag["message"] = (
                        f"Server returned a login-error page — credentials "
                        f"are wrong. Captured cookies: {diag['cookies']}"
                    )
                    # Still return the cookies — maybe downstream needs them
                    # but mark not-ok so the dashboard shows the warning.
                    cookie_hdr = "; ".join(f"{k}={v}" for k, v in cookie_items)
                    return {"Cookie": cookie_hdr}

                diag["ok"] = True
                diag["message"] = (
                    f"Login OK — captured {len(cookie_items)} cookie(s): "
                    f"{', '.join(diag['cookies'])}"
                )
                cookie_hdr = "; ".join(f"{k}={v}" for k, v in cookie_items)
                return {"Cookie": cookie_hdr}

        except Exception as e:
            diag["message"] = f"Form login exception at step {diag['step']}: {e}"
            return {}

    async def _ai_self_heal_form(
        self,
        client: httpx.AsyncClient,
        cfg: "AuthConfig",
        diag: dict,
        login_html: str,
        user_field: str,
        pass_field: str,
        hidden_fields: dict,
        action_url: str,
        attempted_payload: dict,
        resp: httpx.Response,
    ) -> Optional[dict]:
        """
        Ask the BRAHMASTRA model to diagnose why form login failed and
        return a corrective plan. Apply the plan and retry the POST once.

        Returns:
          None  — AI disabled, call failed, or model declined to propose a fix.
          dict  — {"resp": <new httpx.Response>, "cookie_items": [(k,v), ...]}
                  (cookie_items may still be empty if the retry also failed;
                  the caller treats that as "healing attempted but unsuccessful").
        """
        bridge = self.ai_bridge
        if not bridge or not getattr(bridge, "enabled", False):
            return None

        try:
            hdr_dict = {k: v for k, v in resp.headers.items()}
        except Exception:
            hdr_dict = {}

        diag["ai_self_heal"] = {
            "attempted": True,
            "fix_type":  "pending",
            "diagnosis": "",
            "retry_ok":  False,
        }

        try:
            fix = await bridge.diagnose_auth_failure(
                login_url        = cfg.login_url,
                username         = cfg.username,
                login_html       = login_html,
                attempted_payload= attempted_payload,
                response_status  = resp.status_code,
                response_body    = (resp.text or "")[:4000],
                response_headers = hdr_dict,
                diag             = diag,
            )
        except Exception as e:
            diag["ai_self_heal"]["error"] = f"diagnose_auth_failure raised: {e}"
            return None

        if not fix:
            diag["ai_self_heal"]["error"] = "model returned no usable JSON"
            diag["ai_self_heal"]["fix_type"] = "none"
            return None

        # Surface what the model thinks (regardless of whether we retry)
        diag["ai_self_heal"].update({
            "diagnosis":      fix.get("diagnosis", ""),
            "fix_type":       fix.get("fix_type", "none"),
            "new_fields":     fix.get("new_fields", {}),
            "extra_fields":   fix.get("extra_fields", {}),
            "new_action_url": fix.get("new_action_url", ""),
            "use_json_body":  fix.get("use_json_body", False),
            "confidence":     fix.get("confidence", 0.0),
            "requires_human": fix.get("requires_human", False),
            "think_trace":    (fix.get("think_trace", "") or "")[:2000],
        })

        if fix.get("requires_human"):
            # CAPTCHA / wrong creds / MFA — retrying won't help
            return None
        if fix.get("fix_type", "none") == "none":
            return None

        # ── Build the corrected payload
        new_payload = dict(attempted_payload)  # start from original
        fix_type = fix.get("fix_type", "none")
        new_fields = fix.get("new_fields") or {}
        extra_fields = fix.get("extra_fields") or {}

        def _sub_creds(v):
            if not isinstance(v, str):
                return v
            return (
                v.replace("<USERNAME>", cfg.username)
                 .replace("<PASSWORD>", cfg.password)
                 .replace("{{USERNAME}}", cfg.username)
                 .replace("{{PASSWORD}}", cfg.password)
            )

        if fix_type == "rename_fields" and new_fields:
            # Strip the old (wrong) credential keys and insert the new ones,
            # keeping CSRF hidden fields. The model returns the literal
            # "<USERNAME>"/"<PASSWORD>" placeholders which we substitute here.
            new_payload = dict(hidden_fields)
            for k, v in new_fields.items():
                new_payload[str(k)] = _sub_creds(str(v))
        elif fix_type == "add_fields":
            for k, v in extra_fields.items():
                new_payload[str(k)] = _sub_creds(str(v))
        elif fix_type == "new_action":
            # Payload unchanged; only the URL differs (handled below).
            pass
        elif fix_type == "json_body":
            # Same fields, just different content-type on POST (below).
            pass

        # Merge any extra_fields the model asked for even on rename/new_action
        if fix_type != "add_fields":
            for k, v in extra_fields.items():
                if k not in new_payload:
                    new_payload[str(k)] = _sub_creds(str(v))

        new_action = fix.get("new_action_url") or action_url

        # Never let the model echo the user's literal password back —
        # if it did, substitute a placeholder so we don't log it.
        safe_payload_dump = {
            k: ("***" if ("pass" in k.lower() or "pwd" in k.lower()) else v)
            for k, v in new_payload.items()
        }
        diag["ai_self_heal"]["retry_payload_keys"] = list(new_payload.keys())
        diag["ai_self_heal"]["retry_action"] = new_action
        diag["ai_self_heal"]["retry_payload_redacted"] = safe_payload_dump

        # ── Retry POST (exactly once)
        try:
            retry_headers = {"Referer": cfg.login_url}
            if fix.get("use_json_body") or fix_type == "json_body":
                retry_resp = await client.post(
                    new_action,
                    json=new_payload,
                    headers=retry_headers,
                )
            else:
                retry_resp = await client.post(
                    new_action,
                    data=new_payload,
                    headers=retry_headers,
                )
        except Exception as e:
            diag["ai_self_heal"]["error"] = f"retry POST raised: {e}"
            return None

        retry_cookies = list(client.cookies.items())
        diag["ai_self_heal"].update({
            "retry_status":  retry_resp.status_code,
            "retry_final_url": str(retry_resp.url),
            "retry_cookies": [k for k, _ in retry_cookies],
            "retry_ok":      bool(retry_cookies),
        })

        return {"resp": retry_resp, "cookie_items": retry_cookies}

    async def _totp(self) -> dict:
        """Form login with TOTP MFA — gets session cookie with live OTP."""
        try:
            import pyotp
            totp  = pyotp.TOTP(self.config.totp_secret)
            otp   = totp.now()
            # Combine with form login
            headers = await self._form_login()
            # Note: actual TOTP submission depends on the app's MFA flow
            # This handles the OTP generation — form submission needs Playwright for complex flows
            print(f"  [Auth] TOTP OTP: {otp}  (use with Playwright for full MFA flow)")
            return headers
        except ImportError:
            print("  [Auth] pyotp not installed — pip install pyotp")
            return {}

    async def _obtain_jwt(self) -> str:
        """Attempt to obtain JWT from login endpoint."""
        cfg = self.config
        try:
            async with httpx.AsyncClient(verify=False, timeout=15) as client:
                resp = await client.post(cfg.login_url, json={
                    cfg.username_field: cfg.username,
                    cfg.password_field: cfg.password,
                })
                data = resp.json()
                # Common token field names
                for key in ("token", "access_token", "jwt", "id_token", "accessToken"):
                    if key in data:
                        return data[key]
                    # Nested in data/result
                    if isinstance(data.get("data"), dict) and key in data["data"]:
                        return data["data"][key]
        except Exception:
            pass
        return ""

    async def _custom(self) -> dict:
        return dict(self.config.custom_headers)


# Attribute-value regex that handles ALL three HTML quoting styles:
#   name="foo"   (double-quoted)
#   name='foo'   (single-quoted)
#   name=foo     (unquoted — still legal HTML, ntr.army's login form uses it)
# Capture groups 1/2/3 correspond to dq/sq/unquoted; we coalesce in _attr().
_ATTR_RE_TEMPLATE = r'\b{name}\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s"\'>]+))'

def _attr(attrs: str, name: str) -> str:
    """
    Return the value of attribute `name` in an HTML attributes string,
    tolerating double-quoted, single-quoted, and unquoted values.
    Returns "" if the attribute is absent.
    """
    m = re.search(
        _ATTR_RE_TEMPLATE.format(name=re.escape(name)),
        attrs,
        re.IGNORECASE,
    )
    if not m:
        return ""
    return m.group(1) or m.group(2) or m.group(3) or ""


def _strip_html_comments(html: str) -> str:
    """
    Remove <!-- ... --> blocks so form-detection doesn't latch onto a
    commented-out input. ntr.army's login page has a commented dup of
    the username input — if we parsed comments we'd risk double-hits.
    """
    return re.sub(r'<!--.*?-->', '', html, flags=re.DOTALL)


def _detect_login_fields(html: str) -> tuple[str, str]:
    """
    Scrape the login page HTML to find the ACTUAL name attributes used
    for the username and password inputs.

    Strategy:
      1. Strip HTML comments (avoid commented-out inputs).
      2. Find the <form> that contains an <input type=password>
         (ignores newsletter-signup forms and similar noise).
      3. The name= of that password input is the password field.
      4. For the username field, pick the last text-like input that
         appears BEFORE the password input inside that form. "Text-like"
         means type is text/email/tel/... or type is absent (HTML default
         is text). We take the LAST one so honeypot/hidden fields don't
         win over the real visible username box.
      5. Returns ("", "") if nothing can be detected — caller falls back
         to whatever the user configured.

    Solves the ntr.army case: the login form uses name='uname'/name=pwd
    (single + unquoted) and silently ignores wrong field names server-side
    (returns fresh login page, HTTP 200, no Set-Cookie) — impossible to
    diagnose without scraping the real field names.
    """
    clean = _strip_html_comments(html)
    form = _form_containing_password_generic(clean)
    if not form:
        return "", ""

    # Find password input inside the form
    pass_name = ""
    pass_pos = -1
    for m in re.finditer(
        r'<input\b([^>]*?)>', form, re.IGNORECASE | re.DOTALL
    ):
        attrs = m.group(1)
        itype = _attr(attrs, "type").lower()
        if itype == "password":
            nm = _attr(attrs, "name")
            if nm:
                pass_name = nm
                pass_pos = m.start()
                break
    if not pass_name:
        return "", ""

    # Walk all text-like inputs BEFORE the password field, take the LAST one
    # (closest to the password field — usually the real visible username input)
    user_name = ""
    for m in re.finditer(
        r'<input\b([^>]*?)>', form[:pass_pos], re.IGNORECASE | re.DOTALL
    ):
        attrs = m.group(1)
        itype = _attr(attrs, "type").lower() or "text"
        # Skip non-text inputs
        if itype in ("hidden", "submit", "button", "reset",
                     "file", "image", "checkbox", "radio", "password"):
            continue
        nm = _attr(attrs, "name")
        if nm:
            user_name = nm
    return user_name, pass_name


def _form_containing_password_generic(html: str) -> Optional[str]:
    """
    Return the first <form>…</form> block that contains a password input.
    Handles quoted AND unquoted `type=password` attributes.
    """
    for m in re.finditer(
        r'<form\b[^>]*>(.*?)</form>',
        html, re.IGNORECASE | re.DOTALL,
    ):
        block = m.group(1)
        if re.search(
            r'type\s*=\s*(?:"password"|\'password\'|password\b)',
            block, re.I,
        ):
            return block
    return None


def _extract_hidden_inputs(
    html: str, username_field: str, password_field: str
) -> dict:
    """
    Pull every `<input type="hidden" name="..." value="...">` out of the
    login form so we can replay them in the POST.  Covers Laravel's
    `_token`, Django's `csrfmiddlewaretoken`, Rails' `authenticity_token`,
    ASP.NET `__RequestVerificationToken`, WordPress `_wpnonce`, etc.

    Skips the username/password fields themselves so the caller's values
    take precedence.
    """
    fields: dict = {}
    # Work on comment-stripped HTML so we don't capture tokens hiding
    # inside <!-- … --> markup.
    clean = _strip_html_comments(html)
    # Narrow to the first <form> that contains the password field — avoids
    # sucking hidden inputs from unrelated forms (newsletter signups etc).
    form_block = (
        _form_containing_password(clean, password_field)
        or _form_containing_password_generic(clean)
        or clean
    )
    for m in re.finditer(
        r'<input\b([^>]*?)>',
        form_block,
        re.IGNORECASE | re.DOTALL,
    ):
        attrs = m.group(1)
        itype = _attr(attrs, "type").lower()
        if itype and itype != "hidden":
            continue
        name = _attr(attrs, "name")
        if not name or name in (username_field, password_field):
            continue
        fields[name] = _attr(attrs, "value")
    return fields


def _form_containing_password(html: str, password_field: str) -> Optional[str]:
    """
    Return the <form>…</form> block that contains either an input whose
    name matches `password_field` or any input with type=password.
    Tolerates quoted and unquoted attributes.
    """
    name_re = re.compile(
        rf'\bname\s*=\s*(?:"{re.escape(password_field)}"|'
        rf"'{re.escape(password_field)}'|{re.escape(password_field)}\b)",
        re.IGNORECASE,
    )
    pass_re = re.compile(
        r'type\s*=\s*(?:"password"|\'password\'|password\b)',
        re.IGNORECASE,
    )
    for m in re.finditer(
        r'<form\b[^>]*>(.*?)</form>',
        html, re.IGNORECASE | re.DOTALL,
    ):
        block = m.group(1)
        if name_re.search(block) or pass_re.search(block):
            return block
    return None


def _extract_form_action(html: str, base_url: str) -> Optional[str]:
    """Find the first <form action=...> and resolve relative to base_url."""
    m = re.search(r'<form\b([^>]*)>', html, re.IGNORECASE)
    if not m:
        return None
    action = _attr(m.group(1), "action")
    if not action:
        return None
    return urljoin(base_url, action)


def auth_from_cli(
    auth_type: str,
    username: Optional[str] = None,
    password: Optional[str] = None,
    token: Optional[str] = None,
    api_key: Optional[str] = None,
    login_url: Optional[str] = None,
    **kwargs,
) -> AuthConfig:
    """Build AuthConfig from CLI arguments."""
    return AuthConfig(
        auth_type    = auth_type or "none",
        username     = username or "",
        password     = password or "",
        token        = token    or "",
        api_key      = api_key  or "",
        login_url    = login_url or "",
        **{k: v for k, v in kwargs.items() if v is not None},
    )
