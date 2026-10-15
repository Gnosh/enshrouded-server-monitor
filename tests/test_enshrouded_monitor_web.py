#!/usr/bin/env python3
"""
Tests for enshrouded-monitor-web.py
Run from the repo root: python3 -I -m unittest
"""
import base64, hashlib, hmac as _hmac, importlib.util, os, sys
import tempfile, threading, time, unittest
from http.client import HTTPConnection
from http.server import HTTPServer

# ── Load module under test ────────────────────────────────────────────────────
_PW = "testpw_vector_2026"
os.environ["ENSHROUDED_SHARED_PASSWORD"] = _PW

_SRC = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "src")
sys.path.insert(0, _SRC)
os.environ["ENSHROUDED_MONITOR_CONFIG"] = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "fixtures", "test-config.toml")
_spec = importlib.util.spec_from_file_location(
    "web", os.path.join(_SRC, "enshrouded-monitor-web.py"))
web = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(web)

# ── Test server setup ─────────────────────────────────────────────────────────
_PORT   = 18083
_tmpdir = tempfile.mkdtemp(prefix="emtest_")
web.DATA_DIR = _tmpdir

with open(os.path.join(_tmpdir, "index.html"), "wb") as _f:
    _f.write(b"<html><body>MONITOR_SENTINEL_CONTENT</body></html>")
with open(os.path.join(_tmpdir, "live.json"), "wb") as _f:
    _f.write(b'{"players":0}')

_server  = HTTPServer(("127.0.0.1", _PORT), web._Handler)
_srv_thr = threading.Thread(target=_server.serve_forever, daemon=True)
_srv_thr.start()


def req(method, path, headers=None, body=None):
    """Raw HTTP request; returns (status, headers_dict_lower, body_bytes)."""
    conn = HTTPConnection("127.0.0.1", _PORT, timeout=5)
    h = dict(headers or {})
    if body is not None:
        if isinstance(body, str):
            body = body.encode()
        h.setdefault("Content-Type", "application/x-www-form-urlencoded")
        h["Content-Length"] = str(len(body))
    conn.request(method, path, body=body, headers=h)
    r = conn.getresponse()
    return r.status, {k.lower(): v for k, v in r.getheaders()}, r.read()


_KEY = web._cookie_secret()


def valid_cookie(now=None) -> str:
    return f"{web.COOKIE_NAME}={web.make_cookie_value(_KEY, now)}"


# ── Crypto unit tests ─────────────────────────────────────────────────────────

class TestCookieCrypto(unittest.TestCase):

    def test_fresh_cookie_verifies(self):
        now = int(time.time())
        val = web.make_cookie_value(_KEY, now)
        self.assertTrue(web.verify_cookie_value(val, _KEY, now))

    def test_expired_cookie_rejected(self):
        expiry = str(int(time.time()) - 1)
        sig    = web._sign(_KEY, expiry)
        self.assertFalse(web.verify_cookie_value(f"{expiry}.{sig}", _KEY))

    def test_tampered_signature(self):
        now = int(time.time())
        val = web.make_cookie_value(_KEY, now)
        expiry, sig = val.split(".", 1)
        bad = sig[:-1] + ("A" if sig[-1] != "A" else "B")
        self.assertFalse(web.verify_cookie_value(f"{expiry}.{bad}", _KEY))

    def test_future_out_of_range_rejected(self):
        now    = int(time.time())
        expiry = str(now + web.COOKIE_MAX_AGE + 120)
        sig    = web._sign(_KEY, expiry)
        self.assertFalse(web.verify_cookie_value(f"{expiry}.{sig}", _KEY, now))

    def test_wrong_password_rejected(self):
        now = int(time.time())
        val = web.make_cookie_value("wrongpass", now)
        self.assertFalse(web.verify_cookie_value(val, _KEY, now))

    def test_malformed_no_dot(self):
        self.assertFalse(web.verify_cookie_value("nodot", _KEY))

    def test_empty_value(self):
        self.assertFalse(web.verify_cookie_value("", _KEY))

    def test_stateless_survives_restart(self):
        """Cookie issued at t1 is still valid at t2 without any shared state."""
        t1  = int(time.time())
        val = web.make_cookie_value(_KEY, t1)
        t2  = t1 + 3600
        self.assertTrue(web.verify_cookie_value(val, _KEY, t2))

    def test_hmac_vector(self):
        """Fixed vector: sig = b64url(HMAC-SHA256(key, "enshrouded-session-v1:" + expiry))."""
        key, expiry = b"k" * 32, "1700000000"
        raw      = _hmac.new(key, b"enshrouded-session-v1:" + expiry.encode(), hashlib.sha256).digest()
        expected = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
        self.assertEqual(web._sign(key, expiry), expected)

    def test_cookie_not_signed_with_password(self):
        """Signature must not be derivable from the password (offline-guess oracle)."""
        expiry = str(int(time.time()) + 100)
        for msg in (expiry, "enshrouded-session-v1:" + expiry):
            raw = _hmac.new(_PW.encode(), msg.encode(), hashlib.sha256).digest()
            sig = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
            self.assertFalse(web.verify_cookie_value(f"{expiry}.{sig}", _KEY))


class TestStartupChecks(unittest.TestCase):
    def test_identical_password_and_token_rejected(self):
        with self.assertRaises(SystemExit):
            web.startup_checks("same-secret", "same-secret")

    def test_distinct_ok_and_warns_on_random_secret(self):
        w = web.startup_checks("pw-one", "token-two")
        self.assertTrue(any("COOKIE_SECRET" in x for x in w) or os.environ.get("ENSHROUDED_COOKIE_SECRET"))

    def test_insecure_cookie_warns(self):
        old = web.COOKIE_SECURE
        web.COOKIE_SECURE = False
        try:
            self.assertTrue(any("cookie_secure" in x for x in web.startup_checks("a", None)))
        finally:
            web.COOKIE_SECURE = old


# ── Lockout unit tests ────────────────────────────────────────────────────────

class TestLockout(unittest.TestCase):

    def setUp(self):
        with web._lock:
            web._lockouts.clear()

    def test_clean_slate(self):
        self.assertEqual(web.lockout_remaining("192.0.2.4"), 0.0)

    def test_lockout_set(self):
        web.set_lockout("192.0.2.4")
        rem = web.lockout_remaining("192.0.2.4")
        self.assertGreater(rem, 28.0)
        self.assertLessEqual(rem, 31.0)

    def test_lockout_expires(self):
        web.set_lockout("192.0.2.5")
        with web._lock:
            web._lockouts["192.0.2.5"] = time.time() - 0.001
        self.assertEqual(web.lockout_remaining("192.0.2.5"), 0.0)

    def test_cap_evicts_oldest_never_fails_open(self):
        with web._lock:
            web._lockouts.clear()
            for i in range(web.LOCKOUT_CAP):
                web._lockouts[f"10.{i//65536%256}.{i//256%256}.{i%256}"] = time.time() + 10 + i * 1e-3
        web.set_lockout("192.0.2.99")
        self.assertGreater(web.lockout_remaining("192.0.2.99"), 0)
        with web._lock:
            self.assertLessEqual(len(web._lockouts), web.LOCKOUT_CAP)
            self.assertNotIn("10.0.0.0", web._lockouts)   # oldest evicted

    def test_reserve_is_atomic_under_concurrency(self):
        results = []
        def go():
            results.append(web.reserve_attempt("192.0.2.50"))
        ts = [threading.Thread(target=go) for _ in range(30)]
        [t.start() for t in ts]; [t.join() for t in ts]
        self.assertEqual(sum(1 for r in results if r == 0.0), 1)

    def test_release_clears(self):
        self.assertEqual(web.reserve_attempt("192.0.2.51"), 0.0)
        self.assertGreater(web.reserve_attempt("192.0.2.51"), 0)
        web.release_attempt("192.0.2.51")
        self.assertEqual(web.reserve_attempt("192.0.2.51"), 0.0)

    def test_global_limit(self):
        old = web.GLOBAL_LOGIN_PER_MIN
        web.GLOBAL_LOGIN_PER_MIN = 3
        web._global_hits["login"].clear()
        try:
            got = [web.reserve_attempt(f"192.0.2.{100+i}") for i in range(5)]
            self.assertEqual([g == 0.0 for g in got], [True, True, True, False, False])
        finally:
            web.GLOBAL_LOGIN_PER_MIN = old
            web._global_hits["login"].clear()

    def test_ip_canonicalisation(self):
        self.assertEqual(web.canonical_ip("2001:DB8:0:0:0:0:0:1"), "2001:db8::1")
        self.assertEqual(web.canonical_ip("::ffff:192.0.2.7"), "192.0.2.7")


# ── HTTP integration tests ────────────────────────────────────────────────────

class TestHTTP(unittest.TestCase):

    def setUp(self):
        with web._lock:
            web._lockouts.clear()
        web._global_hits["login"].clear()

    # No-cookie access

    def test_no_cookie_returns_login_page(self):
        """GET / without cookie must return login page, not monitor content."""
        status, hdrs, body = req("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b"/_auth/login", body)

    def test_no_cookie_does_not_leak_monitor_content(self):
        """Login page must not contain embedded monitor data or sentinel."""
        _, _, body = req("GET", "/")
        self.assertNotIn(b"MONITOR_SENTINEL_CONTENT", body)
        self.assertNotIn(b"metrics.csv", body)

    def test_live_json_requires_auth(self):
        _, _, body = req("GET", "/live.json")
        self.assertNotIn(b'"players"', body)

    def test_metrics_csv_requires_auth(self):
        _, _, body = req("GET", "/metrics.csv")
        self.assertNotIn(b"timestamp", body)

    # Wrong password / lockout

    def test_wrong_password_returns_429(self):
        status, hdrs, _ = req("POST", "/_auth/login", body="password=wrong")
        self.assertEqual(status, 429)
        self.assertIn("retry-after", hdrs)

    def test_retry_after_correct_value(self):
        """Retry-After value matches (or slightly exceeds) remaining lockout."""
        web.set_lockout("127.0.0.1")
        rem    = web.lockout_remaining("127.0.0.1")
        status, hdrs, _ = req("POST", "/_auth/login", body="password=x")
        self.assertEqual(status, 429)
        ra = int(hdrs.get("retry-after", 0))
        self.assertGreaterEqual(ra, max(0, int(rem)))
        self.assertLessEqual(ra, int(rem) + 3)

    def test_correct_password_rejected_while_locked(self):
        """Even a correct password is rejected during the lockout window."""
        web.set_lockout("127.0.0.1")
        status, _, _ = req("POST", "/_auth/login", body=f"password={_PW}")
        self.assertEqual(status, 429)

    # Successful login

    def test_correct_login_redirects_with_cookie(self):
        status, hdrs, _ = req("POST", "/_auth/login", body=f"password={_PW}")
        self.assertEqual(status, 303)
        self.assertEqual(hdrs.get("location"), "/")
        sc = hdrs.get("set-cookie", "")
        self.assertIn(web.COOKIE_NAME, sc)
        self.assertIn("HttpOnly", sc)
        self.assertIn("SameSite=Lax", sc)
        self.assertIn("; Secure", sc)           # default: always Secure
        self.assertNotIn("Domain=", sc)         # host-only unless cookie_domain set
        self.assertIn(f"Max-Age={web.COOKIE_MAX_AGE}", sc)
        self.assertLessEqual(web.COOKIE_MAX_AGE, 31 * 86400)

    def test_cookie_secure_can_be_disabled_explicitly(self):
        old = web.COOKIE_SECURE
        web.COOKIE_SECURE = False
        try:
            _, hdrs, _ = req("POST", "/_auth/login", body=f"password={_PW}")
            self.assertNotIn("Secure", hdrs["set-cookie"])
        finally:
            web.COOKIE_SECURE = old

    def test_cookie_domain_independent_of_host_header(self):
        old = web.COOKIE_DOMAIN
        web.COOKIE_DOMAIN = "status.example.com"
        try:
            _, hdrs, _ = req("POST", "/_auth/login", body=f"password={_PW}",
                             headers={"Host": "other.invalid"})
            self.assertIn("Domain=status.example.com", hdrs["set-cookie"])
            self.assertIn("; Secure", hdrs["set-cookie"])
        finally:
            web.COOKIE_DOMAIN = old

    def test_correct_login_after_lockout_expiry(self):
        """Login succeeds once the lockout window has elapsed."""
        web.set_lockout("127.0.0.1")
        with web._lock:
            web._lockouts["127.0.0.1"] = time.time() - 0.001
        status, _, _ = req("POST", "/_auth/login", body=f"password={_PW}")
        self.assertEqual(status, 303)

    def test_valid_cookie_serves_monitor(self):
        """Session cookie must grant access to the monitor page."""
        _, _, body = req("GET", "/", headers={"Cookie": valid_cookie()})
        self.assertIn(b"MONITOR_SENTINEL_CONTENT", body)

    # Cookie statelessness

    def test_cookie_survives_without_server_state(self):
        """Cookie verification is purely cryptographic — no stored server state."""
        t1  = int(time.time())
        val = web.make_cookie_value(_KEY, t1)
        with web._lock:
            web._lockouts.clear()   # lockout state is separate from cookies
        self.assertTrue(web.verify_cookie_value(val, _KEY, t1 + 60))

    # Expired / tampered cookies

    def test_expired_cookie_shows_login(self):
        expiry = str(int(time.time()) - 1)
        sig    = web._sign(_KEY, expiry)
        cookie = f"{web.COOKIE_NAME}={expiry}.{sig}"
        _, _, body = req("GET", "/", headers={"Cookie": cookie})
        self.assertIn(b"/_auth/login", body)
        self.assertNotIn(b"MONITOR_SENTINEL_CONTENT", body)

    def test_tampered_cookie_rejected(self):
        val              = web.make_cookie_value(_KEY)
        expiry, sig      = val.split(".", 1)
        bad_sig          = sig[:-1] + ("A" if sig[-1] != "A" else "B")
        cookie           = f"{web.COOKIE_NAME}={expiry}.{bad_sig}"
        _, _, body       = req("GET", "/", headers={"Cookie": cookie})
        self.assertIn(b"/_auth/login", body)
        self.assertNotIn(b"MONITOR_SENTINEL_CONTENT", body)

    # Logout

    def test_logout_post_clears_cookie(self):
        status, hdrs, _ = req("POST", "/_auth/logout")
        self.assertEqual(status, 303)
        sc = hdrs.get("set-cookie", "")
        self.assertIn("Max-Age=0", sc)
        self.assertIn(web.COOKIE_NAME, sc)

    def test_logout_get_not_allowed(self):
        status, hdrs, _ = req("GET", "/_auth/logout")
        self.assertEqual(status, 405)
        self.assertNotIn("set-cookie", hdrs)

    def test_logout_cross_site_rejected(self):
        status, _, _ = req("POST", "/_auth/logout", headers={"Sec-Fetch-Site": "cross-site"})
        self.assertEqual(status, 403)
        status, _, _ = req("POST", "/_auth/logout",
                           headers={"Origin": "https://evil.invalid", "Host": "status.example.com"})
        self.assertEqual(status, 403)

    def test_logout_same_origin_ok(self):
        status, _, _ = req("POST", "/_auth/logout", headers={"Sec-Fetch-Site": "same-origin"})
        self.assertEqual(status, 303)
        status, _, _ = req("POST", "/_auth/logout",
                           headers={"Origin": "https://status.example.com", "Host": "status.example.com"})
        self.assertEqual(status, 303)

    def test_cross_site_login_rejected_and_not_counted(self):
        status, _, _ = req("POST", "/_auth/login", body="password=x",
                           headers={"Sec-Fetch-Site": "cross-site"})
        self.assertEqual(status, 403)
        self.assertEqual(web.lockout_remaining("127.0.0.1"), 0.0)

    def test_no_store_on_every_authenticated_response(self):
        for path in ("/", "/live.json", "/metrics.csv", "/nope"):
            _, hdrs, _ = req("GET", path, headers={"Cookie": valid_cookie()})
            self.assertIn("no-store", hdrs.get("cache-control", ""), path)

    def test_concurrent_wrong_guesses_only_one_compared(self):
        codes = []
        def go():
            codes.append(req("POST", "/_auth/login", body="password=wrong")[0])
        ts = [threading.Thread(target=go) for _ in range(10)]
        [t.start() for t in ts]; [t.join() for t in ts]
        self.assertEqual(codes.count(429), 10)
        # only one attempt was reserved; global window holds exactly one hit
        self.assertEqual(len(web._global_hits["login"]), 1)

    def test_x_real_ip_canonicalised_from_trusted_proxy(self):
        import ipaddress
        old = web._TRUSTED_PROXY_NETS
        web._TRUSTED_PROXY_NETS = [ipaddress.ip_network("127.0.0.0/8")]
        try:
            req("POST", "/_auth/login", body="password=x", headers={"X-Real-IP": "2001:DB8:0::5"})
            self.assertGreater(web.lockout_remaining("2001:db8::5"), 0)
        finally:
            web._TRUSTED_PROXY_NETS = old

    # Security headers

    def test_security_headers_on_login_page(self):
        _, hdrs, _ = req("GET", "/")
        self.assertEqual(hdrs.get("x-content-type-options"), "nosniff")
        self.assertEqual(hdrs.get("x-frame-options"), "DENY")
        self.assertIn("no-referrer", hdrs.get("referrer-policy", ""))

    def test_no_store_on_login_page(self):
        _, hdrs, _ = req("GET", "/")
        self.assertIn("no-store", hdrs.get("cache-control", ""))

    def test_no_store_on_429(self):
        web.set_lockout("127.0.0.1")
        _, hdrs, _ = req("POST", "/_auth/login", body="password=x")
        self.assertIn("no-store", hdrs.get("cache-control", ""))


if __name__ == "__main__":
    unittest.main(verbosity=2)
