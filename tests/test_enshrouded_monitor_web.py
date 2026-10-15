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


def valid_cookie(now=None) -> str:
    return f"{web.COOKIE_NAME}={web.make_cookie_value(_PW, now)}"


# ── Crypto unit tests ─────────────────────────────────────────────────────────

class TestCookieCrypto(unittest.TestCase):

    def test_fresh_cookie_verifies(self):
        now = int(time.time())
        val = web.make_cookie_value(_PW, now)
        self.assertTrue(web.verify_cookie_value(val, _PW, now))

    def test_expired_cookie_rejected(self):
        expiry = str(int(time.time()) - 1)
        sig    = web._sign(_PW, expiry)
        self.assertFalse(web.verify_cookie_value(f"{expiry}.{sig}", _PW))

    def test_tampered_signature(self):
        now = int(time.time())
        val = web.make_cookie_value(_PW, now)
        expiry, sig = val.split(".", 1)
        bad = sig[:-1] + ("A" if sig[-1] != "A" else "B")
        self.assertFalse(web.verify_cookie_value(f"{expiry}.{bad}", _PW))

    def test_future_out_of_range_rejected(self):
        now    = int(time.time())
        expiry = str(now + web.COOKIE_MAX_AGE + 120)
        sig    = web._sign(_PW, expiry)
        self.assertFalse(web.verify_cookie_value(f"{expiry}.{sig}", _PW, now))

    def test_wrong_password_rejected(self):
        now = int(time.time())
        val = web.make_cookie_value("wrongpass", now)
        self.assertFalse(web.verify_cookie_value(val, _PW, now))

    def test_malformed_no_dot(self):
        self.assertFalse(web.verify_cookie_value("nodot", _PW))

    def test_empty_value(self):
        self.assertFalse(web.verify_cookie_value("", _PW))

    def test_stateless_survives_restart(self):
        """Cookie issued at t1 is still valid at t2 without any shared state."""
        t1  = int(time.time())
        val = web.make_cookie_value(_PW, t1)
        t2  = t1 + 3600
        self.assertTrue(web.verify_cookie_value(val, _PW, t2))

    def test_hmac_vector(self):
        """
        Fixed cross-implementation test vector.

        password = "testpw_vector_2026"
        expiry   = "1700000000"
        sig      = base64url_no_padding(HMAC-SHA256(key=password, msg=expiry))

        Use this to validate the JavaScript / Cloudflare Pages implementation.
        """
        expiry   = "1700000000"
        raw      = _hmac.new(_PW.encode(), expiry.encode(), hashlib.sha256).digest()
        expected = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
        got      = web._sign(_PW, expiry)
        self.assertEqual(got, expected)
        print(f"\n  [vector] password={_PW!r}")
        print(f"  [vector] expiry={expiry}")
        print(f"  [vector] sig={expected}")
        print(f"  [vector] cookie={expiry}.{expected}")


# ── Lockout unit tests ────────────────────────────────────────────────────────

class TestLockout(unittest.TestCase):

    def setUp(self):
        with web._lock:
            web._lockouts.clear()

    def test_clean_slate(self):
        self.assertEqual(web.lockout_remaining("1.2.3.4"), 0.0)

    def test_lockout_set(self):
        web.set_lockout("1.2.3.4")
        rem = web.lockout_remaining("1.2.3.4")
        self.assertGreater(rem, 28.0)
        self.assertLessEqual(rem, 31.0)

    def test_lockout_expires(self):
        web.set_lockout("1.2.3.5")
        with web._lock:
            web._lockouts["1.2.3.5"] = time.time() - 0.001
        self.assertEqual(web.lockout_remaining("1.2.3.5"), 0.0)

    def test_cap_prevents_growth(self):
        with web._lock:
            web._lockouts.clear()
            for i in range(web.LOCKOUT_CAP):
                web._lockouts[f"10.{i//65536%256}.{i//256%256}.{i%256}"] = time.time() + 30
        web.set_lockout("192.0.2.99")
        with web._lock:
            self.assertNotIn("192.0.2.99", web._lockouts)


# ── HTTP integration tests ────────────────────────────────────────────────────

class TestHTTP(unittest.TestCase):

    def setUp(self):
        with web._lock:
            web._lockouts.clear()

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
        val = web.make_cookie_value(_PW, t1)
        with web._lock:
            web._lockouts.clear()   # simulate restart (wipes only in-memory state)
        self.assertTrue(web.verify_cookie_value(val, _PW, t1 + 60))

    # Expired / tampered cookies

    def test_expired_cookie_shows_login(self):
        expiry = str(int(time.time()) - 1)
        sig    = web._sign(_PW, expiry)
        cookie = f"{web.COOKIE_NAME}={expiry}.{sig}"
        _, _, body = req("GET", "/", headers={"Cookie": cookie})
        self.assertIn(b"/_auth/login", body)
        self.assertNotIn(b"MONITOR_SENTINEL_CONTENT", body)

    def test_tampered_cookie_rejected(self):
        val              = web.make_cookie_value(_PW)
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

    def test_logout_get_also_works(self):
        status, hdrs, _ = req("GET", "/_auth/logout")
        self.assertEqual(status, 303)
        self.assertIn("Max-Age=0", hdrs.get("set-cookie", ""))

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
