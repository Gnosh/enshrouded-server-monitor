"""Second hardening round: absolute request deadline, auth reservations,
file-mode enforcement, origin-based CSRF, and the exact client flow used by
non-browser integrations. Loopback sockets and tmp dirs only."""
import importlib.util, ipaddress, json, os, socket, stat, sys, tempfile, threading, time, unittest
import unittest.mock as mock
from http.client import HTTPConnection

_HERE = os.path.dirname(os.path.abspath(__file__))
_SRC = os.path.join(_HERE, "..", "src")
sys.path.insert(0, _SRC)
_PW, _TOKEN = "pw-for-tests-only", "admin-token-for-tests-only"
os.environ.setdefault("ENSHROUDED_SHARED_PASSWORD", "unit-test-password")
os.environ["ENSHROUDED_MONITOR_CONFIG"] = os.path.join(_HERE, "fixtures", "test-config.toml")

import enshrouded_monitor_config as cfg  # noqa: E402


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, os.path.join(_SRC, filename))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class _Server:
    """Real bounded server on loopback with a short request deadline."""
    def __init__(self, deadline=0.6, per_recv=0.4, data=None, admin=False):
        # secrets are read per request: patch them only while this server lives
        self._env = mock.patch.dict(os.environ, {"ENSHROUDED_SHARED_PASSWORD": _PW,
                                                 "ENSHROUDED_ADMIN_TOKEN": _TOKEN})
        self._env.start()
        self.web = w = _load("web_h2_%d" % id(self), "enshrouded-monitor-web.py")
        w.REQUEST_TIMEOUT_S = deadline
        if data:
            w.DATA_DIR = data
        if admin:
            w.COMPOSE_FILE, w.COMPOSE_SERVICE = "/srv/x/compose.yml", "game"
            w._do_restart = lambda: {"ok": True, "restarted": True}
        per = per_recv

        class H(w._Handler):
            timeout = per
        self.srv = w._BoundedServer(("127.0.0.1", 0), H, 4)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()
        self.srv.server_close()
        self._env.stop()


def _drip(port, chunks, gap, limit=5.0):
    """Send chunks one by one; return seconds until the server closed on us."""
    s = socket.create_connection(("127.0.0.1", port))
    s.settimeout(0.05)
    t0 = time.time()
    try:
        for c in chunks:
            if time.time() - t0 > limit:
                break
            try:
                s.sendall(c)
            except OSError:
                break
            end = time.time() + gap
            while time.time() < end:
                try:
                    if s.recv(1000) == b"":
                        return time.time() - t0
                except socket.timeout:
                    pass
                except OSError:
                    return time.time() - t0
        # drain until closed
        s.settimeout(1)
        try:
            while s.recv(1000):
                pass
        except OSError:
            pass
        return time.time() - t0
    finally:
        s.close()


class TestAbsoluteDeadline(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.s = _Server(deadline=0.6, per_recv=0.4)

    @classmethod
    def tearDownClass(cls):
        cls.s.close()

    def _bytes(self, b):
        return [bytes([c]) for c in b]

    def test_unfinished_request_line_dripped(self):
        # one byte every 0.15s: each recv is far below the 0.4s per-recv timeout
        t = _drip(self.s.port, self._bytes(b"GET /" + b"a" * 100), 0.15)
        self.assertLess(t, 1.5)

    def test_header_dripped(self):
        pre = b"GET / HTTP/1.1\r\nHost: x\r\nX-A: "
        t = _drip(self.s.port, [pre] + self._bytes(b"a" * 100), 0.15)
        self.assertLess(t, 1.5)

    def test_body_dripped(self):
        head = b"POST /_auth/login HTTP/1.1\r\nHost: x\r\nContent-Length: 100\r\n\r\n"
        t = _drip(self.s.port, [head] + self._bytes(b"p" * 100), 0.15)
        self.assertLess(t, 1.5)

    def test_normal_request_still_works(self):
        c = HTTPConnection("127.0.0.1", self.s.port, timeout=3)
        c.request("GET", "/")
        self.assertEqual(c.getresponse().status, 200)

    def test_reader_enforces_deadline_without_server(self):
        a, b = socket.socketpair()
        import io
        raw = self.s.web._DeadlineRaw(a, time.monotonic() + 0.3, 0.2)
        rf = io.BufferedReader(raw)
        done = []

        def feed():
            for _ in range(40):
                try:
                    b.sendall(b"x")
                except OSError:
                    return
                time.sleep(0.05)
        threading.Thread(target=feed, daemon=True).start()
        t0 = time.time()
        with self.assertRaises(TimeoutError):
            rf.readline()
        self.assertLess(time.time() - t0, 1.0)
        a.close(); b.close()


class TestReservationsHTTP(unittest.TestCase):
    def test_slow_body_blocks_second_attempt_then_cooldown_after_finish(self):
        s = _Server(deadline=3.0, per_recv=1.0)
        try:
            w = s.web
            slow = socket.create_connection(("127.0.0.1", s.port))
            slow.sendall(b"POST /_auth/login HTTP/1.1\r\nHost: x\r\nContent-Length: 20\r\n\r\npassword=")
            time.sleep(0.3)
            c = HTTPConnection("127.0.0.1", s.port, timeout=3)
            c.request("POST", "/_auth/login", body="password=" + _PW,
                      headers={"Content-Type": "application/x-www-form-urlencoded"})
            r = c.getresponse()
            self.assertEqual(r.status, 429)          # first still in flight: no parallel guess
            slow.sendall(b"wrong")                   # finish with a wrong password (fewer bytes read ok)
            slow.sendall(b"x" * 6)
            data = slow.recv(4096)
            self.assertIn(b"429", data)
            self.assertGreater(w.lockout_remaining("127.0.0.1"), w.LOCKOUT_SECS - 1.5)
            slow.close()
        finally:
            s.close()

    def test_reservation_holds_beyond_30s_when_deadline_is_longer(self):
        s = _Server(deadline=120, per_recv=60)
        try:
            w = s.web
            slow = socket.create_connection(("127.0.0.1", s.port))
            slow.sendall(b"POST /_auth/login HTTP/1.1\r\nHost: x\r\nContent-Length: 20\r\n\r\n")
            time.sleep(0.3)
            with w._lock:
                exp = w._active["127.0.0.1"][1] - time.time()
            self.assertGreater(exp, 100)             # tied to the absolute deadline, not 30s
            slow.close()
        finally:
            s.close()


class TestFileModes(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="emmode_")

    def test_existing_world_readable_file_is_tightened(self):
        p = os.path.join(self.d, "metrics.csv")
        open(p, "w").write("h\n")
        os.chmod(p, 0o644)
        cfg.safe_append(p, "row\n", mode=0o640)
        self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o640)
        self.assertEqual(open(p).read(), "h\nrow\n")

    def test_more_restrictive_mode_kept(self):
        p = os.path.join(self.d, "f")
        open(p, "w").write("")
        os.chmod(p, 0o600)
        cfg.safe_append(p, "x", mode=0o640)
        self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o600)

    def test_non_regular_file_refused(self):
        p = os.path.join(self.d, "fifo")
        os.mkfifo(p)
        with self.assertRaises(OSError):
            cfg.safe_append(p, "x")

    def test_foreign_owned_world_accessible_refused_and_group_warns(self):
        p = os.path.join(self.d, "f")
        open(p, "w").write("")
        os.chmod(p, 0o666)
        real = os.fstat
        def fake(fd):
            st = real(fd)
            return os.stat_result((st.st_mode, st.st_ino, st.st_dev, st.st_nlink,
                                   os.geteuid() + 1, st.st_gid, st.st_size,
                                   0, 0, 0))
        with mock.patch("os.fstat", fake):
            with self.assertRaises(PermissionError):
                cfg.safe_append(p, "x")
            os.chmod(p, 0o660)
            with mock.patch.object(cfg, "_warn") as warn:
                cfg.safe_append(p, "x", mode=0o640 & ~0o040)   # group bit beyond mode, no 'other'
                self.assertTrue(warn.called)
        self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o660)   # untouched: not ours

    def test_ensure_dir_tightens_and_keeps_setgid(self):
        p = os.path.join(self.d, "data")
        os.mkdir(p)
        os.chmod(p, 0o2775)
        cfg.ensure_dir(p, 0o750)
        self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o2750)

    def test_ensure_dir_creates_and_rejects_symlink(self):
        p = os.path.join(self.d, "new", "data")
        cfg.ensure_dir(p, 0o750)
        self.assertEqual(stat.S_IMODE(os.stat(p).st_mode), 0o750)
        link = os.path.join(self.d, "lnk")
        os.symlink(p, link)
        with self.assertRaises(OSError):
            cfg.ensure_dir(link, 0o750)


class TestCsrfOrigin(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.web = _load("web_csrf", "enshrouded-monitor-web.py")

    def _h(self, headers, peer="203.0.113.9", public=None, trusted=()):
        w = self.web
        h = w._Handler.__new__(w._Handler)
        h.headers = headers
        h.client_address = (peer, 1)
        return h, mock.patch.multiple(
            w, PUBLIC_ORIGIN=public,
            _TRUSTED_PROXY_NETS=[ipaddress.ip_network(n) for n in trusted])

    def check(self, headers, **kw):
        h, p = self._h(headers, **kw)
        with p:
            return h._same_origin()

    def test_no_browser_headers_pass(self):
        self.assertTrue(self.check({}))

    def test_public_origin_scheme_mismatch(self):
        po = ("https", "status.example.com", 443)
        self.assertTrue(self.check({"Origin": "https://status.example.com", "Host": "x"}, public=po))
        self.assertFalse(self.check({"Origin": "http://status.example.com", "Host": "status.example.com"}, public=po))
        self.assertFalse(self.check({"Origin": "https://status.example.com:8443"}, public=po))
        self.assertFalse(self.check({"Origin": "https://evil.example"}, public=po))
        self.assertTrue(self.check({"Origin": "https://STATUS.example.com:443"}, public=po))

    def test_host_fallback(self):
        self.assertTrue(self.check({"Origin": "http://h.example", "Host": "h.example"}))
        self.assertTrue(self.check({"Origin": "http://h.example:8083", "Host": "h.example:8083"}))
        self.assertFalse(self.check({"Origin": "http://h.example:9", "Host": "h.example:8083"}))
        self.assertFalse(self.check({"Origin": "http://other", "Host": "h.example"}))
        self.assertFalse(self.check({"Origin": "null", "Host": "h.example"}))

    def test_forwarded_proto_only_from_trusted(self):
        hdr = {"Origin": "http://h.example", "Host": "h.example", "X-Forwarded-Proto": "https"}
        # trusted proxy says https: an http Origin is a scheme mismatch
        self.assertFalse(self.check(hdr, peer="10.0.0.2", trusted=["10.0.0.0/8"]))
        # untrusted peer: header ignored (cannot be used to fake or hide a mismatch)
        self.assertTrue(self.check(hdr, peer="203.0.113.9", trusted=["10.0.0.0/8"]))
        ok = dict(hdr, Origin="https://h.example")
        self.assertTrue(self.check(ok, peer="10.0.0.2", trusted=["10.0.0.0/8"]))

    def test_sec_fetch_site_still_decides(self):
        self.assertFalse(self.check({"Sec-Fetch-Site": "cross-site", "Origin": "http://h", "Host": "h"}))
        self.assertTrue(self.check({"Sec-Fetch-Site": "same-origin"}))

    def test_public_origin_config_validation(self):
        self.assertEqual(cfg.parse_public_origin("https://A.example"), ("https", "a.example", 443))
        self.assertEqual(cfg.parse_public_origin("http://a.example:8080/"), ("http", "a.example", 8080))
        for bad in ("a.example", "ftp://a", "https://a/path", "https://", "https://u@a"):
            with self.assertRaises(ValueError):
                cfg.parse_public_origin(bad)


class TestNonBrowserClientFlow(unittest.TestCase):
    """Exactly what the Warders site does: no Origin / Sec-Fetch headers."""

    def test_flow(self):
        d = tempfile.mkdtemp(prefix="emflow_")
        open(os.path.join(d, "live.json"), "w").write(json.dumps(
            {"status": "online", "updated_epoch": int(time.time()), "pings": []}))
        open(os.path.join(d, "metrics.csv"), "w").write("timestamp,cpu\n")
        s = _Server(deadline=5, per_recv=2, data=d, admin=True)
        try:
            def call(method, path, body=None, headers=None):
                c = HTTPConnection("127.0.0.1", s.port, timeout=5)
                h = dict(headers or {})
                if body is not None:
                    h["Content-Type"] = "application/x-www-form-urlencoded"
                c.request(method, path, body=body, headers=h)
                r = c.getresponse()
                return r.status, r.getheader("Set-Cookie"), r.read()
            st, sc, _ = call("POST", "/_auth/login", body="password=" + _PW)
            self.assertEqual(st, 303)
            cookie = sc.split(";")[0]
            st, _, body = call("GET", "/live.json", headers={"Cookie": cookie})
            self.assertEqual(st, 200)
            self.assertEqual(json.loads(body)["status"], "online")
            st, _, body = call("GET", "/metrics.csv", headers={"Cookie": cookie})
            self.assertEqual((st, body), (200, b"timestamp,cpu\n"))
            st, _, body = call("POST", "/admin/restart", headers={"Authorization": "Bearer " + _TOKEN})
            self.assertEqual(st, 200)
            self.assertTrue(json.loads(body)["ok"])
            st, _, _ = call("POST", "/admin/restart", headers={"Authorization": "Bearer nope"})
            self.assertIn(st, (401, 429))
        finally:
            s.close()


class TestConfigCompat(unittest.TestCase):
    def test_production_style_config_loads_unchanged(self):
        p = os.path.join(tempfile.mkdtemp(prefix="emcc_"), "c.toml")
        open(p, "w").write('''
[general]
data_dir = "/var/lib/x"
container = "c"
server_name = "S"
player_display = "anonymous"
steam_lookup = false
cpu_cores = 8
stale_after_seconds = 900
reboot_marker_time = "02:30"
reboot_marker_label = "reboot"
[web]
bind = "127.0.0.1"
port = 8083
cookie_name = "enshrouded_session"
cookie_domain = "example.com"
trusted_proxy_networks = ["127.0.0.1/32"]
[admin]
compose_file = "/srv/x/docker-compose.yml"
compose_service = "enshrouded"
restart_cooldown_seconds = 300
stop_timeout_seconds = 60
post_start_wait_seconds = 15
''')
        c = cfg.load_config(p)
        self.assertEqual(c["web"]["public_origin"], "")
        self.assertEqual(c["admin"]["restart_log"], "")


if __name__ == "__main__":
    unittest.main()
