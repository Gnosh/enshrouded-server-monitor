"""Tests for the hardening changes: config validation, file safety, XSS,
admin restart logic, slowloris/concurrency limits. No Docker, no network."""
import importlib.util, json, os, socket, subprocess, sys, tempfile, threading, time, unittest
import unittest.mock as mock
from http.client import HTTPConnection

_HERE = os.path.dirname(os.path.abspath(__file__))
_SRC = os.path.join(_HERE, "..", "src")
sys.path.insert(0, _SRC)
os.environ.setdefault("ENSHROUDED_SHARED_PASSWORD", "unit-test-password")
os.environ["ENSHROUDED_MONITOR_CONFIG"] = os.path.join(_HERE, "fixtures", "test-config.toml")

import enshrouded_monitor_config as cfg  # noqa: E402


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, os.path.join(_SRC, filename))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _cfg_file(text):
    d = tempfile.mkdtemp(prefix="emhcfg_")
    p = os.path.join(d, "config.toml")
    with open(p, "w") as f:
        f.write(text)
    return p


class TestConfigValidation(unittest.TestCase):
    def bad(self, text):
        with self.assertRaises(ValueError):
            cfg.load_config(path=_cfg_file(text))

    def test_unknown_key_and_section_rejected(self):
        self.bad("[web]\nbogus = 1\n")
        self.bad("[nothere]\nx = 1\n")

    def test_bool_must_be_bool(self):
        self.bad('[general]\nsteam_lookup = "false"\n')
        self.bad("[web]\ncookie_secure = 1\n")

    def test_ports_and_numbers(self):
        self.bad("[web]\nport = 0\n")
        self.bad("[web]\nport = 70000\n")
        self.bad('[web]\nport = "8083"\n')
        self.bad("[web]\nmax_connections = 0\n")
        self.bad("[web]\nrequest_timeout_seconds = -1\n")
        self.bad("[general]\nstale_after_seconds = 0\n")
        self.bad("[general]\nmax_csv_rows = 5\n")
        self.bad("[admin]\nstop_timeout_seconds = 0\n")
        self.bad("[admin]\nrestart_cooldown_seconds = -5\n")
        self.bad("[web]\ncookie_max_age_seconds = 10\n")

    def test_bad_cidr_cookie_name_domain(self):
        self.bad('[web]\ntrusted_proxy_networks = ["not-a-cidr"]\n')
        self.bad('[web]\ncookie_name = "a b;c"\n')
        self.bad('[web]\ncookie_domain = "evil.com; Path=/x"\n')

    def test_compose_service_required_with_compose_file(self):
        self.bad('[admin]\ncompose_file = "/srv/x/docker-compose.yml"\n')
        self.bad('[admin]\ncompose_file = "relative.yml"\ncompose_service = "game"\n')
        self.bad('[admin]\ncompose_file = "/srv/x.yml"\ncompose_service = "a b"\n')
        self.bad('[admin]\ncompose_service = "game"\n')
        c = cfg.load_config(path=_cfg_file(
            '[admin]\ncompose_file = "/srv/x.yml"\ncompose_service = "game"\n'))
        self.assertEqual(c["admin"]["compose_service"], "game")

    def test_secure_defaults(self):
        c = cfg.load_config(path=_cfg_file(""))
        self.assertTrue(c["web"]["cookie_secure"])
        self.assertEqual(c["web"]["cookie_domain"], "")
        self.assertLessEqual(c["web"]["cookie_max_age_seconds"], 31 * 86400)
        self.assertGreater(c["general"]["max_csv_rows"], 1000)

    def test_example_config_has_every_schema_key(self):
        import tomllib
        with open(os.path.join(_HERE, "..", "config.example.toml"), "rb") as f:
            ex = tomllib.load(f)
        for sec, keys in cfg.SCHEMA.items():
            for k in keys:
                self.assertIn(k, ex.get(sec, {}), f"{sec}.{k} missing from config.example.toml")


class TestSafeFiles(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.mkdtemp(prefix="emfs_")

    def test_atomic_write_mode_and_content(self):
        p = os.path.join(self.d, "f.json")
        cfg.atomic_write(p, "hello", mode=0o600)
        self.assertEqual(open(p).read(), "hello")
        self.assertEqual(os.stat(p).st_mode & 0o777, 0o600)
        self.assertEqual([x for x in os.listdir(self.d) if x.endswith(".tmp")], [])

    def test_atomic_write_refuses_symlink(self):
        target = os.path.join(self.d, "victim")
        open(target, "w").write("keep")
        link = os.path.join(self.d, "index.html")
        os.symlink(target, link)
        with self.assertRaises(OSError):
            cfg.atomic_write(link, "pwn")
        self.assertEqual(open(target).read(), "keep")

    def test_predictable_tmp_symlink_not_followed(self):
        target = os.path.join(self.d, "victim")
        open(target, "w").write("keep")
        os.symlink(target, os.path.join(self.d, "f.tmp"))
        cfg.atomic_write(os.path.join(self.d, "f"), "x")
        self.assertEqual(open(target).read(), "keep")

    def test_safe_append_refuses_symlink(self):
        target = os.path.join(self.d, "victim")
        open(target, "w").write("keep")
        link = os.path.join(self.d, "log")
        os.symlink(target, link)
        with self.assertRaises(OSError):
            cfg.safe_append(link, "x\n")
        self.assertEqual(open(target).read(), "keep")

    def test_safe_read_refuses_symlink(self):
        target = os.path.join(self.d, "victim")
        open(target, "w").write("secret")
        link = os.path.join(self.d, "live.json")
        os.symlink(target, link)
        with self.assertRaises(OSError):
            cfg.safe_read(link)


class TestMonitorHardening(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mon = _load("mon_h", "enshrouded-monitor.py")

    def _point(self):
        d = tempfile.mkdtemp(prefix="emmon_")
        m = self.mon
        m.DATA_DIR = d
        m.CSV_FILE, m.HTML_FILE = os.path.join(d, "metrics.csv"), os.path.join(d, "index.html")
        m.LIVE_FILE = os.path.join(d, "live.json")
        return d

    def test_csv_rejects_bad_timestamps_and_nonfinite(self):
        d = self._point()
        m = self.mon
        evil = "2026-01-01T00:00:00Z</script><script>alert(1)</script>"
        with open(m.CSV_FILE, "w") as f:
            f.write(m.CSV_HEADER)
            f.write("2026-01-01T00:00:00Z,1.0,100,1,0,5,4.5,10,10\n")
            f.write(f"{evil},1.0,100,1,0,5,4.5,10,10\n")
            f.write("2026-01-01T00:05:00Z,nan,100,1,0,5,4.5,10,10\n")
            f.write("2026-01-01T00:10:00Z,1.0,inf,1,0,5,4.5,10,10\n")
            f.write("2026-01-01T00:15:00Z,1.0,100,1,0,5,Infinity,10,10\n")
            f.write("2026-13-45T99:99:99Z,1.0,100,1,0,5,4.5,10,10\n")
        rows = m.read_csv()
        self.assertEqual([r["t"] for r in rows], ["2026-01-01T00:00:00Z"])

    def test_html_script_data_cannot_break_out(self):
        h = self.mon.generate_html([{"t": "</script><script>alert(1)</script>", "cpu": 1, "mem": 1,
                                     "players": 0, "bad_perf": 0, "entities": 0, "tick": 0,
                                     "save_kb": 0, "water_kb": 0}], {"status": "online"})
        self.assertNotIn("</script><script>alert", h)
        self.assertEqual(h.count("</script>"), 1)

    def test_malicious_status_is_neutralised(self):
        h = self.mon.generate_html([], {"status": "x';alert(1);//"})
        self.assertNotIn("alert(1)", h)

    def test_chart_guards_for_few_samples(self):
        h = self.mon.generate_html([], {"status": "online"})
        self.assertIn("data.length<2", h)
        self.assertNotIn("Math.max(...", h)

    def test_malformed_log_lines_do_not_crash(self):
        m = self.mon
        logs = {
            ("docker", "inspect"): "true\n",
            ("docker", "stats"): "nan%\t1.5GiB / 8GiB\n",
        }
        def fake_run(*cmd, timeout=10):
            if cmd[1] in ("inspect",):
                return "true\n"
            if cmd[1] == "stats":
                return "nan%\tinfMiB / 8GiB"
            return ("2026 [ecss] Ent:1,234,567 Avg:3.5ms\n"
                    "[savexxx] SAVE size ,\nWaterSaveSize: ,,\n[ecss] Ent:,,, Avg:...ms\n")
        m.run = fake_run
        row = m.collect()
        self.assertEqual(row[1], 0)       # nan cpu ignored
        self.assertEqual(row[5], 0)       # newest line is malformed -> rejected, no crash
        self.assertEqual(row[6], 0.0)
        self.assertEqual(row[7], 0)
        self.assertEqual(row[8], 0)

    def test_valid_thousands_separators(self):
        m = self.mon
        def fake_run(*cmd, timeout=10):
            if cmd[1] == "inspect":
                return "true\n"
            if cmd[1] == "stats":
                return "12.5%\t1.0GiB / 8GiB"
            return "[ecss] Ent:14,663 Avg:4.5ms\n"
        m.run = fake_run
        row = m.collect()
        self.assertEqual((row[5], row[6]), (14663, 4.5))

    def test_trim_csv(self):
        self._point()
        m = self.mon
        with open(m.CSV_FILE, "w") as f:
            f.write(m.CSV_HEADER)
            for i in range(20):
                f.write(f"2026-01-01T00:{i:02d}:00Z,1.0,100,1,0,5,4.5,10,10\n")
        m.trim_csv(5)
        lines = open(m.CSV_FILE).read().splitlines()
        self.assertEqual(len(lines), 6)
        self.assertTrue(lines[0].startswith("timestamp"))
        self.assertTrue(lines[-1].startswith("2026-01-01T00:19"))
        self.assertEqual(os.stat(m.CSV_FILE).st_mode & 0o777, 0o640)

    def test_main_writes_atomically_with_modes_and_refuses_symlink(self):
        d = self._point()
        m = self.mon
        m.run = lambda *a, **k: "false\n"
        old = os.umask(0o022)
        try:
            m.main()
        finally:
            os.umask(old)
        for fn in ("live.json", "index.html", "metrics.csv"):
            self.assertEqual(os.stat(os.path.join(d, fn)).st_mode & 0o777, 0o640, fn)
        self.assertEqual([x for x in os.listdir(d) if x.endswith(".tmp")], [])
        os.unlink(m.HTML_FILE)
        os.symlink(os.path.join(d, "live.json"), m.HTML_FILE)
        with self.assertRaises(OSError):
            m.main()

    def test_steam_cache_is_private(self):
        d = self._point()
        m = self.mon
        m.STEAM_CACHE_FILE = os.path.join(d, "steam_names.json")
        m._save_steam_cache({"1": "x"})
        self.assertEqual(os.stat(m.STEAM_CACHE_FILE).st_mode & 0o777, 0o600)


class TestAdminRestart(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.web = _load("web_adm", "enshrouded-monitor-web.py")

    def setUp(self):
        w = self.web
        w.COMPOSE_FILE, w.COMPOSE_SERVICE = "/srv/x/docker-compose.yml", "game"
        w.GAME_CONTAINER, w.POST_START_WAIT_S = "gamectr", 0
        w.RESTART_LOG = os.path.join(tempfile.mkdtemp(prefix="emadm_"), "r.log")
        w._admin_state.update(last_restart_at=0.0, in_progress=False)

    def _runner(self, inspect_out="true healthy", logs=""):
        calls = []
        def fake(cmd, **kw):
            calls.append(cmd)
            out = ""
            if cmd[1] == "inspect":
                out = inspect_out
            elif cmd[1] == "logs":
                out = logs
            return subprocess.CompletedProcess(cmd, 0, out, "")
        return calls, fake

    def test_only_configured_service_touched(self):
        calls, fake = self._runner()
        with mock.patch.object(self.web.subprocess, "run", fake):
            r = self.web._do_restart()
        self.assertTrue(r["ok"])
        stop, up = calls[0], calls[1]
        self.assertEqual(stop[-1], "game")
        self.assertEqual(up[-1], "game")
        self.assertIn("--no-deps", up)

    def test_update_status_unknown_without_evidence(self):
        _, fake = self._runner(logs="nothing interesting")
        with mock.patch.object(self.web.subprocess, "run", fake):
            r = self.web._do_restart()
        self.assertEqual(r["updateStatus"], "unknown")
        self.assertIsNone(r["updateApplied"])
        self.assertNotIn("no update was pending", r["message"])

    def test_update_applied_with_evidence(self):
        _, fake = self._runner(logs="Installing update 123")
        with mock.patch.object(self.web.subprocess, "run", fake):
            r = self.web._do_restart()
        self.assertEqual(r["updateStatus"], "applied")
        self.assertTrue(r["updateApplied"])

    def test_not_running_after_start_is_failure(self):
        _, fake = self._runner(inspect_out="false ")
        with mock.patch.object(self.web.subprocess, "run", fake):
            r = self.web._do_restart()
        self.assertFalse(r["ok"])
        self.assertEqual(r["reason"], "not_running")

    def test_unhealthy_is_failure(self):
        _, fake = self._runner(inspect_out="true unhealthy")
        with mock.patch.object(self.web.subprocess, "run", fake):
            r = self.web._do_restart()
        self.assertEqual(r["reason"], "unhealthy")

    def test_in_progress_mutex_independent_of_cooldown(self):
        w = self.web
        old = w.RESTART_COOLDOWN_S
        w.RESTART_COOLDOWN_S = 0          # cooldown disabled
        try:
            self.assertEqual(w._claim_restart_slot(), (True, None))
            self.assertEqual(w._claim_restart_slot(), (False, "in_progress"))
            w._release_restart_slot()
            self.assertEqual(w._claim_restart_slot(), (True, None))
            w._release_restart_slot()
            w.RESTART_COOLDOWN_S = 300
            self.assertEqual(w._claim_restart_slot(), (False, "cooldown"))
        finally:
            w.RESTART_COOLDOWN_S = old


class TestConnectionLimits(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.web = _load("web_lim", "enshrouded-monitor-web.py")
        cls.web.REQUEST_TIMEOUT_S = 0.5

        class H(cls.web._Handler):
            timeout = 0.5
        cls.srv = cls.web._BoundedServer(("127.0.0.1", 0), H, 2)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.srv.server_close()

    def test_idle_connection_is_dropped(self):
        s = socket.create_connection(("127.0.0.1", self.port))
        s.settimeout(5)
        s.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n")      # never finishes headers
        t0 = time.time()
        data = s.recv(100)
        self.assertEqual(data, b"")
        self.assertLess(time.time() - t0, 3)
        s.close()

    def test_slow_drip_hits_total_deadline(self):
        s = socket.create_connection(("127.0.0.1", self.port))
        s.settimeout(5)
        t0 = time.time()
        try:
            for ch in b"GET / HTTP/1.1\r\nHost: x\r\nX-A: " + b"a" * 200:
                s.sendall(bytes([ch]))
                time.sleep(0.2)
                if time.time() - t0 > 4:
                    break
        except OSError:
            pass
        self.assertLess(time.time() - t0, 4)     # server cut us off
        s.close()

    def test_503_when_full_and_recovers(self):
        held = [socket.create_connection(("127.0.0.1", self.port)) for _ in range(2)]
        time.sleep(0.1)
        c = HTTPConnection("127.0.0.1", self.port, timeout=3)
        c.request("GET", "/")
        self.assertEqual(c.getresponse().status, 503)
        for h in held:
            h.close()
        time.sleep(0.8)
        c = HTTPConnection("127.0.0.1", self.port, timeout=3)
        c.request("GET", "/")
        self.assertEqual(c.getresponse().status, 200)


class TestRepoHygiene(unittest.TestCase):
    def test_no_legacy_test_ips(self):
        for fn in os.listdir(_HERE):
            if fn.endswith(".py"):
                text = open(os.path.join(_HERE, fn)).read()
                if fn == "test_hardening.py":
                    continue
                self.assertNotIn("1.2.3.", text, fn)


if __name__ == "__main__":
    unittest.main()
