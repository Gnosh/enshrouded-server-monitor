"""Tests for config loading and offline/stale status handling.
No Docker, no network; only localhost HTTP on an ephemeral port."""
import unittest.mock, importlib.util, json, os, sys, urllib.request, tempfile, threading, time, unittest
from http.client import HTTPConnection
from http.server import HTTPServer

_HERE = os.path.dirname(os.path.abspath(__file__))
_SRC = os.path.join(_HERE, "..", "src")
sys.path.insert(0, _SRC)
os.environ.setdefault("ENSHROUDED_SHARED_PASSWORD", "unit-test-password")
os.environ["ENSHROUDED_MONITOR_CONFIG"] = os.path.join(_HERE, "fixtures", "test-config.toml")

import enshrouded_monitor_config as cfg  # noqa: E402

def _no_host_config(environ=None):
    """Stand-in for candidate_paths so a real host config never leaks into default tests."""
    return []


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, os.path.join(_SRC, filename))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


class TestConfigLoading(unittest.TestCase):
    def _write(self, text):
        d = tempfile.mkdtemp(prefix="emcfg_")
        p = os.path.join(d, "config.toml")
        with open(p, "w") as f:
            f.write(text)
        return p

    def test_defaults_when_no_file(self):
        with unittest.mock.patch.object(cfg, "candidate_paths", _no_host_config):
            c = cfg.load_config(path=None, environ={"HOME": "/nonexistent-home"})
        self.assertEqual(c["web"]["bind"], "127.0.0.1")
        self.assertEqual(c["web"]["trusted_proxy_networks"], [])
        self.assertEqual(c["admin"]["compose_file"], "")

    def test_file_overrides_and_merges_sections(self):
        p = self._write('[general]\ncontainer = "foo"\n[web]\nport = 9999\n')
        c = cfg.load_config(path=p)
        self.assertEqual(c["general"]["container"], "foo")
        self.assertEqual(c["web"]["port"], 9999)
        self.assertEqual(c["web"]["bind"], "127.0.0.1")        # default kept
        self.assertEqual(c["general"]["server_name"], "My Enshrouded Server")

    def test_env_var_selects_file(self):
        p = self._write('[general]\ncontainer = "from-env"\n')
        c = cfg.load_config(environ={"ENSHROUDED_MONITOR_CONFIG": p})
        self.assertEqual(c["general"]["container"], "from-env")

    def test_env_var_pointing_nowhere_is_error(self):
        with self.assertRaises(FileNotFoundError):
            cfg.load_config(environ={"ENSHROUDED_MONITOR_CONFIG": "/nonexistent/x.toml"})

    def test_candidate_order(self):
        paths = cfg.candidate_paths({})
        self.assertTrue(paths[0].endswith(".config/enshrouded-monitor/config.toml"))
        self.assertEqual(paths[1], "/etc/enshrouded-monitor/config.toml")

    def test_example_config_parses_and_matches_defaults_keys(self):
        c = cfg.load_config(path=os.path.join(_HERE, "..", "config.example.toml"))
        for section, vals in cfg.DEFAULTS.items():
            self.assertEqual(set(vals), set(c[section]), section)

    def test_tilde_expanded(self):
        p = self._write('[general]\ndata_dir = "~/x"\n')
        self.assertFalse(cfg.load_config(path=p)["general"]["data_dir"].startswith("~"))


class TestRebootMarker(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mon = _load("mon_rm", "enshrouded-monitor.py")

    def _cfg(self, body):
        d = tempfile.mkdtemp(prefix="emcfg_")
        p = os.path.join(d, "c.toml")
        with open(p, "w") as f:
            f.write("[general]\n" + body)
        return p

    def _html(self, t, label="reboot"):
        self.mon.REBOOT_MARKER_TIME, self.mon.REBOOT_MARKER_LABEL = t, label
        return self.mon.generate_html([], {"status": "online"})

    def test_defaults_off(self):
        with unittest.mock.patch.object(cfg, "candidate_paths", _no_host_config):
            g = cfg.load_config(path=None, environ={"HOME": "/nonexistent"})["general"]
        self.assertEqual(g["reboot_marker_time"], "")
        self.assertEqual(g["reboot_marker_label"], "reboot")

    def test_valid_and_invalid_times(self):
        for ok in ("02:30", "00:00", "23:59", ""):
            c = cfg.load_config(path=self._cfg(f'reboot_marker_time = "{ok}"\n'))
            self.assertEqual(c["general"]["reboot_marker_time"], ok)
        for bad in ("2:30", "24:00", "12:60", "0230", "02:30:00", "ab:cd", " 02:30"):
            with self.assertRaises(ValueError, msg=bad):
                cfg.load_config(path=self._cfg(f'reboot_marker_time = "{bad}"\n'))
        with self.assertRaises(ValueError):
            cfg.load_config(path=self._cfg('reboot_marker_time = 230\n'))

    def test_html_off_by_default(self):
        h = self._html("")
        self.assertIn('const REBOOT={"time": "", "label": "reboot"};', h)
        self.assertNotIn("02:30 reboot", h)

    def test_html_on_when_configured(self):
        h = self._html("03:15", "restart")
        self.assertIn('const REBOOT={"time": "03:15", "label": "restart"};', h)
        self.assertIn("ctx.fillText(rebootText", h)

    def test_label_cannot_break_out(self):
        evil = '</script><img src=x onerror=alert(1)>"\u2028&'
        h = self._html("02:30", evil)
        self.assertNotIn("</script><img", h)
        self.assertNotIn("<img", h)
        self.assertNotIn("\u2028", h)
        self.assertIn("\\u003c/script\\u003e", h)

    @classmethod
    def tearDownClass(cls):
        cls.mon.REBOOT_MARKER_TIME, cls.mon.REBOOT_MARKER_LABEL = "", "reboot"


class TestStatusClassification(unittest.TestCase):
    def test_classify(self):
        self.assertEqual(cfg.classify_status("true\n"), "online")
        self.assertEqual(cfg.classify_status("false\n"), "offline")
        self.assertEqual(cfg.classify_status("Error: No such object: x"), "offline")
        self.assertEqual(cfg.classify_status(""), "unknown")      # docker hung/timeout
        self.assertEqual(cfg.classify_status("Cannot connect to the Docker daemon"), "unknown")

    def test_effective_status_fresh(self):
        now = 1_000_000
        for st in ("online", "offline", "unknown"):
            self.assertEqual(cfg.effective_status({"status": st, "updated_epoch": now - 10}, now, 900), st)

    def test_effective_status_stale(self):
        now = 1_000_000
        self.assertEqual(cfg.effective_status({"status": "online", "updated_epoch": now - 901}, now, 900), "stale")
        self.assertEqual(cfg.effective_status({"status": "online"}, now, 900), "stale")
        self.assertEqual(cfg.effective_status({"status": "online", "updated_epoch": "x"}, now, 900), "stale")
        self.assertEqual(cfg.effective_status({"status": "online", "updated_epoch": now + 99999}, now, 900), "stale")


class TestMonitorCollect(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.mon = _load("mon", "enshrouded-monitor.py")

    def _collect_with(self, docker_output):
        calls = []
        def fake_run(*cmd, timeout=10):
            calls.append(cmd)
            return docker_output
        self.mon.run = fake_run
        return self.mon.collect(), calls

    def test_stopped_container_is_offline(self):
        row, calls = self._collect_with("false\n")
        self.assertEqual(row[10], "offline")
        self.assertEqual(len(calls), 1)     # no stats/log queries for a dead container

    def test_docker_hang_is_unknown_not_online(self):
        row, _ = self._collect_with("")
        self.assertEqual(row[10], "unknown")

    def test_missing_docker_binary_is_unknown(self):
        import subprocess
        real = subprocess.run
        self.mon.__dict__.pop("run", None)
        spec_run = _load("mon_fresh", "enshrouded-monitor.py").run
        subprocess.run = lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError("docker"))
        try:
            self.assertEqual(spec_run("docker", "inspect"), "")
        finally:
            subprocess.run = real

    def test_idle_server_carries_entities_forward(self):
        d = tempfile.mkdtemp(prefix="emdata_")
        m = self.mon
        m.CSV_FILE, m.HTML_FILE = os.path.join(d, "metrics.csv"), os.path.join(d, "index.html")
        m.LIVE_FILE, m.DATA_DIR = os.path.join(d, "live.json"), d
        with open(m.CSV_FILE, "w") as f:
            f.write(m.CSV_HEADER + "2026-01-01T00:00:00Z,1.0,1000,0,0,14663,4.5,5836,1317\n")
        m.run = lambda *a, **k: "true\n" if a[1] == "inspect" else ""
        m.main()
        live = json.load(open(m.LIVE_FILE))
        self.assertEqual(live["entity_count"], 14663)
        self.assertEqual(live["avg_tick_ms"], 4.5)

    def test_main_writes_status_and_timestamp(self):
        d = tempfile.mkdtemp(prefix="emdata_")
        m = self.mon
        m.DATA_DIR = d
        m.CSV_FILE, m.HTML_FILE = os.path.join(d, "metrics.csv"), os.path.join(d, "index.html")
        m.LIVE_FILE = os.path.join(d, "live.json")
        m.run = lambda *a, **k: "false\n"
        m.main()
        live = json.load(open(m.LIVE_FILE))
        self.assertEqual(live["status"], "offline")
        self.assertFalse(live["online"])
        self.assertAlmostEqual(live["updated_epoch"], time.time(), delta=5)
        html = open(m.HTML_FILE).read()
        self.assertIn("statusBadge", html)
        self.assertIn("OFFLINE", html)

    def test_html_badge_for_each_status(self):
        for st in ("online", "offline", "unknown"):
            h = self.mon.generate_html([], {"status": st})
            self.assertIn(f"class='{st}'>{st.upper()}</span>", h)

    def test_steam_name_override_file(self):
        d = tempfile.mkdtemp(prefix="emsteam_")
        p = os.path.join(d, "names.json")
        with open(p, "w") as f:
            json.dump({"1": "Alice"}, f)
        self.mon.STEAM_NAMES_FILE = p
        try:
            self.assertEqual(self.mon._load_steam_overrides(), {"1": "Alice"})
        finally:
            self.mon.STEAM_NAMES_FILE = ""
        self.assertEqual(self.mon._load_steam_overrides(), {})

    SLOTS = {2: 40, 1: 25}
    SMAP = {1: "111", 2: "222"}

    def test_anonymous_default_hides_names_and_ids(self):
        out = self.mon.build_player_entries(self.SLOTS, self.SMAP, "anonymous", {"111": "Alice"})
        self.assertEqual(out, [{"ping": 25, "name": "Player 1"}, {"ping": 40, "name": "Player 2"}])
        self.assertNotIn("111", json.dumps(out))

    def test_names_mode_uses_mapping_with_fallback_and_no_ids(self):
        out = self.mon.build_player_entries(self.SLOTS, self.SMAP, "names", {"111": "Alice"})
        self.assertEqual([e["name"] for e in out], ["Alice", "Player 2"])
        self.assertNotIn("steam", json.dumps(out).lower())
        self.assertNotIn("111", json.dumps(out))

    def _lookup_env(self):
        m = self.mon
        d = tempfile.mkdtemp(prefix="emlk_")
        old = (m.STEAM_CACHE_FILE, m._fetch_steam_name, m.STEAM_NAMES_FILE)
        m.STEAM_CACHE_FILE = os.path.join(d, "cache.json")
        calls = []
        def fake(sid):
            calls.append(sid)
            return {"111": "Alice", "222": None}.get(sid)
        m._fetch_steam_name = fake
        self.addCleanup(lambda: (setattr(m, "STEAM_CACHE_FILE", old[0]),
                                 setattr(m, "_fetch_steam_name", old[1]),
                                 setattr(m, "STEAM_NAMES_FILE", old[2])))
        return m, calls

    def test_lookup_off_by_default_no_fetch(self):
        m, calls = self._lookup_env()
        self.assertEqual(m.resolve_names(["111"], "names", False), {})
        self.assertEqual(m.resolve_names(["111"], "anonymous", True), {})  # anonymous never looks up
        self.assertEqual(calls, [])

    def test_lookup_fetches_caches_and_falls_back(self):
        m, calls = self._lookup_env()
        self.assertEqual(m.resolve_names(["111", "222"], "names", True), {"111": "Alice"})
        self.assertEqual(sorted(calls), ["111", "222"])
        with open(m.STEAM_CACHE_FILE) as f:
            self.assertEqual(json.load(f), {"111": "Alice"})
        calls.clear()
        self.assertEqual(m.resolve_names(["111"], "names", True), {"111": "Alice"})
        self.assertEqual(calls, [])          # served from cache

    def test_overrides_win_over_lookup(self):
        m, calls = self._lookup_env()
        d = tempfile.mkdtemp(prefix="emov_")
        p = os.path.join(d, "n.json")
        with open(p, "w") as f:
            json.dump({"111": "Override"}, f)
        m.STEAM_NAMES_FILE = p
        self.assertEqual(m.resolve_names(["111"], "names", True), {"111": "Override"})
        self.assertEqual(calls, [])

    def test_fetch_failure_never_raises(self):
        m = self.mon
        real = urllib.request.urlopen
        urllib.request.urlopen = lambda *a, **k: (_ for _ in ()).throw(OSError("no network"))
        try:
            self.assertIsNone(m._fetch_steam_name("111"))
        finally:
            urllib.request.urlopen = real

    def test_fetch_parses_xml_without_network(self):
        import io
        real = urllib.request.urlopen
        class R(io.BytesIO):
            def __enter__(s): return s
            def __exit__(s, *a): pass
        urllib.request.urlopen = lambda *a, **k: R(b"<profile><steamID>Bob</steamID></profile>")
        try:
            self.assertEqual(self.mon._fetch_steam_name("111"), "Bob")
        finally:
            urllib.request.urlopen = real

    def test_html_never_contains_steam_id_or_link(self):
        live = {"status": "online", "pings": [{"ping": 30, "steam_id": "FAKE-ID-0001", "name": "<b>Al</b>"}]}
        h = self.mon.generate_html([], live)
        self.assertNotIn("FAKE-ID-0001", h)
        self.assertNotIn("steamcommunity", h)
        self.assertIn("&lt;b&gt;Al", h)

    def test_invalid_player_display_rejected(self):
        d = tempfile.mkdtemp(prefix="emcfg_")
        p = os.path.join(d, "c.toml")
        with open(p, "w") as f:
            f.write('[general]\nplayer_display = "everyone"\n')
        with self.assertRaises(ValueError):
            cfg.load_config(path=p)
        with unittest.mock.patch.object(cfg, "candidate_paths", _no_host_config):
            self.assertEqual(cfg.load_config(path=None, environ={"HOME": "/nonexistent"})["general"]["player_display"], "anonymous")


class TestLiveJsonEndpoint(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.web = _load("web2", "enshrouded-monitor-web.py")
        cls.tmp = tempfile.mkdtemp(prefix="emlive_")
        cls.web.DATA_DIR = cls.tmp
        cls.srv = HTTPServer(("127.0.0.1", 0), cls.web._Handler)
        cls.port = cls.srv.server_address[1]
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.cookie = f"{cls.web.COOKIE_NAME}={cls.web.make_cookie_value(os.environ['ENSHROUDED_SHARED_PASSWORD'])}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def _live(self):
        c = HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.request("GET", "/live.json", headers={"Cookie": self.cookie})
        r = c.getresponse()
        return json.loads(r.read())

    def _write(self, obj):
        with open(os.path.join(self.tmp, "live.json"), "w") as f:
            json.dump(obj, f)

    def test_missing_file_is_stale(self):
        p = os.path.join(self.tmp, "live.json")
        if os.path.exists(p):
            os.remove(p)
        self.assertEqual(self._live()["status"], "stale")

    def test_fresh_offline(self):
        self._write({"status": "offline", "online": False, "updated_epoch": int(time.time())})
        d = self._live()
        self.assertEqual(d["status"], "offline")
        self.assertFalse(d["online"])

    def test_old_online_becomes_stale_and_not_online(self):
        self._write({"status": "online", "online": True, "updated_epoch": int(time.time()) - 10_000})
        d = self._live()
        self.assertEqual(d["status"], "stale")
        self.assertFalse(d["online"])

    def test_legacy_file_without_timestamp_is_stale(self):
        self._write({"online": True, "players": 3})
        self.assertEqual(self._live()["status"], "stale")

    def test_live_json_strips_steam_ids(self):
        self._write({"status": "online", "updated_epoch": int(time.time()),
                     "pings": [{"ping": 5, "steam_id": "FAKE-ID-0001", "name": None}]})
        d = self._live()
        self.assertNotIn("FAKE-ID-0001", json.dumps(d))
        self.assertEqual(d["pings"], [{"ping": 5, "name": "Player 1"}])

    def test_garbled_file_is_stale(self):
        with open(os.path.join(self.tmp, "live.json"), "w") as f:
            f.write("{not json")
        self.assertEqual(self._live()["status"], "stale")

    def test_admin_disabled_without_compose_file(self):
        c = HTTPConnection("127.0.0.1", self.port, timeout=5)
        c.request("POST", "/admin/restart", headers={"Authorization": "Bearer x"})
        self.assertEqual(c.getresponse().status, 404)


class TestTrustedProxyConfig(unittest.TestCase):
    def test_no_trusted_proxies_by_default(self):
        web = _load("web3", "enshrouded-monitor-web.py")
        self.assertEqual(web._TRUSTED_PROXY_NETS, [])


if __name__ == "__main__":
    unittest.main()
