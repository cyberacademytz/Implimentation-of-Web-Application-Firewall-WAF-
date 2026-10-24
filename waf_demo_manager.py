#!/usr/bin/env python3
"""
WAF DEMO MANAGER  -  Author: www.tca.ac.tz  -  Version 1.0

Shows how a Web Application Firewall (ModSecurity + OWASP Core Rule Set) acts on attack traffic
sent by an attacker machine against a deliberately vulnerable web app (OWASP Juice Shop).

FOR AUTHORIZED SECURITY TRAINING USE ONLY.

Run:   python3 waf_demo_manager.py

Menu:  1 Setup            - installs Juice Shop + WAF automatically
       2 WAF protection   - ON (block) / OFF (log only) / stricter mode
       3 Live view & logs - attacker IP, attack type, result (blocked / passed)
       4 Guided demo      - runs the attacks itself, prints a before/after table
       5 Tools            - attacker cheat-sheet, clear logs, health check, reset

Fully automated: re-runs itself with sudo, installs/repairs Docker + Compose, tries alternative image
sources, picks a free port, and repairs unreachable containers. Standard library only.
"""
import argparse
import collections
import json
import os
import platform
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import traceback
import urllib.error
import urllib.request
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

VERSION = "1.0"
AUTHOR = "www.tca.ac.tz"

IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0
LAB_HOME = Path(os.environ.get("WAF_DEMO_HOME")
                or ("/opt/waf_demo" if IS_ROOT else str(Path.home() / ".waf_demo")))
STATE_FILE = LAB_HOME / "state.json"
COMPOSE_FILE = LAB_HOME / "docker-compose.yml"
IMAGE_DIR = LAB_HOME / "images"          # drop image .tar files here for fully offline installs
JOURNAL = LAB_HOME / "events.jsonl"      # WAF events kept on the host so they survive mode switches
PROJECT = "wafdemo"
WAF_CONTAINER = "wafdemo-waf"
TARGET_CONTAINER = "wafdemo-juice-shop"
LEGACY_CONTAINERS = ["wafdemo-waf", "wafdemo-target-web", "wafdemo-target-db"]   # from earlier script versions
LEGACY_NETWORK = "wafdemo-wafnet"
LOOPBACK = {"127.0.0.1", "localhost", "::1"}
CONTENT_WIDTH = 110

# --------------------------------------------------------------------------- #
# terminal / layout helpers (colour, centering, clearing)
# --------------------------------------------------------------------------- #
try:
    sys.stdout.reconfigure(errors="replace")          # never crash on odd terminals
except Exception:
    pass

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
UTF8 = "utf" in (getattr(sys.stdout, "encoding", "") or "").lower()
USE_COLOR = sys.stdout.isatty() and os.environ.get("NO_COLOR") is None and os.environ.get("TERM") != "dumb"
COLOR256 = USE_COLOR and ("256" in os.environ.get("TERM", "") or bool(os.environ.get("COLORTERM")))

def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if USE_COLOR else text
def dim(t): return _c("2", t)
def bold(t): return _c("1", t)
def green(t): return _c("1;32", t)
def red(t): return _c("1;31", t)
def yellow(t): return _c("1;33", t)
def cyan(t): return _c("1;36", t)
def magenta(t): return _c("1;35", t)

def vlen(s: str) -> int:
    return len(ANSI_RE.sub("", s))

def tsize():
    return shutil.get_terminal_size((100, 30))

def margin() -> str:
    cols = tsize().columns
    width = min(CONTENT_WIDTH, cols - 2)
    return " " * max(0, (cols - width) // 2)

def out(text: str = "") -> None:
    m = margin()
    for line in str(text).split("\n"):
        print(m + line)

def ok(m): out(green("[ OK ] ") + m)
def warn(m): out(yellow("[WARN] ") + m)
def err(m): out(red("[FAIL] ") + m)
def info(m): out(cyan("[INFO] ") + m)

def header(title: str) -> None:
    out()
    out(cyan(("━━ " if UTF8 else "== ") + title.upper() + (" ━━" if UTF8 else " ==")))
    out()

def clear() -> None:
    if sys.stdout.isatty():
        sys.stdout.write("\033[H\033[2J\033[3J")
        sys.stdout.flush()

def center_line(text: str) -> str:
    pad = max(0, (tsize().columns - vlen(text)) // 2)
    return " " * pad + text

def center_block(lines: List[str]) -> Tuple[List[str], int]:
    width = max((vlen(l) for l in lines), default=0)
    pad = max(0, (tsize().columns - width) // 2)
    return [" " * pad + l for l in lines], pad

def box(lines: List[str], title: str = "") -> List[str]:
    tl, tr, bl, br, h, v = ("╔", "╗", "╚", "╝", "═", "║") if UTF8 else ("+", "+", "+", "+", "-", "|")
    inner = max([vlen(l) for l in lines] + [vlen(title) + 6]) + 4
    if title:
        side = inner - vlen(title) - 2
        left = side // 2
        top = cyan(tl + h * left + " ") + cyan(bold(title)) + cyan(" " + h * (side - left) + tr)
    else:
        top = cyan(tl + h * inner + tr)
    body = [cyan(v) + "  " + l + " " * (inner - vlen(l) - 2) + cyan(v) for l in lines]
    return [top] + body + [cyan(bl + h * inner + br)]

ART = [
    "██╗    ██╗ █████╗ ███████╗",
    "██║    ██║██╔══██╗██╔════╝",
    "██║ █╗ ██║███████║█████╗  ",
    "██║███╗██║██╔══██║██╔══╝  ",
    "╚███╔███╔╝██║  ██║██║     ",
    " ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝     ",
]
GRADIENT_256 = ["38;5;51", "38;5;45", "38;5;39", "38;5;33", "38;5;99", "38;5;135"]
GRADIENT_8 = ["1;36", "1;36", "1;34", "1;34", "1;35", "1;35"]

def banner_lines(compact: bool) -> List[str]:
    if compact or not UTF8:
        t = "WAF DEMO MANAGER"
        line = (_c("1;36", "▌ ") if UTF8 else "") + _c("1;37", t) + (_c("1;36", " ▐") if UTF8 else "")
        sub = (dim("ModSecurity + OWASP CRS") + dim("  |  ") + yellow(f"Author: {AUTHOR}") +
               dim("  |  ") + yellow(f"v{VERSION}"))
        return [center_line(line), center_line(sub)]
    grad = GRADIENT_256 if COLOR256 else GRADIENT_8
    lines = [center_line(_c(grad[i], a)) for i, a in enumerate(ART)]
    lines.append("")
    lines.append(center_line(cyan("ModSecurity + OWASP CRS")))
    lines.append(center_line(dim("Web Application Firewall Demonstration lab")))
    lines.append("")
    lines.append(center_line(yellow("Author: " + AUTHOR) + dim("   │   ") + yellow("Version: " + VERSION)))
    return lines

def print_screen_top(compact: bool, extra: Optional[List[str]] = None, vcenter_height: int = 0) -> None:
    clear()
    lines = banner_lines(compact) + [""] + (extra or [])
    if vcenter_height:
        total = len(lines) + vcenter_height
        for _ in range(max(0, (tsize().lines - total) // 2 - 1)):
            print()
    for l in lines:
        print(l)

# --------------------------------------------------------------------------- #
# state
# --------------------------------------------------------------------------- #
DEFAULT_STATE = {
    "installed": False,
    "bind": "127.0.0.1",
    "bind_chosen": False,
    "waf_port": 8080,
    "paranoia": 1,
    "rule_engine": "DetectionOnly",       # DetectionOnly = protection OFF, On = protection ON
    "acknowledged": False,
    "images": {},
}

class State:
    def __init__(self, dry: bool):
        self.dry = dry
        self.data = dict(DEFAULT_STATE)
        if STATE_FILE.exists():
            try:
                loaded = json.loads(STATE_FILE.read_text())
                self.data.update({k: v for k, v in loaded.items() if k in DEFAULT_STATE})
            except (OSError, ValueError):
                warn("State file unreadable; using defaults.")
        self.data["images"] = {k: v for k, v in (self.data.get("images") or {}).items() if k in ("waf", "juice")}

    def save(self):
        if self.dry:
            return
        try:
            LAB_HOME.mkdir(parents=True, exist_ok=True)
            tmp = STATE_FILE.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.data, indent=2))
            os.replace(tmp, STATE_FILE)
        except OSError as e:
            warn(f"Could not save state: {e}")

# --------------------------------------------------------------------------- #
# images & compose file
# --------------------------------------------------------------------------- #
# Alternatives are tried in order (Docker Hub rate limit / blocked registry -> mirror).
IMAGES = {
    "waf": ["owasp/modsecurity-crs:nginx", "ghcr.io/coreruleset/modsecurity-crs:nginx"],
    "juice": ["bkimminich/juice-shop:latest", "ghcr.io/juice-shop/juice-shop:latest"],
}
IMAGE_ENV = {"waf": "LAB_WAF_IMAGE", "juice": "LAB_JUICE_IMAGE"}

COMPOSE_TEMPLATE = """# wafdemo - generated by waf_demo_manager.py. Do not edit by hand; use the menu.
services:
  juice-shop:
    image: ${LAB_JUICE_IMAGE:-bkimminich/juice-shop:latest}
    container_name: wafdemo-juice-shop
    # Deliberately NO 'ports:' entry - the app is reachable ONLY through the WAF.
    security_opt:
      - no-new-privileges:true
    networks: [wafnet]
    restart: unless-stopped
  waf:
    image: ${LAB_WAF_IMAGE:-owasp/modsecurity-crs:nginx}
    container_name: wafdemo-waf
    ports:
      - "${LAB_BIND:-127.0.0.1}:${LAB_WAF_PORT:-8080}:8080"
    environment:
      - BACKEND=http://juice-shop:3000
      - PARANOIA=${LAB_PARANOIA:-1}
      - MODSEC_RULE_ENGINE=${LAB_RULE_ENGINE:-DetectionOnly}
      - ANOMALY_INBOUND=5
      - ANOMALY_OUTBOUND=4
      - MODSEC_AUDIT_ENGINE=RelevantOnly
      - MODSEC_AUDIT_LOG=/dev/stdout
      - MODSEC_AUDIT_LOG_FORMAT=JSON
      - TZ=${LAB_TZ:-UTC}
    security_opt:
      - no-new-privileges:true
    depends_on: [juice-shop]
    networks: [wafnet]
    restart: unless-stopped
networks:
  wafnet:
    name: wafdemo-net
"""

# --------------------------------------------------------------------------- #
# log parsing + attack classification
# --------------------------------------------------------------------------- #
NOISE_RULES = {"949110", "959100", "980130", "980170"}      # CRS correlation / summary rules
ACCESS_RE = re.compile(r'"(?P<method>[A-Z]+) (?P<uri>\S+) HTTP/[\d.]+" (?P<status>\d{3})')
SCORE_RE = re.compile(r"Total Score:\s*(\d+)", re.I)
EL_ID = re.compile(r'\[id "(\d+)"\]')
EL_MSG = re.compile(r'\[msg "([^"]*)"\]')
EL_URI = re.compile(r'\[uri "([^"]*)"\]')
EL_UID = re.compile(r'\[unique_id "([^"]*)"\]')
EL_CLIENT = re.compile(r"client: ([^,\s]+)")
EL_REQ = re.compile(r'request: "([A-Z]+) (\S+)')
EL_CODE = re.compile(r"Access denied with code (\d+)")

# CRS rule-ID ranges -> plain-words attack type (highest priority first)
CRS_CATEGORY = [
    ("942", "SQL injection"), ("941", "Cross-site scripting"), ("932", "Command injection"),
    ("930", "Path traversal"), ("931", "Remote file inclusion"), ("934", "Node.js injection"),
    ("933", "PHP injection"), ("944", "Java attack"), ("943", "Session fixation"),
    ("913", "Scanner / attack tool"), ("921", "HTTP request smuggling"), ("920", "Protocol violation"),
    ("911", "Method not allowed"), ("910", "Bad IP reputation"), ("912", "DoS protection"),
]

def attack_type(rules: list) -> str:
    ids = [r[0] for r in rules]
    for prefix, label in CRS_CATEGORY:
        if any(i.startswith(prefix) for i in ids):
            return label
    return "Suspicious request"

VERDICT_LABEL = {   # verdict -> (plain-words result, colour)
    "BLOCKED": ("BLOCKED (403)", "1;31"),
    "WOULD BLOCK": ("PASSED - logged only", "1;33"),
    "FLAGGED": ("PASSED - flagged", "33"),
    "ALLOWED": ("ALLOWED", "1;32"),
}

def verdict_for(status: int, exceeded: bool, rules: list) -> str:
    if status == 403:
        return "BLOCKED"
    if exceeded:
        return "WOULD BLOCK"     # protection OFF: threshold crossed but request was forwarded
    if rules:
        return "FLAGGED"         # rule(s) matched, score below threshold
    return "ALLOWED"

def make_event(time_, ip, method, uri, status, rules, score, exceeded, uid="") -> dict:
    return {"uid": uid, "time": time_, "ip": ip, "method": method, "uri": uri, "status": status,
            "rules": rules, "score": score, "attack": attack_type(rules),
            "verdict": verdict_for(status, exceeded, rules), "exceeded": exceeded}

def parse_audit_line(line: str) -> Optional[dict]:
    """One ModSecurity v3 JSON audit-log line -> flat event (None if not an audit record)."""
    line = line.strip()
    if not line.startswith("{"):
        return None
    try:
        d = json.loads(line)
    except ValueError:
        return None
    tx = d.get("transaction") if isinstance(d, dict) else None
    if not isinstance(tx, dict):
        return None
    req, resp = tx.get("request") or {}, tx.get("response") or {}
    try:
        status = int(resp.get("http_code", 0))
    except (TypeError, ValueError):
        status = 0
    rules, score, exceeded = [], None, False
    for m in tx.get("messages") or []:
        det = m.get("details") or {}
        rid, text = str(det.get("ruleId", "")), m.get("message", "") or ""
        if "Anomaly Score Exceeded" in text:
            exceeded = True
        sm = SCORE_RE.search(text)
        if sm:
            score = int(sm.group(1))
        if rid and rid not in NOISE_RULES:
            rules.append((rid, text))
    return make_event(tx.get("time_stamp", ""), tx.get("client_ip", ""), req.get("method", ""),
                      req.get("uri", ""), status, rules, score, exceeded, str(tx.get("unique_id", "")))

def events_from_errorlog(lines: List[str]) -> List[dict]:
    """Fallback: rebuild per-transaction events from nginx error-log 'ModSecurity:' lines."""
    groups: "collections.OrderedDict[str, dict]" = collections.OrderedDict()
    for i, l in enumerate(lines):
        if "ModSecurity" not in l or "[id " not in l:
            continue
        um = EL_UID.search(l)
        g = groups.setdefault(um.group(1) if um else f"line{i}",
                              {"uid": um.group(1) if um else "", "ip": "", "method": "", "uri": "", "status": 0,
                               "rules": [], "score": None, "exceeded": False})
        cl = EL_CLIENT.search(l)
        if cl:
            g["ip"] = cl.group(1)
        rm = EL_REQ.search(l)
        if rm:
            g["method"], g["uri"] = rm.group(1), rm.group(2)
        else:
            u2 = EL_URI.search(l)
            if u2 and not g["uri"]:
                g["uri"] = u2.group(1)
        cm = EL_CODE.search(l)
        if cm:
            g["status"] = int(cm.group(1))
        im, mm = EL_ID.search(l), EL_MSG.search(l)
        rid, text = (im.group(1) if im else ""), (mm.group(1) if mm else "")
        if "Anomaly Score Exceeded" in text:
            g["exceeded"] = True
        sm = SCORE_RE.search(text)
        if sm:
            g["score"] = int(sm.group(1))
        if rid and rid not in NOISE_RULES:
            g["rules"].append((rid, text))
    return [make_event("", g["ip"], g["method"], g["uri"], g["status"], g["rules"], g["score"], g["exceeded"], g["uid"])
            for g in groups.values()]

def parse_access(line: str) -> Optional[Tuple[str, str, str]]:
    m = ACCESS_RE.search(line)
    if m:
        return m.group("method"), m.group("uri"), m.group("status")
    s = line.strip()
    if s.startswith("{"):
        try:
            d = json.loads(s)
        except ValueError:
            return None
        if isinstance(d, dict) and "transaction" not in d:
            req = str(d.get("request") or d.get("request_line") or "")
            st = d.get("status") or d.get("response_code") or d.get("status_code")
            mm = re.match(r"([A-Z]+) (\S+)", req)
            if mm and st:
                return mm.group(1), mm.group(2), str(st)
    return None

class LiveParser:
    """Turns the WAF container's mixed log stream into one event per transaction.
    Uses the JSON audit record when present and the nginx error-log lines as a fallback."""
    def __init__(self):
        self.lines: "collections.OrderedDict[str, list]" = collections.OrderedDict()
        self.emitted: "collections.OrderedDict[str, int]" = collections.OrderedDict()

    @staticmethod
    def _trim(od, n: int = 1000) -> None:
        while len(od) > n:
            od.popitem(last=False)

    def feed(self, line: str) -> Optional[dict]:
        ev = parse_audit_line(line)
        if ev:
            uid = ev.get("uid") or ""
            if uid and uid in self.emitted:
                return None
            if uid:
                self.emitted[uid] = 1
                self._trim(self.emitted)
                self.lines.pop(uid, None)
            return ev
        if "ModSecurity" in line and "[id " in line:
            um = EL_UID.search(line)
            if not um:
                return None
            uid = um.group(1)
            if uid in self.emitted:
                return None
            self.lines.setdefault(uid, []).append(line)
            self._trim(self.lines)
            if '[id "949110"]' in line:                      # transaction summary line
                evs = events_from_errorlog(self.lines.pop(uid, []))
                self.emitted[uid] = 1
                self._trim(self.emitted)
                return evs[0] if evs else None
        return None

def fmt_event(ev: dict, with_time: bool = False) -> str:
    label, col = VERDICT_LABEL.get(ev["verdict"], (ev["verdict"], "0"))
    uri = ev["uri"] if len(ev["uri"]) <= 30 else ev["uri"][:27] + "..."
    t = (dim(time.strftime("%H:%M:%S")) + " ") if with_time else ""
    return (f"{t}{(ev['ip'] or '-')[:15]:<15} {ev['attack']:<21} {_c(col, label.ljust(21))} "
            f"{ev['method']:<5} {uri}")

# --------------------------------------------------------------------------- #
# process / network helpers
# --------------------------------------------------------------------------- #
class Runner:
    def __init__(self, dry: bool):
        self.dry = dry
        self.use_sudo = False

    def _prep(self, cmd: List[str]) -> List[str]:
        if self.use_sudo and cmd and cmd[0] == "docker":
            return ["sudo"] + cmd
        return cmd

    def run(self, cmd: List[str], *, env: Optional[Dict[str, str]] = None, timeout: Optional[int] = 120,
            mutating: bool = False) -> Tuple[int, str, str]:
        cmd = self._prep(cmd)
        if self.dry and mutating:
            out(magenta("[dry-run] $ ") + shlex.join(cmd))
            return 0, "", ""
        full_env = os.environ.copy()
        if env:
            full_env.update(env)
        try:
            cp = subprocess.run(cmd, env=full_env, capture_output=True, text=True, timeout=timeout,
                                check=False, stdin=subprocess.DEVNULL)
            return cp.returncode, cp.stdout or "", cp.stderr or ""
        except FileNotFoundError:
            return 127, "", f"command not found: {cmd[0]}"
        except subprocess.TimeoutExpired:
            return 124, "", f"timed out after {timeout}s"
        except OSError as e:
            return 126, "", str(e)

    def task(self, label: str, cmd: List[str], *, env: Optional[Dict[str, str]] = None,
             timeout: int = 1800, quiet: bool = False) -> Tuple[int, str]:
        """Run a long command with a spinner; show the output tail only when it fails."""
        cmd = self._prep(cmd)
        if self.dry:
            out(magenta("[dry-run] $ ") + shlex.join(cmd))
            return 0, ""
        full_env = os.environ.copy()
        if env:
            full_env.update(env)
        tty = sys.stdout.isatty()
        frames = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏" if UTF8 else "|/-\\"
        with tempfile.TemporaryFile(mode="w+") as tf:
            try:
                p = subprocess.Popen(cmd, stdout=tf, stderr=subprocess.STDOUT, env=full_env,
                                     stdin=subprocess.DEVNULL)
            except (FileNotFoundError, OSError) as e:
                if not quiet:
                    err(f"{label}: {e}")
                return 127, str(e)
            start, i = time.time(), 0
            try:
                while True:
                    rc = p.poll()
                    if rc is not None:
                        break
                    if time.time() - start > timeout:
                        p.kill()
                        rc = 124
                        break
                    if tty:
                        sys.stdout.write("\r" + margin() + cyan(frames[i % len(frames)]) +
                                         f" {label} ({int(time.time() - start)}s)\033[K")
                        sys.stdout.flush()
                    i += 1
                    time.sleep(0.12)
            except KeyboardInterrupt:
                p.kill()
                if tty:
                    sys.stdout.write("\r\033[K")
                raise
            if tty:
                sys.stdout.write("\r\033[K")
            tf.seek(0)
            output = tf.read()
        if rc == 0:
            if not quiet:
                ok(label)
        elif not quiet:
            err(f"{label} (exit {rc})")
            for l in output.strip().splitlines()[-8:]:
                out(dim("    " + l[:CONTENT_WIDTH - 6]))
        return rc, output

    def stream(self, cmd: List[str], handler: Callable[[str], None]) -> None:
        """Run a long-lived command and feed each output line to handler (Ctrl+C stops it)."""
        p = subprocess.Popen(self._prep(cmd), stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             text=True, bufsize=1, stdin=subprocess.DEVNULL)
        try:
            for line in p.stdout:                    # type: ignore[union-attr]
                handler(line.rstrip("\n"))
        except KeyboardInterrupt:
            pass
        finally:
            p.terminate()

def http_request(url: str, method: str = "GET", headers: Optional[Dict[str, str]] = None,
                 body: Optional[str] = None, timeout: int = 15) -> Tuple[Optional[int], str]:
    hdrs = {"User-Agent": "waf-demo-manager/1.0"}
    hdrs.update(headers or {})
    try:
        req = urllib.request.Request(url, data=body.encode() if body is not None else None,
                                     headers=hdrs, method=method)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        try:
            return e.code, e.read().decode("utf-8", "replace")
        except Exception:
            return e.code, ""
    except Exception:
        return None, ""

def http_get(url: str, timeout: int = 6) -> Optional[int]:
    return http_request(url, timeout=timeout)[0]

def port_free(host: str, port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1" if host == "localhost" else host, port))
        return True
    except OSError:
        return False
    finally:
        s.close()

def tcp_reachable(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False

def lan_ips() -> List[str]:
    ips: List[str] = []
    try:
        r = subprocess.run(["hostname", "-I"], capture_output=True, text=True, timeout=5)
        ips = [i for i in r.stdout.split() if re.match(r"^\d+\.\d+\.\d+\.\d+$", i)
               and not i.startswith("172.17.") and not i.startswith("127.")]
    except Exception:
        pass
    if not ips:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("192.0.2.1", 9))
            ips = [s.getsockname()[0]]
            s.close()
        except OSError:
            pass
    return ips

# --------------------------------------------------------------------------- #
# guided-demo attack definitions (sent only to the lab WAF on this machine)
# --------------------------------------------------------------------------- #
JSON_H = {"Content-Type": "application/json"}

def _attack(method: str, path: str, headers: Optional[Dict[str, str]] = None,
            body: Optional[str] = None) -> Callable[[str], Optional[int]]:
    return lambda base: http_request(base + path, method, headers, body)[0]

def business_logic_probe(base: str) -> Optional[int]:
    """A well-formed, authenticated request that tampers with ANOTHER user's basket (broken access
    control). Nothing in it looks like an attack pattern, so the WAF has nothing to match."""
    rnd = str(int(time.time() * 1000))[-8:]
    email, pw = f"demo{rnd}@juice-sh.op", "Demo#12345"
    http_request(base + "/api/Users", "POST", JSON_H, json.dumps({
        "email": email, "password": pw, "passwordRepeat": pw, "securityAnswer": "demo",
        "securityQuestion": {"id": 1, "question": "Your eldest siblings middle name?",
                             "createdAt": "2020-01-01T00:00:00.000Z", "updatedAt": "2020-01-01T00:00:00.000Z"}}))
    _, body = http_request(base + "/rest/user/login", "POST", JSON_H, json.dumps({"email": email, "password": pw}))
    headers, bid = dict(JSON_H), 1
    try:
        auth = json.loads(body)["authentication"]
        headers["Authorization"] = "Bearer " + auth["token"]
        bid = int(auth["bid"])
    except (ValueError, KeyError, TypeError):
        pass
    other = bid - 1 if bid > 1 else bid + 1
    payload = '{"ProductId":1,"BasketId":"%s","quantity":1,"BasketId":"%s"}' % (bid, other)
    return http_request(base + "/api/BasketItems", "POST", headers, payload)[0]

DEMO_ATTACKS: List[Tuple[str, Callable[[str], Optional[int]], bool]] = [
    ("SQL injection (login bypass)", _attack("POST", "/rest/user/login", JSON_H,
        json.dumps({"email": "' OR 1=1--", "password": "x"})), False),
    ("SQL injection (search UNION)", _attack("GET",
        "/rest/products/search?q=apple%27))%20UNION%20SELECT%20*%20FROM%20Users--"), False),
    ("Cross-site scripting", _attack("GET",
        "/rest/products/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"), False),
    ("Path traversal", _attack("GET", "/ftp/..%2f..%2f..%2f..%2fetc%2fpasswd"), False),
    ("Command injection", _attack("GET", "/rest/products/search?q=%3Bcat%20%2Fetc%2Fpasswd"), False),
    ("Automated scanner (sqlmap)", _attack("GET", "/",
        {"User-Agent": "sqlmap/1.7.2#stable (https://sqlmap.org)"}), False),
    ("Business logic: basket tampering", business_logic_probe, True),
]

# --------------------------------------------------------------------------- #
# lab controller
# --------------------------------------------------------------------------- #
class Lab:
    def __init__(self, args: argparse.Namespace):
        self.args = args
        self.dry = args.dry_run
        self.yes = args.yes
        self.state = State(self.dry)
        self.runner = Runner(self.dry)
        self.compose: Optional[List[str]] = None
        self._preflight_done = False
        self._detect_compose()

    @property
    def s(self) -> dict:
        return self.state.data

    # ---- prompts ---------------------------------------------------------
    def confirm(self, q: str, default: bool = True) -> bool:
        if self.yes:
            out(f"{q} [auto-yes]")
            return True
        try:
            a = input(margin() + f"{q} {'[Y/n]' if default else '[y/N]'} ").strip().lower()
        except EOFError:
            return default
        return default if not a else a in ("y", "yes")

    def ask(self, prompt: str, default: str = "") -> str:
        if self.yes:
            return default
        try:
            v = input(margin() + prompt).strip()
        except EOFError:
            return default
        return v or default

    # ---- docker detection / auto-install / auto-repair -------------------
    def _detect_compose(self) -> None:
        self.compose = None
        if shutil.which("docker"):
            rc, _, _ = self.runner.run(["docker", "compose", "version"], timeout=20)
            if rc == 0:
                self.compose = ["docker", "compose"]
                return
        if shutil.which("docker-compose"):
            self.compose = ["docker-compose"]

    def docker_versions(self) -> Tuple[Optional[str], Optional[str], str]:
        if not shutil.which("docker"):
            return None, None, "docker CLI not found"
        rc, o, e = self.runner.run(["docker", "version", "--format", "{{.Server.Version}}"], timeout=25)
        server = o.strip() if rc == 0 and o.strip() else None
        why = "" if server else (e.strip().splitlines()[-1] if e.strip() else "daemon not reachable")
        comp = None
        if self.compose:
            rc2, o2, _ = self.runner.run(self.compose + ["version", "--short"], timeout=20)
            comp = o2.strip() if rc2 == 0 else None
        return server, comp, why

    def sudo(self) -> Optional[List[str]]:
        if IS_ROOT:
            return []
        return ["sudo"] if shutil.which("sudo") else None

    def _apt_has(self, pkg: str) -> bool:
        _, o, _ = self.runner.run(["apt-cache", "policy", pkg], timeout=40)
        m = re.search(r"Candidate:\s*(\S+)", o)
        return bool(m and m.group(1) != "(none)")

    def start_daemon(self, sudo: List[str]) -> bool:
        for label, cmd in (("Starting Docker service", sudo + ["systemctl", "enable", "--now", "docker"]),
                           ("Starting Docker service (sysv)", sudo + ["service", "docker", "start"])):
            if not shutil.which(cmd[len(sudo)]):
                continue
            self.runner.task(label, cmd, timeout=120, quiet=True)
            if self.dry:
                return True
            for _ in range(15):
                if self.docker_versions()[0]:
                    return True
                time.sleep(2)
        return False

    def install_compose_plugin(self, sudo: List[str]) -> None:
        """Last resort: download the official Compose v2 plugin binary from GitHub."""
        arch = {"x86_64": "x86_64", "amd64": "x86_64", "aarch64": "aarch64", "arm64": "aarch64",
                "armv7l": "armv7"}.get(platform.machine().lower())
        if not arch:
            warn(f"No Compose binary known for architecture {platform.machine()}.")
            return
        url = f"https://github.com/docker/compose/releases/latest/download/docker-compose-linux-{arch}"
        dest = Path("/usr/local/lib/docker/cli-plugins/docker-compose")
        if self.dry:
            out(magenta("[dry-run] would download ") + url)
            return
        if sudo != []:
            warn("Root rights are needed to install the Compose plugin.")
            return
        info("Downloading Docker Compose plugin from GitHub...")
        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            part = str(dest) + ".part"
            with urllib.request.urlopen(url, timeout=60) as r, open(part, "wb") as f:
                shutil.copyfileobj(r, f)
            os.chmod(part, 0o755)
            os.replace(part, str(dest))
            ok("Docker Compose plugin installed.")
        except Exception as e:
            warn(f"Compose download failed: {e}")
        self._detect_compose()

    def install_docker(self, sudo: List[str]) -> None:
        need_cli, need_comp = not shutil.which("docker"), self.compose is None
        if not need_cli and not need_comp:
            return
        if shutil.which("apt-get"):
            apt = sudo + ["env", "DEBIAN_FRONTEND=noninteractive", "apt-get", "-y", "-q",
                          "-o", "DPkg::Lock::Timeout=300"]
            self.runner.task("Updating package lists", apt + ["update"], quiet=True)
            pkgs = ["ca-certificates", "curl"]
            if need_cli:
                pkgs.append("docker.io")
            if need_comp:
                for cand in ("docker-compose-v2", "docker-compose-plugin", "docker-compose"):
                    if self.dry or self._apt_has(cand):
                        pkgs.append(cand)
                        break
            label = "Installing " + ", ".join(pkgs)
            rc, _ = self.runner.task(label, apt + ["install"] + pkgs, quiet=True)
            if rc != 0:
                warn("Package install failed - repairing package state and retrying...")
                self.runner.task("dpkg --configure -a", sudo + ["dpkg", "--configure", "-a"], quiet=True)
                self.runner.task("apt-get -f install", apt + ["-f", "install"], quiet=True)
                self.runner.task(label, apt + ["install"] + pkgs)
            else:
                ok(label)
            self._detect_compose()
        if not shutil.which("docker") and not self.dry:
            warn("Package manager route failed - trying the official Docker installer script...")
            script = LAB_HOME / "get-docker.sh"
            try:
                with urllib.request.urlopen("https://get.docker.com", timeout=40) as r:
                    script.write_bytes(r.read())
            except Exception as e:
                warn(f"Could not download the installer: {e}")
                return
            self.runner.task("Running official Docker installer", sudo + ["sh", str(script)], timeout=1800)
            self._detect_compose()

    def ensure_docker(self) -> bool:
        server, comp, why = self.docker_versions()
        if server and self.compose:
            return True
        sudo = self.sudo()
        if sudo is None:
            err("Root rights are needed to install/start Docker, and 'sudo' is not available. Run as root.")
            return False
        if shutil.which("docker") and not server:
            info(f"Docker daemon not responding ({why}) - starting it...")
            if self.start_daemon(sudo):
                server, comp, why = self.docker_versions()
        if not (server and self.compose):
            warn("Docker / Compose missing - installing automatically...")
            self.install_docker(sudo)
            if shutil.which("docker") and not self.docker_versions()[0]:
                self.start_daemon(sudo)
            if self.compose is None and shutil.which("docker"):
                self.install_compose_plugin(sudo)
            server, comp, why = self.docker_versions()
            if not server and "permission denied" in why.lower() and sudo == ["sudo"]:
                info("Using sudo for docker commands in this session.")
                self.runner.use_sudo = True
                server, comp, why = self.docker_versions()
        if server and self.compose:
            ok(f"Docker {server} ready (Compose {comp or '?'}).")
            return True
        if self.dry:
            self.compose = self.compose or ["docker", "compose"]
            return True
        err(f"Docker is still not usable ({why or 'Compose missing'}). See https://docs.docker.com/engine/install/")
        return False

    # ---- pre-flight (silent unless something is wrong) ---------------------
    def preflight(self) -> None:
        if self._preflight_done:
            return
        self._preflight_done = True
        issues: List[str] = []
        try:
            free = shutil.disk_usage("/").free / 1e9
            if free < 4:
                issues.append(f"Low disk space: {free:.1f} GB free (images need ~3 GB).")
        except OSError:
            pass
        try:
            for l in Path("/proc/meminfo").read_text().splitlines():
                if l.startswith("MemAvailable") and int(l.split()[1]) / 1e6 < 1:
                    issues.append("Low free memory (< 1 GB); Juice Shop may start slowly.")
                    break
        except (OSError, ValueError):
            pass
        if not (tcp_reachable("registry-1.docker.io", 443) or tcp_reachable("ghcr.io", 443)):
            issues.append(f"No internet to the image registries - local images or tarballs in {IMAGE_DIR} will be used.")
        if issues:
            header("Pre-flight warnings")
            for i in issues:
                warn(i)
            out()

    def prepare(self) -> bool:
        self.preflight()
        return self.ensure_acknowledged() and self.ensure_docker()

    def ensure_acknowledged(self) -> bool:
        if self.s.get("acknowledged"):
            return True
        header("Security notice")
        out("OWASP Juice Shop is INTENTIONALLY VULNERABLE.\n"
            " * Use this lab only on an isolated / trusted virtual network.\n"
            " * Do not enter real credentials or personal data.\n"
            " * Only expose the WAF to a LAN you control.")
        if not (self.args.accept_risk or self.yes) and self.ask("Type I UNDERSTAND to continue: ") != "I UNDERSTAND":
            warn("Not acknowledged; aborting.")
            return False
        self.s["acknowledged"] = True
        self.state.save()
        return True

    # ---- compose plumbing -------------------------------------------------
    def env_for_state(self) -> Dict[str, str]:
        s = self.s
        env = {"LAB_BIND": s["bind"], "LAB_WAF_PORT": str(s["waf_port"]),
               "LAB_PARANOIA": str(s["paranoia"]), "LAB_RULE_ENGINE": s["rule_engine"]}
        for key, image in s["images"].items():
            env[IMAGE_ENV[key]] = image
        return env

    def write_compose(self) -> None:
        if self.dry:
            out(magenta("[dry-run] would write ") + str(COMPOSE_FILE))
            return
        LAB_HOME.mkdir(parents=True, exist_ok=True)
        COMPOSE_FILE.write_text(COMPOSE_TEMPLATE)

    def dc_task(self, label: str, *args: str, quiet: bool = False) -> Tuple[int, str]:
        if not self.compose:
            if self.dry:
                self.compose = ["docker", "compose"]
            else:
                return 1, "Docker Compose is not available."
        self.write_compose()
        cmd = self.compose + ["-p", PROJECT, "-f", str(COMPOSE_FILE)] + list(args)
        return self.runner.task(label, cmd, env=self.env_for_state(), quiet=quiet)

    def cstate(self, name: str) -> str:
        rc, o, _ = self.runner.run(["docker", "inspect", "-f", "{{.State.Status}}", name], timeout=20)
        return o.strip() if rc == 0 and o.strip() else "missing"

    def legacy_cleanup(self) -> None:
        """Remove containers/network left by earlier versions of this tool (different compose project)."""
        for name in LEGACY_CONTAINERS:
            rc, o, _ = self.runner.run(["docker", "inspect", "-f",
                                        '{{index .Config.Labels "com.docker.compose.project"}}', name], timeout=20)
            if rc == 0 and o.strip() != PROJECT:
                self.runner.task(f"Removing old container {name}", ["docker", "rm", "-f", name], quiet=True)
        if self.runner.run(["docker", "network", "inspect", LEGACY_NETWORK], timeout=20)[0] == 0:
            self.runner.run(["docker", "network", "rm", LEGACY_NETWORK], mutating=True, timeout=30)

    def reconcile(self) -> None:
        """Adopt reality: sync saved state with the containers that really exist."""
        if not shutil.which("docker"):
            return
        rc, o, _ = self.runner.run(["docker", "ps", "-a", "--filter", "name=wafdemo-",
                                    "--format", "{{.Names}}"], timeout=25)
        if rc != 0:
            return
        names = set(o.split())
        self.s["installed"] = TARGET_CONTAINER in names and WAF_CONTAINER in names
        self.state.save()

    # ---- images -----------------------------------------------------------
    def image_local(self, image: str) -> bool:
        return self.runner.run(["docker", "image", "inspect", image], timeout=25)[0] == 0

    def ensure_image(self, key: str) -> bool:
        cands = IMAGES[key]
        chosen = self.s["images"].get(key)
        if chosen and self.image_local(chosen):
            return True
        for c in cands:                                   # already on this machine?
            if self.image_local(c):
                self.s["images"][key] = c
                self.state.save()
                return True
        if IMAGE_DIR.is_dir():                            # offline route: docker load local tarballs
            for t in sorted(p for p in IMAGE_DIR.iterdir() if p.suffix in (".tar", ".gz", ".tgz")):
                self.runner.task(f"Loading local image {t.name}", ["docker", "load", "-i", str(t)], quiet=True)
            for c in cands:
                if self.image_local(c):
                    self.s["images"][key] = c
                    self.state.save()
                    return True
        for c in cands:                                   # network route, alternative registries
            for attempt in (1, 2):
                rc, _ = self.runner.task(f"Downloading {c}" + (" (retry)" if attempt == 2 else ""),
                                         ["docker", "pull", c], quiet=(attempt == 1))
                if rc == 0:
                    self.s["images"][key] = c
                    self.state.save()
                    if attempt == 1:
                        ok(f"Downloaded {c}")
                    return True
                time.sleep(3)
            warn(f"Could not download {c}; trying the next source...")
        if self.dry:
            return True
        err(f"No image source worked for '{key}'. If this machine is offline, run "
            f"'docker save <image> -o file.tar' elsewhere, copy the file to {IMAGE_DIR}/ and retry.")
        return False

    # ---- generic wait with spinner & stall handler -------------------------
    def wait_until(self, label: str, pred: Callable[[], bool], timeout: int = 120, interval: float = 2.0,
                   stall_after: Optional[int] = None, on_stall: Optional[Callable[[], None]] = None) -> bool:
        if self.dry:
            out(magenta("[dry-run] would wait for: ") + label)
            return True
        tty = sys.stdout.isatty()
        frames = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏" if UTF8 else "|/-\\"
        start, last, i, stalled = time.time(), 0.0, 0, False
        while True:
            el = time.time() - start
            if time.time() - last >= interval:
                last = time.time()
                try:
                    if pred():
                        if tty:
                            sys.stdout.write("\r\033[K")
                        ok(f"{label} ({int(el)}s)")
                        return True
                except Exception:
                    pass
            if el >= timeout:
                if tty:
                    sys.stdout.write("\r\033[K")
                warn(f"{label}: timed out after {timeout}s")
                return False
            if on_stall and not stalled and stall_after is not None and el >= stall_after:
                stalled = True
                if tty:
                    sys.stdout.write("\r\033[K")
                on_stall()
            if tty:
                sys.stdout.write("\r" + margin() + cyan(frames[i % len(frames)]) + f" {label} ({int(el)}s)\033[K")
                sys.stdout.flush()
            i += 1
            time.sleep(0.15)

    # ===================================================================== #
    # 1. SETUP
    # ===================================================================== #
    def waf_host(self) -> str:
        return "127.0.0.1" if self.s["bind"] in ("0.0.0.0", "::", "localhost") else self.s["bind"]

    def attacker_host(self) -> str:
        if self.s["bind"] in ("0.0.0.0", "::"):
            ips = lan_ips()
            return ips[0] if ips else "<server-ip>"
        return self.s["bind"]

    def choose_bind(self) -> None:
        out("Where will the attacker machine connect from?")
        out("  [1] Another machine on the lab network (LAN)  - typical two-VM demo")
        out("  [2] This machine only (localhost)")
        choice = self.ask("Select [1/2] (default 1): ", "1")
        if choice == "2":
            self.s["bind"] = "127.0.0.1"
        else:
            self.s["bind"] = "0.0.0.0"
            warn("The WAF will accept connections from your LAN - use an isolated/trusted lab network only.")
        self.s["bind_chosen"] = True
        self.state.save()

    def pick_port(self) -> None:
        if self.cstate(WAF_CONTAINER) == "running":
            return                                    # our own container holds the port
        host, port = self.s["bind"], self.s["waf_port"]
        if port_free(host, port):
            return
        for p in range(port + 1, port + 30):
            if port_free(host, p):
                warn(f"Port {port} is already in use - using {p} instead.")
                self.s["waf_port"] = p
                self.state.save()
                return
        warn(f"Port {port} looks busy and no free alternative was found; trying anyway.")

    def open_firewall(self) -> None:
        if self.s["bind"] in LOOPBACK or not shutil.which("ufw") or self.dry:
            return
        rc, o, _ = self.runner.run(["ufw", "status"], timeout=15)
        if rc == 0 and "Status: active" in o:
            self.runner.task(f"Opening port {self.s['waf_port']}/tcp in ufw",
                             (self.sudo() or []) + ["ufw", "allow", f"{self.s['waf_port']}/tcp"], quiet=True)

    def setup(self) -> bool:
        if not self.prepare():
            return False
        self.legacy_cleanup()
        running = self.cstate(WAF_CONTAINER) == "running" and self.cstate(TARGET_CONTAINER) == "running"
        if running and self.s["installed"]:
            ok("Juice Shop and the WAF are already installed and running.")
            if self.confirm("Change who can connect (LAN / this machine only)?", default=False):
                self.choose_bind()
                self.pick_port()
                self.recreate_waf()
                self.wait_ready(timeout=90)
            self.show_urls()
            return True
        if not self.s["bind_chosen"] and not self.yes:
            self.choose_bind()
        if not (self.ensure_image("juice") and self.ensure_image("waf")):
            return False
        self.pick_port()
        rc, _ = self.dc_task("Starting Juice Shop + WAF", "up", "-d")
        if rc != 0:
            info("Retrying with a clean recreate...")
            rc, _ = self.dc_task("Recreating containers", "up", "-d", "--force-recreate")
            if rc != 0:
                return False
        self.s["installed"] = True
        self.state.save()
        self.open_firewall()
        if self.dry:
            return True
        if not self.wait_ready():
            return False
        self.quick_check()
        self.show_urls()
        return True

    def quick_check(self) -> None:
        base = f"http://{self.waf_host()}:{self.s['waf_port']}"
        normal = http_get(base + "/", timeout=15)
        attack = http_get(base + "/rest/products/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E", timeout=15)
        blocking = self.s["rule_engine"] == "On"
        out(f"  {green('PASS') if normal and normal < 400 else red('FAIL')}  Normal request reaches Juice Shop  (HTTP {normal})")
        good = attack == 403 if blocking else (attack is not None and attack != 403)
        mode = "blocked" if blocking else "forwarded and logged"
        out(f"  {green('PASS') if good else red('FAIL')}  XSS probe {mode}  (HTTP {attack})")
        out()

    def heal_stack(self) -> None:
        """Automatic repair when the WAF does not answer: start everything, recreate the WAF."""
        warn("No healthy answer yet - running automatic repair...")
        self.dc_task("Starting containers", "up", "-d", quiet=True)
        time.sleep(8)
        self.recreate_waf(quiet=True)

    def wait_ready(self, timeout: int = 200) -> bool:
        base = f"http://{self.waf_host()}:{self.s['waf_port']}/"

        def pred() -> bool:
            code = http_get(base, timeout=5)
            return code is not None and code < 500
        if self.wait_until("Waiting for the WAF to proxy Juice Shop", pred, timeout=timeout,
                           stall_after=60, on_stall=self.heal_stack):
            return True
        err("The WAF did not become ready. Diagnostics:")
        self.show_tail(WAF_CONTAINER)
        self.show_tail(TARGET_CONTAINER)
        return False

    def show_tail(self, name: str, n: int = 12) -> None:
        _, so, se = self.runner.run(["docker", "logs", "--tail", str(n), name], timeout=25)
        short = name.replace("wafdemo-", "")
        for l in (so + "\n" + se).strip().splitlines()[-n:]:
            out(dim(f"    [{short}] " + l[:CONTENT_WIDTH - 20]))

    def show_urls(self) -> None:
        out()
        if self.s["bind"] in ("0.0.0.0", "::"):
            hosts = lan_ips() or ["<server-ip>"]
        else:
            hosts = [self.s["bind"]]
        out(bold("  Attacker should target:"))
        for h in hosts:
            out(green(f"    http://{h}:{self.s['waf_port']}/"))
        out(dim("  Juice Shop itself is NOT published - it can only be reached through the WAF."))
        out()

    def recreate_waf(self, quiet: bool = False, archive: bool = True) -> bool:
        if not self.s["installed"] and self.cstate(WAF_CONTAINER) == "missing":
            warn("Not installed yet - the setting is saved and will apply at Setup.")
            return False
        if archive:
            self.archive_events()
        self.pick_port()
        rc, _ = self.dc_task("Applying configuration to the WAF", "up", "-d", "--force-recreate", "waf",
                             quiet=quiet)
        return rc == 0

    # ===================================================================== #
    # 2. WAF PROTECTION
    # ===================================================================== #
    def apply_mode(self, engine: str, quiet: bool = False) -> bool:
        self.s["rule_engine"] = engine
        self.state.save()
        if not self.recreate_waf(quiet=quiet):
            return False
        label = "Switching protection ON" if engine == "On" else "Switching protection OFF"
        return self.wait_ready(timeout=90) if not quiet else self.wait_until(
            label, lambda: (http_get(f"http://{self.waf_host()}:{self.s['waf_port']}/", 5) or 999) < 500, timeout=90)

    def set_protection(self, on: bool) -> None:
        if self.apply_mode("On" if on else "DetectionOnly"):
            if on:
                ok("PROTECTION ON: matched attacks now get 403 and never reach Juice Shop.")
            else:
                ok("PROTECTION OFF: attacks reach Juice Shop, but the WAF still logs them.")

    def set_paranoia(self, level: Optional[int] = None) -> None:
        out("Stricter mode = higher CRS paranoia level (1 normal, 2 stricter, 3 strictest).")
        out("It catches more attacks but may block legitimate requests - a good talking point.\n")
        if level is None:
            raw = self.ask("Paranoia level [1/2/3] (default 1): ", "1")
            level = int(raw) if raw in ("1", "2", "3") else 1
        self.s["paranoia"] = level
        self.state.save()
        if self.recreate_waf():
            self.wait_ready(timeout=90)
            ok(f"Paranoia level {level} applied.")

    # ===================================================================== #
    # 3. LIVE VIEW & LOGS
    # ===================================================================== #
    def _need_waf(self) -> bool:
        if not shutil.which("docker"):
            err("Docker not found - run Setup first.")
            return False
        if self.cstate(WAF_CONTAINER) != "running":
            warn("The WAF is not running. Run Setup (main menu option 1) first.")
            return False
        return True

    def waf_lines(self, n: int = 3000) -> List[str]:
        """The WAF writes its audit log (JSON), error log and access log to the container output."""
        _, so, se = self.runner.run(["docker", "logs", "--tail", str(n), WAF_CONTAINER], timeout=60)
        return (so + "\n" + se).splitlines()

    @staticmethod
    def events_from_lines(lines: List[str]) -> Tuple[List[dict], str]:
        audit = [e for e in (parse_audit_line(l) for l in lines) if e]
        if audit and not any(e.get("uid") for e in audit):
            return audit, "audit log"
        seen = {e["uid"] for e in audit if e.get("uid")}
        extra = [e for e in events_from_errorlog(lines) if not (e.get("uid") and e["uid"] in seen)]
        return audit + extra, ("audit log" if audit else "error log")

    def fetch_events(self, n: int = 3000, journal: bool = True) -> Tuple[List[dict], str]:
        ev, source = self.events_from_lines(self.waf_lines(n))
        if journal:
            seen = {e["uid"] for e in ev if e.get("uid")}
            ev = [e for e in self.load_journal() if not (e.get("uid") and e["uid"] in seen)] + ev
        return ev, source

    def load_journal(self, n: int = 3000) -> List[dict]:
        try:
            lines = JOURNAL.read_text().splitlines()[-n:]
        except OSError:
            return []
        events = []
        for l in lines:
            try:
                events.append(json.loads(l))
            except ValueError:
                pass
        return events

    def archive_events(self) -> None:
        """Save current WAF events on the host before the container is recreated (mode switch)."""
        if self.dry or self.cstate(WAF_CONTAINER) != "running":
            return
        try:
            events, _ = self.fetch_events(3000, journal=False)
            if events:
                LAB_HOME.mkdir(parents=True, exist_ok=True)
                with open(JOURNAL, "a") as f:
                    for e in events:
                        f.write(json.dumps(e) + "\n")
        except Exception:
            pass

    def wipe_journal(self) -> None:
        try:
            JOURNAL.unlink()
        except OSError:
            pass

    def logs_live(self) -> None:
        if not self._need_waf():
            return
        mode = "PROTECTION ON" if self.s["rule_engine"] == "On" else "PROTECTION OFF (log only)"
        out(f"Mode: {bold(mode)}   |   Watching the WAF live - press Ctrl+C to stop.")
        out(dim("Only requests that trigger WAF rules are listed (normal browsing is not logged by ModSecurity).\n"))
        out(dim(f"{'TIME':<8} {'ATTACKER IP':<15} {'ATTACK TYPE':<21} {'RESULT':<21} {'REQUEST'}"))
        out(dim("─" * 100 if UTF8 else "-" * 100))
        parser = LiveParser()

        def h(line: str) -> None:
            ev = parser.feed(line)
            if ev and ev["verdict"] != "ALLOWED":
                out(fmt_event(ev, with_time=True))
        self.runner.stream(["docker", "logs", "-f", "--tail", "0", WAF_CONTAINER], h)

    def logs_summary(self) -> None:
        if not self._need_waf():
            return
        lines = self.waf_lines()
        events, source = self.fetch_events()
        statuses: collections.Counter = collections.Counter()
        for line in lines:
            a = parse_access(line)
            if a:
                statuses[a[2]] += 1
        total, blocked_http = sum(statuses.values()), statuses.get("403", 0)
        mode = "PROTECTION ON" if self.s["rule_engine"] == "On" else "PROTECTION OFF (log only)"
        out(f"Mode: {bold(mode)}   Paranoia: {bold(str(self.s['paranoia']))}\n")
        out(bold(f"Traffic seen by the WAF since its last restart: {total} requests"))
        out(f"   {green('Allowed (not 403)')} : {total - blocked_http}")
        out(f"   {red('Blocked (403)')}     : {blocked_http}\n")
        if not events:
            info("No attack events yet. Send some attacks from the attacker machine (or run the Guided demo).")
            n_audit = sum(1 for l in lines if parse_audit_line(l))
            n_mod = sum(1 for l in lines if "ModSecurity" in l)
            out(dim(f"   (WAF log lines read: {len(lines)}, audit records: {n_audit}, ModSecurity messages: {n_mod}."))
            out(dim("    If you sent attacks and these are 0, open 'Raw WAF log' in this menu to see what the WAF writes.)"))
            return
        by_type: Dict[str, collections.Counter] = collections.defaultdict(collections.Counter)
        for e in events:
            by_type[e["attack"]]["blocked" if e["verdict"] == "BLOCKED" else "passed"] += 1
        out(bold(f"Attacks detected, by type   [{len(events)} events, from the WAF {source}]"))
        out(dim(f"   {'ATTACK TYPE':<24} {'BLOCKED':>8} {'PASSED (logged)':>16}"))
        for atk, c in sorted(by_type.items(), key=lambda kv: -(kv[1]['blocked'] + kv[1]['passed'])):
            out(f"   {atk:<24} {red(str(c['blocked']).rjust(8)) if c['blocked'] else dim('0'.rjust(8))} "
                f"{yellow(str(c['passed']).rjust(16)) if c['passed'] else dim('0'.rjust(16))}")
        out(bold("\nMost recent attacks"))
        out(dim(f"   {'ATTACKER IP':<15} {'ATTACK TYPE':<21} {'RESULT':<21} REQUEST"))
        for ev in events[-10:]:
            out("   " + fmt_event(ev))
        top = collections.Counter(r[0] for e in events for r in e["rules"])
        names = {r[0]: r[1] for e in events for r in e["rules"]}
        out(bold("\nTop CRS rules triggered"))
        for rid, n in top.most_common(5):
            out(f"   {rid:<8} x{n:<4} {names[rid][:70]}")

    def logs_raw(self) -> None:
        if not self._need_waf():
            return
        out(dim("Last 30 lines exactly as the WAF container wrote them (for troubleshooting):\n"))
        for l in self.waf_lines(30)[-30:]:
            out(dim(l[:CONTENT_WIDTH - 2]))

    # ===================================================================== #
    # 4. GUIDED DEMO
    # ===================================================================== #
    def guided_demo(self) -> bool:
        if not self._need_waf():
            return False
        base = f"http://{self.waf_host()}:{self.s['waf_port']}"
        original = self.s["rule_engine"]
        out("The script now sends the same attacks twice - first with protection OFF, then ON -")
        out("against the lab WAF on this machine, and compares the results.\n")
        results: Dict[str, Dict[str, Optional[int]]] = {name: {} for name, _, _ in DEMO_ATTACKS}
        for mode, title in (("DetectionOnly", "PHASE 1 - PROTECTION OFF (log only)"),
                            ("On", "PHASE 2 - PROTECTION ON (blocking)")):
            out(bold(cyan(title)))
            if not self.apply_mode(mode, quiet=True):
                err("Could not switch the WAF mode; stopping the demo.")
                return False
            for name, fn, _ in DEMO_ATTACKS:
                code = fn(base)
                results[name][mode] = code
                shown = "no response" if code is None else (red(f"HTTP {code}  blocked") if code == 403 else yellow(f"HTTP {code}  reached the app"))
                out(f"   {name:<36} {shown}")
            out()
        if original != self.s["rule_engine"]:
            self.apply_mode(original, quiet=True)
            info(f"WAF returned to its previous setting: protection {'ON' if original == 'On' else 'OFF'}.")
        out()
        self.render_demo_table(results)
        return True

    def render_demo_table(self, results: Dict[str, Dict[str, Optional[int]]]) -> None:
        w1, w2, w3 = 36, 26, 26
        sep = dim(" │ " if UTF8 else " | ")
        out(bold("Attack".ljust(w1)) + sep + bold("Protection OFF".ljust(w2)) + sep + bold("Protection ON".ljust(w3)))
        out(dim(("─" if UTF8 else "-") * (w1 + w2 + w3 + 6)))
        blocked, attacks = 0, 0
        for name, _, is_logic in DEMO_ATTACKS:
            off, on = results[name].get("DetectionOnly"), results[name].get("On")
            if off is None:
                off_t, off_c = "no response", "1;31"
            elif off == 403:
                off_t, off_c = "blocked (403)", "1;32"
            else:
                off_t, off_c = f"passed through ({off})", "1;33"
            if on is None:
                on_t, on_c = "no response", "1;31"
            elif on == 403:
                on_t, on_c = "BLOCKED (403)", "1;32"
            elif is_logic:
                on_t, on_c = f"STILL PASSES ({on})", "1;31"
            else:
                on_t, on_c = f"NOT blocked ({on})", "1;31"
            if not is_logic:
                attacks += 1
                blocked += 1 if on == 403 else 0
            out(name.ljust(w1) + sep + _c(off_c, off_t.ljust(w2)) + sep + _c(on_c, on_t.ljust(w3)))
        out()
        out(bold(f"Result: with protection ON the WAF blocked {blocked} of {attacks} attack-pattern requests."))
        out(dim("'passed through' = the WAF let the request reach Juice Shop (it is still logged in the WAF log)."))
        out(yellow("The last row is the key lesson: it is a well-formed request with no attack pattern, so the WAF"))
        out(yellow("cannot see anything wrong. Broken access control must be fixed in the application itself."))

    # ===================================================================== #
    # 5. TOOLS
    # ===================================================================== #
    def cheat_sheet(self) -> None:
        base = f"http://{self.attacker_host()}:{self.s['waf_port']}"
        out(dim("Copy these into a terminal on the ATTACKER machine (Kali).\n"))
        items = [
            ("Normal request", f'curl -i "{base}/"'),
            ("SQL injection - search", f'curl -i "{base}/rest/products/search?q=apple%27))%20UNION%20SELECT%20*%20FROM%20Users--"'),
            ("SQL injection - login bypass",
             f'curl -i -X POST {base}/rest/user/login -H "Content-Type: application/json" '
             '-d "{\\"email\\":\\"\' OR 1=1--\\",\\"password\\":\\"x\\"}"'),
            ("Cross-site scripting", f'curl -i "{base}/rest/products/search?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E"'),
            ("Path traversal", f'curl -i "{base}/ftp/..%2f..%2f..%2f..%2fetc%2fpasswd"'),
            ("Command injection", f'curl -i "{base}/rest/products/search?q=%3Bcat%20%2Fetc%2Fpasswd"'),
            ("Automated scanner - nikto", f"nikto -h {base}"),
            ("Automated scanner - sqlmap", f'sqlmap -u "{base}/rest/products/search?q=test" --batch'),
        ]
        for label, cmd in items:
            out(bold(label))
            out("  " + green(cmd))
            out()
        out(dim("Protection OFF: these succeed and are logged. Protection ON: all but the normal request return 403."))

    def clear_logs(self) -> None:
        if self.cstate(WAF_CONTAINER) == "missing":
            warn("The WAF is not installed - nothing to clear.")
            return
        info("Recreating the WAF container gives it fresh, empty logs.")
        self.wipe_journal()
        if self.recreate_waf(archive=False):
            self.wait_ready(timeout=90)
            ok("Logs cleared - the audience will now see only what happens from this point on.")

    def reset(self) -> None:
        out("This removes the Juice Shop and WAF containers (downloaded images are kept).")
        if not self.confirm("Reset / uninstall the lab?", default=False):
            info("Cancelled.")
            return
        rc, _ = self.dc_task("Removing containers and network", "down", "--remove-orphans")
        self.legacy_cleanup()
        if rc == 0:
            self.wipe_journal()
            self.s["installed"] = False
            self.s["bind_chosen"] = False
            self.state.save()
            ok("Lab removed. Run Setup (option 1) to install it again.")

    # ---- health check / config / repair -----------------------------------
    def diagnose(self) -> List[str]:
        problems: List[str] = []
        server, _, why = self.docker_versions()
        if not server:
            return [f"Docker daemon not ready ({why})"]
        if self.s["installed"]:
            if self.cstate(TARGET_CONTAINER) != "running":
                problems.append(f"Juice Shop container is {self.cstate(TARGET_CONTAINER)}")
            if self.cstate(WAF_CONTAINER) != "running":
                problems.append(f"WAF container is {self.cstate(WAF_CONTAINER)}")
        rc, o, _ = self.runner.run(["docker", "port", TARGET_CONTAINER], timeout=20)
        if rc == 0 and o.strip():
            problems.append(f"ISOLATION BROKEN: Juice Shop publishes {o.strip()}")
        if self.s["installed"] and not problems:
            code = http_get(f"http://{self.waf_host()}:{self.s['waf_port']}/", timeout=8)
            if code is None or code >= 500:
                problems.append(f"WAF does not return a healthy answer (HTTP {code})")
        return problems

    def repair(self) -> bool:
        header("Auto-repair")
        if not self.prepare():
            return False
        self.legacy_cleanup()
        for key in ("juice", "waf"):
            self.ensure_image(key)
        self.pick_port()
        rc, _ = self.dc_task("Recreating Juice Shop + WAF", "up", "-d", "--force-recreate")
        if rc != 0:
            return False
        self.s["installed"] = True
        self.state.save()
        return self.wait_ready()

    def show_config(self) -> None:
        s = self.s
        rows = [
            ("Target app", "OWASP Juice Shop  (" + ("installed" if s["installed"] else "not installed") + ")"),
            ("WAF protection", "ON - blocking attacks" if s["rule_engine"] == "On" else "OFF - logging only"),
            ("Paranoia level", str(s["paranoia"])),
            ("Attacker URL", f"http://{self.attacker_host()}:{s['waf_port']}/"
                             + ("" if s["bind"] in LOOPBACK else "   (LAN-exposed)")),
            ("Bind address", f"{s['bind']}:{s['waf_port']}"),
            ("Images", ", ".join(f"{k}={v}" for k, v in s["images"].items()) or "-"),
            ("Offline images dir", str(IMAGE_DIR)),
            ("State dir", str(LAB_HOME)),
        ]
        for k, v in rows:
            out(f"  {cyan(f'{k:<20}')}: {v}")
        if not shutil.which("docker"):
            warn("Docker is not installed yet - run Setup (option 1) to install everything automatically.")
            return
        out(bold("\n  Containers"))
        _, o, _ = self.runner.run(["docker", "ps", "-a", "--filter", "name=wafdemo-",
                                   "--format", "{{.Names}}\t{{.Status}}\t{{.Ports}}"], timeout=30)
        if o.strip():
            for line in o.strip().splitlines():
                p = (line.split("\t") + ["", ""])[:3]
                out(f"    {p[0]:<22} {p[1]:<24} {p[2]}")
        else:
            out("    (none)")
        rc, o, _ = self.runner.run(["docker", "inspect", "-f", "{{range .Config.Env}}{{println .}}{{end}}",
                                    WAF_CONTAINER], timeout=20)
        if rc == 0:
            out(bold("\n  Effective WAF settings (from the running container)"))
            for l in o.splitlines():
                if l.startswith(("BACKEND", "PARANOIA", "MODSEC_RULE_ENGINE", "ANOMALY_", "MODSEC_AUDIT")):
                    out("    " + l)
        out(bold("\n  Health check"))
        problems = self.diagnose()
        if not problems:
            ok("Everything looks healthy; Juice Shop is isolated (no published port).")
            return
        for p in problems:
            err(p)
        if self.confirm("Run automatic repair now?", default=True):
            self.repair()

# --------------------------------------------------------------------------- #
# menus
# --------------------------------------------------------------------------- #
MenuItem = Tuple[str, str, Callable[[], object], bool]      # (label, description, action, opens_submenu)

def status_line(lab: Lab) -> str:
    s = lab.s
    dot = "●" if UTF8 else "*"
    app = (green(dot) + " Juice Shop") if s["installed"] else (red(dot) + " not installed")
    if s["installed"]:
        prot = (green(dot) + " PROTECTION ON") if s["rule_engine"] == "On" else (yellow(dot) + " PROTECTION OFF")
    else:
        prot = red(dot) + " WAF not installed"
    return f"{app}    {prot}    {dim(s['bind'] + ':' + str(s['waf_port']))}"

def pause(lab: Lab) -> None:
    if lab.yes:
        return
    try:
        input(margin() + dim("Press Enter to continue ..."))
    except (EOFError, KeyboardInterrupt):
        print()

def run_item(lab: Lab, label: str, fn: Callable[[], object]) -> None:
    print_screen_top(compact=True)
    header(label)
    try:
        fn()
    except KeyboardInterrupt:
        print()
        warn("Stopped.")
    except Exception as e:                                   # never crash the menu
        err(f"Unexpected error: {e}")
        try:
            LAB_HOME.mkdir(parents=True, exist_ok=True)
            (LAB_HOME / "error.log").write_text(traceback.format_exc())
            out(dim(f"    (details saved to {LAB_HOME / 'error.log'})"))
        except OSError:
            pass
    pause(lab)

def draw_menu(lab: Lab, title: str, items: List[MenuItem], full: bool, back_label: str) -> int:
    rows = []
    width = max(len(label) for label, _, _, _ in items)
    for i, (label, desc, _, _) in enumerate(items, 1):
        rows.append(f"{yellow(f'[{i}]')}  {bold(label.ljust(width))}" + (f"   {dim(desc)}" if desc else ""))
    rows.append(f"{red('[0]')}  {bold(back_label)}")
    block, pad = center_block(box(rows, title))
    print_screen_top(compact=not full, extra=[center_line(status_line(lab)), ""],
                     vcenter_height=len(block) + 2)
    for l in block:
        print(l)
    print()
    return pad

def menu(lab: Lab, title: str, items: List[MenuItem], full: bool = False, back_label: str = "Back") -> None:
    while True:
        pad = draw_menu(lab, title, items, full, back_label)
        try:
            raw = input(" " * pad + cyan("Select ▸ " if UTF8 else "Select > ")).strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        if raw == "0":
            return
        if not raw.isdigit() or not (1 <= int(raw) <= len(items)):
            continue                                         # screen is redrawn (cleared) on next loop
        label, _, fn, is_sub = items[int(raw) - 1]
        if is_sub:
            fn()
        else:
            run_item(lab, label, fn)

def build_menus(lab: Lab) -> List[MenuItem]:
    protection: List[MenuItem] = [
        ("Protection ON  (block attacks)", "attacks get 403", lambda: lab.set_protection(True), False),
        ("Protection OFF (log only)", "attacks pass, but are logged", lambda: lab.set_protection(False), False),
        ("Stricter mode (paranoia 1/2/3)", "optional: shows false positives", lab.set_paranoia, False),
    ]
    logs: List[MenuItem] = [
        ("Live attack view", "attacker IP, attack type, result", lab.logs_live, False),
        ("Summary: blocked vs passed", "totals, by attack type, top rules", lab.logs_summary, False),
        ("Raw WAF log", "last 30 lines, for troubleshooting", lab.logs_raw, False),
    ]
    tools: List[MenuItem] = [
        ("Attacker cheat-sheet", "ready-to-copy commands with your IP", lab.cheat_sheet, False),
        ("Clear logs / fresh start", "audience sees only new events", lab.clear_logs, False),
        ("Show config & health check", "with automatic repair", lab.show_config, False),
        ("Reset / uninstall", "remove containers", lab.reset, False),
    ]
    return [
        ("Setup", "Install Juice Shop + WAF automatically", lab.setup, False),
        ("WAF protection", "Switch ON (block) / OFF (log only)",
         lambda: menu(lab, "WAF PROTECTION", protection), True),
        ("Live view & logs", "Attacker, attack type, result",
         lambda: menu(lab, "LIVE VIEW & LOGS", logs), True),
        ("Guided demo", "Automatic before/after attack test", lab.guided_demo, False),
        ("Tools", "Cheat-sheet, clear logs, health check, reset",
         lambda: menu(lab, "TOOLS", tools), True),
    ]

def main_loop(lab: Lab) -> None:
    menu(lab, "MAIN MENU", build_menus(lab), full=True, back_label="Exit")

# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
ACTIONS = {
    "setup": lambda l: l.setup(),
    "protection_on": lambda l: l.set_protection(True),
    "protection_off": lambda l: l.set_protection(False),
    "demo": lambda l: l.guided_demo(),
    "summary": lambda l: l.logs_summary(),
    "live": lambda l: l.logs_live(),
    "raw": lambda l: l.logs_raw(),
    "cheatsheet": lambda l: l.cheat_sheet(),
    "clear_logs": lambda l: l.clear_logs(),
    "config": lambda l: l.show_config(),
    "repair": lambda l: l.repair(),
    "reset": lambda l: l.reset(),
}

def parse_args(argv=None) -> argparse.Namespace:
    ap = argparse.ArgumentParser(description=f"WAF Demo Manager v{VERSION} - {AUTHOR}")
    ap.add_argument("--install", action="store_true", help="run Setup non-interactively, then exit")
    ap.add_argument("--run", metavar="ACTION", help="run one action and exit: " + ", ".join(ACTIONS))
    ap.add_argument("--mode", choices=["detect", "block"], help="initial WAF mode (detect = protection OFF)")
    ap.add_argument("--paranoia", type=int, choices=[1, 2, 3], help="paranoia level")
    ap.add_argument("--bind", help="bind address for the WAF port (127.0.0.1 or 0.0.0.0)")
    ap.add_argument("--yes", "-y", action="store_true", help="auto-confirm prompts")
    ap.add_argument("--accept-risk", action="store_true", help="acknowledge the vulnerable-app notice")
    ap.add_argument("--dry-run", action="store_true", help="show what would happen; change nothing")
    ap.add_argument("--version", action="version", version=f"{VERSION} ({AUTHOR})")
    return ap.parse_args(argv)

def elevate(args: argparse.Namespace) -> None:
    """Re-run the script with sudo so every install/repair step has the rights it needs."""
    if IS_ROOT or args.dry_run or os.environ.get("WAF_DEMO_ELEVATED"):
        return
    if not shutil.which("sudo"):
        print("sudo not found - continuing without root; installs may fail.")
        return
    print("Root rights are needed to install/repair Docker - re-running with sudo ...")
    cmd = ["sudo", "env", "WAF_DEMO_ELEVATED=1"]
    if os.environ.get("WAF_DEMO_HOME"):
        cmd.append("WAF_DEMO_HOME=" + os.environ["WAF_DEMO_HOME"])
    cmd += [sys.executable, os.path.abspath(sys.argv[0])] + sys.argv[1:]
    try:
        os.execvp("sudo", cmd)
    except OSError as e:
        print(f"Could not elevate ({e}); continuing without root.")

def main(argv=None) -> int:
    if os.name != "posix":
        print("This tool supports Linux (Ubuntu/Debian) only.")
        return 2
    args = parse_args(argv)
    elevate(args)
    if not args.dry_run:
        try:
            LAB_HOME.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            print(f"Cannot create {LAB_HOME}: {e}")
            return 1
    lab = Lab(args)
    lab.reconcile()
    if args.bind:
        lab.s["bind"], lab.s["bind_chosen"] = args.bind, True
    if args.paranoia:
        lab.s["paranoia"] = args.paranoia
    if args.mode:
        lab.s["rule_engine"] = "On" if args.mode == "block" else "DetectionOnly"
    lab.state.save()
    if args.install:
        return 0 if lab.setup() else 1
    if args.run:
        if args.run not in ACTIONS:
            err("--run must be one of: " + ", ".join(ACTIONS))
            return 2
        ACTIONS[args.run](lab)
        return 0
    try:
        main_loop(lab)
    except KeyboardInterrupt:
        print()
    clear()
    print("\n" + center_line(green("Goodbye!  ") + dim(AUTHOR)) + "\n")
    return 0

if __name__ == "__main__":
    sys.exit(main())
