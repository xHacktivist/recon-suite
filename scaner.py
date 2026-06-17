#!/usr/bin/env python3
"""
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
  RECON SUITE  v4.0  —  menu-driven recon console

Ishlatish:
    python3 recon_suite.py

Kerakli kutubxonalar:
    pip install requests colorama rich
"""

from __future__ import annotations

import ipaddress
import json
import os
import platform
import socket
import ssl
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Optional

# ── dep check ─────────────────────────────────────────────────────────────────
try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    from urllib3.exceptions import InsecureRequestWarning
    requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    sys.exit("[!] pip install requests")

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.progress import (
        Progress, SpinnerColumn, BarColumn,
        TextColumn, TimeElapsedColumn, MofNCompleteColumn, TaskProgressColumn,
    )
    from rich.text import Text
    from rich.rule import Rule
    from rich.align import Align
    from rich import box
    import colorama; colorama.init()
except ImportError:
    sys.exit("[!] pip install rich colorama")


# ══════════════════════════════════════════════════════════════════════════════
# THEME
# ══════════════════════════════════════════════════════════════════════════════

P = {
    "v":  "#7C3AED",   # violet  — accent
    "c":  "#06B6D4",   # cyan    — accent2
    "g":  "#10B981",   # emerald — success
    "a":  "#F59E0B",   # amber   — warn
    "r":  "#EF4444",   # red     — danger
    "b":  "#3B82F6",   # blue    — redirect
    "m":  "#6B7280",   # gray    — muted
    "d":  "#374151",   # dim
    "w":  "#F9FAFB",   # white
}

con = Console(highlight=False)

def mk(text, k):       return f"[{P[k]}]{text}[/{P[k]}]"
def mkb(text, k):      return f"[{P[k]} bold]{text}[/{P[k]} bold]"
def rule(title=""):    con.print(Rule(title, style=P["d"]))


# ══════════════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class SubResult:
    fqdn:   str;  ip: str;  status: Optional[int] = None
    server: str = "";        title:  str           = ""
    https:  bool = False;    cname:  str           = ""

@dataclass
class PortResult:
    port:    int;  service: str;  state:   str  = "open"
    banner:  str = "";            version: str  = "";   tls: bool = False

@dataclass
class FuzzResult:
    path:    str;  url: str;  status: int;  size: int
    title:   str  = "";  redirect: str = "";  ctype: str = ""

@dataclass
class ScanSummary:
    target:      str;   mode:        str
    started_at:  str;   finished_at: str   = ""
    duration:    float  = 0.0;   total:   int   = 0
    found:       int    = 0;     results: list  = field(default_factory=list)


# ══════════════════════════════════════════════════════════════════════════════
# SESSION STATE  — hamma konfiguratsiya shu yerda yashaydi
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class SessionState:
    # ── umumiy ──────────────────────────────────────────────────────────────
    target:   str  = ""
    mode:     str  = "port"          # subdomain | port | fuzz | full

    # ── subdomain ───────────────────────────────────────────────────────────
    sub_wordlist: str  = ""          # bo'sh = built-in
    sub_threads:  int  = 50
    sub_timeout:  float = 2.5

    # ── port ────────────────────────────────────────────────────────────────
    port_mode:    str   = "default"  # default | range | custom | full
    port_list:    str   = ""         # "80,443,22"
    port_range:   str   = "1-1024"
    port_threads: int   = 150
    port_timeout: float = 0.8

    # ── fuzz ────────────────────────────────────────────────────────────────
    fuzz_scheme:   str   = "http"
    fuzz_wordlist: str   = ""
    fuzz_threads:  int   = 50
    fuzz_timeout:  float = 4.0
    fuzz_filter:   str   = "404"     # vergul bilan: "404,400"

    # ── chiqish ─────────────────────────────────────────────────────────────
    output_fmt:   str   = "n"        # json | txt | n
    output_path:  str   = ""         # bo'sh = avtomatik nom

    # ── joriy sessiya natijalar ──────────────────────────────────────────────
    history: list = field(default_factory=list)   # ScanSummary list


ST = SessionState()   # global holat


# ══════════════════════════════════════════════════════════════════════════════
# ATOMIC COUNTER
# ══════════════════════════════════════════════════════════════════════════════

class AC:
    __slots__ = ("total","_c","_f","_l","_t")
    def __init__(self, n):
        self.total=n; self._c=0; self._f=0
        self._l=threading.Lock(); self._t=time.monotonic()
    def tick(self, hit=False):
        with self._l:
            self._c+=1
            if hit: self._f+=1
            return self._c, self._f
    @property
    def checked(self): return self._c
    @property
    def found(self):   return self._f
    @property
    def elapsed(self): return time.monotonic()-self._t
    @property
    def rate(self):
        e=self.elapsed; return self._c/e if e else 0


# ══════════════════════════════════════════════════════════════════════════════
# NETWORK UTILS
# ══════════════════════════════════════════════════════════════════════════════

UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

SERVICE_MAP: dict[int,str] = {
    21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",69:"TFTP",
    79:"Finger",80:"HTTP",88:"Kerberos",110:"POP3",111:"RPCBind",
    119:"NNTP",123:"NTP",135:"MSRPC",137:"NetBIOS-NS",139:"NetBIOS",
    143:"IMAP",161:"SNMP",389:"LDAP",443:"HTTPS",445:"SMB",
    465:"SMTPS",512:"rexec",513:"rlogin",514:"syslog",515:"LPD",
    587:"Submission",593:"RPC-HTTP",636:"LDAPS",873:"rsync",
    902:"VMware",993:"IMAPS",995:"POP3S",1080:"SOCKS5",1194:"OpenVPN",
    1433:"MSSQL",1521:"Oracle",1723:"PPTP",2049:"NFS",2181:"Zookeeper",
    2375:"Docker-API",2376:"Docker-TLS",2379:"etcd",2380:"etcd-peer",
    3000:"Grafana",3306:"MySQL",3389:"RDP",3690:"SVN",4369:"EPMD",
    4444:"Metasploit",5000:"Flask",5432:"PostgreSQL",5601:"Kibana",
    5900:"VNC",5985:"WinRM-HTTP",5986:"WinRM-HTTPS",6379:"Redis",
    6443:"K8s-API",7001:"WebLogic",8000:"HTTP-Dev",8008:"HTTP-Alt",
    8080:"HTTP-Proxy",8081:"HTTP-Alt2",8443:"HTTPS-Alt",8888:"Jupyter",
    9000:"PHP-FPM",9090:"Prometheus",9092:"Kafka",9200:"Elasticsearch",
    9300:"ES-Cluster",10250:"Kubelet",15672:"RabbitMQ-Mgmt",
    27017:"MongoDB",50000:"SAP",
}

DEFAULT_SUBS = [
    "www","mail","ftp","admin","api","dev","staging","app","test","blog",
    "shop","vpn","smtp","ns1","ns2","m","portal","dashboard","secure","login",
    "static","cdn","media","support","docs","help","beta","old","new",
    "webmail","remote","server","db","git","jenkins","ci","jira","confluence",
    "monitor","grafana","kibana","elastic","redis","mysql","pg","backup",
    "files","download","upload","assets","images","api2","v2","v1","internal",
    "auth","oauth","id","sso","registry","hub","k8s","consul","vault",
    "proxy","gateway","lb","waf","mx","mx1","mx2","pop","imap","mobile",
    "android","ios","sandbox","demo","preview","status","health","ops",
    "infra","devops","data","analytics","bi","crm","erp","helpdesk",
]

DEFAULT_PATHS = [
    "admin","login","dashboard","config",".env",".env.local",".env.prod",
    "wp-admin","wp-login.php","wp-config.php","xmlrpc.php",
    "api/v1","api/v2","api/v3","api/users","api/admin","api/config","api/keys",
    "backup","backup.zip","backup.tar.gz","backup.sql","db.sql","database.sql",
    "uploads","files","static","assets","media","public","private","data",
    "robots.txt","sitemap.xml",".htaccess",".htpasswd","web.config",
    "readme.txt","README.md","CHANGELOG","VERSION","version.txt",
    "phpinfo.php","info.php","test.php","shell.php","cmd.php","exec.php",
    "setup","install","install.php","setup.php","upgrade","update",
    "console","manager","phpmyadmin","adminer","adminer.php","pma",
    ".git/config",".git/HEAD",".git/COMMIT_EDITMSG","/.gitignore",
    ".svn/entries",".DS_Store","Thumbs.db",
    "server-status","server-info","nginx_status","status",
    "actuator","actuator/env","actuator/health","actuator/mappings",
    "swagger","swagger-ui","swagger-ui.html","api-docs","openapi.json",
    "graphql","graphiql","__graphql",
    "metrics","health","ping","heartbeat","alive","ready","liveness",
    ".well-known/security.txt",".well-known/openid-configuration",
    "oauth/authorize","oauth/token","auth/login","auth/token",
    "cgi-bin/admin.cgi","cgi-bin/test.cgi",
]


def dns_resolve(host: str) -> Optional[str]:
    try:    return socket.gethostbyname(host)
    except: return None

def detect_tls(host: str, port: int, to: float = 1.2) -> bool:
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=to) as s:
            with ctx.wrap_socket(s, server_hostname=host): return True
    except: return False

def extract_title(b: bytes) -> str:
    try:
        raw = b[:4096].decode("utf-8", errors="replace").lower()
        s = raw.find("<title>")
        if s == -1: return ""
        e = raw.find("</title>", s+7)
        return b[s+7:e].decode("utf-8", errors="replace").strip()[:60]
    except: return ""

def make_session(timeout: float) -> requests.Session:
    sess = requests.Session()
    a = HTTPAdapter(
        max_retries=Retry(total=1, backoff_factor=0.1,
                          status_forcelist=[429,502,503,504],
                          allowed_methods=["GET","HEAD"], raise_on_status=False),
        pool_connections=100, pool_maxsize=200,
    )
    sess.mount("http://", a); sess.mount("https://", a)
    sess.headers.update({"User-Agent": UA})
    sess.timeout = timeout; sess.verify = False
    return sess

def _load_wl(path: str, default: list[str]) -> list[str]:
    if not path: return default
    try:
        with open(path) as f:
            items = [l.strip() for l in f if l.strip() and not l.startswith("#")]
        return items or default
    except FileNotFoundError:
        con.print(f"  {mk('[!]','a')} Wordlist topilmadi: {path}. Built-in ishlatiladi.")
        return default


# ══════════════════════════════════════════════════════════════════════════════
# SCAN ENGINES
# ══════════════════════════════════════════════════════════════════════════════

def _make_progress(label: str, total: int):
    return Progress(
        SpinnerColumn(style=P["v"]),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=28, style=P["d"], complete_style=P["v"]),
        MofNCompleteColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        TextColumn(mk("hits:{task.fields[h]}", "g")),
        console=con, transient=True,
    ), label, total

# ─── SUBDOMAIN ────────────────────────────────────────────────────────────────

def _sub_worker(sub, target, sess, counter, plock, progress, tid, table):
    fqdn = f"{sub}.{target}"
    ip   = dns_resolve(fqdn)
    hit  = ip is not None
    counter.tick(hit=hit)
    progress.advance(tid)
    if not ip: return None

    res = SubResult(fqdn=fqdn, ip=ip)
    for scheme in ("https","http"):
        try:
            r = sess.get(f"{scheme}://{fqdn}", timeout=sess.timeout,
                         allow_redirects=True, verify=False)
            res.status = r.status_code
            res.server = r.headers.get("Server","")[:24]
            res.title  = extract_title(r.content)
            res.https  = (scheme == "https")
            break
        except: continue

    cc = {200:P["g"],301:P["b"],302:P["b"],403:P["a"]}.get(res.status, P["r"]) if res.status else P["m"]
    with plock:
        table.add_row(
            mk(res.fqdn,"g"), mk(res.ip,"c"),
            f"[{cc}]{res.status or '—'}[/{cc}]",
            mk("HTTPS" if res.https else "HTTP","m"),
            mk(res.server,"m"), mk(res.title[:36],"w"),
        )
    return res


def run_subdomain(target, wordlist="", threads=50, timeout=2.5) -> ScanSummary:
    subs = _load_wl(wordlist, DEFAULT_SUBS)
    sm   = ScanSummary(target=target, mode="subdomain",
                       started_at=datetime.now().isoformat(), total=len(subs))
    _scan_header("SUBDOMAIN", target, {"Wordlist":f"{len(subs)} giriş",
                 "Threads":str(threads), "Timeout":f"{timeout}s"})

    tbl = Table("FQDN","IP","HTTP","TLS","SERVER","TITLE",
                box=box.SIMPLE_HEAD, border_style=P["d"],
                header_style=f"bold {P['c']}", show_edge=False, padding=(0,1))

    sess    = make_session(timeout)
    ctr     = AC(len(subs))
    plock   = threading.Lock()
    results = []; rlock = threading.Lock()

    prog, lbl, tot = _make_progress("subdomain", len(subs))
    with prog:
        tid = prog.add_task(mk(lbl,"c"), total=tot, h=0)
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futs = {pool.submit(_sub_worker, s, target, sess,
                                ctr, plock, prog, tid, tbl): s for s in subs}
            for f in as_completed(futs):
                r = f.result()
                if r:
                    with rlock: results.append(r)
                prog.update(tid, h=ctr.found)

    con.print(tbl)
    sm.finished_at = datetime.now().isoformat()
    sm.duration = ctr.elapsed; sm.found = len(results)
    sm.results  = [asdict(r) for r in sorted(results, key=lambda x: x.fqdn)]
    _scan_footer(ctr)
    return sm

# ─── PORT ─────────────────────────────────────────────────────────────────────

def _port_worker(host, port, timeout, ctr, plock, progress, tid, tbl):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    err = s.connect_ex((host, port))
    banner = ""; tls = False

    if err == 0:
        probes = {80:b"GET / HTTP/1.0\r\nHost:x\r\n\r\n",
                  443:b"GET / HTTP/1.0\r\nHost:x\r\n\r\n",
                  8080:b"GET / HTTP/1.0\r\nHost:x\r\n\r\n"}
        try:
            p = probes.get(port, b"\r\n")
            if p: s.send(p)
            s.settimeout(1.5)
            banner = s.recv(1024).decode("utf-8",errors="replace").strip()[:80]
        except: pass
        tls = port in (443,8443,465,993,995) or detect_tls(host, port, timeout)
    s.close()

    open_ = err == 0
    ctr.tick(hit=open_)
    progress.advance(tid)
    if not open_: return None

    svc = SERVICE_MAP.get(port,"UNKNOWN")
    res = PortResult(port=port, service=svc, banner=banner, tls=tls)
    tb  = mk("TLS","g") if tls else mk("plain","m")
    bn  = banner.replace("\n"," ").replace("\r","")[:50] or "—"

    with plock:
        tbl.add_row(mkb(str(port),"g"), mk(svc,"c"), mk("OPEN","g"), tb, mk(bn,"m"))
    return res


def run_ports(target, ports=None, port_range=None, threads=150, timeout=0.8) -> ScanSummary:
    if port_range:
        scan_list = list(range(port_range[0], port_range[1]+1))
    else:
        scan_list = ports or list(SERVICE_MAP.keys())

    try:    host = socket.gethostbyname(target)
    except: con.print(mk(f"[x] DNS xatosi: {target}","r")); \
            return ScanSummary(target=target,mode="port",started_at=datetime.now().isoformat())

    sm = ScanSummary(target=target, mode="port",
                     started_at=datetime.now().isoformat(), total=len(scan_list))
    _scan_header("PORT SCAN", target, {"Host":host, "Portlar":str(len(scan_list)),
                 "Threads":str(threads), "Timeout":f"{timeout}s", "Banner":"ON"})

    tbl = Table("PORT","SERVICE","STATE","TLS","BANNER",
                box=box.SIMPLE_HEAD, border_style=P["d"],
                header_style=f"bold {P['c']}", show_edge=False, padding=(0,1))

    ctr = AC(len(scan_list)); plock = threading.Lock()
    results = []; rlock = threading.Lock()

    prog, lbl, tot = _make_progress("port scan", len(scan_list))
    with prog:
        tid = prog.add_task(mk(lbl,"c"), total=tot, h=0)
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futs = {pool.submit(_port_worker, host, port, timeout,
                                ctr, plock, prog, tid, tbl): port for port in scan_list}
            for f in as_completed(futs):
                r = f.result()
                if r:
                    with rlock: results.append(r)
                prog.update(tid, h=ctr.found)

    con.print(tbl)
    sm.finished_at = datetime.now().isoformat(); sm.duration = ctr.elapsed
    sm.found = len(results)
    sm.results = [asdict(r) for r in sorted(results, key=lambda x: x.port)]
    _scan_footer(ctr)
    return sm

# ─── FUZZ ─────────────────────────────────────────────────────────────────────

def _fuzz_worker(base, path, sess, ctr, fc, plock, progress, tid, tbl):
    url = f"{base.rstrip('/')}/{path.lstrip('/')}"
    try:
        r     = sess.get(url, timeout=sess.timeout, allow_redirects=False, verify=False)
        code  = r.status_code
        size  = len(r.content)
        title = extract_title(r.content) if "html" in r.headers.get("Content-Type","") else ""
        redir = r.headers.get("Location","")[:70]
        ctype = r.headers.get("Content-Type","")[:30]
    except: ctr.tick(); progress.advance(tid); return None

    hit = code not in fc
    ctr.tick(hit=hit)
    progress.advance(tid)
    if not hit: return None

    res = FuzzResult(path=path, url=url, status=code, size=size,
                     title=title, redirect=redir, ctype=ctype)
    cc = {200:P["g"],301:P["b"],302:P["b"],307:P["b"],308:P["b"],
          403:P["a"],401:P["a"],500:P["r"],503:P["r"]}.get(code, P["m"])
    extra = f" → {mk(redir[:38],'m')}" if redir else (f" {mk(title[:38],'m')}" if title else "")

    with plock:
        tbl.add_row(
            f"[{cc} bold]{code}[/{cc} bold]",
            mk(f"/{path}","w"),
            mk(f"{size:>8,}","c"),
            mk(ctype[:22],"m"),
            Text.from_markup(extra),
        )
    return res


def run_fuzz(target, wordlist="", threads=50, timeout=4.0,
             filter_codes=None, scheme="http") -> ScanSummary:
    paths = _load_wl(wordlist, DEFAULT_PATHS)
    fc    = filter_codes or {404}
    base  = f"{scheme}://{target}"

    sm = ScanSummary(target=target, mode="fuzz",
                     started_at=datetime.now().isoformat(), total=len(paths))
    _scan_header("PATH FUZZ", target, {"Base":base, "Yo'llar":str(len(paths)),
                 "Threads":str(threads), "Timeout":f"{timeout}s",
                 "Filter":str(sorted(fc))})

    tbl = Table("CODE","PATH","SIZE","CONTENT-TYPE","INFO",
                box=box.SIMPLE_HEAD, border_style=P["d"],
                header_style=f"bold {P['c']}", show_edge=False, padding=(0,1))

    sess = make_session(timeout); ctr = AC(len(paths))
    plock = threading.Lock(); results = []; rlock = threading.Lock()

    prog, lbl, tot = _make_progress("fuzzing", len(paths))
    with prog:
        tid = prog.add_task(mk(lbl,"c"), total=tot, h=0)
        with ThreadPoolExecutor(max_workers=threads) as pool:
            futs = {pool.submit(_fuzz_worker, base, path, sess,
                                ctr, fc, plock, prog, tid, tbl): path for path in paths}
            for f in as_completed(futs):
                r = f.result()
                if r:
                    with rlock: results.append(r)
                prog.update(tid, h=ctr.found)

    con.print(tbl)
    sm.finished_at = datetime.now().isoformat(); sm.duration = ctr.elapsed
    sm.found = len(results)
    sm.results = [asdict(r) for r in sorted(results, key=lambda x: x.status)]
    _scan_footer(ctr)
    return sm


# ══════════════════════════════════════════════════════════════════════════════
# SCAN UI HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _scan_header(title: str, target: str, meta: dict) -> None:
    con.print()
    rule(mkb(title,"v"))
    con.print(f"  {mk('target:','m')} {mkb(target,'w')}  "
              + "  ".join(f"{mk(k+':','m')}{mk(v,'c')}" for k,v in meta.items()))
    rule()
    con.print()

def _scan_footer(ctr: AC) -> None:
    con.print(); rule()
    con.print(
        f"  {mk('checked:','m')} {mk(f'{ctr.checked}/{ctr.total}','w')}   "
        f"{mk('found:','m')} {mkb(str(ctr.found),'g')}   "
        f"{mk('elapsed:','m')} {mk(f'{ctr.elapsed:.2f}s','a')}   "
        f"{mk('rate:','m')} {mk(f'{ctr.rate:.0f}/s','c')}"
    )
    rule(); con.print()


# ══════════════════════════════════════════════════════════════════════════════
# REPORT
# ══════════════════════════════════════════════════════════════════════════════

def save_summary(sm: ScanSummary) -> str:
    fmt  = ST.output_fmt
    ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = ST.output_path or f"recon_{sm.mode}_{sm.target.replace('.','_')}_{ts}"

    if fmt in ("json","j"):
        fname = base if base.endswith(".json") else base+".json"
        with open(fname,"w") as f: json.dump(asdict(sm), f, indent=2, ensure_ascii=False)
    else:
        fname = base if base.endswith(".txt") else base+".txt"
        with open(fname,"w") as f:
            f.write(f"RECON SUITE v4.0 — {sm.mode.upper()} REPORT\n{'═'*60}\n")
            f.write(f"Target  : {sm.target}\n")
            f.write(f"Started : {sm.started_at}\n")
            f.write(f"Elapsed : {sm.duration:.2f}s\n")
            f.write(f"Found   : {sm.found}/{sm.total}\n{'─'*60}\n")
            for r in sm.results: f.write(json.dumps(r)+"\n")
    return fname


# ══════════════════════════════════════════════════════════════════════════════
# TUI  INPUT HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def inp(prompt: str, default: str = "", secret: bool = False) -> str:
    """Rangdor input. Ctrl-C = chiqish."""
    hint = f" {mk(f'[{default}]','m')}" if default else ""
    con.print(f"  {mk('›','c')} {prompt}{hint} ", end="")
    try:
        val = input().strip()
        return val or default
    except (KeyboardInterrupt, EOFError):
        con.print(); _exit_app()

def inp_int(prompt: str, default: int, lo: int = 1, hi: int = 10000) -> int:
    while True:
        raw = inp(prompt, str(default))
        try:
            v = int(raw)
            if lo <= v <= hi: return v
            con.print(f"  {mk(f'[!] {lo}–{hi} orasida bo\'lsin','a')}")
        except ValueError:
            con.print(f"  {mk('[!] Butun son kiriting','a')}")

def inp_float(prompt: str, default: float) -> float:
    raw = inp(prompt, str(default))
    try:    return max(0.05, float(raw))
    except: return default

def confirm(prompt: str) -> bool:
    v = inp(f"{prompt} (y/n)", "n").lower()
    return v in ("y","yes","ha","1")


# ══════════════════════════════════════════════════════════════════════════════
# MENU SECTIONS
# ══════════════════════════════════════════════════════════════════════════════

def _banner() -> None:
    art = (
        f"  {mk('██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗','v')}\n"
        f"  {mk('██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║','v')}\n"
        f"  {mk('██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║','v')}\n"
        f"  {mk('██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║','v')}\n"
        f"  {mk('██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║','v')}\n"
        f"  {mk('╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝','v')}"
    )
    con.print(art)
    con.print(
        f"  {mk('RECON SUITE','m')}  {mkb('v4.0','c')}  "
        f"{mk('subdomain · port · fuzz','m')}  "
        f"{mk(f'python {platform.python_version()} · {platform.system().lower()}','d')}"
    )
    con.print()


def _status_bar() -> None:
    """Ana menyuda target + mode + settings xulosa."""
    tgt = mkb(ST.target,"c") if ST.target else mk("(belgilanmagan)","r")
    mode_color = {"subdomain":"g","port":"c","fuzz":"a","full":"v"}.get(ST.mode,"m")
    mode_str = mkb(ST.mode.upper(), mode_color)
    out  = mk(ST.output_fmt.upper() if ST.output_fmt != "n" else "SAQLANMAYDI","m")

    con.print(Panel(
        f"  {mk('Target:','m')} {tgt}   "
        f"{mk('Mode:','m')} {mode_str}   "
        f"{mk('Output:','m')} {out}",
        border_style=P["d"], padding=(0,1), expand=True,
    ))


def _main_menu() -> None:
    """Ana menyu — chiqmaguncha aylanib turadi."""
    while True:
        con.clear()
        _banner()
        _status_bar()
        con.print()

        items = [
            ("1", "Target sozlash",         mk(ST.target or "bo'sh","m")),
            ("2", "Scan rejimi",             mk(ST.mode.upper(),"c")),
            ("3", "Subdomain sozlamalari",   mk(f"threads:{ST.sub_threads}  to:{ST.sub_timeout}s","m")),
            ("4", "Port sozlamalari",        mk(f"rejim:{ST.port_mode}  threads:{ST.port_threads}  to:{ST.port_timeout}s","m")),
            ("5", "Fuzz sozlamalari",        mk(f"scheme:{ST.fuzz_scheme}  threads:{ST.fuzz_threads}  to:{ST.fuzz_timeout}s","m")),
            ("6", "Chiqish sozlamalari",     mk(f"fmt:{ST.output_fmt}  path:{ST.output_path or 'avto'}","m")),
            ("",  "",                        ""),
            ("R", "SCAN BOSHLASH",           mk(f"→ {ST.mode}","g")),
            ("H", "Sessiya tarixi",          mk(f"{len(ST.history)} ta scan","m")),
            ("0", "Chiqish",                 ""),
        ]

        rule(mk("  BOSH MENYU  ","v"))
        for key, label, hint in items:
            if not key:
                con.print()
                continue
            col = "g" if key == "R" else ("r" if key == "0" else "c")
            con.print(f"   {mkb(f'[{key}]',col)}  {mk(label,'w')}  {hint}")
        con.print()

        ch = inp("Tanlang").upper()
        if   ch == "1": _menu_target()
        elif ch == "2": _menu_mode()
        elif ch == "3": _menu_sub_settings()
        elif ch == "4": _menu_port_settings()
        elif ch == "5": _menu_fuzz_settings()
        elif ch == "6": _menu_output_settings()
        elif ch == "R": _dispatch_scan()
        elif ch == "H": _menu_history()
        elif ch == "0": _exit_app()
        else:
            con.print(f"  {mk('[!] Noto\'g\'ri tanlov.','a')}")
            time.sleep(0.6)


# ─── TARGET ───────────────────────────────────────────────────────────────────

def _menu_target() -> None:
    con.clear(); _banner()
    rule(mk("  TARGET  ","v"))
    con.print(f"  Joriy: {mkb(ST.target or 'belgilanmagan','c')}\n")
    con.print(f"  {mk('Misol:','m')} example.com  |  192.168.1.1  |  10.0.0.0/24")
    con.print()
    val = inp("Yangi target (bo'sh = o'zgartirmaslik)", ST.target)
    if not val:
        return
    ST.target = val.strip()

    # DNS tekshiruv
    try:
        ipaddress.ip_address(ST.target)
        con.print(f"  {mk('IP manzil qabul qilindi.','g')}")
    except ValueError:
        ip = dns_resolve(ST.target)
        if ip:
            con.print(f"  {mk('DNS:','m')} {mk(ST.target,'w')} {mk('→','m')} {mk(ip,'c')}")
        else:
            con.print(f"  {mk('[!] DNS resolve muvaffaqiyatsiz. Scan vaqtida xato chiqishi mumkin.','a')}")
    time.sleep(1.2)


# ─── MODE ─────────────────────────────────────────────────────────────────────

def _menu_mode() -> None:
    con.clear(); _banner()
    rule(mk("  SCAN REJIMI  ","v"))
    con.print(f"  Joriy: {mkb(ST.mode.upper(),'c')}\n")
    modes = [
        ("1","subdomain","DNS brute-force + HTTP probe + TLS detect"),
        ("2","port",     "TCP connect + banner grab + TLS detect"),
        ("3","fuzz",     "HTTP dir/file enum + redirect + content-type"),
        ("4","full",     "Subdomain → Port → Fuzz ketma-ket"),
    ]
    for k, m, d in modes:
        cur = mk(" ◀ joriy","g") if m == ST.mode else ""
        con.print(f"   {mkb(f'[{k}]','c')}  {mk(m.upper(),'w')}  {mk(d,'m')}{cur}")
    con.print()
    ch = inp("Tanlang (bo'sh = o'zgartirmaslik)", "")
    mapping = {"1":"subdomain","2":"port","3":"fuzz","4":"full"}
    if ch in mapping:
        ST.mode = mapping[ch]
        con.print(f"  {mk('Rejim:','m')} {mkb(ST.mode.upper(),'g')}")
        time.sleep(0.8)


# ─── SUBDOMAIN SETTINGS ───────────────────────────────────────────────────────

def _menu_sub_settings() -> None:
    while True:
        con.clear(); _banner()
        rule(mk("  SUBDOMAIN SOZLAMALARI  ","v"))
        _print_settings([
            ("1","Wordlist",  ST.sub_wordlist or "built-in"),
            ("2","Threads",   str(ST.sub_threads)),
            ("3","Timeout",   f"{ST.sub_timeout}s"),
            ("0","Orqaga",    ""),
        ])
        ch = inp("Tanlang").strip()
        if ch == "1":
            v = inp("Wordlist yo'li (bo'sh = built-in)", ST.sub_wordlist)
            ST.sub_wordlist = v
        elif ch == "2":
            ST.sub_threads = inp_int("Threads soni", ST.sub_threads, 1, 500)
        elif ch == "3":
            ST.sub_timeout = inp_float("Timeout (soniya)", ST.sub_timeout)
        elif ch == "0": break
        else: _bad()


# ─── PORT SETTINGS ────────────────────────────────────────────────────────────

def _menu_port_settings() -> None:
    while True:
        con.clear(); _banner()
        rule(mk("  PORT SCAN SOZLAMALARI  ","v"))
        _print_settings([
            ("1","Port rejimi",  ST.port_mode),
            ("2","Custom portlar", ST.port_list or "—"),
            ("3","Port oraliq",  ST.port_range),
            ("4","Threads",      str(ST.port_threads)),
            ("5","Timeout",      f"{ST.port_timeout}s"),
            ("0","Orqaga",       ""),
        ])
        ch = inp("Tanlang").strip()
        if ch == "1":
            _menu_port_mode()
        elif ch == "2":
            v = inp("Portlar (vergul bilan: 80,443,22)", ST.port_list)
            ST.port_list = v; ST.port_mode = "custom" if v else ST.port_mode
        elif ch == "3":
            v = inp("Oraliq (masalan: 1-10000)", ST.port_range)
            ST.port_range = v; ST.port_mode = "range" if v else ST.port_mode
        elif ch == "4":
            ST.port_threads = inp_int("Threads soni", ST.port_threads, 1, 1000)
        elif ch == "5":
            ST.port_timeout = inp_float("Timeout (soniya)", ST.port_timeout)
        elif ch == "0": break
        else: _bad()


def _menu_port_mode() -> None:
    con.clear(); _banner()
    rule(mk("  PORT REJIMI  ","v"))
    opts = [
        ("1","default",f"Standart ({len(SERVICE_MAP)} port)"),
        ("2","range",  f"Oraliq ({ST.port_range})"),
        ("3","custom", f"Custom ({ST.port_list or 'belgilanmagan'})"),
        ("4","full",   "To'liq (1–65535)"),
    ]
    for k,m,d in opts:
        cur = mk(" ◀ joriy","g") if m == ST.port_mode else ""
        con.print(f"   {mkb(f'[{k}]','c')}  {mk(m.upper(),'w')}  {mk(d,'m')}{cur}")
    con.print()
    ch = inp("Tanlang", "")
    mm = {"1":"default","2":"range","3":"custom","4":"full"}
    if ch in mm:
        ST.port_mode = mm[ch]
        con.print(f"  {mk('Port rejimi:','m')} {mkb(ST.port_mode,'g')}")
        time.sleep(0.7)


# ─── FUZZ SETTINGS ────────────────────────────────────────────────────────────

def _menu_fuzz_settings() -> None:
    while True:
        con.clear(); _banner()
        rule(mk("  PATH FUZZ SOZLAMALARI  ","v"))
        _print_settings([
            ("1","Protokol",    ST.fuzz_scheme),
            ("2","Wordlist",    ST.fuzz_wordlist or "built-in"),
            ("3","Threads",     str(ST.fuzz_threads)),
            ("4","Timeout",     f"{ST.fuzz_timeout}s"),
            ("5","Filter kodlar", ST.fuzz_filter),
            ("0","Orqaga",      ""),
        ])
        ch = inp("Tanlang").strip()
        if ch == "1":
            v = inp("Protokol (http/https)", ST.fuzz_scheme).lower()
            if v in ("http","https"): ST.fuzz_scheme = v
        elif ch == "2":
            ST.fuzz_wordlist = inp("Wordlist yo'li (bo'sh = built-in)", ST.fuzz_wordlist)
        elif ch == "3":
            ST.fuzz_threads = inp_int("Threads soni", ST.fuzz_threads, 1, 500)
        elif ch == "4":
            ST.fuzz_timeout = inp_float("Timeout (soniya)", ST.fuzz_timeout)
        elif ch == "5":
            v = inp("Filtr kodlar (vergul: 404,400)", ST.fuzz_filter)
            ST.fuzz_filter = v or "404"
        elif ch == "0": break
        else: _bad()


# ─── OUTPUT SETTINGS ──────────────────────────────────────────────────────────

def _menu_output_settings() -> None:
    while True:
        con.clear(); _banner()
        rule(mk("  CHIQISH SOZLAMALARI  ","v"))
        _print_settings([
            ("1","Format",     ST.output_fmt),
            ("2","Fayl nomi",  ST.output_path or "avto"),
            ("0","Orqaga",     ""),
        ])
        ch = inp("Tanlang").strip()
        if ch == "1":
            con.print(f"\n  {mk('json','c')} — JSON fayl\n"
                      f"  {mk('txt','c')}  — oddiy matn\n"
                      f"  {mk('n','c')}    — saqlanmasin\n")
            v = inp("Format", ST.output_fmt).lower()
            if v in ("json","txt","n"): ST.output_fmt = v
        elif ch == "2":
            ST.output_path = inp("Fayl nomi/yo'li (bo'sh = avto)", ST.output_path)
        elif ch == "0": break
        else: _bad()


# ─── HISTORY ──────────────────────────────────────────────────────────────────

def _menu_history() -> None:
    con.clear(); _banner()
    rule(mk("  SESSIYA TARIXI  ","v"))

    if not ST.history:
        con.print(f"  {mk('Hech qanday scan bajarilmagan.','m')}\n")
        inp("Enter — orqaga"); return

    tbl = Table("№","Mode","Target","Found","Elapsed","Saqlanadimi",
                box=box.SIMPLE_HEAD, border_style=P["d"],
                header_style=f"bold {P['c']}", show_edge=False, padding=(0,1))

    for i, sm in enumerate(ST.history, 1):
        tbl.add_row(
            mk(str(i),"m"),
            mk(sm.mode.upper(),"c"),
            mk(sm.target,"w"),
            mkb(str(sm.found),"g"),
            mk(f"{sm.duration:.1f}s","a"),
            mk(ST.output_fmt.upper() if ST.output_fmt!="n" else "YO'Q","m"),
        )
    con.print(tbl)
    con.print()

    ch = inp("Saqlash № kiriting yoki Enter — orqaga", "").strip()
    if ch.isdigit():
        idx = int(ch) - 1
        if 0 <= idx < len(ST.history):
            sm   = ST.history[idx]
            fname = save_summary(sm)
            con.print(f"  {mk('[✓] Saqlandi:','g')} {mk(fname,'w')}")
            time.sleep(1.2)


# ═════════════════════════════════════════════════════════════════════════════
# SCAN DISPATCHER
# ═════════════════════════════════════════════════════════════════════════════

def _dispatch_scan() -> None:
    if not ST.target:
        con.print(f"  {mk('[!] Avval target belgilang (menyu 1).','a')}")
        time.sleep(1.2); return

    con.clear(); _banner()

    def _run_sub():
        sm = run_subdomain(
            ST.target,
            wordlist=ST.sub_wordlist or None,
            threads=ST.sub_threads,
            timeout=ST.sub_timeout,
        )
        ST.history.append(sm)
        _post_scan(sm)

    def _run_port():
        ports = None; pr = None
        if ST.port_mode == "custom" and ST.port_list:
            ports = [int(x) for x in ST.port_list.split(",") if x.strip().isdigit()]
        elif ST.port_mode == "range":
            try:
                lo, hi = map(int, ST.port_range.split("-"))
                pr = (max(1,lo), min(65535,hi))
            except ValueError: pass
        elif ST.port_mode == "full":
            pr = (1, 65535)
        sm = run_ports(
            ST.target, ports=ports, port_range=pr,
            threads=ST.port_threads, timeout=ST.port_timeout,
        )
        ST.history.append(sm)
        _post_scan(sm)

    def _run_fuzz():
        fc = {int(x) for x in ST.fuzz_filter.split(",") if x.strip().isdigit()} or {404}
        sm = run_fuzz(
            ST.target,
            wordlist=ST.fuzz_wordlist or None,
            threads=ST.fuzz_threads,
            timeout=ST.fuzz_timeout,
            filter_codes=fc,
            scheme=ST.fuzz_scheme,
        )
        ST.history.append(sm)
        _post_scan(sm)

    mode = ST.mode
    if   mode == "subdomain": _run_sub()
    elif mode == "port":      _run_port()
    elif mode == "fuzz":      _run_fuzz()
    elif mode == "full":
        _run_sub(); _run_port(); _run_fuzz()

    inp("Enter — bosh menyuga qaytish")


def _post_scan(sm: ScanSummary) -> None:
    if ST.output_fmt == "n" or not sm.results: return
    fname = save_summary(sm)
    con.print(f"  {mk('[✓]','g')} Saqlandi: {mk(fname,'w')}\n")


# ══════════════════════════════════════════════════════════════════════════════
# MISC HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def _print_settings(rows: list) -> None:
    tbl = Table(box=box.SIMPLE_HEAD, border_style=P["d"],
                header_style=f"bold {P['c']}", show_edge=False,
                show_header=False, padding=(0,2))
    tbl.add_column("K", style=f"bold {P['c']}", width=4)
    tbl.add_column("Sozlama", style=P["w"])
    tbl.add_column("Qiymat",  style=P["m"])
    for k, label, val in rows:
        tbl.add_row(f"[{k}]", label, val)
    con.print(tbl)
    con.print()

def _bad() -> None:
    con.print(f"  {mk('[!] Noto\'g\'ri tanlov.','a')}"); time.sleep(0.5)

def _exit_app() -> None:
    con.print(f"\n  {mk('Chiqildi.','m')}\n"); sys.exit(0)


# ══════════════════════════════════════════════════════════════════════════════
# MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main() -> None:
    try:
        _main_menu()
    except KeyboardInterrupt:
        _exit_app()

if __name__ == "__main__":
    main()
