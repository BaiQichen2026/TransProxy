#!/usr/bin/env python3
"""TransProxy 监控面板（运行在 监控端上）。

职责只有两件事：
  1. 定时从服务端的监控接口增量拉取访问记录，落到本地文件；
  2. 起一个网页，把本地记录渲染成一个可查询的面板。

为什么是「拉」而不是「推」：监控端在 10.x 内网，服务端在公网，服务端根本连不到 监控端。
由 监控端 主动去拉，方向天然是通的，也不用在服务端开口子。

数据边界（很重要，别把它当成能看一切的审计系统）：
  - 只有**目标主机名**：来自内核的 TLS SNI / HTTP Host。HTTPS 的路径与搜索词
    全程加密，日志里根本不存在，拿不到。
  - 只有通道A（REALITY）的流量。走通道B（Hysteria2）的流量在 hysteria 进程里
    就终止了，不经过内核，因此不在记录范围内。
  - 记录粒度是「连接」而不是「请求」：同一域名的多次连接会是多条记录。
"""

import base64
import getpass
import hashlib
import hmac
import json
import os
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BASE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE, "config.json")
DATA_DIR = os.path.join(BASE, "data")
LOG_DIR = os.path.join(BASE, "logs")
EVENTS_PATH = os.path.join(DATA_DIR, "events.jsonl")
STATE_PATH = os.path.join(DATA_DIR, "state.json")
RATES_PATH = os.path.join(DATA_DIR, "rates.jsonl")

MAX_LOG_BYTES = 4 << 20
# 记录时间统一用 Unix 微秒（与服务端一致）。不能用毫秒：一次 DNS 突发会在同一
# 毫秒里产生多条一模一样的记录，按毫秒去重会把真实记录当成重复丢掉。
#
# 拉取重叠窗口：服务端是「读到日志才落库」，一条记录可能在它自己的时间戳之后
# 最多两秒才出现。按 last+1 拉会漏掉这些迟到的记录，所以往回重叠几秒，
# 再用去重集合把重复的剔除。
OVERLAP_US = 5_000_000
DEDUPE_KEEP = 40000

# 速率曲线的三档范围：range -> (覆盖多少秒, 画多少个点)。
# 点数固定，换范围只改横轴跨度，曲线的疏密观感一致。
# 「全天」按 24 小时算，正好对应下面的保留时长。
RATE_RANGES = {
    "1h": (3600, 180),
    "12h": (43200, 240),
    "24h": (86400, 288),
}

# 速率采样的保留时长。24 小时够「全天」用；采样是秒级的，
# 留太久会让这个文件白长（一天约两万条），所以定死在一天。
RATES_RETAIN_SECONDS = 24 * 3600
# 两次采样之间的最小间隔。概览是 5 秒拉一次，短于这个间隔的都是重复值。
RATES_MIN_GAP_SECONDS = 4


def log(msg):
    line = "%s  %s\n" % (time.strftime("%Y-%m-%d %H:%M:%S"), msg)
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        if os.path.exists(os.path.join(LOG_DIR, "monitor.log")) and \
                os.path.getsize(os.path.join(LOG_DIR, "monitor.log")) > MAX_LOG_BYTES:
            os.replace(os.path.join(LOG_DIR, "monitor.log"),
                       os.path.join(LOG_DIR, "monitor.log.1"))
        with open(os.path.join(LOG_DIR, "monitor.log"), "a", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        pass
    sys.stdout.write(line)
    sys.stdout.flush()


def load_config():
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    cfg.setdefault("listen_host", "192.0.2.10")
    cfg.setdefault("listen_port", 18443)
    cfg.setdefault("poll_seconds", 15)
    cfg.setdefault("retain_days", 14)
    cfg.setdefault("user", "admin")
    cfg.setdefault("api_base", "https://proxy.example.com:8443")
    cfg.setdefault("verify_tls", True)
    return cfg


def save_config(cfg):
    """原子写回配置文件，并保持 0600。

    必须先写临时文件再改名：直接截断重写的话，写到一半出错就会留下一个残缺的
    config.json，服务下次启动直接失败——而配置里存着登录口令哈希，
    等于把自己锁在面板外面。
    """
    tmp = CONFIG_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp, 0o600)
    os.replace(tmp, CONFIG_PATH)


# PBKDF2 迭代次数。面板口令保护的是「能读写全部账号与访问记录」的管理凭据，
# 值得让它算得慢一点：这个量级在普通 监控端上也要几十毫秒，人工登录无感，
# 但把离线爆破的成本抬高了几个数量级。
PBKDF2_ROUNDS = 200000
PBKDF2_PREFIX = "pbkdf2_sha256$"


def hash_password(pw):
    """加盐 + 迭代派生口令，返回自描述的字符串。

    早先的实现是「无盐 SHA-256」：同一个口令永远得到同一个值，而且快得离谱。
    配置文件一旦被读走，攻击者既能直接查彩虹表，也能每秒试上亿次。
    加盐让彩虹表失效，迭代让逐条尝试变得昂贵。参数写在结果里，
    将来调大迭代次数也不会让已有口令失效。
    """
    salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return "%s%d$%s$%s" % (
        PBKDF2_PREFIX,
        PBKDF2_ROUNDS,
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(dk).decode("ascii"),
    )


def password_ok(cfg, given):
    """常数时间比对口令，避免按字节比较带来的时序侧信道。"""
    stored = cfg.get("password_hash") or ""
    if not stored:
        return False
    if stored.startswith(PBKDF2_PREFIX):
        try:
            _, rounds, salt_b64, hash_b64 = stored.split("$")
            salt = base64.b64decode(salt_b64)
            want = base64.b64decode(hash_b64)
            got = hashlib.pbkdf2_hmac("sha256", given.encode("utf-8"), salt, int(rounds))
        except Exception:
            return False
        return hmac.compare_digest(got, want)
    # 兼容历史的无盐 SHA-256 记录：先让它过，再由 upgrade_password_if_legacy 换成新格式。
    return hmac.compare_digest(hashlib.sha256(given.encode("utf-8")).hexdigest(), stored)


def password_is_legacy(cfg):
    stored = cfg.get("password_hash") or ""
    return bool(stored) and not stored.startswith(PBKDF2_PREFIX)


_pw_upgrade_lock = threading.Lock()


def upgrade_password_if_legacy(cfg, given):
    """登录成功且库里仍是旧格式时，顺手换成 PBKDF2。

    放在登录路径上做，是因为这是唯一能同时拿到明文口令和「验证通过」结论的地方：
    用户什么都不用做，老口令就在下一次登录时自动升级。
    """
    if not password_is_legacy(cfg):
        return
    with _pw_upgrade_lock:
        if not password_is_legacy(cfg):
            return
        old = cfg.get("password_hash")
        cfg["password_hash"] = hash_password(given)
        try:
            save_config(cfg)
        except Exception as e:
            cfg["password_hash"] = old
            log("口令哈希升级失败（不影响本次登录）：%s" % e)
            return
        log("面板口令哈希已从无盐 SHA-256 升级为 PBKDF2")


# ---------- 与服务端通信 ----------

def tls_ctx(cfg):
    ctx = ssl.create_default_context()
    if not cfg.get("verify_tls", True):
        # 只有在明确关掉校验时才放宽。默认走标准校验：
        # 这些接口带着管理员令牌，是能读写全部账号与记录的高权凭据。
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def api_get(cfg, path, params=None, timeout=25):
    url = cfg["api_base"] + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    req = urllib.request.Request(url)
    req.add_header("X-Admin-Token", cfg["admin_token"])
    with urllib.request.urlopen(req, timeout=timeout, context=tls_ctx(cfg)) as r:
        return json.loads(r.read().decode("utf-8"))


def api_post(cfg, path, payload, timeout=25):
    """转发一次账号操作，返回 (HTTP 码, 响应体)。"""
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    req = urllib.request.Request(cfg["api_base"] + path, data=body, method="POST")
    req.add_header("X-Admin-Token", cfg["admin_token"])
    req.add_header("Content-Type", "application/json; charset=utf-8")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=tls_ctx(cfg)) as r:
            return r.status, json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        # 服务端把失败原因放在 {"error": ...} 里，原样带回给页面，
        # 比只报一个 HTTP 码有用得多（例如「账号名只能包含…」）。
        try:
            return e.code, json.loads(e.read().decode("utf-8"))
        except Exception:
            return e.code, {"error": "节点返回 HTTP %d" % e.code}


# ---------- 本地存储 ----------

class Store:
    """本地记录存储。单文件追加，查询时流式扫。

    规模很小（每天几万条、保留 14 天），不值得上数据库；
    单文件也让「出问题直接看文件」这件事变得可能。
    """

    def __init__(self, retain_days):
        self.retain_days = retain_days
        self.lock = threading.Lock()
        self.seen = {}
        self.last_ms = 0
        self.pull_error = ""
        self.last_sync = 0
        self.overview = {"users": []}
        self.stored = 0

    def key(self, e):
        return "%d|%s|%s|%d|%s" % (e.get("t", 0), e.get("u", ""), e.get("h", ""),
                                   e.get("p", 0), e.get("n", ""))

    def load(self):
        os.makedirs(DATA_DIR, exist_ok=True)
        if os.path.exists(STATE_PATH):
            try:
                with open(STATE_PATH, "r", encoding="utf-8") as f:
                    st = json.load(f)
                self.last_ms = int(st.get("last_ms", 0))
            except Exception as e:
                log("读取本地状态失败（将从头拉取）：%s" % e)
        # 一次遍历同时做两件事：数出总条数，并用尾部重建去重集合。
        # 保留尾部而不是全部，是为了让内存占用与保留期长短无关；
        # 重启之后重叠窗口内的记录也不会被重复写一遍。
        if os.path.exists(EVENTS_PATH):
            try:
                tail = deque(maxlen=DEDUPE_KEEP)
                total = 0
                with open(EVENTS_PATH, "r", encoding="utf-8") as f:
                    for line in f:
                        if not line.strip():
                            continue
                        total += 1
                        tail.append(line)
                self.stored = total
                for line in tail:
                    try:
                        e = json.loads(line)
                    except Exception:
                        continue
                    self.seen[self.key(e)] = 1
                    if e.get("t", 0) > self.last_ms:
                        self.last_ms = e["t"]
            except Exception as e:
                log("重建去重集合失败：%s" % e)
        log("本地状态：last_ms=%d 已存=%d 去重集合=%d" % (self.last_ms, self.stored, len(self.seen)))

    def append(self, events):
        if not events:
            return 0
        os.makedirs(DATA_DIR, exist_ok=True)
        added = 0
        with open(EVENTS_PATH, "a", encoding="utf-8") as f:
            for e in events:
                k = self.key(e)
                if k in self.seen:
                    continue
                self.seen[k] = 1
                f.write(json.dumps(e, separators=(",", ":"), ensure_ascii=False) + "\n")
                added += 1
                if e.get("t", 0) > self.last_ms:
                    self.last_ms = e["t"]
        # 去重集合不能无限增长，超了就丢掉最早的一批。
        if len(self.seen) > DEDUPE_KEEP * 2:
            for k in list(self.seen.keys())[:DEDUPE_KEEP]:
                self.seen.pop(k, None)
        self.stored += added
        return added

    def save_state(self):
        tmp = STATE_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"last_ms": self.last_ms}, f)
        os.replace(tmp, STATE_PATH)

    def prune(self):
        """删掉保留期之外的记录。整文件重写，只保留剩下的。"""
        cutoff = int((time.time() - self.retain_days * 86400) * 1_000_000)
        if not os.path.exists(EVENTS_PATH):
            return
        tmp = EVENTS_PATH + ".tmp"
        kept = 0
        try:
            with open(EVENTS_PATH, "r", encoding="utf-8") as src, \
                    open(tmp, "w", encoding="utf-8") as dst:
                for line in src:
                    try:
                        e = json.loads(line)
                    except Exception:
                        continue
                    if e.get("t", 0) >= cutoff:
                        dst.write(line)
                        kept += 1
            os.replace(tmp, EVENTS_PATH)
            self.stored = kept
            log("清理过期记录完成，保留 %d 条" % kept)
        except Exception as e:
            log("清理过期记录失败：%s" % e)

    def scan(self, days, user="", query="", limit=3000):
        """按时间窗/账号/关键字过滤，返回最新的 limit 条（时间升序）。"""
        cutoff = int((time.time() - days * 86400) * 1_000_000)
        if not os.path.exists(EVENTS_PATH):
            return []
        out = []
        q = query.lower()
        with open(EVENTS_PATH, "r", encoding="utf-8") as f:
            for line in f:
                try:
                    e = json.loads(line)
                except Exception:
                    continue
                if e.get("t", 0) < cutoff:
                    continue
                if user and e.get("u") != user:
                    continue
                if q and q not in str(e.get("h", "")).lower():
                    continue
                out.append(e)
                if len(out) > limit * 3:
                    out = out[-limit:]
        return out[-limit:]

    def aggregate(self, days, user="", query=""):
        """域名 TopN 与每账号条数。流式统计，不把记录堆进内存。

        过滤条件必须与 scan 完全一致：否则用户按关键字搜一下，
        表格里只剩几条、上面的统计却还是全量，看上去就像统计坏了。
        """
        cutoff = int((time.time() - days * 86400) * 1_000_000)
        q = query.lower()
        hosts, by_user, total = {}, {}, 0
        if os.path.exists(EVENTS_PATH):
            with open(EVENTS_PATH, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        e = json.loads(line)
                    except Exception:
                        continue
                    if e.get("t", 0) < cutoff:
                        continue
                    if user and e.get("u") != user:
                        continue
                    h = e.get("h", "")
                    if q and q not in h.lower():
                        continue
                    hosts[h] = hosts.get(h, 0) + 1
                    by_user[e.get("u", "")] = by_user.get(e.get("u", ""), 0) + 1
                    total += 1
        top = sorted(hosts.items(), key=lambda kv: (-kv[1], kv[0]))
        return top, by_user, total


class RatesStore:
    """按时间顺序保存各账号的速率采样，供面板画 1 小时 / 12 小时 / 全天的曲线。

    一条记录 = 一个时刻 + 该时刻所有账号的上下行，而不是每个账号单独一条：
    一天的采样量已到万级，再按账号拆行会让行数乘上账号数。

    为什么不放在内存里就好：面板进程重启（或 监控端 重启）之后，
    「12 小时」「全天」这两档如果只有内存数据，就会变成空图——
    而这两个视图的意义恰恰在于看过去。
    """

    def __init__(self, path=RATES_PATH):
        self.path = path
        self.lock = threading.Lock()
        self.rows = []          # [(ts, {name: (up, down)})]
        self.last_ts = 0

    def load(self):
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        d = json.loads(line)
                        per = {}
                        for name, v in (d.get("u") or {}).items():
                            per[name] = (int(v[0]), int(v[1]))
                        self.rows.append((int(d["t"]), per))
                    except Exception:
                        continue        # 半行或坏行跳过，不影响其余数据
        except FileNotFoundError:
            pass
        except Exception as e:
            log("读取速率采样失败：%s" % e)
        self.rows.sort(key=lambda r: r[0])
        if self.rows:
            self.last_ts = self.rows[-1][0]
        self.prune()

    def add(self, ts, per_user):
        """记一次采样。距上次不足 RATES_MIN_GAP_SECONDS 就当作重复值丢掉。"""
        if not per_user:
            return
        with self.lock:
            if ts - self.last_ts < RATES_MIN_GAP_SECONDS:
                return
            self.last_ts = ts
            row = {n: (int(u), int(d)) for n, (u, d) in per_user.items()}
            self.rows.append((ts, row))
            try:
                os.makedirs(DATA_DIR, exist_ok=True)
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(json.dumps(_rates_line(ts, row), separators=(",", ":")) + "\n")
            except Exception as e:
                log("写入速率采样失败：%s" % e)

    def prune(self):
        cutoff = int(time.time()) - RATES_RETAIN_SECONDS
        with self.lock:
            if not self.rows or self.rows[0][0] >= cutoff:
                return
            self.rows = [r for r in self.rows if r[0] >= cutoff]
            tmp = self.path + ".tmp"
            try:
                with open(tmp, "w", encoding="utf-8") as f:
                    for ts, row in self.rows:
                        f.write(json.dumps(_rates_line(ts, row), separators=(",", ":")) + "\n")
                os.replace(tmp, self.path)
                log("清理速率采样完成，保留 %d 条" % len(self.rows))
            except Exception as e:
                log("重写速率采样失败：%s" % e)

    def series(self, seconds, buckets):
        """把最近 seconds 秒的采样压成 buckets 个等宽区间，返回每账号两条数组。

        每个区间取平均。用峰值的话，12 小时/全天 的曲线会被个别突发顶满，
        其余部分全被压平；平均反映的是「这段时间的常态速率」，更适合看趋势。
        区间内没有采样（面板或节点断过）就记 0，不去猜补值。
        """
        now = int(time.time())
        start = now - seconds
        width = float(seconds) / buckets
        with self.lock:
            rows = list(self.rows)

        acc = {}        # name -> [[sum_up, sum_down, count], ...]
        used = 0
        for ts, per in rows:
            if ts < start or ts > now:
                continue
            used += 1
            idx = int((ts - start) / width)
            if idx < 0 or idx >= buckets:
                idx = buckets - 1
            for name, (up, down) in per.items():
                a = acc.get(name)
                if a is None:
                    a = acc[name] = [[0, 0, 0] for _ in range(buckets)]
                slot = a[idx]
                slot[0] += up
                slot[1] += down
                slot[2] += 1

        users = {}
        for name, a in acc.items():
            up, down = [], []
            for su, sd, c in a:
                if c:
                    up.append(int(su / c))
                    down.append(int(sd / c))
                else:
                    up.append(0)
                    down.append(0)
            users[name] = {"up": up, "down": down}
        return {
            "from": start * 1000, "to": now * 1000,     # 与记录一致，用毫秒
            "step": int(width),
            "samples": used,
            "users": users,
        }


def _rates_line(ts, row):
    """把一条采样序列化成落盘/传输用的紧凑结构：{"t":秒, "u":{账号:[上行,下行]}}。"""
    return {"t": ts, "u": {n: [v[0], v[1]] for n, v in row.items()}}


# ---------- 拉取循环 ----------

def pull_once(cfg, store):
    try:
        since = max(0, store.last_ms - OVERLAP_US)
        data = api_get(cfg, "/api/v1/admin/events", {"since": since, "limit": 5000})
        events = data.get("events") or []
        with store.lock:
            added = store.append(events)
            store.last_ms = max(store.last_ms, int(data.get("latest") or 0))
            store.save_state()
            store.last_sync = int(time.time())
            store.pull_error = ""
        if added:
            log("拉取到 %d 条新记录（本次返回 %d 条）" % (added, len(events)))
    except Exception as e:
        with store.lock:
            store.pull_error = "%s: %s" % (type(e).__name__, e)
        log("拉取访问记录失败：%s" % store.pull_error)


def pull_overview(cfg, store):
    try:
        d = api_get(cfg, "/api/v1/admin/overview")
        with store.lock:
            store.overview = d
        # 顺手采一次速率快照，供 1 小时 / 12 小时 / 全天 的曲线使用。
        # 只采节点确实下发了速率的账号：老版本节点没有这两个字段，
        # 那就一条都不记，曲线自然是空的（面板会显示「—」而不是画成 0）。
        per = {}
        for u in d.get("users") or []:
            if "upSpeed" not in u or "downSpeed" not in u:
                continue
            name = u.get("name") or ""
            if name:
                per[name] = (u.get("upSpeed") or 0, u.get("downSpeed") or 0)
        if per and getattr(store, "rates", None) is not None:
            store.rates.add(int(time.time()), per)
    except Exception as e:
        log("拉取账号概览失败：%s: %s" % (type(e).__name__, e))


# 实时速率的刷新节奏（秒），要与节点侧的采集间隔（transctl 每 5 秒一次）配合：
# 比它快拿不到新数据，比它慢就会把面板拖成「慢动作」。
RATES_REFRESH_SECONDS = 5


def build_rates(store):
    """只返回各账号的实时速率，供面板高频刷新。

    刻意与 /api/data 分开：data 里带着访问记录、Top 域名这些重东西，几十秒刷一次就够；
    速率要 5 秒一刷，混在一起就等于为了几个数字反复传整张表。
    """
    with store.lock:
        ov = store.overview or {}
    users = []
    for u in ov.get("users") or []:
        row = {
            "name": u.get("name") or "",
            "lastActive": u.get("lastActive") or 0,
        }
        # 只在节点确实下发了速率的节点上带上这两个字段，其余留空。
        # 这样面板能区分「节点太旧、没这个数据」（显示「—」）和
        # 「速率确实是 0」（显示 0 B/s）——否则升级面板之后所有账号
        # 都会显示成 0，看着像全站都没流量。
        if "upSpeed" in u:
            row["up"] = u.get("upSpeed") or 0
        if "downSpeed" in u:
            row["down"] = u.get("downSpeed") or 0
        if "sessionUp" in u:
            row["sessionUp"] = u.get("sessionUp") or 0
        if "sessionDown" in u:
            row["sessionDown"] = u.get("sessionDown") or 0
        users.append(row)
    return {"speedAt": ov.get("speedAt") or 0, "users": users}


def pull_loop(cfg, store):
    last_overview = 0
    last_prune = 0
    while True:
        pull_once(cfg, store)
        now = time.time()
        # 概览里带着每个账号的实时速率（节点每 5 秒从内核与 hysteria 各采一次）。
        # 原来 60 秒拉一次，面板上的「实时速率」就变成一分钟跳一次，看着像坏了；
        # 概览本身很小（就几个账号），跟着节点的采集节奏走即可。
        if now - last_overview > RATES_REFRESH_SECONDS:
            pull_overview(cfg, store)
            last_overview = now
        if now - last_prune > 3600:
            with store.lock:
                store.prune()
            if getattr(store, "rates", None) is not None:
                store.rates.prune()
            last_prune = now
        time.sleep(max(5, int(cfg["poll_seconds"])))

# ---------- 网页 ----------

DASHBOARD = r"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow">
<title>TransProxy 监控</title>
<style>
  :root{
    --bg:#f4f6fa; --card:#fff; --line:#eef1f6; --text:#1f2430; --dim:#6b7280;
    --faint:#9ca4b2; --accent:#2f6bff; --accent-soft:#e8efff; --warn:#8a5a00;
    --ok:#16b364; --bad:#e5484d; color-scheme:light;
  }
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--text);
       font:15px/1.6 -apple-system,"Segoe UI","Microsoft YaHei UI",sans-serif}
  .wrap{max-width:1180px;margin:0 auto;padding:26px 20px 60px}
  header{display:flex;align-items:baseline;gap:12px;flex-wrap:wrap;margin-bottom:4px}
  h1{font-size:24px;margin:0}
  .sub{color:var(--dim);font-size:13px}
  .dot{display:inline-block;width:8px;height:8px;border-radius:50%;background:var(--ok);
       margin-right:6px;vertical-align:middle}
  .dot.bad{background:var(--bad)}
  .dot.stale{background:#e8a33d}
  .row{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}
  .stat{flex:1 1 180px;background:var(--card);border-radius:10px;padding:14px 16px}
  .stat .k{color:var(--faint);font-size:12px}
  .stat .v{font-size:20px;font-weight:600;margin-top:2px}
  .card{background:var(--card);border-radius:10px;padding:16px 18px;margin:14px 0}
  h2{font-size:15px;margin:0 0 10px;display:flex;align-items:center;gap:8px}
  h2 .hint{font-weight:400;color:var(--faint);font-size:12px}
  table{width:100%;border-collapse:collapse;font-size:13px}
  th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);white-space:nowrap}
  th{color:var(--faint);font-weight:500;font-size:12px}
  tbody tr:hover{background:#fafbfe}
  td.host{font-family:ui-monospace,Consolas,monospace;white-space:normal;word-break:break-all}
  .tag{display:inline-block;padding:1px 6px;border-radius:4px;font-size:11px;background:var(--line);color:var(--dim)}
  .tag.udp{background:#fff3e0;color:var(--warn)}
  .tag.chb{background:var(--accent-soft);color:var(--accent)}
  .bar{display:grid;grid-template-columns:minmax(120px,1fr) 3fr auto;gap:10px;align-items:center;
       padding:5px 0;font-size:13px}
  .bar .name{font-family:ui-monospace,Consolas,monospace;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
  .bar .track{background:var(--line);border-radius:5px;height:9px;overflow:hidden}
  .bar .fill{background:var(--accent);height:100%;border-radius:5px;
             transition:width .5s cubic-bezier(.4,0,.2,1)}
  .bar .num{color:var(--faint);font-size:12px;min-width:52px;text-align:right}
  .users{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:10px}
  .u{background:var(--bg);border-radius:8px;padding:11px 13px}
  .u .n{font-weight:600;margin-bottom:4px;display:flex;align-items:center;gap:6px}
  .u .m{color:var(--dim);font-size:12px}
  .controls{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:10px}
  input[type=search],select{font:inherit;font-size:13px;padding:6px 9px;border:1px solid #dfe4ee;
       border-radius:7px;background:#fff;color:var(--text)}
  input[type=search]{min-width:200px}
  .seg{display:inline-flex;background:var(--line);border-radius:8px;padding:2px}
  .seg button{font:inherit;font-size:12px;border:0;background:transparent;color:var(--dim);
       padding:5px 11px;border-radius:6px;cursor:pointer}
  .seg button.on{background:#fff;color:var(--text);font-weight:600;box-shadow:0 1px 2px rgba(31,36,48,.08)}
  .scroll{max-height:520px;overflow:auto}
  .err{color:var(--bad);font-size:13px}
  .foot{color:var(--faint);font-size:12px;margin-top:22px;line-height:1.9}
  .foot code{background:var(--line);border-radius:4px;padding:1px 5px}
  .grow{flex:1}
  .btn{font:inherit;font-size:13px;padding:5px 11px;border:1px solid #dfe4ee;border-radius:7px;
       background:#fff;color:var(--text);cursor:pointer}
  .btn:hover{background:#f7f9fd}
  .btn.primary{background:var(--accent);border-color:var(--accent);color:#fff}
  .btn.primary:hover{background:#2559dd}
  .btn.danger{color:var(--bad);border-color:#f2c9ca}
  .btn.danger:hover{background:#fff5f5}
  .btn:disabled{opacity:.5;cursor:default}
  .acts{display:flex;gap:6px;flex-wrap:wrap;margin-top:9px}
  .acts .btn{font-size:12px;padding:3px 9px}
  .u.off{opacity:.72}
  .overlay{position:fixed;inset:0;background:rgba(31,36,48,.38);display:none;
           align-items:center;justify-content:center;padding:20px;z-index:20}
  .overlay.on{display:flex}
  .modal{background:#fff;border-radius:12px;padding:20px 20px 16px;width:100%;max-width:420px;
         box-shadow:0 18px 48px rgba(31,36,48,.22)}
  .modal h3{margin:0 0 14px;font-size:16px}
  .modal label{display:block;color:var(--dim);font-size:12px;margin:12px 0 4px}
  .modal input{width:100%;font:inherit;font-size:14px;padding:8px 10px;border:1px solid #dfe4ee;
               border-radius:7px;background:#fff;color:var(--text)}
  .modal .tip{color:var(--faint);font-size:12px;margin-top:5px}
  .modal .confirmText{font-size:14px;margin:8px 0 2px;
       font-family:ui-monospace,Consolas,monospace;word-break:break-all}
  .mFoot{display:flex;justify-content:flex-end;gap:8px;margin-top:18px}
  .toast{position:fixed;left:50%;bottom:34px;transform:translate(-50%,20px);
         background:var(--text);color:#fff;font-size:13px;padding:9px 16px;border-radius:8px;
         opacity:0;pointer-events:none;transition:opacity .25s,transform .25s;z-index:30;max-width:80vw}
  .toast.on{opacity:1;transform:translate(-50%,0)}
  .toast.bad{background:var(--bad)}
  /* 实时速率：数字 + 约 3 分钟的趋势线 */
  .u .live{margin-top:8px}
  .u .live .spark{height:30px;background:#fff;border-radius:6px;overflow:hidden}
  .u .live .spark svg{display:block;width:100%;height:30px}
  .u .live .spark polyline{fill:none;stroke-width:1.4;vector-effect:non-scaling-stroke}
  .u .live .spark .s-dn{stroke:var(--accent)}
  .u .live .spark .s-up{stroke:#e0993a}
  .u .live .rt{display:flex;gap:14px;font-size:12px;margin-top:5px;
               font-variant-numeric:tabular-nums}
  .u .live .dn{color:var(--accent);font-weight:600}
  .u .live .up{color:#b8730a;font-weight:600}
  .u .live .idle{color:var(--faint);font-weight:400}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>TransProxy 监控</h1>
    <span class="sub" id="conn"><span class="dot"></span>正在连接…</span>
    <span class="grow"></span>
    <button class="btn" id="chpw">修改密码</button>
  </header>
  <div class="sub" id="meta"></div>
  <div id="err" class="err"></div>

  <div class="row" id="stats"></div>

  <div class="card">
    <h2>账号 <span class="hint" id="userHint">新增/改密/停用/删除都会即时同步到内核，不影响其他在线用户</span>
      <span class="grow"></span>
      <button class="btn primary" id="addUser">+ 新建账号</button>
    </h2>
    <div class="controls">
      <span class="sub">速率曲线范围</span>
      <div class="seg" id="rateRange">
        <button data-r="live" class="on">实时</button>
        <button data-r="1h">1 小时</button>
        <button data-r="12h">12 小时</button>
        <button data-r="24h">全天</button>
      </div>
      <span class="sub" id="rateHint"></span>
    </div>
    <div class="users" id="users"></div>
  </div>

  <div class="card">
    <h2>访问最多的域名 <span class="hint" id="topHint"></span></h2>
    <div id="top"></div>
  </div>

  <div class="card">
    <h2>访问记录</h2>
    <div class="controls">
      <div class="seg" id="range">
        <button data-d="1" class="on">今天</button>
        <button data-d="7">7 天</button>
        <button data-d="14">14 天</button>
      </div>
      <select id="user"><option value="">全部账号</option></select>
      <input type="search" id="q" placeholder="按域名过滤，例如 google">
      <label class="sub"><input type="checkbox" id="auto" checked> 自动刷新</label>
    </div>
    <div class="scroll">
      <table>
        <thead><tr><th>时间</th><th>账号</th><th>目标</th><th>端口</th><th>通道</th><th>协议</th><th>出站</th></tr></thead>
        <tbody id="rows"></tbody>
      </table>
    </div>
  </div>

  <div class="foot">
    数据来自两个源头：<strong>通道A</strong> 取节点内核的访问日志，<strong>通道B</strong> 取 hysteria 的
    统计数据接口。记录的是<strong>目标主机名</strong>（TLS SNI / HTTP Host，或客户端请求的原始地址），
    不包含完整 URL、路径或搜索关键词——HTTPS 的内容全程加密，记录里不存在。<br>
    明文 DNS 查询（53 端口）不记录：能拿到的只有「查询发给了哪个解析器」（例如 1.1.1.1），
    没有「查了什么域名」，对监控没有意义。加密 DNS（853 端口，DNS over TLS / QUIC）同理，
    手机开了「私人 DNS」时会每半分钟连一次解析器，同样只记解析器、不记域名，所以一并丢掉。
    UDP 443（QUIC）是真实访问，照常记录。<br>
    通道B 的记录有个固有限制：那个接口只返回<strong>当前活跃</strong>的流，不是历史日志，
    所以建立又关闭都发生在两次采集（2 秒）之间的短连接可能被漏掉；
    它也拿不到传输层类型与出站标签，所以协议/出站两列显示为 —。<br>
    时间段：<span id="retain"></span>　刷新间隔：每 15 秒自动拉取。
  </div>
</div>

<div class="overlay" id="overlay">
  <div class="modal">
    <h3 id="mTitle"></h3>
    <div id="mBody"></div>
    <div class="mFoot">
      <button class="btn" id="mCancel">取消</button>
      <button class="btn primary" id="mOk">确定</button>
    </div>
  </div>
</div>
<div class="toast" id="toast"></div>
<script>
const $ = s => document.querySelector(s);
let days = 1, timer = null;

function fmtTime(us){
  const d = new Date(us/1000);
  const p = n => String(n).padStart(2,'0');
  return p(d.getMonth()+1)+'-'+p(d.getDate())+' '+p(d.getHours())+':'+p(d.getMinutes())+':'+p(d.getSeconds());
}
function since(us){
  if(!us) return '从未';
  // 记录时间是微秒，Date.now() 是毫秒，先换算到同一单位再比。
  const s = Math.max(0, (Date.now()*1000-us)/1e6);
  if(s < 90) return '刚刚';
  if(s < 3600) return Math.round(s/60)+' 分钟前';
  if(s < 86400) return Math.round(s/3600)+' 小时前';
  return Math.round(s/86400)+' 天前';
}
function esc(s){ return String(s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
function bytes(n){
  n = Number(n||0); const u=['B','KB','MB','GB','TB']; let i=0;
  while(n >= 1024 && i < u.length-1){ n/=1024; i++; }
  return (i===0? n+' B' : n.toFixed(2)+' '+u[i]);
}

async function load(){
  const u = $('#user').value, q = $('#q').value.trim();
  const url = `api/data?days=${days}&user=${encodeURIComponent(u)}&q=${encodeURIComponent(q)}`;
  try{
    const r = await fetch(url, {cache:'no-store'});
    if(!r.ok) throw new Error('HTTP '+r.status);
    const d = await r.json();
    render(d);
    $('#err').textContent = '';
    const c = $('#conn');
    if(d.pullError){ c.innerHTML = '<span class="dot bad"></span>拉取失败：'+esc(d.pullError); }
    else { c.innerHTML = '<span class="dot"></span>已同步 · '+esc(d.lastSyncText); }
  }catch(e){
    $('#conn').innerHTML = '<span class="dot bad"></span>面板读取失败';
    $('#err').textContent = String(e);
  }
  if($('#auto').checked){ clearTimeout(timer); timer = setTimeout(load, 15000); }
}

function render(d){
  const s = d.server || {};
  $('#meta').textContent = `节点 ${s.domain || '-'} · 服务器时间 ${fmtTime(s.serverTime||Date.now()*1000)}`
     + (s.collectorOn===false ? ' · 采集器未运行' : '')
     + (s.parseFailed ? ` · 解析失败 ${s.parseFailed} 行` : '');
  $('#retain').textContent = `本地保留 ${d.retainDays} 天 · 已存 ${d.stored} 条`;

  const users = s.users || [];
  CURRENT_USERS = users;
  CURRENT_NODES = s.relayNodes || [];
  const byUser = d.byUser || {};
  const active = users.filter(u => byUser[u.name]).length;
  $('#stats').innerHTML = [
    ['账号数', users.length + ' 个'],
    ['本时段活跃', active + ' 个'],
    ['本时段访问条数', (d.total||0).toLocaleString()],
    ['域名数', (d.hosts||[]).length + ' 个'],
  ].map(([k,v]) => `<div class="stat"><div class="k">${k}</div><div class="v">${v}</div></div>`).join('')
    // 总速率由 renderRates() 每 5 秒填一次，所以这里固定带个 id。
    + `<div class="stat"><div class="k">当前总速率 下行 / 上行</div><div class="v" id="totalRate">—</div></div>`;

  $('#users').innerHTML = users.length ? users.map(u => `
    <div class="u ${u.enabled?'':'off'}">
      <div class="n">${esc(u.name)}
        ${u.enabled?'':'<span class="tag">已停用</span>'}
        ${byUser[u.name]?`<span class="tag" style="background:var(--accent-soft);color:var(--accent)">本时段 ${byUser[u.name]}</span>`:''}
      </div>
      ${u.note?`<div class="m">${esc(u.note)}</div>`:''}
      ${(u.allowNodes && u.allowNodes.length)
        ? `<div class="m">可用线路：${u.allowNodes.map(n => esc(nodeName(n))).join('、')}</div>`
        : (CURRENT_NODES.length ? '<div class="m sub">可用线路：仅默认线路</div>' : '')}
      <div class="m">累计用量 ${bytes(u.usedBytes)}${u.quotaBytes>0?` / ${bytes(u.quotaBytes)}`:'（不限量）'}</div>
      <div class="m">最近活动 ${since(u.lastActive)}</div>
      <div class="live" data-live="${esc(u.name)}">
        <div class="spark"></div>
        <div class="rt"><span class="dn">↓ —</span><span class="up">↑ —</span></div>
      </div>
      <div class="acts">
        <button class="btn" data-act="edit" data-u="${esc(u.name)}">编辑</button>
        <button class="btn" data-act="pass" data-u="${esc(u.name)}">重置密码</button>
        <button class="btn" data-act="toggle" data-u="${esc(u.name)}" data-on="${u.enabled?1:0}">${u.enabled?'停用':'启用'}</button>
        <button class="btn danger" data-act="del" data-u="${esc(u.name)}">删除</button>
      </div>
    </div>`).join('') : '<div class="m">暂无账号</div>';

  const top = d.hosts || [];
  $('#topHint').textContent = top.length ? `（本时段共 ${d.total} 条）` : '';
  const max = top.length ? top[0].count : 1;
  $('#top').innerHTML = top.length ? top.slice(0,20).map(h => `
    <div class="bar">
      <div class="name" title="${esc(h.host)}">${esc(h.host)}</div>
      <div class="track"><div class="fill" style="width:${Math.max(2, h.count/max*100)}%"></div></div>
      <div class="num">${h.count}</div>
    </div>`).join('') : '<div class="m sub">本时段没有记录</div>';

  const sel = $('#user'), cur = sel.value;
  sel.innerHTML = '<option value="">全部账号</option>' +
    users.map(u => `<option value="${esc(u.name)}">${esc(u.name)}</option>`).join('');
  sel.value = cur;

  const rows = d.events || [];
  $('#rows').innerHTML = rows.length ? rows.slice().reverse().map(e => `
    <tr>
      <td>${fmtTime(e.t)}</td>
      <td>${esc(e.u)}</td>
      <td class="host">${esc(e.h)}</td>
      <td>${e.p}</td>
      <td><span class="tag ${e.c==='B'?'chb':''}">${e.c==='B'?'B':'A'}</span></td>
      <td>${e.n?`<span class="tag ${e.n==='udp'?'udp':''}">${esc(e.n)}</span>`:'<span class="sub">—</span>'}</td>
      <td>${esc(e.o||'—')}</td>
    </tr>`).join('') : '<tr><td colspan="7" class="sub">没有符合条件的记录</td></tr>';

  // 卡片刚重建过，把实时速率与趋势线立刻补上，
  // 否则每次 15 秒的整页刷新都会让速率闪回「—」。
  renderRates();
}

/* ---------------- 实时速率 ----------------
   节点每 5 秒采一次各账号的上下行，这里跟着 5 秒刷一次，
   而且只改几个数字和一条折线，不动下面那张记录表（那是 15 秒一刷的重活）。
   单独走 /api/rates 就是为了这个：把「高频的小数据」和「低频的大数据」分开。 */
const RATE_WINDOW = 36;      // 采样点数：36 × 5 秒 ≈ 3 分钟
let RATES = {};              // name -> {up,down,sessionUp,sessionDown,lastActive}
let HIST = {};               // name -> [{up,down}, ...]

function speed(n){
  n = Number(n||0);
  if(n < 1024) return n + ' B/s';
  if(n < 1024*1024) return (n/1024).toFixed(1) + ' KB/s';
  if(n < 1024*1024*1024) return (n/1048576).toFixed(2) + ' MB/s';
  return (n/1073741824).toFixed(2) + ' GB/s';
}

function pushHist(name, up, down){
  const h = HIST[name] || (HIST[name] = []);
  h.push({up: up, down: down});
  while(h.length > RATE_WINDOW) h.shift();
}

/* 折线从右侧往左铺：新采样点出现在右边，旧的往左移出去。
   纵轴按窗口内的峰值归一化——否则数值一大一小就被压成一条平线，看不出变化。 */
function spark(hist){
  const W = 180, H = 30;
  if(hist.length < 2) return '';
  const peak = Math.max(1, ...hist.map(p => Math.max(p.up, p.down)));
  const pts = key => hist.map((p, i) => {
    const x = W - (hist.length - 1 - i) * (W / (RATE_WINDOW - 1));
    const y = H - 2 - (p[key] / peak) * (H - 6);
    return x.toFixed(1) + ',' + y.toFixed(1);
  }).join(' ');
  return `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">`
       + `<polyline class="s-dn" points="${pts('down')}"/>`
       + `<polyline class="s-up" points="${pts('up')}"/></svg>`;
}

/* ---------------- 速率曲线：1 小时 / 12 小时 / 全天 ----------------
   历史序列由面板侧的 RatesStore 落盘保存（节点只管报「此刻的速率」，
   它没有历史）。三档的点数固定，换范围只改横轴跨度。
   曲线范围与数字是两回事：下面的 ↓/↑ 数字始终是「此刻」的速率，
   只切换曲线看的那段时间。 */
let RATE_RANGE = 'live';     // live | 1h | 12h | 24h
let SERIES = null;           // 最近一次拉到的历史：{samples, users:{账号:{up:[],down:[]}}}

function sparkSeries(down, up){
  const W = 180, H = 30, n = Math.max(down.length, up.length);
  if(n < 2) return '';
  const peak = Math.max(1, ...down, ...up);
  const pts = arr => arr.map((v, i) => {
    const x = (i / (n - 1)) * W;
    const y = H - 2 - (v / peak) * (H - 6);
    return x.toFixed(1) + ',' + y.toFixed(1);
  }).join(' ');
  return `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">`
       + `<polyline class="s-dn" points="${pts(down)}"/>`
       + `<polyline class="s-up" points="${pts(up)}"/></svg>`;
}

/* 拉历史曲线。历史本身是分钟级的，没必要跟着 5 秒刷，默认 60 秒一次；
   切换范围时立刻拉一次，不然要等一整分钟才有反应。 */
async function loadSeries(){
  if(RATE_RANGE === 'live'){ SERIES = null; renderRates(); return; }
  try{
    const r = await fetch('api/history?range=' + encodeURIComponent(RATE_RANGE), {cache:'no-store'});
    if(r.ok) SERIES = await r.json();
  }catch(e){ /* 拉不到就沿用上一次的曲线，不清空 */ }
  renderRates();
}

function renderRates(){
  document.querySelectorAll('[data-live]').forEach(box => {
    const name = box.dataset.live, r = RATES[name];
    const dn = box.querySelector('.dn'), up = box.querySelector('.up');
    const sp = box.querySelector('.spark');
    // up/down 缺失 = 节点版本太旧、根本没这个数据，显示「—」而不是 0 B/s。
    if(!r || r.up === undefined || r.down === undefined){
      dn.textContent = '↓ —'; up.textContent = '↑ —';
      dn.classList.add('idle'); up.classList.add('idle');
      sp.innerHTML = '';
      return;
    }
    dn.textContent = '↓ ' + speed(r.down);
    up.textContent = '↑ ' + speed(r.up);
    // 静止时把数字压暗：一眼能分出「就是没流量」和「显示坏了」
    dn.classList.toggle('idle', !r.down);
    up.classList.toggle('idle', !r.up);
    // 曲线按所选范围取数据：实时用页面内存里这几分钟，其余用面板存下来的历史。
    const s = (RATE_RANGE !== 'live' && SERIES && SERIES.users) ? SERIES.users[name] : null;
    sp.innerHTML = s ? sparkSeries(s.down, s.up)
                     : (RATE_RANGE === 'live' ? spark(HIST[name] || []) : '');
  });
  const tot = $('#totalRate');
  if(tot){
    let up = 0, down = 0, any = false;
    Object.keys(RATES).forEach(n => {
      if(RATES[n].up === undefined) return;   // 老节点没有速率数据，不参与合计
      any = true;
      up += RATES[n].up || 0; down += RATES[n].down || 0;
    });
    tot.innerHTML = any
      ? `<span style="color:var(--accent)">↓ ${speed(down)}</span> `
        + `<span style="color:#b8730a">↑ ${speed(up)}</span>`
      : '—';
  }
  const hint = $('#rateHint');
  if(hint){
    if(RATE_RANGE === 'live') hint.textContent = '（曲线是最近约 3 分钟）';
    else if(!SERIES) hint.textContent = '正在加载…';
    else if(!SERIES.samples) hint.textContent = '这段时间还没有采样数据（面板刚启动或节点离线）';
    else hint.textContent = `（曲线来自面板保存的采样，每 60 秒更新）`;
  }
}

async function pollRates(){
  // 用户按了「暂停自动刷新」就别在背后偷偷刷，否则那个开关等于没用了。
  if($('#auto') && $('#auto').checked){
    try{
      const r = await fetch('api/rates', {cache:'no-store'});
      if(r.ok){
        const d = await r.json();
        const seen = {};
        (d.users || []).forEach(u => {
          if(!u.name) return;
          seen[u.name] = 1;
          RATES[u.name] = u;
          pushHist(u.name, u.up, u.down);
        });
        // 账号被删掉后，留在内存里的旧速率与历史要一起清掉，不然总速率会一直算着它。
        Object.keys(RATES).forEach(n => {
          if(!seen[n]){ delete RATES[n]; delete HIST[n]; }
        });
        renderRates();
      }
    }catch(e){ /* 网络抖一下就跳过这一拍，下一拍再来 */ }
  }
  setTimeout(pollRates, 5000);
}

// 曲线范围：切换后立刻拉一次，不然要等下一个 60 秒周期才有反应。
$('#rateRange').addEventListener('click', ev => {
  const b = ev.target.closest('button'); if(!b) return;
  [...ev.currentTarget.children].forEach(x => x.classList.toggle('on', x === b));
  RATE_RANGE = b.dataset.r;
  loadSeries();
});

async function pollSeries(){
  // 与实时数值一样尊重「暂停自动刷新」；范围是「实时」时本来就不需要拉历史。
  if(RATE_RANGE !== 'live' && (!$('#auto') || $('#auto').checked)) await loadSeries();
  setTimeout(pollSeries, 60000);
}

$('#range').addEventListener('click', ev => {
  const b = ev.target.closest('button'); if(!b) return;
  [...ev.currentTarget.children].forEach(x => x.classList.toggle('on', x === b));
  days = Number(b.dataset.d); load();
});
$('#user').addEventListener('change', load);
let deb = null;
$('#q').addEventListener('input', () => { clearTimeout(deb); deb = setTimeout(load, 300); });
$('#auto').addEventListener('change', () => { if($('#auto').checked) load(); });

/* ---------------- 账号管理 ----------------
   所有改动都经 监控端转发给节点的管理接口。管理员令牌只存在 监控端上，
   浏览器拿不到，所以即使面板页面被人看到，也拿不到直接操作节点的能力。 */

let CURRENT_USERS = [];
let CURRENT_NODES = [];   // 可选线路清单（服务端下发的 relayNodes），用来渲染授权勾选项与卡片上的线路名
let mSubmit = null;

function toast(msg, bad){
  const t = $('#toast');
  t.textContent = msg;
  t.classList.toggle('bad', !!bad);
  t.classList.add('on');
  clearTimeout(toast._t);
  toast._t = setTimeout(() => t.classList.remove('on'), 2800);
}

function openModal(title, fields, okText, onSubmit, danger){
  $('#mTitle').textContent = title;
  $('#mBody').innerHTML = fields.map(f => f.checks ? `
    <label>${esc(f.label||'')}</label>
    <div class="checks" id="mf_${f.name}" style="display:flex;flex-direction:column;gap:6px;margin:2px 0 6px">
      ${f.checks.map(c => `<label class="chk" style="display:flex;align-items:center;gap:8px;font-weight:400;cursor:pointer"><input type="checkbox" value="${esc(c.value)}"${c.on?' checked':''}>
        <span>${esc(c.label)}</span></label>`).join('')}
    </div>
    ${f.tip?`<div class="tip">${esc(f.tip)}</div>`:''}` : f.text ? `
    <label>${esc(f.label||'')}</label>
    <div class="confirmText">${esc(f.value===undefined?'':f.value)}</div>
    ${f.tip?`<div class="tip">${esc(f.tip)}</div>`:''}` : `
    <label for="mf_${f.name}">${esc(f.label)}</label>
    <input id="mf_${f.name}" type="${f.type||'text'}" value="${esc(f.value===undefined?'':f.value)}"
           placeholder="${esc(f.placeholder||'')}" autocomplete="off" spellcheck="false">
    ${f.tip?`<div class="tip">${esc(f.tip)}</div>`:''}`).join('');
  $('#mOk').textContent = okText || '确定';
  $('#mOk').classList.toggle('danger', !!danger);
  $('#mOk').classList.toggle('primary', !danger);
  mSubmit = onSubmit;
  $('#overlay').classList.add('on');
  const first = $('#mBody input');
  if(first) setTimeout(() => first.focus(), 30);
}

function closeModal(){ $('#overlay').classList.remove('on'); mSubmit = null; }
function mval(n){ const e = $('#mf_'+n); return e ? e.value : ''; }

// mchecks 读回一组勾选框里被选中的值。
function mchecks(n){
  const box = $('#mf_'+n);
  if(!box) return [];
  return Array.from(box.querySelectorAll('input[type="checkbox"]')).filter(i => i.checked).map(i => i.value);
}

// nodeName 把线路 id 换成显示名。
function nodeName(id){
  const n = CURRENT_NODES.find(x => x.id === id);
  return n ? n.name : id;
}

// nodeChecks 生成「可用线路」的勾选字段。
//
// 只给勾选、不让手打 id：授权值要与节点登记表里的 id 对上，手打早晚会打错，
// 而打错的后果是「看起来授了权、实际用不了」，极难排查。
// 没有任何可选线路时返回 null —— 单线路部署下显示一个空框只会让人困惑。
function nodeChecks(selected){
  if(!CURRENT_NODES.length) return null;
  const sel = selected || [];
  return {
    name: 'nodes',
    label: '可用线路（不勾 = 只能用默认线路）',
    checks: CURRENT_NODES.map(n => ({
      value: n.id,
      label: n.name + (n.ready ? '' : '（尚未上报，暂不可用）'),
      on: sel.includes(n.id),
    })),
    tip: '授权后该账号的客户端才会出现这条线路。撤销授权会在节点下一次同步（约半分钟）后把它从节点内核里摘掉。',
  };
}

$('#mCancel').addEventListener('click', closeModal);
$('#overlay').addEventListener('click', ev => { if(ev.target === $('#overlay')) closeModal(); });
document.addEventListener('keydown', ev => {
  if(ev.key === 'Escape') closeModal();
  if(ev.key === 'Enter' && $('#overlay').classList.contains('on')) $('#mOk').click();
});
$('#mOk').addEventListener('click', async () => {
  if(!mSubmit) return;
  const btn = $('#mOk');
  btn.disabled = true;
  try{ await mSubmit(); }
  catch(e){ toast(String((e && e.message) || e), true); }
  finally{ btn.disabled = false; }
});

async function adminPost(path, payload){
  const r = await fetch(path, {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify(payload),
  });
  let d = {};
  try{ d = await r.json(); }catch(e){}
  if(!r.ok || d.error) throw new Error(d.error || ('HTTP ' + r.status));
  return d;
}

const NAME_RE = /^[A-Za-z0-9_-]{1,32}$/;
const GB = 1024*1024*1024;
function toBytesGB(v){
  const n = Number(v);
  if(!isFinite(n) || n <= 0) return 0;
  return Math.round(n * GB);
}

$('#addUser').addEventListener('click', () => {
  const fields = [
    {name:'name', label:'账号名', placeholder:'字母、数字、下划线、短横线'},
    {name:'pass', label:'密码', type:'password', tip:'至少 6 位'},
    {name:'note', label:'备注（选填）', placeholder:'给谁用的'},
    {name:'quota', label:'额度 GB（留空或 0 = 不限量）', placeholder:'0'},
  ];
  const nc = nodeChecks([]);
  if(nc) fields.push(nc);
  openModal('新建账号', fields, '创建', async () => {
    const name = mval('name').trim(), pass = mval('pass');
    if(!NAME_RE.test(name)) return toast('账号名只能包含字母、数字、下划线、短横线，长度 1-32', true);
    if(pass.length < 6) return toast('密码至少 6 位', true);
    const d = await adminPost('api/user/create', {
      name: name, password: pass, note: mval('note').trim(), quotaBytes: toBytesGB(mval('quota')),
      allowNodes: mchecks('nodes'),
    });
    closeModal(); toast(d.message || '已创建'); load();
  });
});

$('#users').addEventListener('click', async ev => {
  const b = ev.target.closest('button[data-act]');
  if(!b) return;
  const name = b.dataset.u;
  const u = CURRENT_USERS.find(x => x.name === name) || {};
  const act = b.dataset.act;

  if(act === 'edit'){
    const fields = [
      {name:'note', label:'备注', value: u.note || ''},
      {name:'quota', label:'额度 GB（留空或 0 = 不限量）',
       value: u.quotaBytes > 0 ? (u.quotaBytes / GB).toFixed(2) : '0'},
    ];
    const nc = nodeChecks(u.allowNodes);
    if(nc) fields.push(nc);
    openModal('编辑 ' + name, fields, '保存', async () => {
      const payload = {
        name: name, note: mval('note').trim(), quotaBytes: toBytesGB(mval('quota')),
      };
      // 只有界面上真的显示了勾选框才提交权限。否则「界面上没有这一项」会被
      // 当成「提交了空列表」，一保存就把已有授权清空了。
      if(nc) payload.allowNodes = mchecks('nodes');
      const d = await adminPost('api/user/update', payload);
      closeModal(); toast(d.message || '已保存'); load();
    });
  } else if(act === 'pass'){
    openModal('重置 ' + name + ' 的密码', [
      {name:'pass', label:'新密码', type:'password',
       tip:'至少 6 位。重置会同时更换该账号的连接身份，旧参数立即失效，本人需重新登录。'},
    ], '重置', async () => {
      const pass = mval('pass');
      if(pass.length < 6) return toast('密码至少 6 位', true);
      const d = await adminPost('api/user/update', {name: name, newPassword: pass});
      closeModal(); toast(d.message || '已重置'); load();
    });
  } else if(act === 'toggle'){
    const on = b.dataset.on === '1';
    b.disabled = true;
    try{
      const d = await adminPost('api/user/update', {name: name, enabled: !on});
      toast(d.message || '已更新'); load();
    }catch(e){
      toast(String((e && e.message) || e), true);
    }finally{
      b.disabled = false;
    }
  } else if(act === 'del'){
    openModal('删除账号', [
      {text:true, value:name,
       tip:'此操作不可撤销。该账号会立刻从内核移除，正在使用它的设备随即断线；本地的浏览记录不受影响。'},
    ], '删除', async () => {
      const d = await adminPost('api/user/delete', {name: name});
      closeModal(); toast(d.message || '已删除'); load();
    }, true);
  }
});

/* ---------------- 修改面板登录密码 ----------------
   改的是「登录这个面板」的口令，与节点上的账号无关。
   改完浏览器里缓存的还是旧凭据，所以直接重载页面让浏览器重新询问。 */

$('#chpw').addEventListener('click', () => {
  openModal('修改面板密码', [
    {name:'cur', label:'当前密码', type:'password'},
    {name:'n1', label:'新密码', type:'password', tip:'至少 8 位'},
    {name:'n2', label:'确认新密码', type:'password'},
  ], '保存', async () => {
    const cur = mval('cur'), n1 = mval('n1'), n2 = mval('n2');
    if(!cur) return toast('请输入当前密码', true);
    if(n1.length < 8) return toast('新密码至少 8 位', true);
    if(n1 !== n2) return toast('两次输入的新密码不一致', true);
    const d = await adminPost('api/password', {current: cur, next: n1});
    closeModal();
    toast(d.message || '密码已修改');
    setTimeout(() => location.reload(), 1600);
  });
});

load();
pollRates();    // 实时速率独立于整页刷新，自己按 5 秒一拍跑
pollSeries();   // 历史曲线按范围取，60 秒一拍（切到「实时」时不拉）
</script>
</body>
</html>
"""


class Handler(BaseHTTPRequestHandler):
    cfg = None
    store = None
    server_version = "TransProxyMonitor"

    def log_message(self, fmt, *args):
        pass  # 访问日志由我们自己控制，默认的逐请求打印太吵

    def auth_ok(self):
        h = self.headers.get("Authorization", "")
        if not h.startswith("Basic "):
            return False
        try:
            raw = base64.b64decode(h[6:]).decode("utf-8")
            user, _, given = raw.partition(":")
        except Exception:
            return False
        if user != self.cfg.get("user", "admin"):
            return False
        if not password_ok(self.cfg, given):
            return False
        upgrade_password_if_legacy(self.cfg, given)
        return True

    def deny(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="TransProxy", charset="UTF-8"')
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.end_headers()
        self.wfile.write("需要登录".encode("utf-8"))

    def send_json(self, obj, code=200):
        body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if not self.auth_ok():
            self.deny()
            return
        u = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(u.query)
        if u.path == "/" or u.path == "/index.html":
            body = DASHBOARD.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("X-Robots-Tag", "noindex, nofollow")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if u.path == "/api/data":
            self.send_json(self.build_data(qs))
            return
        if u.path == "/api/rates":
            self.send_json(build_rates(self.store))
            return
        if u.path == "/api/history":
            # 曲线用的历史序列。range 三档与 RATE_RANGES 对应。
            rng = (qs.get("range") or ["1h"])[0]
            spec = RATE_RANGES.get(rng)
            if spec is None:
                self.send_json({"error": "range 只支持 %s" % "、".join(RATE_RANGES)}, 400)
                return
            rates = getattr(self.store, "rates", None)
            if rates is None:
                self.send_json({"from": 0, "to": 0, "step": 0, "samples": 0, "users": {}})
                return
            self.send_json(rates.series(spec[0], spec[1]))
            return
        self.send_response(404)
        self.end_headers()

    # 账号管理。浏览器只跟 监控端 说话，管理员令牌不下发到浏览器。
    ADMIN_ROUTES = {
        "/api/user/create": "/api/v1/admin/user/create",
        "/api/user/update": "/api/v1/admin/user/update",
        "/api/user/delete": "/api/v1/admin/user/delete",
    }

    def do_POST(self):
        if not self.auth_ok():
            self.deny()
            return
        path = urllib.parse.urlparse(self.path).path
        if path == "/api/password":
            self.change_password()
            return
        target = self.ADMIN_ROUTES.get(path)
        if not target:
            self.send_response(404)
            self.end_headers()
            return

        payload, err = self.read_json(16384)
        if err:
            self.send_json({"error": err}, 400)
            return

        try:
            code, data = api_post(self.cfg, target, payload)
        except Exception as e:
            log("账号操作失败（%s）：%s: %s" % (path, type(e).__name__, e))
            self.send_json({"error": "无法连接节点：%s: %s" % (type(e).__name__, e)}, 502)
            return

        # 一律用 400 回给浏览器，而不是把节点的状态码原样透传：
        # 401 会带上浏览器的 Basic 认证弹窗语义，把「令牌不对」显示成「请重新登录面板」，
        # 反而看不出真正的原因。真正的原因在 body 的 error 里。
        self.send_json(data, 200 if 200 <= code < 300 else 400)
        if 200 <= code < 300:
            log("账号操作成功：%s %s" % (path, payload.get("name", "")))

    def read_json(self, limit):
        """读取并解析请求体，返回 (对象, 错误文案)。"""
        try:
            n = int(self.headers.get("Content-Length") or 0)
            if n > limit:
                return None, "请求体过大"
            obj = json.loads(self.rfile.read(n).decode("utf-8") or "{}")
            if not isinstance(obj, dict):
                return None, "请求体必须是对象"
            return obj, ""
        except Exception as e:
            return None, "请求格式错误：%s" % e

    def change_password(self):
        """修改面板登录口令。

        要求同时提供当前口令：请求本身虽然已经过了 Basic 认证，但浏览器会
        自动带上缓存的凭据，单凭这一点无法区分「本人操作」和「浏览器自动重放」。
        """
        payload, err = self.read_json(4096)
        if err:
            self.send_json({"error": err}, 400)
            return
        cur = str(payload.get("current") or "")
        nxt = str(payload.get("next") or "")
        if not password_ok(self.cfg, cur):
            log("修改面板口令失败：当前口令不正确（来自 %s）" % (self.client_address[0],))
            self.send_json({"error": "当前密码不正确"}, 400)
            return
        if len(nxt) < 8:
            self.send_json({"error": "新密码至少 8 位"}, 400)
            return
        if nxt == cur:
            self.send_json({"error": "新密码不能与当前密码相同"}, 400)
            return

        # 先落盘再改内存：写失败时内存与磁盘仍然一致，不会出现
        # 「这个进程认新口令、重启后又变回旧口令」这种诡异状态。
        old = self.cfg.get("password_hash")
        self.cfg["password_hash"] = hash_password(nxt)
        try:
            save_config(self.cfg)
        except Exception as e:
            self.cfg["password_hash"] = old
            self.send_json({"error": "写入配置失败：%s" % e}, 500)
            return
        # cfg 就是所有请求处理器共用的那个字典，改完立即生效，不需要重启服务。
        log("面板登录口令已修改（来自 %s）" % (self.client_address[0],))
        self.send_json({"ok": True, "message": "密码已修改，请用新密码重新登录"})

    def build_data(self, qs):
        def one(name, default=""):
            v = qs.get(name)
            return v[0] if v else default

        try:
            days = max(1, min(int(one("days", "1")), int(self.cfg["retain_days"])))
        except ValueError:
            days = 1
        user, q = one("user"), one("q")
        st = self.store
        # 只在读可变标量时加锁，扫文件的耗时操作放在锁外：
        # 拉取线程每 15 秒要写一次，把扫描压在锁里会让它白等。
        # 扫描期间文件可能被追加，读到半行也无所谓——解析失败的行会被跳过。
        with st.lock:
            overview = st.overview
            pull_error = st.pull_error
            last_sync = st.last_sync
            stored = st.stored
        events = st.scan(days, user, q, 3000)
        top, by_user, total = st.aggregate(days, user, q)
        return {
            "server": overview,
            "events": events,
            "hosts": [{"host": h, "count": c} for h, c in top[:50]],
            "byUser": by_user,
            "total": total,
            "days": days,
            "retainDays": self.cfg["retain_days"],
            "stored": stored,
            "pullError": pull_error,
            "lastSyncText": time.strftime("%H:%M:%S", time.localtime(last_sync))
            if last_sync else "尚未同步",
        }


def read_new_password():
    """读取新口令：终端交互时无回显输入，管道输入时读一行。

    不走命令行参数：监控端上进程的 argv 对同机所有用户可见，
    把口令写在命令行里等于公开它，而且会留在 shell 历史里。
    """
    if sys.stdin.isatty():
        return getpass.getpass("新密码：")
    return sys.stdin.readline().rstrip("\r\n")


def main():
    # 忘记口令时的补救通道：在监控端上直接改配置文件。
    # 走命令行改的话，正在服务的内存里仍是旧口令，必须重启才生效，所以提示写清楚。
    if len(sys.argv) >= 2 and sys.argv[1] == "--set-password":
        pw = read_new_password()
        if not pw:
            print("没有读到新密码。请交互输入，或用管道：")
            print("  echo '新密码' | python3 monitor.py --set-password")
            return
        cfg = load_config()
        cfg["password_hash"] = hash_password(pw)
        save_config(cfg)
        print("面板密码已重置。若服务正在运行，需要重启才会生效：")
        print("  sudo systemctl restart transproxy-monitor")
        return

    cfg = load_config()
    store = Store(int(cfg["retain_days"]))
    store.load()
    # 速率历史单独一份文件：它跟访问记录是两种数据，保留期也不同（一天 vs 两周）。
    store.rates = RatesStore()
    store.rates.load()

    threading.Thread(target=pull_loop, args=(cfg, store), daemon=True).start()

    Handler.cfg, Handler.store = cfg, store
    addr = (cfg["listen_host"], int(cfg["listen_port"]))
    srv = ThreadingHTTPServer(addr, Handler)
    srv.daemon_threads = True
    log("监控面板已启动：http://%s:%d/  数据源 %s" % (addr[0], addr[1], cfg["api_base"]))
    srv.serve_forever()


if __name__ == "__main__":
    main()
