// transrelay 跑在「落地节点」（分支节点A）上，是那台机器上唯一需要我们自己的进程。
//
// 它循环做四件事：
//  1. 向出口节点上报自己（入口地址/端口/伪装域名/公钥/shortId），供出口下发给客户端；
//  2. 拉取「被授权使用本节点」的账号 UUID 与密码哈希；
//  3. 账号集合变了才重渲染通道A 的内核配置并重载内核；
//  4. 把本机的每用户流量与访问记录报回出口汇总。
//
// 若本节点还提供通道B（hysteria），它另外负责两件事：渲染 hysteria 的配置，
// 以及在 127.0.0.1 上提供 hysteria 的认证回调（见 hysteriaauth.go）。
//
// 刻意不做的事：
//   - 不存账号库（名单只在内存里留一份，用于渲染与认证）；
//   - 数据面不碰出口节点 —— 本机自己出网，连回出口节点的只有控制面；
//   - 不自建控制面、不对外开放任何端口（内核管理接口与认证回调都只听 127.0.0.1）。
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"transproxy/internal/ctl"
)

const (
	// syncInterval 是账号同步周期。
	//
	// 它同时决定了「撤销授权后多久真正生效」：出口节点把被撤销的账号从列表里去掉，
	// 这里下一轮才会把它从内核配置里摘掉并重载。半分钟是自己用规模下的合适取舍 ——
	// 再短只是徒增无谓的重载，再长则撤权不够及时。
	syncInterval = 30 * time.Second
	// httpTimeout 要能覆盖出口节点渲染配置的时间，又要短到卡住的请求能尽快重试。
	httpTimeout = 20 * time.Second

	// 单次上报最多带多少条访问记录、以及最多读多少字节。
	// 出口不在本机，这些数字只能自己报了，但报的时候要有上限。
	maxAccessLines = 1500
	maxAccessBytes = 512 << 10
)

func main() {
	cfgPath := flag.String("config", "/usr/local/etc/transrelay/relay.json", "中转节点配置文件")
	once := flag.Bool("once", false, "只同步一轮就退出（部署时用来校验配置）")
	flag.Parse()

	logf := func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, time.Now().Format("2006-01-02 15:04:05 ")+format+"\n", args...)
	}

	rs, err := ctl.LoadRelaySettings(*cfgPath)
	if err != nil {
		logf("读取配置失败: %v", err)
		os.Exit(1)
	}
	id, err := ctl.LoadOrCreateRelayIdentity(rs.IdentityPath)
	if err != nil {
		logf("加载本机身份失败: %v", err)
		os.Exit(1)
	}
	pub, err := id.PublicKey()
	if err != nil {
		logf("推导本机公钥失败: %v", err)
		os.Exit(1)
	}

	// 通道B 的认证回调只监听回环。配成对外地址是**启动即拒绝**而不是打个警告就跑：
	// 那种配置下通道B 一切正常，但机器上多了一个对公网的口令校验接口，
	// 而运行日志里没有任何迹象提示运维。
	if rs.HysteriaEnabled() {
		if err := checkLoopbackListen(rs.HysteriaAuthListen); err != nil {
			logf("配置有误: %v", err)
			os.Exit(1)
		}
	}

	// 内核以 nobody 运行，不会自己创建访问日志文件。少了这一步的现象是内核启动即失败：
	//   Failed to start: ... open /var/log/xray/access.log: permission denied
	// 而这台是远端机器，报错只在 journalctl 里，很容易被当成「配置写错了」查很久。
	if err := ensureAccessLog(rs.AccessLog); err != nil {
		logf("准备访问日志失败（内核可能起不来）: %v", err)
	}

	a := &agent{
		rs: rs, id: id, pub: pub, logf: logf, hy: newHysteriaAuth(logf),
		// 用默认 Transport，也就是**正常校验证书**。
		// 这条连接带着节点口令，是这个节点唯一的对外通道；为了省一张证书的麻烦
		// 去关校验，等于把节点身份交给同网段的任何人。
		hc: &http.Client{Timeout: httpTimeout},
	}

	if *once {
		if err := a.syncOnce(); err != nil {
			logf("同步失败: %v", err)
			os.Exit(1)
		}
		logf("同步完成")
		return
	}

	logf("落地节点 %s 启动：出口 %s，本机监听 %d，上报地址 %s",
		rs.NodeID, rs.ControlURL, rs.ListenPort, rs.Advertise)
	a.run()
}

type agent struct {
	rs   ctl.RelaySettings
	id   ctl.RelayIdentity
	pub  string
	hc   *http.Client
	logf func(string, ...any)

	// hy 是通道B 的认证回调服务（本节点不提供通道B 时它就是个空壳，不会被启动）。
	hy *hysteriaAuth
	// haveHashes / authStarted / hysteriaOK 由 run() 与 syncOnce() 串行读写，
	// 都是「单 goroutine」状态，不需要加锁。
	haveHashes  bool
	authStarted bool
	hysteriaOK  bool
	revision    string
	haveRev     bool
	// stat 记住上一轮的计数与日志偏移，用来算增量（见 stats.go）。
	stat statsState
}

func (a *agent) run() {
	for {
		if err := a.syncOnce(); err != nil {
			a.logf("同步失败（%v），%s 后重试", err, syncInterval)
		}
		a.startAuthOnce()
		time.Sleep(syncInterval)
	}
}

// startAuthOnce 在**拿到第一份名单之后**才起认证监听，且只起一次。
//
// 为什么不一开始就起：名单是空的时侯每个连接都会被判为「密码错误」，
// 而那些失败会记进限速表 —— 十来次之后真实账号也会被封锁 10 分钟。
// 宁可让 hysteria 那边先连不上认证服务（它自己会重试），也不要制造这种自伤。
func (a *agent) startAuthOnce() {
	if !a.rs.HysteriaEnabled() || a.authStarted || !a.haveHashes {
		return
	}
	a.authStarted = true
	go func() {
		a.logf("通道B 认证回调监听 %s", a.rs.HysteriaAuthListen)
		if err := a.hy.serve(a.rs.HysteriaAuthListen); err != nil {
			a.logf("通道B 认证回调退出: %v（通道A 与上报不受影响）", err)
		}
	}()
}

func (a *agent) syncOnce() error {
	if err := a.register(); err != nil {
		return fmt.Errorf("上报自身失败: %w", err)
	}
	rev, users, err := a.fetchUsers()
	if err != nil {
		return fmt.Errorf("拉取账号失败: %w", err)
	}
	// 上报与「账号集合有没有变」无关：每一轮都要报，面板的速率靠这个节奏。
	a.report()
	// 通道B 的凭据只在真的提供通道B 时才领：用不上就不该拿。
	if a.rs.HysteriaEnabled() {
		if hs, err := a.fetchHashes(); err != nil {
			// 沿用上一份名单（对应「撤销授权晚生效一轮」），而不是清空。
			a.logf("拉取通道B 凭据失败（沿用上一份名单）: %v", err)
		} else {
			a.hy.setUsers(hs)
			a.haveHashes = true
		}
	}
	// hysteria 的配置与账号集合无关（凭据在内存里），所以单独一个「写成了没有」的标记：
	// 失败下一轮重试，而不是被下面的 revision 早退挡住。
	if a.rs.HysteriaEnabled() && !a.hysteriaOK {
		if err := a.applyHysteriaConfig(); err != nil {
			a.logf("刷新 hysteria 配置失败（通道A 不受影响，下一轮重试）: %v", err)
		} else {
			a.hysteriaOK = true
		}
	}
	// 账号集合没变就什么都不做。这里是「不要白踢在线用户」的落点：
	// 每轮都无脑重载的话，走这条线路的人每半分钟断一次。
	if a.haveRev && rev == a.revision {
		return nil
	}
	cfg, err := ctl.RenderRelayConfig(a.rs, a.id, users)
	if err != nil {
		return fmt.Errorf("渲染内核配置失败: %w", err)
	}
	if err := a.applyConfig(cfg); err != nil {
		return err
	}
	// 先记下 revision 再干别的：否则后面任何一步出错，都会让下一轮再重载一次内核，
	// 反复踢掉正在用这条线路的人。
	a.revision, a.haveRev = rev, true
	a.logf("已按最新账号集合（%d 个）重载内核", len(users))
	return nil
}

// register 把本机的入口参数报给出口节点。
//
// 每轮都报：出口那边用「最后上报时间」判断这个节点还活着，也让入口地址变更能被自动纠正。
//
// 出口不会回任何参数过来 —— 本机自己出网，不需要出口的任何东西。
func (a *agent) register() error {
	body, err := json.Marshal(map[string]any{
		"id": a.rs.NodeID, "token": a.rs.Token,
		"address": a.rs.Advertise, "port": a.rs.ListenPort, "sni": a.rs.DecoySNI,
		"publicKey": a.pub, "shortId": a.id.ShortID,
		"fingerprint": a.rs.Fingerprint, "flow": a.rs.Flow,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, a.rs.ControlURL+"/api/v1/node/register", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	var out struct{}
	return a.do(req, &out)
}

func (a *agent) fetchUsers() (string, []ctl.RelayUser, error) {
	req, err := http.NewRequest(http.MethodGet, a.rs.ControlURL+"/api/v1/node/users", nil)
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("X-Node-Id", a.rs.NodeID)
	req.Header.Set("X-Node-Token", a.rs.Token)

	var out struct {
		Revision string          `json:"revision"`
		Users    []ctl.RelayUser `json:"users"`
	}
	if err := a.do(req, &out); err != nil {
		return "", nil, err
	}
	return out.Revision, out.Users, nil
}

// fetchHashes 领「被授权使用本节点」的账号的 bcrypt 哈希，用于在本机校验通道B。
//
// 这些哈希只进 a.hy 的内存，不落盘、不写日志。为什么要领、代价是什么，
// 见 ctl.handleNodeHashes 的说明。
func (a *agent) fetchHashes() ([]ctl.NodeHash, error) {
	req, err := http.NewRequest(http.MethodGet, a.rs.ControlURL+"/api/v1/node/hashes", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Node-Id", a.rs.NodeID)
	req.Header.Set("X-Node-Token", a.rs.Token)

	var out struct {
		Users []ctl.NodeHash `json:"users"`
	}
	if err := a.do(req, &out); err != nil {
		return nil, err
	}
	return out.Users, nil
}

func (a *agent) do(req *http.Request, out any) error {
	resp, err := a.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// 限长读取：接口在公网上，对面万一返回一个超大响应不该把本机内存拖垮。
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, short(b))
	}
	return json.Unmarshal(b, out)
}

// applyConfig 写配置并重载内核。
//
// 顺序刻意是「写临时文件 → 内核自校验 → 原子改名 → 重载」：这是台远端机器，
// 一份写坏的配置就等于要人工 SSH 上去救，而校验的代价只有几十毫秒。
func (a *agent) applyConfig(cfg []byte) error {
	if err := os.MkdirAll(filepath.Dir(a.rs.ConfigPath), 0o700); err != nil {
		return err
	}
	// 临时文件名必须保留 .json 扩展名，理由见 ctl.CfgTempPath（内核按扩展名判断格式）。
	tmp := ctl.CfgTempPath(a.rs.ConfigPath)
	if err := os.WriteFile(tmp, cfg, 0o640); err != nil {
		return err
	}
	// 内核以 nobody 运行：配置里有全部账号的 UUID（等价于连接凭据）与本机私钥，
	// 不能给其他本地用户读到；但 0600 又会让 nobody 读不到自己的配置起不来。
	// 折中是 root:<nobody 的组> + 0640，与出口节点同一套做法。
	if gid := ctl.XrayRunGID(); gid >= 0 {
		_ = os.Chown(tmp, 0, gid)
		_ = os.Chmod(tmp, 0o640)
	}

	if _, err := os.Stat(a.rs.XrayBin); err == nil {
		out, err := exec.Command(a.rs.XrayBin, "run", "-test", "-config", tmp).CombinedOutput()
		if err != nil {
			_ = os.Remove(tmp)
			return fmt.Errorf("内核拒绝这份配置，线上原配置未动: %v (%s)", err, strings.TrimSpace(string(out)))
		}
	} else {
		// 找不到内核只能跳过校验。这里的取舍是：宁可冒一次「写坏配置」的风险，
		// 也不要因为路径配错就让节点永远不更新账号（那等于永久冻结在旧名单上）。
		a.logf("警告：找不到 %s，跳过配置校验", a.rs.XrayBin)
	}
	// 上面那一步是**以 root 跑的**，而它会顺手把访问日志创建成 root:root；
	// 真正以 nobody 启动的内核随后就打不开它。所以校验完立刻把属主纠正回来。
	if err := ensureAccessLog(a.rs.AccessLog); err != nil {
		a.logf("纠正访问日志属主失败（内核可能起不来）: %v", err)
	}

	if old, err := os.ReadFile(a.rs.ConfigPath); err == nil {
		_ = os.WriteFile(a.rs.ConfigPath+".bak", old, 0o640)
	}
	// rename 才是原子的：直接往目标文件写，中途出错会留下半截配置。
	if err := os.Rename(tmp, a.rs.ConfigPath); err != nil {
		return err
	}

	if out, err := exec.Command("systemctl", "restart", a.rs.XrayUnit).CombinedOutput(); err != nil {
		return fmt.Errorf("重载内核失败: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ensureAccessLog 保证内核能写自己的访问日志 —— 目录与文件都要管，两处真会出问题：
//
//   - **目录**必须是 root:<内核用户的组> + 0770。内核以 nobody 运行，它不预建也不轮转
//     日志文件；0750 没有组写权限，nobody 连文件都建不出来。
//   - **文件**如果存在，属主也必须是内核用户。因为创建它的常常是「以 root 跑的
//     `xray run -test`」（配置自校验那一步），留下一个 root:root 的文件，
//     真正以 nobody 启动的内核随后就打不开它。症状是
//     open /var/log/xray/access.log: permission denied —— 而看日志的人只会
//     怀疑权限配置，不会想到是前一步的自校验把文件占了。
//
// 权限只放开到内核用户那一组（nogroup，这组里通常只有 nobody），
// 其他本地用户看不到访问记录。
func ensureAccessLog(path string) error {
	if path == "" {
		return nil
	}
	gid := ctl.XrayRunGID()
	if gid < 0 {
		return fmt.Errorf("找不到内核运行用户（nobody），无法给 %s 设置可写权限", path)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	if err := os.Chown(dir, 0, gid); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o770); err != nil {
		return err
	}
	// O_CREATE 只在文件不存在时起作用；已存在的话不改属主，所以下面还要显式 Chown。
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	f.Close()
	uid := ctl.XrayRunUID()
	if uid < 0 {
		return fmt.Errorf("找不到内核运行用户（nobody）的 UID，%s 的属主可能不对", path)
	}
	return os.Chown(path, uid, gid)
}

// applyHysteriaConfig 写 hysteria 配置，并在内容变化时重启它。
//
// 「内容没变就什么都不做」不是优化，是必须的：hysteria 只在启动时读一次配置，
// 无脑重启会把正在用通道B 的人每半分钟踢下线一次。而账号集合变化**不需要**重启 ——
// 凭据在 transrelay 的内存里，与这份配置文件无关（这也是选 HTTP 回调而非 userpass 的理由）。
//
// 0600：文件里有混淆口令与统计密钥。hysteria 以 root 运行，能读到。
func (a *agent) applyHysteriaConfig() error {
	want, err := ctl.RenderHysteriaConfig(a.rs)
	if err != nil {
		return err
	}
	if cur, err := os.ReadFile(a.rs.HysteriaConfigPath); err == nil && bytes.Equal(cur, want) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(a.rs.HysteriaConfigPath), 0o700); err != nil {
		return err
	}
	// 同样保留 .yaml 扩展名：hysteria 也按扩展名区分 yaml/json。
	tmp := ctl.CfgTempPath(a.rs.HysteriaConfigPath)
	if err := os.WriteFile(tmp, want, 0o600); err != nil {
		return err
	}
	if old, err := os.ReadFile(a.rs.HysteriaConfigPath); err == nil {
		_ = os.WriteFile(a.rs.HysteriaConfigPath+".bak", old, 0o600)
	}
	// rename 才是原子的：直接往目标文件写，中途出错会留下半截配置。
	if err := os.Rename(tmp, a.rs.HysteriaConfigPath); err != nil {
		return err
	}
	if out, err := exec.Command("systemctl", "restart", a.rs.HysteriaUnit).CombinedOutput(); err != nil {
		return fmt.Errorf("重启 %s 失败: %v (%s)", a.rs.HysteriaUnit, err, strings.TrimSpace(string(out)))
	}
	a.logf("已写入 hysteria 配置并重启 %s", a.rs.HysteriaUnit)
	return nil
}

func short(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return s
}
