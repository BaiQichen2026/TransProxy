package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"transproxy/internal/ctl"
)

const defaultDataDir = "/usr/local/etc/transctl"

// 迁移用的账号清单文件名（放在数据目录下）。
//
// 早期版本把 5 个账号的 UUID 直接写在这个源码文件里，那是错的：UUID 就是连接凭据，
// 写进源码等于随代码一起泄露——任何拿到代码的人都能免密白用这些账号。
// 现在改成从数据目录下的 JSON 文件读取，迁移完就把文件删掉。
const legacyUsersFile = "legacy-users.json"

// legacyUser 是迁移清单里的一条。
type legacyUser struct {
	Name string `json:"name"`
	// UUID 留空表示新生成一个。只有确实需要保留旧身份（已发出去的客户端配置
	// 还在用）时才填。
	UUID string `json:"uuid"`
}

// loadLegacyUsers 读取迁移清单。文件不存在是预期情况（迁移早已完成）。
func loadLegacyUsers(path string) ([]legacyUser, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取迁移清单 %s 失败: %w。该文件只在对旧部署做一次性迁移时才需要，"+
			"格式是 [{\"name\":\"user1\",\"uuid\":\"...\"}]，uuid 留空则新生成", path, err)
	}
	var out []legacyUser
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("迁移清单不是合法 JSON: %w", err)
	}
	return out, nil
}

func logf(format string, args ...any) {
	fmt.Printf("%s  %s\n", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprintf(format, args...))
}

// readSecretLine 从标准输入读一行作为密码。
//
// 密码不走命令行参数：服务端是多用户 Linux，进程的 argv 对同机所有用户可见
// （一个 ps 就能看到），把密码放进去等于把它写在公告板上。
// 用管道喂给标准输入则不会出现在任何进程表里。
func readSecretLine() (string, error) {
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && err != io.EOF {
		return "", fmt.Errorf("读取标准输入失败: %w", err)
	}
	s := strings.TrimRight(line, "\r\n")
	if s == "" {
		return "", fmt.Errorf("没有从标准输入读到密码")
	}
	return s, nil
}

func usage() {
	fmt.Print(`transctl —— 节点控制面

  serve    [-data 目录] [-listen :8443] [-cert 证书链] [-key 私钥]
           启动 HTTPS 控制服务（登录/流量/改密/监控接口），并采集流量与访问记录
  useradd  <账号> [备注]            初始密码从标准输入读取
  userdel  <账号>
  passwd   <账号>                   新密码从标准输入读取；会同时更换该账号的 UUID，使旧参数立即失效
  quota    <账号> <字节数>          0 表示不限量
  enable   <账号>  /  disable <账号>
  list                              列出账号与用量
  sync                              按账号库重渲染内核配置并重启内核
  seed     [-password-stdin]        把历史裸 UUID 用户迁移为账号
  admintoken [-data 目录]           打印监控接口用的管理员令牌（不存在则生成）

默认数据目录：` + defaultDataDir + `
`)
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	cmd, args := os.Args[1], os.Args[2:]

	var err error
	switch cmd {
	case "serve":
		err = cmdServe(args)
	case "useradd":
		err = cmdUserAdd(args)
	case "userdel":
		err = cmdUserDel(args)
	case "passwd":
		err = cmdPasswd(args)
	case "quota":
		err = cmdQuota(args)
	case "enable":
		err = cmdEnable(args, true)
	case "disable":
		err = cmdEnable(args, false)
	case "list":
		err = cmdList(args)
	case "sync":
		err = cmdSync(args)
	case "seed":
		err = cmdSeed(args)
	case "rotateuuid":
		err = cmdRotateUUID(args)
	case "showparams":
		err = cmdShowParams()
	case "admintoken":
		err = cmdAdminToken(args)
	case "help", "-h", "--help":
		usage()
		return
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误："+err.Error())
		os.Exit(1)
	}
}

func load(dataDir string) (*ctl.Store, ctl.ServerSettings, *ctl.Service, error) {
	st, err := ctl.LoadStore(filepath.Join(dataDir, "users.json"))
	if err != nil {
		return nil, ctl.ServerSettings{}, nil, err
	}
	s, err := ctl.LoadServerSettings(filepath.Join(dataDir, "server.json"))
	if err != nil {
		return nil, ctl.ServerSettings{}, nil, err
	}
	return st, s, ctl.NewService(st, s, logf), nil
}

// ---------- serve ----------

func cmdServe(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	dataDir := fs.String("data", defaultDataDir, "数据目录")
	listen := fs.String("listen", ":8443", "HTTPS 监听地址")
	certPath := fs.String("cert", "", "证书链 PEM（默认 <data>/cert/fullchain.pem）")
	keyPath := fs.String("key", "", "私钥 PEM（默认 <data>/cert/privkey.pem）")
	_ = fs.Parse(args)

	cert, key := *certPath, *keyPath
	if cert == "" {
		cert = filepath.Join(*dataDir, "cert", "fullchain.pem")
	}
	if key == "" {
		key = filepath.Join(*dataDir, "cert", "privkey.pem")
	}
	for _, p := range []string{cert, key} {
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("证书文件不可用 %s: %w", p, err)
		}
	}

	_, s, svc, err := load(*dataDir)
	if err != nil {
		return err
	}

	changed, err := ensureXrayConfig(svc)
	if err != nil {
		return err
	}
	// 只比对配置文件是不够的：运行时增删用户失败会让「文件」与「运行中的内核」静默分叉，
	// 表现为账号存在却连不上。这里再核对一次内核里真正生效的用户数，分叉就重启校正。
	want := 0
	for _, u := range svc.Store.List() {
		if u.Enabled {
			want++
		}
	}
	got, apiErr := ctl.UserCount(svc.Settings.APIPort, ctl.InboundTag, 5*time.Second)
	drift := apiErr != nil || got != want

	switch {
	case changed:
		logf("内核配置与账号库不一致，已按账号库重写")
	case drift:
		logf("内核与账号库分叉（期望 %d 个用户，内核实际 %v），重启内核校正", want, got)
	default:
		logf("内核与账号库一致（%d 个用户），无需重启", want)
	}
	if changed || drift {
		if err := restartXray(); err != nil {
			return err
		}
	}

	stop := make(chan struct{})
	svc.StartPoller(stop)

	// 访问记录采集。放在控制面里而不是独立的服务：
	// 它只需要读一个本地文件，独立进程带来的部署与排障成本远大于收益。
	token, err := ctl.LoadAdminToken(*dataDir)
	if err != nil {
		return fmt.Errorf("管理员令牌不可用: %w", err)
	}
	svc.AdminToken = token
	svc.Mon = ctl.NewMonitor(filepath.Join(*dataDir, "access"), ctl.XrayAccessLog, logf)
	// 通道B 的访问不经过内核，得去 hysteria 的统计接口取。
	// 未部署双通道时这两个值为空，采集器会自动只跑通道A。
	svc.Mon.SetHysteria(s.HysteriaStatsListen, s.HysteriaStatsSecret)
	go svc.Mon.Run(stop)

	srv := &http.Server{
		Addr:              *listen,
		Handler:           svc.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		// 只有 ReadHeaderTimeout 是不够的：正文读取、响应写入与空闲连接都还没有上限，
		// 慢速发完请求头再一点一点发正文就能长期占住连接与 goroutine。
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	logf("控制服务已启动 %s（域名 %s，伪装 SNI %s，%d 个账号）",
		*listen, s.Domain, s.SNI, len(svc.Store.List()))
	return srv.ListenAndServeTLS(cert, key)
}

// cmdAdminToken 打印监控接口用的管理员令牌，必要时生成。
//
// 单独做成命令而不是在启动时打到日志里：日志会进 journald，
// 令牌不该出现在任何会自动留存的地方。
func cmdAdminToken(args []string) error {
	fs := flag.NewFlagSet("admintoken", flag.ExitOnError)
	dataDir := fs.String("data", defaultDataDir, "数据目录")
	_ = fs.Parse(args)

	t, err := ctl.LoadAdminToken(*dataDir)
	if err != nil {
		return err
	}
	fmt.Println(t)
	return nil
}

// ensureXrayConfig 让内核配置文件与账号库一致，返回是否发生了改动。
func ensureXrayConfig(svc *ctl.Service) (bool, error) {
	want, err := ctl.RenderXrayConfig(svc.Settings, svc.Store.List())
	if err != nil {
		return false, err
	}
	if cur, err := os.ReadFile(ctl.XrayCfgPath); err == nil &&
		bytes.Equal(bytes.TrimSpace(cur), bytes.TrimSpace(want)) {
		return false, nil
	}
	// 后缀必须加在扩展名之前，理由见 ctl.CfgTempPath。
	tmp := ctl.CfgTempPath(ctl.XrayCfgPath)
	// 0644：内核以 nobody 身份运行，权限过紧会读不到配置。
	if err := os.WriteFile(tmp, want, 0o644); err != nil {
		return false, err
	}
	if err := os.Rename(tmp, ctl.XrayCfgPath); err != nil {
		return false, err
	}
	return true, nil
}

func restartXray() error {
	out, err := exec.Command("systemctl", "restart", "xray").CombinedOutput()
	if err != nil {
		return fmt.Errorf("重启内核失败: %v (%s)", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// ---------- 账号管理 ----------

func cmdUserAdd(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("用法: transctl useradd <账号> [备注]（初始密码从标准输入读取）")
	}
	note := ""
	if len(args) > 1 {
		note = args[1]
	}
	pw, err := readSecretLine()
	if err != nil {
		return err
	}
	_, _, svc, err := load(defaultDataDir)
	if err != nil {
		return err
	}
	u, err := svc.Store.Add(args[0], pw, note, 0)
	if err != nil {
		return err
	}
	if err := svc.ApplyUser(u); err != nil {
		return fmt.Errorf("账号已创建，但同步内核失败: %w", err)
	}
	logf("已添加账号 %s，并已在内核中即时生效（无需重启）", u.Name)
	return nil
}

func cmdUserDel(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("用法: transctl userdel <账号>")
	}
	_, _, svc, err := load(defaultDataDir)
	if err != nil {
		return err
	}
	if err := svc.Store.Remove(args[0]); err != nil {
		return err
	}
	if err := svc.DropUser(args[0]); err != nil {
		return err
	}
	logf("已删除账号 %s，并已在内核中即时失效", args[0])
	return nil
}

func cmdPasswd(args []string) error {
	if len(args) < 1 {
		return fmt.Errorf("用法: transctl passwd <账号>（新密码从标准输入读取）")
	}
	pw, err := readSecretLine()
	if err != nil {
		return err
	}
	_, _, svc, err := load(defaultDataDir)
	if err != nil {
		return err
	}
	if err := svc.Store.SetPassword(args[0], pw); err != nil {
		return err
	}
	if u, ok := svc.Store.Snapshot(args[0]); ok {
		if err := svc.ApplyUser(&u); err != nil {
			return err
		}
	}
	logf("已重置账号 %s 的密码并更换其 UUID，旧连接参数立即失效", args[0])
	return nil
}

func cmdQuota(args []string) error {
	if len(args) < 2 {
		return fmt.Errorf("用法: transctl quota <账号> <字节数>（0 表示不限量）")
	}
	n, err := parseBytes(args[1])
	if err != nil {
		return err
	}
	_, _, svc, err := load(defaultDataDir)
	if err != nil {
		return err
	}
	found := false
	if err := svc.Store.Update(func(u *ctl.User) bool {
		if u.Name != args[0] {
			return false
		}
		u.QuotaBytes = n
		found = true
		return true
	}); err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("账号 %s 不存在", args[0])
	}
	logf("账号 %s 的配额已设为 %s", args[0], humanBytes(n))
	return nil
}

func cmdEnable(args []string, on bool) error {
	if len(args) < 1 {
		return fmt.Errorf("用法: transctl enable|disable <账号>")
	}
	_, _, svc, err := load(defaultDataDir)
	if err != nil {
		return err
	}
	found := false
	if err := svc.Store.Update(func(u *ctl.User) bool {
		if u.Name != args[0] {
			return false
		}
		u.Enabled = on
		found = true
		return true
	}); err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("账号 %s 不存在", args[0])
	}
	if on {
		if u, ok := svc.Store.Snapshot(args[0]); ok {
			if err := svc.ApplyUser(&u); err != nil {
				return err
			}
		}
	} else if err := svc.DropUser(args[0]); err != nil {
		return err
	}
	logf("账号 %s 已%s", args[0], map[bool]string{true: "启用", false: "停用"}[on])
	return nil
}

func cmdList(args []string) error {
	fs := flag.NewFlagSet("list", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "以 JSON 输出，供管理面板解析")
	_ = fs.Parse(args)

	st, _, _, err := load(defaultDataDir)
	if err != nil {
		return err
	}
	users := st.List()
	sort.Slice(users, func(i, j int) bool { return users[i].Name < users[j].Name })

	type listRow struct {
		Name       string `json:"name"`
		UUID       string `json:"uuid"`
		Enabled    bool   `json:"enabled"`
		UsedBytes  int64  `json:"usedBytes"`
		QuotaBytes int64  `json:"quotaBytes"`
		Note       string `json:"note"`
		// LastActive 取代了此前不可用的「在线数」，原因见 ctl.User.LastActive 的说明。
		LastActive int64 `json:"lastActive"`
	}
	rows := make([]listRow, 0, len(users))
	for _, u := range users {
		rows = append(rows, listRow{
			u.Name, u.UUID, u.Enabled, u.UsedBytes, u.QuotaBytes, u.Note, u.LastActive.Unix(),
		})
	}

	// 管理面板走 JSON：终端里的空格对齐表格在中文环境下天然对不齐
	// （中文是双宽字符，而 %-14s 只按字符个数补空格），不适合拿来解析。
	if *asJSON {
		b, err := json.MarshalIndent(rows, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(b))
		return nil
	}

	fmt.Printf("%-12s %-6s %-12s %-12s %-12s %s\n", "账号", "状态", "累计用量", "配额", "最近活动", "UUID")
	for _, r := range rows {
		status := "启用"
		if !r.Enabled {
			status = "停用"
		}
		fmt.Printf("%-12s %-6s %-12s %-12s %-12s %s\n",
			r.Name, status, humanBytes(r.UsedBytes), humanBytes(r.QuotaBytes),
			ctl.SinceText(r.LastActive), r.UUID)
	}
	fmt.Printf("共 %d 个账号\n", len(rows))
	return nil
}

// cmdShowParams 打印客户端连接参数（JSON），供管理工具在本机读取。
//
// 以前这些参数由公开的 /api/v1/health 下发，等于把节点身份暴露给任何扫描者：
// 知道 publicKey + shortId 的人可以确认「这台机器就是这个 REALITY 节点」。
// 现在只保留一条需要服务器权限才能走的路径。
func cmdShowParams() error {
	_, s, _, err := load(defaultDataDir)
	if err != nil {
		return err
	}
	p, err := s.ClientParams()
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(map[string]any{
		"domain": p.Address, "port": p.Port, "sni": p.SNI,
		"publicKey": p.PublicKey, "shortId": p.ShortID,
		"hysteriaEnabled": s.HysteriaEnabled, "hysteriaPort": s.HysteriaPort,
	}, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(b))
	return nil
}

func cmdSync(args []string) error {
	_, _, svc, err := load(defaultDataDir)
	if err != nil {
		return err
	}
	changed, err := ensureXrayConfig(svc)
	if err != nil {
		return err
	}
	if !changed {
		logf("配置已是最新，无需重启")
		return nil
	}
	if err := restartXray(); err != nil {
		return err
	}
	logf("已重写内核配置并重启内核")
	return nil
}

func cmdSeed(args []string) error {
	fs := flag.NewFlagSet("seed", flag.ExitOnError)
	passwordStdin := fs.Bool("password-stdin", false,
		"从标准输入读取一个初始密码，供本次迁移的所有账号统一使用；不加则为每个账号生成随机密码")
	listPath := fs.String("users", filepath.Join(defaultDataDir, legacyUsersFile),
		"迁移清单文件；格式为 [{\"name\":\"...\",\"uuid\":\"...\"}]")
	_ = fs.Parse(args)

	fixed := ""
	if *passwordStdin {
		pw, err := readSecretLine()
		if err != nil {
			return err
		}
		fixed = pw
	}

	_, _, svc, err := load(defaultDataDir)
	if err != nil {
		return err
	}
	legacy, err := loadLegacyUsers(*listPath)
	if err != nil {
		return err
	}
	type created struct{ name, password string }
	var out []created
	for _, l := range legacy {
		if l.Name == "" {
			continue
		}
		if _, ok := svc.Store.Snapshot(l.Name); ok {
			logf("跳过已存在的账号 %s", l.Name)
			continue
		}
		pw := fixed
		if pw == "" {
			pw = randomPassword(12)
		}
		// UUID 留空就新生成：只在「旧客户端配置还在用这个身份」时才需要保留原值。
		if _, err := svc.Store.Import(l.Name, pw, l.UUID, "历史用户迁移", 0); err != nil {
			return err
		}
		out = append(out, created{l.Name, pw})
	}
	if len(out) == 0 {
		logf("没有需要迁移的账号")
		return nil
	}
	logf("已迁移 %d 个账号，初始密码如下（请尽快通知本人自行修改）：", len(out))
	for _, c := range out {
		fmt.Printf("    %-10s %s\n", c.name, c.password)
	}
	return syncAfterSeed(svc)
}

// cmdRotateUUID 轮换账号的连接身份（UUID），密码不变。
//
// 用途：连接身份一旦泄露（例如被写进了源码、聊天记录、截图），
// 只改密码是没用的——UUID 才是内核认的凭据。这里把它整条换掉，
// 并立刻同步进运行中的内核，让旧身份当场失效。
//
// 影响：这些账号的客户端需要重新登录以获取新参数（我们的客户端登录时会自动取），
// 而任何手工分发的、写死旧 UUID 的配置会失效。
func cmdRotateUUID(args []string) error {
	fs := flag.NewFlagSet("rotateuuid", flag.ExitOnError)
	all := fs.Bool("all", false, "轮换全部账号")
	_ = fs.Parse(args)
	if !*all && len(args) == 0 {
		return fmt.Errorf("用法: transctl rotateuuid <账号>... 或 transctl rotateuuid -all")
	}

	_, _, svc, err := load(defaultDataDir)
	if err != nil {
		return err
	}
	want := map[string]bool{}
	for _, a := range args {
		want[a] = true
	}
	var rotated []string
	if err := svc.Store.Update(func(u *ctl.User) bool {
		if !*all && !want[u.Name] {
			return false
		}
		u.UUID = ctl.NewUUID()
		rotated = append(rotated, u.Name)
		return true
	}); err != nil {
		return err
	}
	if len(rotated) == 0 {
		return fmt.Errorf("没有匹配的账号")
	}
	sort.Strings(rotated)

	// 逐个同步进运行中的内核。只写文件不动内核的话，
	// 旧身份在本次内核运行期内仍然可用——那就完全没起到轮换的作用。
	for _, name := range rotated {
		u, ok := svc.Store.Snapshot(name)
		if !ok || !u.Enabled {
			continue
		}
		if err := svc.ApplyUser(&u); err != nil {
			return fmt.Errorf("账号 %s 的身份已轮换但同步内核失败: %w", name, err)
		}
	}
	if _, err := ensureXrayConfig(svc); err != nil {
		return err
	}
	logf("已轮换 %d 个账号的连接身份: %s", len(rotated), strings.Join(rotated, " "))
	logf("旧连接参数已立即失效；这些账号需重新登录以获取新参数。")
	return nil
}

func syncAfterSeed(svc *ctl.Service) error {
	changed, err := ensureXrayConfig(svc)
	if err != nil {
		return err
	}
	if changed {
		return restartXray()
	}
	return nil
}

// ---------- 小工具 ----------

func humanBytes(n int64) string {
	if n <= 0 {
		return "不限"
	}
	units := []string{"B", "KB", "MB", "GB", "TB", "PB"}
	f := float64(n)
	i := 0
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	return fmt.Sprintf("%.2f %s", f, units[i])
}

// parseBytes 支持 1024 / 10MB / 5GB 这类写法。
func parseBytes(s string) (int64, error) {
	t := strings.TrimSpace(strings.ToUpper(s))
	mult := int64(1)
	for _, u := range []struct {
		suf string
		m   int64
	}{{"PB", 1 << 50}, {"TB", 1 << 40}, {"GB", 1 << 30}, {"MB", 1 << 20}, {"KB", 1 << 10}, {"B", 1}} {
		if strings.HasSuffix(t, u.suf) {
			mult = u.m
			t = strings.TrimSpace(strings.TrimSuffix(t, u.suf))
			break
		}
	}
	var f float64
	if _, err := fmt.Sscanf(t, "%f", &f); err != nil {
		return 0, fmt.Errorf("无法解析容量 %q", s)
	}
	if f < 0 {
		return 0, fmt.Errorf("容量不能为负")
	}
	return int64(f * float64(mult)), nil
}

func randomPassword(n int) string {
	const chars = "abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	out := make([]byte, n)
	for i := range out {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(chars))))
		if err != nil {
			out[i] = chars[0]
			continue
		}
		out[i] = chars[idx.Int64()]
	}
	return string(out)
}
