package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/lxn/walk"
	declarative "github.com/lxn/walk/declarative"
	"github.com/skip2/go-qrcode"

	"transproxy/internal/common"
)

// 服务端命令入口。账号的一切变更都必须走它，
// 因为内核配置由控制服务独占渲染，直接改配置文件会被覆盖。
const transctlBin = "/usr/local/bin/transctl"

type settings struct {
	Host    string `json:"host"`
	Port    int    `json:"port"`
	User    string `json:"user"`
	KeyPath string `json:"keyPath"`
}

// userRow 与 transctl list -json 的输出一一对应。
type userRow struct {
	Name       string `json:"name"`
	UUID       string `json:"uuid"`
	Enabled    bool   `json:"enabled"`
	UsedBytes  int64  `json:"usedBytes"`
	QuotaBytes int64  `json:"quotaBytes"`
	Note       string `json:"note"`
	// LastActive 取代了内核不提供的「在线数」，原因见 ctl.User.LastActive 的说明。
	LastActive int64 `json:"lastActive"`
}

// userModel 把账号列表喂给表格控件，避免用空格去拼一张「看起来对齐」的文本表。
type userModel struct {
	walk.TableModelBase
	rows []userRow
}

func (m *userModel) RowCount() int { return len(m.rows) }

func (m *userModel) Value(row, col int) interface{} {
	if row < 0 || row >= len(m.rows) {
		return ""
	}
	r := m.rows[row]
	switch col {
	case 0:
		return r.Name
	case 1:
		if r.Enabled {
			return "启用"
		}
		return "停用"
	case 2:
		return humanBytes(r.UsedBytes)
	case 3:
		if r.QuotaBytes <= 0 {
			return "不限"
		}
		return humanBytes(r.QuotaBytes)
	case 4:
		return common.SinceText(r.LastActive)
	case 5:
		return r.UUID
	case 6:
		return r.Note
	}
	return ""
}

type admin struct {
	mw       *walk.MainWindow
	table    *walk.TableView
	model    *userModel
	status   *walk.Label
	nameBox  *walk.LineEdit
	newPwBox *walk.LineEdit
	msgBox   *walk.TextEdit

	st  settings
	sid string

	params struct {
		Domain    string
		Port      int
		SNI       string
		PublicKey string
	}
}

func main() {
	selftest := flag.Bool("selftest", false, "无界面自检后退出")
	host := flag.String("host", "", "服务器地址")
	user := flag.String("user", "", "SSH 用户")
	key := flag.String("key", "", "SSH 私钥路径")
	port := flag.Int("port", 0, "SSH 端口")
	flag.Parse()

	a := &admin{model: &userModel{}}
	a.loadSettings()
	if *host != "" {
		a.st.Host = *host
	}
	if *user != "" {
		a.st.User = *user
	}
	if *key != "" {
		a.st.KeyPath = *key
	}
	if *port != 0 {
		a.st.Port = *port
	}

	if *selftest {
		report, ok := a.selftest()
		_ = os.WriteFile(filepath.Join(os.TempDir(), "transadmin-selftest.txt"), []byte(report), 0o644)
		fmt.Print(report)
		if !ok {
			os.Exit(1)
		}
		return
	}

	if err := a.runGUI(); err != nil {
		walk.MsgBox(nil, "TransAdmin 启动失败", err.Error(), walk.MsgBoxIconError)
		os.Exit(1)
	}
}

func (a *admin) runGUI() error {
	if err := (declarative.MainWindow{
		AssignTo: &a.mw,
		Title:    "TransAdmin · 账号管理",
		Size:     declarative.Size{Width: 880, Height: 660},
		Layout:   declarative.VBox{},
		Children: []declarative.Widget{
			declarative.Label{Text: fmt.Sprintf("服务器 %s@%s:%d · 经 SSH 调用服务端 transctl", a.st.User, a.st.Host, a.st.Port)},
			declarative.Label{AssignTo: &a.status, Text: "未连接"},
			declarative.Composite{
				Layout: declarative.HBox{},
				Children: []declarative.Widget{
					declarative.PushButton{Text: "连接 / 刷新列表", MinSize: declarative.Size{Width: 150}, OnClicked: a.onRefresh},
					declarative.HSpacer{},
				},
			},
			declarative.Label{Text: "账号列表（点击某一行即可选中，再点下方按钮操作）"},
			declarative.TableView{
				AssignTo: &a.table,
				MinSize:  declarative.Size{Height: 240},
				Columns: []declarative.TableViewColumn{
					{Title: "账号", Width: 110},
					{Title: "状态", Width: 60},
					{Title: "累计用量", Width: 100},
					{Title: "配额", Width: 90},
					{Title: "最近活动", Width: 90},
					{Title: "UUID", Width: 300},
					{Title: "备注", Width: 130},
				},
			},
			declarative.Composite{
				Layout: declarative.Grid{Columns: 4},
				Children: []declarative.Widget{
					declarative.Label{Text: "账号名"},
					declarative.LineEdit{AssignTo: &a.nameBox, CueBanner: "选中表格行会自动填入"},
					declarative.Label{Text: "新密码"},
					declarative.LineEdit{AssignTo: &a.newPwBox, CueBanner: "留空则自动生成随机密码"},
				},
			},
			declarative.Composite{
				Layout: declarative.HBox{},
				Children: []declarative.Widget{
					declarative.PushButton{Text: "新增账号", MinSize: declarative.Size{Width: 100}, OnClicked: a.onAdd},
					declarative.PushButton{Text: "删除选中", MinSize: declarative.Size{Width: 100}, OnClicked: a.onDelete},
					declarative.PushButton{Text: "重置密码", MinSize: declarative.Size{Width: 100}, OnClicked: a.onResetPassword},
					declarative.PushButton{Text: "分享链接 / 二维码", MinSize: declarative.Size{Width: 160}, OnClicked: a.onLink},
					declarative.HSpacer{},
				},
			},
			declarative.Label{Text: "操作记录"},
			declarative.TextEdit{AssignTo: &a.msgBox, ReadOnly: true, VScroll: true, MinSize: declarative.Size{Height: 90}},
			declarative.Label{Text: "提示：用户可在客户端内自行修改密码；此面板仅用于账号管理。"},
		},
	}).Create(); err != nil {
		return err
	}

	// 表格模型在窗口创建之后再挂上去，此时列宽已经生效。
	if err := a.table.SetModel(a.model); err != nil {
		// 挂不上模型就会是一张空表，必须明确报出来而不是静默失败。
		walk.MsgBox(a.mw, "账号表格初始化失败", err.Error(), walk.MsgBoxIconError)
	}
	a.table.CurrentIndexChanged().Attach(func() {
		if n := a.selectedName(); n != "" {
			_ = a.nameBox.SetText(n)
		}
	})

	// 打开即自动拉一次列表，省得用户还要先点一次刷新。
	go func() {
		time.Sleep(300 * time.Millisecond)
		a.mw.Synchronize(a.onRefresh)
	}()

	a.mw.Run()
	return nil
}

// ---------- 界面动作 ----------

func (a *admin) onRefresh() {
	a.setStatus("正在连接…")
	if err := a.refresh(); err != nil {
		a.setStatus("连接失败")
		a.say("错误：" + err.Error())
		return
	}
	a.setStatus(fmt.Sprintf("已连接 · %d 个账号 · 出口 %s:%d · 伪装 SNI %s",
		len(a.model.rows), a.params.Domain, a.params.Port, a.params.SNI))
}

func (a *admin) onAdd() {
	name := strings.TrimSpace(a.nameBox.Text())
	if name == "" {
		a.say("请先填写账号名（新账号没有对应表格行，需要手动输入）")
		return
	}
	pw := strings.TrimSpace(a.newPwBox.Text())
	if pw == "" {
		pw = randomPassword(12)
	}
	if err := a.runTransctlSecret(pw, "useradd", name, "管理面板创建"); err != nil {
		a.say("新增失败：" + err.Error())
		return
	}
	a.say(fmt.Sprintf("已新增账号 %s，初始密码：%s（请转告本人并尽快修改）", name, pw))
	_ = a.refresh()
}

func (a *admin) onDelete() {
	name := a.selectedName()
	if name == "" {
		a.say("请先在表格里选中一个账号，或在账号名里手动输入")
		return
	}
	if err := a.runTransctl("userdel", name); err != nil {
		a.say("删除失败：" + err.Error())
		return
	}
	a.say("已删除账号 " + name + "（其身份已在内核中即时失效）")
	_ = a.refresh()
}

func (a *admin) onResetPassword() {
	name := a.selectedName()
	if name == "" {
		a.say("请先在表格里选中一个账号，或在账号名里手动输入")
		return
	}
	pw := strings.TrimSpace(a.newPwBox.Text())
	if pw == "" {
		pw = randomPassword(12)
	}
	if err := a.runTransctlSecret(pw, "passwd", name); err != nil {
		a.say("重置失败：" + err.Error())
		return
	}
	a.say(fmt.Sprintf("已重置 %s 的密码为：%s（该账号的连接身份已更换，旧参数立即失效）", name, pw))
	_ = a.refresh()
}

func (a *admin) onLink() {
	name := a.selectedName()
	if name == "" {
		a.say("请先在表格里选中一个账号，或在账号名里手动输入")
		return
	}
	var uuid string
	for _, r := range a.model.rows {
		if r.Name == name {
			uuid = r.UUID
		}
	}
	if uuid == "" {
		a.say("列表里没有账号 " + name + "，请先点「连接 / 刷新列表」")
		return
	}
	if a.params.PublicKey == "" {
		a.say("尚未取到服务端连接参数，请先刷新")
		return
	}
	p := common.Default()
	p.Remark = name
	p.UUID = uuid
	p.ServerAddr = a.params.Domain
	p.ServerPort = a.params.Port
	p.SNI = a.params.SNI
	p.PublicKey = a.params.PublicKey
	p.ShortID = a.sid
	link := common.ShareLink(p)

	_ = walk.Clipboard().SetText(link)
	a.say("链接已复制到剪贴板：" + link)
	a.showQR(link)
}

func (a *admin) showQR(link string) {
	png, err := qrcode.Encode(link, qrcode.Medium, 340)
	if err != nil {
		return
	}
	qrPath := filepath.Join(os.TempDir(), "transproxy-qr.png")
	if err := os.WriteFile(qrPath, png, 0o644); err != nil {
		return
	}

	var win *walk.MainWindow
	var iv *walk.ImageView
	var box *walk.LineEdit
	if err := (declarative.MainWindow{
		AssignTo: &win,
		Title:    "分享链接与二维码",
		Size:     declarative.Size{Width: 520, Height: 620},
		Layout:   declarative.VBox{},
		Children: []declarative.Widget{
			declarative.Label{Text: "扫码可用官方客户端临时接入；正式使用请装 TransProxy 客户端并用账号密码登录。"},
			declarative.LineEdit{AssignTo: &box, Text: link, ReadOnly: true},
			declarative.ImageView{AssignTo: &iv, MinSize: declarative.Size{Width: 380, Height: 380}},
			declarative.PushButton{Text: "关闭", OnClicked: func() { win.Close() }},
		},
	}).Create(); err != nil {
		return
	}
	if bm, err := walk.NewBitmapFromFile(qrPath); err == nil {
		_ = iv.SetImage(bm)
	}
	win.Run()
}

// ---------- 远程调用 ----------

func (a *admin) sshRun(remote string) (string, error) {
	return a.sshRunStdin(remote, "")
}

// sshRunStdin 与 sshRun 相同，但会把 stdin 内容喂给远端命令。
//
// 密码这类秘密必须走这里：ssh 的命令行参数在本地与远端的进程表里都是明文，
// 同机任何用户 ps 一下就能看到；走标准输入则不会出现在任何进程表里。
func (a *admin) sshRunStdin(remote, stdin string) (string, error) {
	dir := filepath.Join(os.Getenv("APPDATA"), "TransAdmin")
	_ = os.MkdirAll(dir, 0o755)
	cmd := exec.Command("ssh",
		"-i", a.st.KeyPath,
		"-p", strconv.Itoa(a.st.Port),
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=accept-new",
		"-o", "UserKnownHostsFile="+filepath.Join(dir, "known_hosts"),
		"-o", "ConnectTimeout=10",
		fmt.Sprintf("%s@%s", a.st.User, a.st.Host),
		remote,
	)
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	// stdout 与 stderr 必须分开：ssh 会往 stderr 打主机指纹之类的提示，
	// 一旦混进 stdout 就会污染后续的解析（曾把提示行误当成一个账号）。
	var out, errb bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = err.Error()
		}
		return out.String(), fmt.Errorf("%s", msg)
	}
	return out.String(), nil
}

// runTransctl 在服务端执行一条账号管理命令。
func (a *admin) runTransctl(args ...string) error {
	return a.runTransctlSecret("", args...)
}

// runTransctlSecret 在服务端执行一条账号管理命令，并把密码从标准输入喂进去。
func (a *admin) runTransctlSecret(secret string, args ...string) error {
	quoted := make([]string, 0, len(args))
	for _, s := range args {
		quoted = append(quoted, "'"+strings.ReplaceAll(s, "'", `'\''`)+"'")
	}
	stdin := ""
	if secret != "" {
		stdin = secret + "\n"
	}
	_, err := a.sshRunStdin("sudo "+transctlBin+" "+strings.Join(quoted, " "), stdin)
	return err
}

// refresh 拉取账号列表与服务端连接参数。
func (a *admin) refresh() error {
	raw, err := a.sshRun("sudo " + transctlBin + " list -json")
	if err != nil {
		return err
	}
	var rows []userRow
	if err := json.Unmarshal([]byte(raw), &rows); err != nil {
		return fmt.Errorf("解析账号列表失败: %w", err)
	}
	a.model.rows = rows
	a.model.PublishRowsReset()
	if len(rows) > 0 && a.table != nil {
		_ = a.table.SetCurrentIndex(0)
	}

	// 连接参数从本机命令取，而不是去 curl 公开的 /api/v1/health。
	//
	// 那个接口现在只回「服务是否活着」：publicKey + shortId 能让任何人确认
	// 「这台机器就是这个 REALITY 节点」，没必要摆在公网上。
	// showparams 需要服务器权限，而管理工具本来就走 SSH + sudo。
	health, err := a.sshRun("sudo " + transctlBin + " showparams")
	if err != nil {
		return fmt.Errorf("读取服务端参数失败: %w", err)
	}
	var h struct {
		Domain    string `json:"domain"`
		Port      int    `json:"port"`
		SNI       string `json:"sni"`
		PublicKey string `json:"publicKey"`
		ShortID   string `json:"shortId"`
	}
	if err := json.Unmarshal([]byte(health), &h); err != nil {
		return fmt.Errorf("解析服务端参数失败: %w", err)
	}
	a.params.Domain, a.params.Port, a.params.SNI, a.params.PublicKey = h.Domain, h.Port, h.SNI, h.PublicKey
	a.sid = h.ShortID
	return nil
}

// ---------- 自检 ----------

func (a *admin) selftest() (string, bool) {
	var sb strings.Builder
	pass := true
	check := func(name string, ok bool, detail string) {
		st := "PASS"
		if !ok {
			st = "FAIL"
			pass = false
		}
		fmt.Fprintf(&sb, "[%s] %s%s\n", st, name, detail)
	}

	if err := a.refresh(); err != nil {
		check("读取账号列表与服务端参数", false, " -> "+err.Error())
		return sb.String(), false
	}
	check("读取账号列表与服务端参数", true, fmt.Sprintf(" -> %d 个账号", len(a.model.rows)))
	fmt.Fprintf(&sb, "  账号列表:\n")
	for _, r := range a.model.rows {
		fmt.Fprintf(&sb, "    %-12s %-8s %-10s %s\n", r.Name, statusText(r.Enabled),
			humanBytes(r.UsedBytes), r.UUID)
	}
	check("服务端已下发连接参数", a.params.PublicKey != "" && a.params.SNI != "" && a.sid != "",
		fmt.Sprintf(" -> %s:%d SNI=%s sid=%s", a.params.Domain, a.params.Port, a.params.SNI, a.sid))

	if len(a.model.rows) > 0 {
		p := common.Default()
		p.Remark = a.model.rows[0].Name
		p.UUID = a.model.rows[0].UUID
		p.ServerAddr = a.params.Domain
		p.ServerPort = a.params.Port
		p.SNI = a.params.SNI
		p.PublicKey = a.params.PublicKey
		p.ShortID = a.sid
		link := common.ShareLink(p)
		check("生成分享链接", strings.HasPrefix(link, "vless://") && strings.Contains(link, "sid="), "")
		if _, err := common.ParseShareLink(link); err != nil {
			check("链接可被回读解析", false, " -> "+err.Error())
		} else {
			check("链接可被回读解析", true, "")
		}
	}

	out, err := a.sshRun("systemctl is-active xray transctl")
	check("服务端内核与控制服务均运行中", err == nil && strings.Count(out, "active") == 2,
		" -> "+strings.TrimSpace(strings.ReplaceAll(out, "\n", " ")))

	return sb.String(), pass
}

// ---------- 小工具 ----------

func (a *admin) selectedName() string {
	if a.table != nil {
		if i := a.table.CurrentIndex(); i >= 0 && i < len(a.model.rows) {
			return a.model.rows[i].Name
		}
	}
	if a.nameBox != nil {
		return strings.TrimSpace(a.nameBox.Text())
	}
	return ""
}

func statusText(enabled bool) string {
	if enabled {
		return "启用"
	}
	return "停用"
}

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
	if i == 0 {
		return fmt.Sprintf("%d B", n)
	}
	return fmt.Sprintf("%.2f %s", f, units[i])
}

// say 追加一行操作记录。
// 必须补 \r\n：Win32 编辑框只认 CRLF，直接给 \n 会把所有内容挤成一段。
func (a *admin) say(s string) {
	if a.msgBox == nil {
		return
	}
	a.msgBox.Synchronize(func() {
		cur := strings.TrimRight(a.msgBox.Text(), "\r\n")
		if cur != "" {
			cur += "\r\n"
		}
		_ = a.msgBox.SetText(cur + s)
	})
}

func (a *admin) setStatus(s string) {
	if a.status == nil {
		return
	}
	a.status.Synchronize(func() { _ = a.status.SetText(s) })
}

func (a *admin) settingsPath() string {
	return filepath.Join(os.Getenv("APPDATA"), "TransAdmin", "settings.json")
}

func (a *admin) loadSettings() {
	a.st = settings{
		// 默认用域名：SSH 连接与生成给客户端的入口地址都用它，
		// 服务器 IP 变更时只需改 DNS，无需重新给所有用户发配置。
		Host:    "proxy.example.com",
		Port:    22,
		User:    "admin",
		KeyPath: filepath.Join(filepath.Dir(os.Args[0]), "admin_key"),
	}
	b, err := os.ReadFile(a.settingsPath())
	if err != nil {
		return
	}
	_ = json.Unmarshal(b, &a.st)
}

// randomPassword 用系统随机源生成初始密码。
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
