package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/lxn/walk"
	declarative "github.com/lxn/walk/declarative"
	"golang.org/x/sys/windows"

	"transproxy/internal/common"
)

const (
	defaultHost    = "proxy.example.com"
	defaultAPIPort = 8443
	defaultSocks   = 17900
	defaultHTTP    = 17901
	pollEvery      = 5 * time.Second
	expectEgress   = "43.108.99.4"
)

// 界面上露出的名字。集中在这里定义，避免同一个名字在多处各写一遍、
// 改的时候漏掉某一处（托盘、标题栏、弹窗标题就是这么散开的）。
const (
	// appName 是应用名，用在托盘提示与弹窗标题这类「短名字」的位置。
	appName = "TransProxy"
	// appUITitle 是主窗口标题，与 appName 保持一致。
	appUITitle = "TransProxy"
)

// settings 是客户端本地记住的设置，避免每次都要重填。
type settings struct {
	Host      string `json:"host"`
	APIPort   int    `json:"apiPort"`
	User      string `json:"user"`
	SocksPort int    `json:"socksPort"`
	HTTPPort  int    `json:"httpPort"`
	// AllowLAN 为真时本地代理端口绑到 0.0.0.0，局域网内其它设备可以借本机上网。
	AllowLAN bool   `json:"allowLan,omitempty"`
	Mode     string `json:"mode"`
	TunMode  bool   `json:"tunMode"`
	// 登录便利性设置。PassEnc 存的是经 DPAPI 加密后的密码，不是明文。
	RememberPass bool   `json:"rememberPass"`
	AutoLogin    bool   `json:"autoLogin"`
	PassEnc      string `json:"passEnc,omitempty"`
	// CloseAction 记住用户点标题栏 X 时的选择，空表示每次都要问。
	CloseAction string `json:"closeAction,omitempty"`
	// Protocol 记住用户选定的通道（auto / reality / hysteria）。
	Protocol string `json:"protocol,omitempty"`

	// InstanceID 记住用户选定的线路（服务端下发的线路 id），空表示默认线路。
	//
	// 只存「选了哪一条」，不存线路本身的参数：线路表每次登录都由服务端下发，
	// 这样服务端加线路、改线路名、换线路地址都不用动本地这份设置。
	InstanceID string `json:"instanceId,omitempty"`

	// ---------- 启动相关的三个选项 ----------

	// CleanOnBoot 决定「下次登录时自动还原系统代理」这条一次性启动项要不要登记。
	//
	// 用指针而不是普通 bool：需要区分「没设置过」和「明确关掉」。
	// 这个功能是异常退出后的兜底（进程被强杀、直接关机时，注册表里的代理
	// 会留在指向已退出进程的死端口上，表现是整台机器上不了网），
	// 所以首次运行必须按**开启**处理；普通 bool 的零值恰好是 false，
	// 会把老用户升级上来的默认行为从「开」悄悄变成「关」。
	CleanOnBoot *bool `json:"cleanProxyOnBoot,omitempty"`

	// AutoStart 为真时随开机自动启动本程序。
	AutoStart bool `json:"autoStart,omitempty"`

	// AutoConnect 为真时启动后自动登录并直接连上服务器，用户不用再点一次连接。
	// 需要配合 RememberPass：没有存下来的密码就无法自动登录。
	AutoConnect bool `json:"autoConnect,omitempty"`

	// MinimizeOnStart 为真时启动后直接把主窗口收进托盘，不显示界面。
	//
	// 只有 AutoConnect 也开着时才允许勾选（界面上会跟着禁用/取消）：
	// 单开这一项等于把程序藏起来却什么都没连，用户既看不到界面、也不知道到底
	// 连上没有，只能去猜托盘图标。两个一起用才是「开机静默上网」。
	MinimizeOnStart bool `json:"minimizeOnStart,omitempty"`
}

// cleanOnBoot 返回「开机自动清理代理」是否生效，未设置过时按开启处理（理由见字段注释）。
func (s settings) cleanOnBoot() bool {
	return s.CleanOnBoot == nil || *s.CleanOnBoot
}

// minimizeAllowed 是「启动后自动最小化到托盘」的依赖规则：必须先勾上「自动连接」。
//
// 单独最小化等于把程序藏起来却什么都没连——用户既看不到界面，也不知道到底连没连上，
// 只能去猜托盘图标。读取设置与保存设置两处都走这一个函数，避免两边判断不一致，
// 出现「保存时写进去了、启动时又不认」这种最难查的状态。
func minimizeAllowed(autoConnect, minimizeOnStart bool) bool {
	return autoConnect && minimizeOnStart
}

const (
	closeToTray = "tray"
	closeToExit = "exit"
)

type app struct {
	mw      *walk.MainWindow
	workDir string

	// 登录面板
	loginPanel   *walk.ScrollView
	hostBox      *walk.LineEdit
	apiPortBox   *walk.LineEdit
	userBox      *walk.LineEdit
	passBox      *walk.LineEdit
	rememberBox  *walk.CheckBox
	autoLoginBox *walk.CheckBox
	loginTip     *walk.Label
	loginBtn     *accentButton

	// 主面板。内容比窗口高，所以用可滚动的容器承载，避免小屏上被裁掉。
	mainPanel    *walk.ScrollView
	accountLabel *walk.Label
	stateLabel   *walk.Label
	stateDetail  *walk.Label
	connectBtn   *accentButton

	// 自绘与动画控件，见 ui.go
	dot         *statusDot
	upBar       *meterBar
	downBar     *meterBar
	upLabel     *walk.Label
	downLabel   *walk.Label
	totalLabel  *walk.Label
	limitLabel  *walk.Label
	rateLabel   *walk.Label
	activeLabel *walk.Label
	socksBox    *walk.LineEdit
	httpBox     *walk.LineEdit
	lanBox      *walk.CheckBox
	modeBox     *walk.ComboBox
	protoBox    *walk.ComboBox
	protoHint   *walk.Label
	// 线路（多实例）选择。lineIDs 与下拉框下标一一对应：
	// ComboBox 的 Model 只存显示文字，而连接时要用的是服务端给的 id。
	lineBox    *walk.ComboBox
	lineHint   *walk.Label
	lineIDs    []string
	tunBox     *walk.CheckBox
	tunHint    *walk.Label
	oldPassBox *walk.LineEdit
	newPassBox *walk.LineEdit

	// 启动选项：开机自动清理代理 / 开机自启 / 启动后自动连接 / 启动后收进托盘
	cleanBox     *walk.CheckBox
	autoStartBox *walk.CheckBox
	autoConnBox  *walk.CheckBox
	minimizeBox  *walk.CheckBox
	// autoConnectPending 表示「这次是启动后自动登录，登录成功就顺手连上」。
	// 用完即清零：它只服务于启动那一次，之后用户手动登录/断开都不该被它接管。
	autoConnectPending bool
	// minimizeOnStart 表示「这次启动要把窗口收进托盘」，只在启动那一刻读一次设置。
	minimizeOnStart bool

	// 托盘与退出控制
	ni       *walk.NotifyIcon
	quitting bool

	// 运行时状态
	client *common.APIClient
	login  *common.LoginResult
	tunnel *common.Tunnel
	// hysteria 是第二条通道的旁挂进程，仅在使用通道B时非空。
	hysteria *common.Tunnel
	// activeProto 记录当前实际生效的通道（智能优选时是择优后的结果），用于界面展示。
	activeProto string
	// sessionPass 是本会话内的明文密码，只存在于内存。
	// Hysteria2 的认证需要「账号:密码」原文，而登录成功后输入框会被清空，
	// 因此必须在这里留一份；它不会落盘（落盘的是 DPAPI 加密结果）。
	sessionPass string
	// tunnelIsTun 记录当前这条隧道是不是 TUN 模式，断开时要据此还原系统设置。
	tunnelIsTun bool
	// tunSetup 持有 TUN 模式下自己加的地址/路由，断开时必须显式回收。
	tunSetup    *common.TunSetup
	tunErr      string
	snap        common.ProxySnapshot
	hasSnap     bool
	sessionBase int64

	mu       sync.Mutex
	pollStop chan struct{}

	// 速率由客户端自己按两次采样的差除以真实间隔算出，见 updateRate。
	ratePrevUp   int64
	ratePrevDown int64
	ratePrevAt   time.Time
	rateUpEMA    float64
	rateDownEMA  float64
	rateReady    bool

	// closeAction 是记住的关闭行为，空表示每次都要问。
	closeAction string
	// restoredStaleProxy 记录启动时是否补还原过一次系统代理，
	// 用于在界面上告知用户「上次是异常退出」。
	restoredStaleProxy bool
	// savedPassEnc 是待落盘的加密密码。单独存一份是为了让 saveSettings
	// 不依赖「此刻输入框里是什么」，避免因为清空输入框而把记住的密码弄丢。
	savedPassEnc string
}

func main() {
	selftest := flag.Bool("selftest", false, "无人值守自检后退出")
	user := flag.String("user", "", "自检用账号")
	pass := flag.String("pass", "", "自检用密码；留空则从标准输入读一行，避免密码出现在进程表里")
	host := flag.String("host", defaultHost, "服务器地址")
	apiPort := flag.Int("apiPort", defaultAPIPort, "控制端口")
	workDir := flag.String("dir", "", "工作目录")
	elevatedTried := flag.Bool("elevated", false, "内部标记：已尝试过提权")
	tunMode := flag.Bool("tun", false, "自检时启用 TUN 模式（需要管理员权限）")
	proto := flag.String("proto", "reality", "自检通道：reality 或 hysteria")
	restoreProxy := flag.Bool(common.FlagRestoreProxy, false, "内部标记：还原系统代理后立即退出（由登录启动项调用）")
	flag.Parse()

	// 清掉本 exe 上的「来自 Internet」标记。放在最前面：越早清掉，这次运行剩下的
	// 时间里就不会因为别的原因再被系统重新判定。详见 common.ClearSelfMarkOfTheWeb。
	// 失败不处理——exe 在只读目录时删不掉是正常的。
	common.ClearSelfMarkOfTheWeb()

	dir := *workDir
	if dir == "" {
		dir = filepath.Join(os.Getenv("LOCALAPPDATA"), "TransProxy")
	}

	a := &app{workDir: dir}

	// 单实例闸门必须放在任何「会改动系统状态」的动作之前。
	// 第二个实例若先跑了代理还原，会把正在运行的那个实例的代理在背后关掉，
	// 用户看到的是「用着用着突然上不了网」，而且极难定位到是重复启动造成的。
	lock, ok, err := common.AcquireInstanceLock(dir)
	if err != nil {
		if *selftest {
			fmt.Println("[FAIL] " + err.Error())
			os.Exit(2)
		}
		walk.MsgBox(nil, appName+" 启动失败", err.Error(), walk.MsgBoxIconError)
		return
	}
	if !ok {
		switch {
		case *selftest:
			// 自检要独占代理设置，否则校验结果会被另一个实例搅乱。
			fmt.Println("[FAIL] 已有客户端实例在运行，请先关闭再自检")
			os.Exit(2)
		case *restoreProxy:
			// 这是登录时静默执行的还原入口：锁被占说明本进程不该有任何动作，
			// 安静退出即可，弹窗只会让用户莫名其妙。
		default:
			walk.MsgBox(nil, appName+" 已在运行",
				"客户端已经开着一个了，请使用已打开的窗口。\r\n\r\n"+
					"同时运行两个实例会互相争抢本地代理端口，还会把对方的系统代理设置改掉。",
				walk.MsgBoxIconInformation)
		}
		return
	}
	// 句柄要一直持有到进程退出：关掉就等于放锁。
	defer func() { _ = windows.CloseHandle(lock) }()

	// 登录启动项调用：上次没还原干净的系统代理在这里补还原，然后立刻退出。
	// 这条路径不做任何界面、不联网，只把注册表改回去，越简单越不容易再出问题。
	if *restoreProxy {
		st := a.loadSettings()
		common.RestoreProxyFromBackup(dir, a.ownProxyPorts(st))
		return
	}

	if *selftest {
		p := *pass
		if p == "" {
			line, err := readSecretLine()
			if err != nil {
				fmt.Println("自检需要密码：用 -pass 传入，或从标准输入提供一行")
				os.Exit(2)
			}
			p = line
		}
		os.Exit(a.selfTest(*host, *apiPort, *user, p, *tunMode, *proto))
	}

	// 只有上次设置里确实开着 TUN 才申请提权。
	//
	// 这里原来是无条件提权，加上后面 initTun 与 onInstallTun 各自还有一条申请路径，
	// 一次启动最多能连弹三个 UAC/确认框：即使选的是普通代理模式（根本不需要管理员
	// 权限），用户也得先过一遍。观感上像是有程序在反复索要权限，非常劝退。
	//
	// 除了 TUN（创建虚拟网卡）之外，客户端做的事情——读写自己的工作目录、
	// 改 HKCU 里的系统代理设置——都不需要管理员权限，所以没开 TUN 就完全不提权。
	// -elevated 是防止「提权后仍判定为非管理员」时无限自我重启的标记。
	// 用户拒绝提权不做退出：普通代理模式照常可用，只是 TUN 不可选。
	if !common.Elevated() && !*elevatedTried && a.loadSettings().TunMode {
		// 显式带上 -dir：UAC 提权后环境变量可能换到另一个账户名下，
		// 不指定就会把工作目录（含配置与驱动）落到别人的用户目录里。
		if common.Elevate("-elevated", "-dir", dir) {
			return
		}
	}

	if err := a.run(); err != nil {
		walk.MsgBox(nil, appName+" 启动失败", err.Error(), walk.MsgBoxIconError)
		os.Exit(1)
	}
}

// readSecretLine 从标准输入读一行作为密码。
//
// 密码不走命令行参数：进程的 argv 对本机所有用户可见，把密码放进去
// 等于把它写在公告板上；走标准输入则不会出现在任何进程表里。
func readSecretLine() (string, error) {
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && err != io.EOF {
		return "", err
	}
	s := strings.TrimRight(line, "\r\n")
	if s == "" {
		return "", fmt.Errorf("没有从标准输入读到密码")
	}
	return s, nil
}

// selfTest 无人值守走完整链路：登录 → 取参数 → 建隧道 → 校验出口与分流 → 清理。
func (a *app) selfTest(host string, apiPort int, user, pass string, tunMode bool, proto string) int {
	if user == "" || pass == "" {
		fmt.Println("自检需要 -user 与 -pass")
		return 2
	}
	if err := common.ValidateHost(host); err != nil {
		msg := "[FAIL] 服务器地址: " + err.Error() + "\n"
		a.writeReport(msg)
		fmt.Print(msg)
		return 2
	}
	if tunMode && !common.TunReady(a.workDir) {
		// 环境不就绪就直接说明白，不要留到连接失败再去猜原因。
		msg := "[FAIL] TUN 环境未就绪 -> " + common.TunStatusText(a.workDir) +
			"\n       请以管理员身份运行，并确认工作目录下已释放 wintun.dll\n"
		a.writeReport(msg)
		fmt.Print(msg)
		return 1
	}
	var sb strings.Builder
	sb.WriteString("=== 登录 ===\n")
	cli := common.NewAPIClient(host, apiPort)
	res, err := cli.Login(user, pass)
	if err != nil {
		sb.WriteString("[FAIL] 登录: " + err.Error() + "\n")
		a.writeReport(sb.String())
		fmt.Print(sb.String())
		return 1
	}
	sb.WriteString(fmt.Sprintf("[PASS] 登录成功，账号 %s（备注 %s）\n", res.Username, res.Note))
	sb.WriteString(fmt.Sprintf("       服务端下发出口 %s:%d，伪装 SNI %s\n",
		res.Params.Address, res.Params.Port, res.Params.SNI))

	if t, err := cli.Traffic(res.Token); err == nil {
		sb.WriteString(fmt.Sprintf("[PASS] 流量接口可用，累计用量 %d 字节，剩余额度 %d\n",
			t.UsedBytes, t.RemainingBytes))
	} else {
		sb.WriteString("[FAIL] 流量接口: " + err.Error() + "\n")
	}

	profile := res.Profile(common.ModeSmart, defaultSocks, defaultHTTP)
	profile.TunMode = tunMode
	// 通道由 -proto 指定。默认只测通道A：服务端不一定部署了第二条通道，
	// 把「没部署」当成失败会让自检结果产生误导。
	if proto == common.ProtoHysteria {
		profile.Protocol = common.ProtoHysteria
	} else {
		profile.Protocol = common.ProtoReality
	}
	modeText := ""
	if tunMode {
		modeText = " · TUN 模式"
	}
	sb.WriteString(fmt.Sprintf("=== 隧道与分流（通道 %s%s）===\n",
		common.ProtocolLabel(profile.Protocol), modeText))
	if profile.Protocol == common.ProtoHysteria && !profile.HysteriaAvailable() {
		sb.WriteString("[FAIL] 服务端未下发 Hysteria2 参数，通道B 不可用\n")
	}
	// 用与服务端下发的账号密码同源的凭据自检：Hysteria2 的认证就是「账号:密码」，
	// 与通道A 共用同一套账号体系。
	report, ok := common.SelfTestChannel(a.workDir, profile, res.Username, pass, expectEgress)
	sb.WriteString(report)

	a.writeReport(sb.String())
	fmt.Print(sb.String())
	if !ok {
		return 1
	}
	return 0
}

func (a *app) writeReport(s string) {
	_ = os.MkdirAll(a.workDir, 0o755)
	_ = os.WriteFile(filepath.Join(os.TempDir(), "transproxy-client-selftest.txt"), []byte(s), 0o644)
}

func (a *app) run() error {
	st := a.loadSettings()
	a.closeAction = st.CloseAction
	a.savedPassEnc = st.PassEnc
	// 记住「这次启动要不要自动连上」：登录成功之后才用得上。
	a.autoConnectPending = st.AutoConnect
	// 「启动后收进托盘」只有配合「自动连接」才有意义：单独最小化等于把程序
	// 藏起来却什么都没连。这里再与一次，防止设置文件被手工改坏。
	a.minimizeOnStart = minimizeAllowed(st.AutoConnect, st.MinimizeOnStart)

	// 上次若是被强杀或直接关机，系统代理会被留在「指向已退出进程的端口」上，
	// 表现为整台机器上不了网。启动时先补还原，再去建界面。
	if common.RestoreProxyFromBackup(a.workDir, a.ownProxyPorts(st)) {
		a.restoredStaleProxy = true
	}

	// 有记住的密码就预填，省得每次重输。
	savedPass := ""
	if st.RememberPass && st.PassEnc != "" {
		if p, err := common.Unprotect(st.PassEnc); err == nil {
			savedPass = p
		}
	}

	// 先构造自绘控件，再交给 declarative 建窗口：绘制与交互都是这些结构体的方法值，
	// 必须先把方法从结构体上取出来。
	a.dot = &statusDot{}
	a.upBar = &meterBar{fill: theme().accent}
	a.downBar = &meterBar{fill: theme().green}
	a.loginBtn = newAccentButton("登录", btnPrimary, theme().card, a.doLogin)
	a.connectBtn = newAccentButton("连接", btnPrimary, theme().card, a.toggleConnect)

	if err := (declarative.MainWindow{
		AssignTo: &a.mw,
		Title:    appUITitle,
		Size:     declarative.Size{Width: winWLogin, Height: winHLogin},
		// Visible=false 会让 declarative 在窗口建好后**不调用 Show()**，
		// 于是整个启动过程窗口都不会出现，只会留下托盘图标。
		// 这比「建好之后再 Hide()」干净：后者会先闪一下。
		// 用户点托盘菜单的「显示主窗口」仍然能随时把它调出来。
		Visible:    !a.minimizeOnStart,
		Background: declarative.SolidColorBrush{Color: colWindowBG},
		Layout: declarative.VBox{
			Margins: declarative.Margins{Left: 14, Top: 12, Right: 14, Bottom: 12},
			Spacing: 7,
		},
		Children: []declarative.Widget{
			// ---------- 登录 ----------
			// 同样用可滚动容器：登录表单虽然不高，但窗口尺寸受系统 DPI 缩放影响，
			// 万一算小了一点点，普通容器会把底部内容直接裁掉、连提示都看不见；
			// 可滚动容器最坏也只是多一根滚动条。
			declarative.ScrollView{
				AssignTo:        &a.loginPanel,
				Background:      declarative.SolidColorBrush{Color: colCard},
				HorizontalFixed: true,
				Layout: declarative.VBox{
					Margins: declarative.Margins{Left: 20, Top: 20, Right: 20, Bottom: 18},
					Spacing: 8,
				},
				Children: []declarative.Widget{
					declarative.Label{Text: appName, Font: uiFont(20, true), TextColor: colText},
					declarative.Label{Text: "免费学习版 · 加密隧道代理", Font: uiFont(9, false), TextColor: colTextDim},
					// 这里不再放 VSpacer：可滚动容器按内容高度布局，弹簧撑不开，
					// 只会白白多出间距，不如让表单自上而下整齐排列。
					fieldLabel("服务器地址"),
					declarative.LineEdit{AssignTo: &a.hostBox, Text: st.Host},
					fieldLabel("控制端口"),
					declarative.LineEdit{AssignTo: &a.apiPortBox, Text: strconv.Itoa(st.APIPort)},
					fieldLabel("账号"),
					declarative.LineEdit{AssignTo: &a.userBox, Text: st.User},
					fieldLabel("密码"),
					declarative.LineEdit{AssignTo: &a.passBox, PasswordMode: true, Text: savedPass},
					declarative.Composite{
						Layout: declarative.HBox{MarginsZero: true},
						Children: []declarative.Widget{
							declarative.CheckBox{AssignTo: &a.rememberBox, Text: "记住密码", Checked: st.RememberPass, Font: uiFont(9, false)},
							declarative.CheckBox{AssignTo: &a.autoLoginBox, Text: "自动登录", Checked: st.AutoLogin, Font: uiFont(9, false)},
							declarative.HSpacer{},
						},
					},
					accentButtonWidget(a.loginBtn, 40),
					declarative.Label{AssignTo: &a.loginTip, Text: "请输入服务端分配的账号密码", Font: uiFont(9, false), TextColor: colTextDim},
					declarative.Label{Text: common.NoticeLines()[0], TextColor: colNotice, Font: uiFont(8, false), MaxSize: declarative.Size{Width: 360}},
					declarative.Label{Text: common.NoticeLines()[1], TextColor: colNotice, Font: uiFont(8, false), MaxSize: declarative.Size{Width: 360}},
				},
			},
			// ---------- 使用中 ----------
			// 用可滚动容器承载：卡片式布局比原来的分组框占地方，小屏笔记本上
			// 直接排会超出窗口被裁掉，滚动是最省事的兜底。
			declarative.ScrollView{
				AssignTo:        &a.mainPanel,
				Visible:         false,
				Background:      declarative.SolidColorBrush{Color: colWindowBG},
				HorizontalFixed: true,
				Layout:          declarative.VBox{MarginsZero: true, Spacing: 9},
				Children: []declarative.Widget{
					card(
						declarative.Composite{
							Layout: declarative.HBox{MarginsZero: true, Spacing: 12},
							Children: []declarative.Widget{
								declarative.CustomWidget{
									AssignTo:            &a.dot.w,
									MinSize:             declarative.Size{Width: 54, Height: 54},
									MaxSize:             declarative.Size{Width: 54, Height: 54},
									PaintPixels:         a.dot.paint,
									PaintMode:           declarative.PaintBuffered,
									InvalidatesOnResize: true,
								},
								declarative.Composite{
									Layout: declarative.VBox{MarginsZero: true, Spacing: 2},
									Children: []declarative.Widget{
										declarative.Label{AssignTo: &a.accountLabel, Text: "未登录", Font: uiFont(9, false), TextColor: colTextDim},
										declarative.Label{AssignTo: &a.stateLabel, Text: "未连接", Font: uiFont(13, true), TextColor: colText},
										declarative.Label{AssignTo: &a.stateDetail, Text: "", Font: uiFont(8, false), TextColor: colTextDim, MaxSize: declarative.Size{Width: 285}},
									},
								},
							},
						},
						accentButtonWidget(a.connectBtn, 42),
					),
					card(
						cardTitle("流量"),
						barBlock("本次上传", &a.upLabel, a.upBar),
						barBlock("本次下载", &a.downLabel, a.downBar),
						declarative.Composite{
							// 四项统计排成 4 列 2 行，而不是 2 列 4 行：
							// 少两行就少占约 44px，正是「一屏放得下」的关键。
							Layout: declarative.Grid{Columns: 4, Spacing: 6},
							Children: []declarative.Widget{
								fieldLabel("累计用量"), valueLabel(&a.totalLabel, "—"),
								fieldLabel("剩余额度"), valueLabel(&a.limitLabel, "—"),
								fieldLabel("实时速率"), valueLabel(&a.rateLabel, "—"),
								fieldLabel("最近活动"), valueLabel(&a.activeLabel, "—"),
							},
						},
					),
					card(
						cardTitle("代理设置"),
						declarative.Composite{
							Layout: declarative.Grid{Columns: 2, Spacing: 6},
							Children: []declarative.Widget{
								fieldLabel("SOCKS 端口"),
								declarative.LineEdit{AssignTo: &a.socksBox, Text: strconv.Itoa(st.SocksPort), MaxSize: declarative.Size{Width: 100}},
								fieldLabel("HTTP 端口"),
								declarative.LineEdit{AssignTo: &a.httpBox, Text: strconv.Itoa(st.HTTPPort), MaxSize: declarative.Size{Width: 100}},
								fieldLabel("局域网访问"),
								// 默认关闭。开启后端口绑到 0.0.0.0，同一局域网内的其它设备
								// （例如自己的服务器）就能用「本机 IP + 端口」借这条隧道上网。
								// 入站是无认证的 SOCKS/HTTP，所以把风险写在旁边。
								labelAboveControl(
									declarative.CheckBox{
										AssignTo: &a.lanBox,
										Text:     "允许其他设备借本机端口上网",
										Checked:  st.AllowLAN,
										Font:     uiFont(9, false),
									},
									declarative.Label{
										Text:      "端口无密码，仅在可信网络里开启",
										Font:      uiFont(8, false),
										TextColor: colNotice,
										MaxSize:   declarative.Size{Width: 215},
									},
								),
								fieldLabel("代理规则"),
								declarative.ComboBox{
									AssignTo: &a.modeBox,
									MaxSize:  declarative.Size{Width: 215},
									Model:    []string{common.ModeLabel(common.ModeSmart), common.ModeLabel(common.ModeGlobal)},
									CurrentIndex: func() int {
										if st.Mode == common.ModeGlobal {
											return 1
										}
										return 0
									}(),
								},
								fieldLabel("线路"),
								// 线路表要登录之后才拿得到，所以这里先只有「默认线路」一项，
								// 登录成功由 applyLines() 重建。
								declarative.Composite{
									Layout: declarative.HBox{MarginsZero: true, Spacing: 6},
									Children: []declarative.Widget{
										declarative.ComboBox{
											AssignTo:              &a.lineBox,
											MaxSize:               declarative.Size{Width: 185},
											Model:                 []string{"默认线路"},
											OnCurrentIndexChanged: a.onLineChanged,
										},
										declarative.Label{AssignTo: &a.lineHint, Text: "", Font: uiFont(8, false), TextColor: colTextDim, MaxSize: declarative.Size{Width: 200}},
										declarative.HSpacer{},
									},
								},
								fieldLabel("传输通道"),
								// 提示与下拉框并排，而非另起一行：登录后这条提示才有内容，
								// 单独占一行会把内容顶高约 19px，正好吃掉本就紧张的余量。
								declarative.Composite{
									Layout: declarative.HBox{MarginsZero: true, Spacing: 6},
									Children: []declarative.Widget{
										declarative.ComboBox{
											AssignTo: &a.protoBox,
											MaxSize:  declarative.Size{Width: 185},
											Model: []string{
												common.ProtocolLabel(common.ProtoAuto),
												common.ProtocolLabel(common.ProtoReality),
												common.ProtocolLabel(common.ProtoHysteria),
											},
											CurrentIndex: protoIndex(st.Protocol),
										},
										declarative.Label{AssignTo: &a.protoHint, Text: "", Font: uiFont(8, false), TextColor: colTextDim, MaxSize: declarative.Size{Width: 200}},
										declarative.HSpacer{},
									},
								},
								fieldLabel("TUN 模式"),
								labelAboveControl(
									declarative.Composite{
										Layout: declarative.HBox{MarginsZero: true, SpacingZero: true},
										Children: []declarative.Widget{
											declarative.CheckBox{
												AssignTo:         &a.tunBox,
												Text:             "全局接管（含 UDP）",
												Checked:          st.TunMode,
												Font:             uiFont(9, false),
												OnCheckedChanged: a.onTunToggle,
											},
											declarative.HSpacer{},
											declarative.PushButton{Text: "安装虚拟网卡", OnClicked: a.onInstallTun},
										},
									},
									declarative.Label{AssignTo: &a.tunHint, Text: "", Font: uiFont(8, false), TextColor: colTextDim, MaxSize: declarative.Size{Width: 215}},
								),
							},
						},
						declarative.PushButton{Text: "保存设置并重连", MinSize: declarative.Size{Height: 26}, OnClicked: a.applySettings},
					),
					// ---------- 启动选项 ----------
					// 三项都会改动系统状态（注册表），所以各自把「作用」与「代价」
					// 写在下面：用户关掉哪一项之后会失去什么，必须一眼能看明白。
					card(
						cardTitle("启动选项"),
						labelAboveControl(
							declarative.CheckBox{
								AssignTo: &a.cleanBox,
								Text:     "开机自动清理系统代理",
								Checked:  st.cleanOnBoot(),
								Font:     uiFont(9, false),
							},
							hintText("上次异常退出（被强杀/直接关机）会残留代理设置，使整台电脑上不了网；"+
								"开机时自动还原一次。"+
								"关掉后不再有任何开机动作，但异常退出时需要手动打开本程序才能恢复上网。"),
						),
						labelAboveControl(
							declarative.CheckBox{
								AssignTo: &a.autoStartBox,
								Text:     "开机自动启动本软件",
								Checked:  st.AutoStart,
								Font:     uiFont(9, false),
							},
							hintText("登录 Windows 后自动启动本软件。"+
								"与下面的「自动连接」「最小化到托盘」一起用，开机即可直接上网。"),
						),
						labelAboveControl(
							declarative.CheckBox{
								AssignTo:         &a.autoConnBox,
								Text:             "启动后自动连接服务器",
								Checked:          st.AutoConnect,
								Font:             uiFont(9, false),
								OnCheckedChanged: a.onStartupOptionToggle,
							},
							hintText("启动后自动登录并直接连上，使用上次成功的服务器、账号与通道参数，"+
								"不用再点一次「连接」。"+
								"需要同时勾选登录页的「记住密码」，否则没有可用的密码，无法自动登录。"),
						),
						labelAboveControl(
							declarative.CheckBox{
								AssignTo:         &a.minimizeBox,
								Text:             "启动后自动最小化到托盘",
								Checked:          st.MinimizeOnStart,
								Font:             uiFont(9, false),
								OnCheckedChanged: a.onStartupOptionToggle,
							},
							hintText("勾上后启动时不显示主窗口，直接收进托盘；托盘右键菜单里有「显示主窗口」。"+
								"必须先勾选上面的「启动后自动连接服务器」才能勾这一项——"+
								"否则程序藏起来了，却还没连上，用户既看不到界面也不知道连没连上。"),
						),
						declarative.PushButton{Text: "保存设置并重连", MinSize: declarative.Size{Height: 26}, OnClicked: a.applySettings},
					),
					card(
						cardTitle("账号"),
						declarative.Composite{
							Layout: declarative.Grid{Columns: 2, Spacing: 6},
							Children: []declarative.Widget{
								fieldLabel("原密码"),
								declarative.LineEdit{AssignTo: &a.oldPassBox, PasswordMode: true, MaxSize: declarative.Size{Width: 150}},
								fieldLabel("新密码"),
								declarative.LineEdit{AssignTo: &a.newPassBox, PasswordMode: true, MaxSize: declarative.Size{Width: 150}},
								declarative.Label{Text: ""},
								declarative.PushButton{Text: "修改密码", OnClicked: a.changePassword},
							},
						},
					),
					declarative.Composite{
						Layout: declarative.HBox{MarginsZero: true},
						Children: []declarative.Widget{
							declarative.PushButton{Text: "打开目录", OnClicked: func() {
								_ = exec.Command("explorer", a.workDir).Start()
							}},
							declarative.PushButton{Text: "退出登录", OnClicked: a.logout},
							declarative.HSpacer{},
							declarative.PushButton{Text: "最小化到托盘", OnClicked: func() { a.mw.Hide() }},
							declarative.PushButton{Text: "退出程序", OnClicked: func() { a.quit() }},
						},
					},
					declarative.Label{Text: common.NoticeLines()[0], TextColor: colNotice, Font: uiFont(8, false)},
					declarative.Label{Text: common.NoticeLines()[1], TextColor: colNotice, Font: uiFont(8, false)},
				},
			},
		},
	}).Create(); err != nil {
		return err
	}

	// 动画调度器：把会动的控件登记进去，之后由它统一驱动，见 ui.go。
	animatorRef = &animator{mw: a.mw}
	animatorRef.add(a.dot, a.upBar, a.downBar)

	a.setupTray()

	// 把启动选项同步到系统（写注册表，不产生子进程）。
	//
	// 放在界面建好之后：这一步可能失败（组策略拦注册表、权限异常），
	// 失败要通过 setLoginTip 告诉用户，而界面没建起来时提示是写不出去的、
	// 用户永远看不到——那就等于悄悄失败了。同时它必须在下面的自动登录之前完成，
	// 否则自动连接时用的还是旧设置。
	//
	// 无条件重写一遍而不是「只在勾选变化时改」，是为了兜住两种情况：
	// 注册表被手工清理过；程序被挪了目录，自启项里留下一条指向旧路径的命令，
	// 系统每次开机都会去执行一个已经不存在的文件。
	a.syncStartupOptions(st)

	if a.restoredStaleProxy {
		// 明确告知：上次是异常退出，系统代理已被自动还原。
		// 不提示的话，用户只会觉得「上次关机后上不了网，这次又莫名其妙好了」。
		a.setLoginTip("检测到上次未正常退出，已自动还原系统代理")
	}

	// 窗口就绪后再做两件事，都必须等窗口真正显示出来：
	//  1. 重新设置一次尺寸——创建时窗口还不知道自己落在哪块显示器上，
	//     此时按 1/96" 单位换算会按 96 DPI 算，得到的是未缩放的尺寸；
	//  2. TUN 环境检测——检测过程可能弹出提权确认框，需要窗口已经显示，
	//     否则对话框会挂在一个不可见的父窗口上。
	go func() {
		time.Sleep(400 * time.Millisecond)
		a.mw.Synchronize(func() {
			// 仅在仍停留在登录界面时纠正尺寸：勾了自动登录的话，
			// 稍后 enterMain 会把窗口改成使用界面的尺寸，这里不该再抢回去。
			if a.login == nil {
				applyPanelSize(a.mw, winWLogin, winHLogin)
			}
		})
		a.mw.Synchronize(a.initTun)
	}()

	// 勾了自动登录且存有密码：直接进使用界面，不用再点一次登录。
	// 登录失败（密码错、网络不通）会停在登录界面并给出提示，需要用户手动重试。
	if st.AutoLogin && strings.TrimSpace(st.User) != "" && savedPass != "" {
		go func() {
			time.Sleep(500 * time.Millisecond)
			a.mw.Synchronize(a.doLogin)
		}()
	}

	if a.ni == nil {
		// 托盘不可用时，关窗即安全退出：必须先把内核停掉并把系统代理还原，
		// 否则窗口没了但代理设置还指向一个已经失效的本地端口，浏览器会整体不可用。
		a.mw.Closing().Attach(func(canceled *bool, _ walk.CloseReason) {
			if a.quitting {
				return
			}
			a.disconnect()
		})
	}

	a.mw.Run()
	return nil
}

// setupTray 建立托盘图标：关窗只最小化，代理继续运行。
func (a *app) setupTray() {
	ni, err := walk.NewNotifyIcon(a.mw)
	if err != nil {
		return
	}
	a.ni = ni

	// 托盘图标必须显式从本 exe 的资源里取。
	//
	// 这里原来用的是 walk.IconApplication()，它返回的是 Windows **内置**的
	// 通用程序图标（IDI_APPLICATION），跟 exe 里嵌的图标毫无关系——
	// 所以换了图标之后任务栏和 exe 都变了，托盘却一直还是那个默认图标。
	// 资源 id 1 就是 mkicon 写进 rsrc.syso 的那个图标组。
	if ic, err := walk.NewIconFromResourceId(1); err == nil {
		_ = ni.SetIcon(ic)
	} else {
		// 读资源失败也得给个图标，否则托盘里连个影子都没有。
		_ = ni.SetIcon(walk.IconApplication())
	}
	_ = ni.SetToolTip(appName)

	ni.MouseUp().Attach(func(_ int, _ int, button walk.MouseButton) {
		if button == walk.LeftButton {
			a.showWindow()
		}
	})

	showAct := walk.NewAction()
	_ = showAct.SetText("显示主窗口")
	showAct.Triggered().Attach(a.showWindow)

	connAct := walk.NewAction()
	_ = connAct.SetText("连接 / 断开")
	connAct.Triggered().Attach(a.toggleConnect)

	quitAct := walk.NewAction()
	_ = quitAct.SetText("退出")
	quitAct.Triggered().Attach(a.quit)

	menu := ni.ContextMenu()
	for _, act := range []*walk.Action{showAct, connAct, walk.NewSeparatorAction(), quitAct} {
		_ = menu.Actions().Add(act)
	}
	_ = ni.SetVisible(true)

	a.mw.Closing().Attach(func(canceled *bool, _ walk.CloseReason) {
		if a.quitting {
			return
		}
		// 点标题栏的 X：按记住过的选择执行；没记住过就问一次，并把选择记下来。
		*canceled = true
		switch a.closeAction {
		case closeToTray:
			a.mw.Hide()
		case closeToExit:
			a.quit()
		default:
			a.askClose()
		}
	})
}

func (a *app) showWindow() {
	a.mw.Show()
	_ = a.mw.Activate()
}

// ---------- 登录 / 登出 ----------

func (a *app) doLogin() {
	host := strings.TrimSpace(a.hostBox.Text())
	user := strings.TrimSpace(a.userBox.Text())
	pass := a.passBox.Text()
	port, err := strconv.Atoi(strings.TrimSpace(a.apiPortBox.Text()))
	if err != nil {
		a.setLoginTip("控制端口必须是数字")
		return
	}
	if host == "" || user == "" || pass == "" {
		a.setLoginTip("请填写服务器地址、账号与密码")
		return
	}
	if err := common.ValidateHost(host); err != nil {
		a.setLoginTip(err.Error())
		return
	}
	a.setLoginTip("正在登录…")
	a.loginBtn.SetEnabled(false)

	go func() {
		cli := common.NewAPIClient(host, port)
		res, err := cli.Login(user, pass)
		a.ui(func() {
			a.loginBtn.SetEnabled(true)
			if err != nil {
				a.setLoginTip("登录失败：" + err.Error())
				return
			}
			a.client = cli
			a.login = res
			// 明文密码只留在内存里供 Hysteria2 认证使用，不写盘。
			a.sessionPass = pass
			a.saveCredentials(user, pass)
			_ = a.passBox.SetText("")
			a.saveSettings()
			a.enterMain()
			// 启动后自动连接：只在启动那一次自动登录时生效。
			// 立刻清掉标记，否则用户之后手动登出再登录，会被莫名其妙地自动连上。
			if a.autoConnectPending {
				a.autoConnectPending = false
				a.connect()
			}
		})
	}()
}

func (a *app) enterMain() {
	// 先把线路下拉按登录结果建好：下面要显示「出口/入口」，得先知道用户选的是哪条。
	a.applyLines()
	chosen := a.login.Choose(a.uiInstanceID())
	a.accountLabel.SetText(fmt.Sprintf("账号：%s", a.login.Username))
	// 每次进入主界面都从「未连接」的静止状态开始，避免沿用上一次会话的动画状态。
	a.dot.SetState(dotIdle)
	a.connectBtn.SetText("连接")
	a.connectBtn.SetStyle(btnPrimary)
	a.connectBtn.SetEnabled(true)
	a.stateLabel.SetText("未连接")
	// 当前服务端下发的都是 exit（每条线路都是自己的出口），所以正常会走 else，
	// 显示「出口 <落地节点 IP>」。relay 分支是把这个协议字段当真时的渲染方式：
	// 万一以后出现「第一跳 + 出口在别处」的形态，界面必须如实说 —— 否则用户会
	// 以为出口变了（这正是早先那套「中转到总节点」方案最容易误导人的地方）。
	if chosen.IsRelay() {
		a.stateDetail.SetText(fmt.Sprintf("入口 %s:%d · 经中转出网", chosen.Address, chosen.Port))
	} else {
		a.stateDetail.SetText(fmt.Sprintf("出口 %s:%d · 伪装 SNI %s",
			chosen.Address, chosen.Port, chosen.SNI))
	}
	a.refreshProtoUI()
	a.loginPanel.SetVisible(false)
	a.mainPanel.SetVisible(true)
	// 四张卡片比登录表单高得多，进使用界面时把窗口一起放大。
	applyPanelSize(a.mw, winWMain, winHMain)
	a.refreshTraffic()
	a.startPolling()
}

// refreshProtoUI 在通道下拉框旁标出第二条通道是否可用。
// 服务端没开就直说，避免用户选了一个注定连不上的通道再来排查。
func (a *app) refreshProtoUI() {
	if a.protoHint == nil {
		return
	}
	if a.login == nil {
		_ = a.protoHint.SetText("")
		return
	}
	pr := a.login.Params
	if pr.HysteriaEnabled && pr.HysteriaPort > 0 && pr.HysteriaObfs != "" {
		_ = a.protoHint.SetText(fmt.Sprintf("通道B 可用（UDP %d）", pr.HysteriaPort))
		return
	}
	_ = a.protoHint.SetText("通道B 不可用（服务端未启用）")
}

func (a *app) logout() {
	a.disconnect()
	a.stopPolling()
	a.client = nil
	a.login = nil
	a.sessionPass = ""
	a.activeProto = ""
	a.sessionBase = 0
	for _, lb := range []*walk.Label{a.upLabel, a.downLabel, a.totalLabel, a.limitLabel, a.rateLabel, a.activeLabel} {
		_ = lb.SetText("—")
	}
	// 速率采样基线也要清掉，否则下次登录时第一次采样会算出跨会话的假速率。
	a.rateReady = false
	a.rateUpEMA, a.rateDownEMA = 0, 0
	// 速率条同样要归零：它显示的是上一个会话的缓动值，留着等于展示错的数据。
	a.upBar.SetFraction(0)
	a.downBar.SetFraction(0)
	a.mainPanel.SetVisible(false)
	a.loginPanel.SetVisible(true)
	// 回到登录界面时把窗口收回紧凑尺寸，否则表单会浮在一大片空白里。
	applyPanelSize(a.mw, winWLogin, winHLogin)
	a.setLoginTip("已退出登录")
}

func (a *app) quit() {
	a.disconnect()
	a.stopPolling()
	a.quitting = true
	if a.ni != nil {
		_ = a.ni.SetVisible(false)
		_ = a.ni.Dispose()
		a.ni = nil
	}
	a.mw.Close()
}

// ---------- 界面取值 ----------
//
// 这些取值函数刻意不依赖 a.login：保存设置、TUN 检测等流程可能在登录之前就跑起来，
// 走 currentProfile 会因为解引用空指针而崩掉。

func (a *app) uiSocksPort() int {
	n, _ := strconv.Atoi(strings.TrimSpace(a.socksBox.Text()))
	if n <= 0 {
		return defaultSocks
	}
	return n
}

func (a *app) uiHTTPPort() int {
	n, _ := strconv.Atoi(strings.TrimSpace(a.httpBox.Text()))
	if n <= 0 {
		return defaultHTTP
	}
	return n
}

// uiListenAddr 返回本地代理入站该绑定的地址。
// 控件还没建出来时按「仅本机」处理，避免在界面初始化之前取值时崩溃。
func (a *app) uiListenAddr() string {
	if a.lanBox != nil && a.lanBox.Checked() {
		return common.ListenAny
	}
	return common.ListenLocal
}

// lanText 把监听地址翻译成给用户看的中文。
func lanText(addr string) string {
	if addr == common.ListenAny {
		return "0.0.0.0（同局域网设备可访问）"
	}
	return "127.0.0.1（仅本机）"
}

func (a *app) uiMode() string {
	if a.modeBox != nil && a.modeBox.CurrentIndex() == 1 {
		return common.ModeGlobal
	}
	return common.ModeSmart
}

func (a *app) uiProtocol() string {
	if a.protoBox == nil {
		return common.ProtoAuto
	}
	switch a.protoBox.CurrentIndex() {
	case 1:
		return common.ProtoReality
	case 2:
		return common.ProtoHysteria
	default:
		return common.ProtoAuto
	}
}

// protoIndex 把存档里的通道映射成下拉框下标。
func protoIndex(proto string) int {
	switch proto {
	case common.ProtoReality:
		return 1
	case common.ProtoHysteria:
		return 2
	default:
		return 0
	}
}

// uiInstanceID 返回当前选中的线路 id（登录前、或老服务端不下发线路表时为空）。
func (a *app) uiInstanceID() string {
	if a.lineBox == nil || len(a.lineIDs) == 0 {
		return ""
	}
	i := a.lineBox.CurrentIndex()
	if i < 0 || i >= len(a.lineIDs) {
		return ""
	}
	return a.lineIDs[i]
}

// onLineChanged 在用户切换线路时把选择落盘。
//
// 与「代理规则」「传输通道」两个下拉框保持一致：改完不立刻重连，下次连接时生效。
// 已连接时额外点一句，免得用户以为当场就切过去了。
func (a *app) onLineChanged() {
	a.saveSettings()
	a.refreshLineUI()
	if a.tunnel != nil && a.lineHint != nil {
		a.lineHint.SetText("已切换，重连后生效")
	}
}

// applyLines 用登录响应里的线路表重建下拉框，并尽量沿用用户上次的选择。
//
// 沿用不到（服务端撤掉了那条线路、或第一次登录）就退回第一项 —— 与 common 里
// Choose() 的兜底规则一致：宁可换一条能用的线路，也不要把用户卡在连不上。
func (a *app) applyLines() {
	if a.lineBox == nil {
		return
	}
	insts := a.login.Instances
	a.lineIDs = nil
	model := []string{}
	want := -1
	saved := a.loadSettings().InstanceID
	for i, ins := range insts {
		name := ins.Name
		if name == "" {
			name = ins.ID
		}
		a.lineIDs = append(a.lineIDs, ins.ID)
		model = append(model, name)
		if ins.ID == saved {
			want = i
		}
	}
	if len(model) == 0 {
		// 老服务端不下发线路表：留一个占位项，行为与过去完全一致。
		a.lineIDs = []string{""}
		model = []string{"默认线路"}
		want = 0
	}
	if want < 0 {
		want = 0
	}
	_ = a.lineBox.SetModel(model)
	_ = a.lineBox.SetCurrentIndex(want)
	a.refreshLineUI()
}

// refreshLineUI 在提示里说明这条线路是不是自己出网 —— 用户最关心「从哪儿出网」。
//
// 当前服务端下发的都是 exit，所以正常显示「直连出口」；relay 分支的理由同 enterMain。
func (a *app) refreshLineUI() {
	if a.lineHint == nil || a.lineBox == nil {
		return
	}
	i := a.lineBox.CurrentIndex()
	if i < 0 || i >= len(a.login.Instances) {
		a.lineHint.SetText("")
		return
	}
	ins := a.login.Instances[i]
	if !ins.IsRelay() {
		a.lineHint.SetText("直连出口")
		return
	}
	via := ins.Via
	for _, x := range a.login.Instances {
		if x.ID == ins.Via {
			via = x.Name
			break
		}
	}
	a.lineHint.SetText("经「" + via + "」出网")
}

func (a *app) currentProfile() common.Profile {
	p := a.login.ProfileFor(a.uiInstanceID(), a.uiMode(), a.uiSocksPort(), a.uiHTTPPort())
	p.Protocol = a.uiProtocol()
	p.TunMode = a.tunBox != nil && a.tunBox.Checked()
	p.ListenAddr = a.uiListenAddr()
	return p
}

func (a *app) toggleConnect() {
	if a.tunnel != nil {
		a.disconnect()
		return
	}
	a.connect()
}

func (a *app) connect() {
	if a.login == nil {
		return
	}
	p := a.currentProfile()
	a.dot.SetState(dotConnecting)
	a.connectBtn.SetEnabled(false)
	a.stateDetail.SetText("")
	a.stateLabel.SetText("正在连接…")

	// 在界面线程上把凭据取成局部变量，再交给后台协程使用：
	// sessionPass 会被改密流程改写，直接在协程里读存在数据竞争。
	username, pass := a.login.Username, a.sessionPass

	go func() {
		// 物理默认网关必须在接管路由之前读取：一旦 TUN 抢走默认路由，
		// 读到的就会是 TUN 自己，绕行路由也就无从设起。
		var setup *common.TunSetup
		if p.TunMode {
			var err error
			setup, err = common.NewTunSetup(p.ServerAddr)
			if err != nil {
				a.failConnect(err.Error())
				return
			}
			// 必须显式告诉内核：direct 出站绑定物理网卡地址。
			// 少了它，国内直连流量会被接管路由送回 TUN 形成死循环，
			// 现象就是「外网能用、国内网站全部打不开」。
			p.SendThrough = setup.PhysIP
		}

		var lastErr string
		for i, proto := range a.candidates(p) {
			pp := p
			pp.Protocol = proto
			if i > 0 {
				a.ui(func() { a.stateLabel.SetText("通道切换中…") })
			}

			tun, hys, err := a.startChain(pp, username, pass)
			if err != nil {
				lastErr = err.Error()
				continue
			}
			// 先用本地代理探一次，确认隧道真的通了，再动系统侧的设置。
			// 这样在两条通道之间回退时不会反复改路由表与系统代理，少一层出错面；
			// 也避免了「端口在监听但其实不通」被当成连接成功。
			if !common.WaitPort(pp.HTTPPort, 20*time.Second) {
				lastErr = "内核未就绪：" + common.LastErrorLine(tun.LogText(4000))
				stopAll(tun, hys)
				continue
			}
			if !common.ProbeProxy(pp.HTTPPort, 12*time.Second) {
				lastErr = common.ProtocolLabel(proto) + " 探测未通过"
				stopAll(tun, hys)
				continue
			}
			if pp.TunMode {
				// 这一步决定 TUN 是否真的生效：内核只负责建网卡，
				// 地址、DNS、路由由客户端自己配，出错也能把原因原样报出来。
				if err := setup.Apply(); err != nil {
					lastErr = "TUN 系统配置失败：" + err.Error()
					stopAll(tun, hys)
					continue
				}
			}
			a.commit(pp, tun, hys, setup)
			return
		}

		if setup != nil {
			setup.Cleanup()
		}
		if lastErr == "" {
			lastErr = "没有可用的通道"
		}
		a.failConnect(lastErr)
	}()
}

// candidates 给出本次连接的通道尝试顺序。
//
// 用户明确指定通道时只试那一条：失败了就如实报错，不偷偷换到另一条，
// 否则用户选择「通道A」却走了通道B，行为与预期不符且难以理解。
// 选「智能优选」时按隐蔽性优先尝试：REALITY 排在最前，探测不通过再退到 Hysteria2。
func (a *app) candidates(p common.Profile) []string {
	switch p.Protocol {
	case common.ProtoReality:
		return []string{common.ProtoReality}
	case common.ProtoHysteria:
		return []string{common.ProtoHysteria}
	}
	if p.HysteriaAvailable() {
		return []string{common.ProtoReality, common.ProtoHysteria}
	}
	return []string{common.ProtoReality}
}

// startChain 按所选通道拉起需要的进程。
//
// Hysteria2 是「旁挂」结构：先起 hysteria 进程，确认它的 SOCKS 端口就绪，
// 再起 xray 并把 proxy 出站指向该端口；REALITY 只需要 xray 一个进程。
// 两条通道的入站、分流、TUN 逻辑完全共用，差异只在这一个出站上。
func (a *app) startChain(p common.Profile, username, pass string) (*common.Tunnel, *common.Tunnel, error) {
	var hys *common.Tunnel
	if p.Protocol == common.ProtoHysteria {
		if !p.HysteriaAvailable() {
			return nil, nil, fmt.Errorf("服务端未下发 Hysteria2 通道参数")
		}
		h, err := common.StartHysteria(a.workDir, common.HysteriaConfig(p, username, pass))
		if err != nil {
			return nil, nil, err
		}
		hys = h
		if !common.WaitPort(p.HysteriaSocksPort, 15*time.Second) {
			msg := common.LastErrorLine(hys.LogText(4000))
			hys.Stop()
			return nil, nil, fmt.Errorf("Hysteria2 未就绪：%s", msg)
		}
	}

	tun, err := common.Start(a.workDir, common.ClientConfig(p))
	if err != nil {
		stopAll(nil, hys)
		return nil, nil, err
	}
	// TUN 起不来时（缺驱动、权限不足、网卡名冲突）内核会立刻退出。
	// 先判断进程是否还活着，就能把内核日志里的真实原因直接摆出来，
	// 而不是让用户干等一个含糊的端口超时。
	time.Sleep(1200 * time.Millisecond)
	if !tun.Alive() {
		msg := common.LastErrorLine(tun.LogText(4000))
		stopAll(tun, hys)
		return nil, nil, fmt.Errorf("%s", msg)
	}
	return tun, hys, nil
}

// stopAll 收掉一次尝试里拉起的进程。
// 每次尝试都必须彻底清理，否则残留进程会占着端口，
// 让下一次尝试的端口探测「假成功」而实际用的是旧进程。
func stopAll(tun, hys *common.Tunnel) {
	if tun != nil {
		tun.Stop()
	}
	if hys != nil {
		hys.Stop()
	}
}

// commit 在探测通过后落地系统侧设置并刷新界面。
func (a *app) commit(p common.Profile, tun, hys *common.Tunnel, setup *common.TunSetup) {
	a.ui(func() {
		a.snap = common.SnapshotProxy()
		a.hasSnap = true
		// 任何改动系统代理的分支之前，先把原始设置落盘并登记「登录时还原」。
		// 这样即使进程被强杀、或用户开着客户端直接关机，下次开机登录也会
		// 自动把系统代理还原回去，不会留下「必须开着客户端才有网」的死局。
		// 顺序很关键：备份必须早于注册表改动。
		a.persistProxyBackup()
		if p.TunMode {
			// TUN 已经接管全部流量，系统代理再叠一层只会让链路更绕，
			// 所以显式关掉它（断开时按快照还原）。
			_ = common.DisableSystemProxy()
		} else if err := common.EnableSystemProxy(p.HTTPPort); err != nil {
			stopAll(tun, hys)
			if setup != nil {
				setup.Cleanup()
			}
			a.dot.SetState(dotError)
			a.stateLabel.SetText("连接失败：系统代理设置失败 " + err.Error())
			return
		}

		a.tunnel = tun
		a.hysteria = hys
		a.tunnelIsTun = p.TunMode
		a.tunSetup = setup
		a.activeProto = p.Protocol
		// 记录连接瞬间的累计用量，用于算「本次」用量。
		if t, err := a.client.Traffic(a.login.Token); err == nil {
			a.mu.Lock()
			a.sessionBase = t.UsedBytes
			a.mu.Unlock()
		}
		a.dot.SetState(dotConnected)
		a.connectBtn.SetStyle(btnDanger)
		a.connectBtn.SetEnabled(true)
		a.stateLabel.SetText("已连接")
		if p.TunMode {
			a.stateDetail.SetText(fmt.Sprintf("TUN 全局接管（IPv4 走隧道、IPv6 走本机）· %s · 通道 %s · 规则：%s",
				setup.Describe(), common.ProtocolLabel(p.Protocol), common.ModeLabel(p.Mode)))
		} else {
			a.stateDetail.SetText(fmt.Sprintf("本地代理 %s:%d（HTTP）/ %d（SOCKS）· 通道 %s · 规则：%s",
				a.uiListenAddr(), p.HTTPPort, p.SocksPort, common.ProtocolLabel(p.Protocol), common.ModeLabel(p.Mode)))
		}
		a.connectBtn.SetText("断开")
		a.refreshTraffic()
	})
}

// persistProxyBackup 把改动前的系统代理设置落盘，并登记登录时的一次性还原。
// 备份或登记失败只记录到状态栏，不阻断连接：这两步是「异常退出后的补救」，
// 正常退出路径本来就靠内存快照还原。
func (a *app) persistProxyBackup() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	if err := common.SaveProxyBackup(a.workDir, a.snap); err != nil {
		return
	}
	// 备份文件无论如何都要写：本程序启动时的那次补还原（run 开头）靠它才能
	// 精确回到改动前的设置。受用户开关控制的是**登录时**那条一次性启动项。
	if a.cleanOnBootEnabled() {
		_ = common.RegisterProxyRecovery(exe, a.workDir)
	}
}

// cleanOnBootEnabled 读取「开机自动清理系统代理」当前是否启用。
// 界面尚未建起来时（例如静默的 -restore-proxy 路径）回落到设置文件。
func (a *app) cleanOnBootEnabled() bool {
	if a.cleanBox != nil {
		return a.cleanBox.Checked()
	}
	return a.loadSettings().cleanOnBoot()
}

// syncStartupOptions 把启动选项落到系统上（写注册表，不产生任何子进程）。
//
// 时间点选在「启动时」与「保存设置时」两处：前者修正历史遗留，
// 后者让用户一勾就生效，不用重启程序。
func (a *app) syncStartupOptions(st settings) {
	// 「自动最小化」依赖「自动连接」，先把两者的可用状态重算一遍，
	// 免得界面停在「显示成可勾、其实不生效」的状态。
	a.onStartupOptionToggle()

	exe, err := os.Executable()
	if err != nil {
		return
	}
	if err := common.SetAutoStart(exe, a.workDir, st.AutoStart); err != nil {
		a.setLoginTip("设置开机自启失败：" + err.Error())
	}
	if st.cleanOnBoot() {
		if err := common.RegisterProxyRecovery(exe, a.workDir); err != nil {
			a.setLoginTip("登记代理还原启动项失败：" + err.Error())
		}
	} else {
		// 关掉时必须把已登记的项撤掉。只改设置文件是不够的：
		// 注册表里那条还在，系统下次登录照样会执行，用户会认为这个开关根本没用。
		common.UnregisterProxyRecovery()
	}
}

// onStartupOptionToggle 维护「启动后最小化」对「启动后自动连接」的依赖。
//
// 只有「自动连接」开着时，「自动最小化」才可用；依赖项一关，就顺手把
// 子选项也取消掉——留一个勾着却不生效的复选框，比直接禁用它更让人迷惑。
func (a *app) onStartupOptionToggle() {
	if a.minimizeBox == nil || a.autoConnBox == nil {
		return
	}
	on := a.autoConnBox.Checked()
	// SetEnabled 会让复选框连同文字一起变灰，用户一眼能看出「现在还不能选」。
	a.minimizeBox.SetEnabled(on)
	if !on && a.minimizeBox.Checked() {
		a.minimizeBox.SetChecked(false)
	}
}

// failConnect 统一处理「所有通道都没连上」的收尾。
func (a *app) failConnect(msg string) {
	a.ui(func() {
		// 失败后必须把按钮放开：连接过程中它是禁用的，不解开用户就没法重试。
		a.dot.SetState(dotError)
		a.connectBtn.SetEnabled(true)
		a.stateLabel.SetText("连接失败")
		a.stateDetail.SetText(msg)
	})
}

func (a *app) disconnect() {
	if a.tunnel == nil && a.hysteria == nil {
		return
	}
	wasTun := a.tunnelIsTun
	if a.tunnel != nil {
		a.tunnel.Stop()
	}
	// 第二条通道是独立进程，xray 退出不会带走它，必须单独收掉，
	// 否则它会一直占着 SOCKS 端口并保持着到服务器的 QUIC 连接。
	if a.hysteria != nil {
		a.hysteria.Stop()
		a.hysteria = nil
	}
	// 虚拟网卡会随内核进程一起消失，但自己加的静态路由不会，必须显式回收，
	// 否则残留的接管路由会让断开后依然上不了网。
	if a.tunSetup != nil {
		a.tunSetup.Cleanup()
		a.tunSetup = nil
	}
	// 断开后自检默认路由还在不在。TUN 这一路必然改动系统路由表，
	// 任何环节出错都可能让用户陷入「能开机但上不了网」，这种故障必须当场喊出来，
	// 而不是让用户自己去猜。
	if wasTun && !common.HasDefaultRoute() {
		walk.MsgBox(a.mw, "注意：系统缺少默认路由",
			"检测到当前没有 IPv4 默认路由，可能无法上网。\r\n\r\n"+
				"可在管理员命令行执行下面这条恢复（网关地址请换成你自己的，\r\n"+
				"在网卡属性或 ipconfig 里能查到）：\r\n\r\n"+
				"route add 0.0.0.0 mask 0.0.0.0 <你的网关> metric 1\r\n\r\n"+
				"若需要重启后依然生效，加上 -p 参数。",
			walk.MsgBoxIconWarning)
	}
	a.tunnel = nil
	a.tunnelIsTun = false
	// TUN 模式下虚拟网卡和它带来的路由会随内核进程一起消失，
	// 这里只需要把连接时关掉的系统代理按快照还原。
	if a.hasSnap {
		common.RestoreProxy(a.snap)
		// 还原成功后再撤掉备份与登录启动项：先撤后还原的话，
		// 中间一旦失败就再也没有第二次机会补还原了。
		common.ClearProxyBackup(a.workDir)
		common.UnregisterProxyRecovery()
		a.hasSnap = false
	} else {
		_ = common.DisableSystemProxy()
	}
	a.connectBtn.SetText("连接")
	a.connectBtn.SetStyle(btnPrimary)
	a.connectBtn.SetEnabled(true)
	a.dot.SetState(dotIdle)
	a.stateLabel.SetText("未连接")
	if wasTun {
		a.stateDetail.SetText("已断开，虚拟网卡与路由已随内核退出而回收")
	} else {
		a.stateDetail.SetText("系统代理已还原")
	}
}

// ---------- TUN 环境 ----------

// initTun 在启动时检测 TUN 环境：不就绪就明确告知并引导安装，一切就绪则不打扰用户。
func (a *app) initTun() {
	// 驱动内嵌在 exe 内，先释放到工作目录，这一步就是「安装」的第一半。
	if err := common.EnsureTunDriver(a.workDir); err != nil {
		a.tunErr = err.Error()
	}
	a.refreshTunUI()

	if common.Elevated() || a.tunErr != "" || !a.loadSettings().TunMode {
		return
	}
	// 要弹的确认框挂在主窗口上；勾了「启动后自动最小化到托盘」时窗口是隐藏的，
	// 对话框跟着一起看不见，整个程序就卡在一个用户根本看不到的问题上。
	// 要问问题就得先把窗口亮出来。
	if !a.mw.Visible() {
		a.showWindow()
	}
	// 上次开着 TUN、这次却没提权，问一次是否提权重启；拒绝就退回普通代理模式。
	choice := walk.MsgBox(a.mw, "启用 TUN 模式需要管理员权限",
		"TUN 模式需要创建虚拟网卡，必须以管理员身份运行。\r\n\r\n"+
			"是否现在以管理员身份重新启动客户端？\r\n"+
			"选择「否」仍可使用普通代理模式，只是无法启用 TUN。",
		walk.MsgBoxYesNo|walk.MsgBoxIconQuestion)
	if choice == walk.DlgCmdYes && common.Elevate("-elevated", "-dir", a.workDir) {
		a.quit()
		return
	}
	// 用户没同意提权：TUN 这次确实用不了，就别留着一个勾着却连不上的状态。
	// 注意这句只在「用户拒绝」这条路径上执行——原来它写在判断之前，
	// 于是每次启动都会把用户的 TUN 勾选悄悄取消掉并写盘。
	a.tunBox.SetChecked(false)
	a.saveSettings()
	a.refreshTunUI()
}

// refreshTunUI 同步 TUN 相关控件的提示文字。
func (a *app) refreshTunUI() {
	if a.tunHint == nil {
		return
	}
	txt := common.TunStatusText(a.workDir)
	if a.tunErr != "" {
		txt = "驱动不可用：" + a.tunErr
	}
	_ = a.tunHint.SetText(txt)
}

// onTunToggle 处理勾选：环境不就绪时先走安装或提权，成功后勾选才真正生效。
func (a *app) onTunToggle() {
	if a.tunBox == nil {
		return
	}
	if !a.tunBox.Checked() || common.TunReady(a.workDir) {
		a.refreshTunUI()
		a.saveSettings()
		return
	}
	a.onInstallTun()
	if !common.TunReady(a.workDir) {
		// 没装成就不要留下一个勾着却连不上的状态。
		a.tunBox.SetChecked(false)
	}
	a.refreshTunUI()
	a.saveSettings()
}

// onInstallTun 安装或修复虚拟网卡驱动。驱动已内嵌在 exe 中，实际动作是释放并校验。
func (a *app) onInstallTun() {
	if !common.Elevated() {
		if walk.MsgBox(a.mw, "需要管理员权限",
			"安装虚拟网卡驱动需要管理员权限。\r\n\r\n是否现在以管理员身份重新启动客户端？",
			walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) == walk.DlgCmdYes {
			if common.Elevate("-elevated", "-dir", a.workDir) {
				a.quit()
			}
		}
		return
	}
	if walk.MsgBox(a.mw, "安装虚拟网卡驱动",
		"将从客户端内置资源安装虚拟网卡驱动：\r\n"+
			"wintun v0.14.1，约 420KB，签名方 WireGuard LLC。\r\n\r\n"+
			"安装后会创建一块名为 TransProxy 的虚拟网卡，\r\n"+
			"它只在 TUN 模式连接期间存在，断开时自动回收。\r\n\r\n是否继续？",
		walk.MsgBoxYesNo|walk.MsgBoxIconQuestion) != walk.DlgCmdYes {
		return
	}
	if err := common.EnsureTunDriver(a.workDir); err != nil {
		a.tunErr = err.Error()
	} else {
		a.tunErr = ""
	}
	a.refreshTunUI()
	if common.TunReady(a.workDir) {
		walk.MsgBox(a.mw, "完成", "虚拟网卡环境已就绪，现在可以勾选 TUN 模式。", walk.MsgBoxIconInformation)
		return
	}
	walk.MsgBox(a.mw, "未能就绪",
		"环境仍未就绪："+common.TunStatusText(a.workDir)+"\r\n\r\n"+
			"若反复失败，请确认客户端确实以管理员身份运行，\r\n"+
			"并检查安全软件是否拦截了对系统目录的写入。",
		walk.MsgBoxIconWarning)
}

// ---------- 流量轮询 ----------

func (a *app) startPolling() {
	a.stopPolling()
	stop := make(chan struct{})
	a.mu.Lock()
	a.pollStop = stop
	a.mu.Unlock()
	go func() {
		t := time.NewTicker(pollEvery)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-t.C:
				a.refreshTraffic()
			}
		}
	}()
}

func (a *app) stopPolling() {
	a.mu.Lock()
	if a.pollStop != nil {
		close(a.pollStop)
		a.pollStop = nil
	}
	a.mu.Unlock()
}

func (a *app) refreshTraffic() {
	if a.client == nil || a.login == nil {
		return
	}
	cli, tok := a.client, a.login.Token
	a.mu.Lock()
	base := a.sessionBase
	a.mu.Unlock()

	go func() {
		t, err := cli.Traffic(tok)
		if err != nil {
			return
		}
		a.ui(func() {
			session := t.UsedBytes - base
			if session < 0 {
				session = 0
			}
			a.upLabel.SetText(humanBytes(t.SessionUp))
			a.downLabel.SetText(humanBytes(t.SessionDown))
			a.totalLabel.SetText(humanBytes(t.UsedBytes))
			if t.QuotaBytes > 0 {
				a.limitLabel.SetText(fmt.Sprintf("%s / %s", humanBytes(t.RemainingBytes), humanBytes(t.QuotaBytes)))
			} else {
				a.limitLabel.SetText("不限量")
			}
			a.updateRate(t.SessionUp, t.SessionDown)
			// 内核没有可用的在线数统计（策略里也无对应开关），改用「最近活动时间」：
			// 同样能回答「现在有人在用吗」，而且是真实观测到的数据。
			a.activeLabel.SetText(common.SinceText(t.LastActive))
			if a.tunnel != nil {
				loc := fmt.Sprintf("本地代理 %s:%d", a.uiListenAddr(), a.uiHTTPPort())
				if a.tunnelIsTun {
					loc = "TUN 全局接管"
				}
				a.stateDetail.SetText(fmt.Sprintf("已连接 · 通道 %s · 本次用量 %s · %s",
					common.ProtocolLabel(a.activeProto), humanBytes(session), loc))
			}
		})
	}()
}

// ---------- 设置 / 改密 ----------

func (a *app) applySettings() {
	if a.client == nil {
		return
	}
	a.saveSettings()
	wasConnected := a.tunnel != nil
	if wasConnected {
		a.disconnect()
	}
	walk.MsgBox(a.mw, "已保存",
		fmt.Sprintf("设置已保存。\r\n模式：%s\r\n本地端口：HTTP %s / SOCKS %s\r\n监听地址：%s",
			common.ModeLabel(a.currentProfile().Mode),
			strings.TrimSpace(a.httpBox.Text()), strings.TrimSpace(a.socksBox.Text()),
			lanText(a.uiListenAddr())),
		walk.MsgBoxIconInformation)
	if wasConnected {
		a.connect()
	}
}

func (a *app) changePassword() {
	if a.client == nil || a.login == nil {
		return
	}
	oldPw := a.oldPassBox.Text()
	newPw := a.newPassBox.Text()
	if oldPw == "" || newPw == "" {
		walk.MsgBox(a.mw, "提示", "请填写原密码与新密码。", walk.MsgBoxIconWarning)
		return
	}
	if len(newPw) < 6 {
		walk.MsgBox(a.mw, "提示", "新密码至少 6 位。", walk.MsgBoxIconWarning)
		return
	}
	cli, tok, user := a.client, a.login.Token, a.login.Username
	wasConnected := a.tunnel != nil

	go func() {
		if err := cli.ChangePassword(tok, oldPw, newPw); err != nil {
			a.ui(func() { walk.MsgBox(a.mw, "修改失败", err.Error(), walk.MsgBoxIconError) })
			return
		}
		// 改密后必须立刻把新密码同步到登录界面与存档：
		// 否则用户下次看到的还是旧密码，会一直登不上且不明白为什么。
		a.ui(func() {
			_ = a.passBox.SetText(newPw)
			_ = a.oldPassBox.SetText("")
			_ = a.newPassBox.SetText("")
			// 本会话的明文密码也要跟着换：Hysteria2 认证用的是它，
			// 不改就会出现「REALITY 能连、切到通道B 认证被拒」的怪现象。
			a.sessionPass = newPw
			a.saveCredentials(user, newPw)
			a.saveSettings()
		})
		// 改密会更换账号的连接身份，必须重新登录才能拿到新的连接参数。
		res, err := cli.Login(user, newPw)
		a.ui(func() {
			if err != nil {
				walk.MsgBox(a.mw, "已修改但要重新登录", "密码已修改成功，请重新登录。", walk.MsgBoxIconInformation)
				a.logout()
				return
			}
			if wasConnected {
				a.disconnect()
			}
			a.login = res
			_ = a.oldPassBox.SetText("")
			_ = a.newPassBox.SetText("")
			a.accountLabel.SetText(fmt.Sprintf("账号：%s", res.Username))
			walk.MsgBox(a.mw, "已修改", "密码已修改，旧连接参数已失效，正在使用新身份重新连接。", walk.MsgBoxIconInformation)
			if wasConnected {
				a.connect()
			}
		})
	}()
}

// ---------- 界面小工具 ----------

func (a *app) ui(fn func()) {
	if a.mw != nil {
		a.mw.Synchronize(fn)
	}
}

func (a *app) setLoginTip(s string) {
	if a.loginTip != nil {
		_ = a.loginTip.SetText(s)
	}
}

func (a *app) settingsPath() string {
	return filepath.Join(a.workDir, "client-settings.json")
}

// ownProxyPorts 列出台客户端自己会监听的本机端口。
// 用于判断「系统代理指向的那个死端口」是不是我方留下的，避免误关用户自己的代理。
func (a *app) ownProxyPorts(st settings) []int {
	ports := []int{st.SocksPort, st.HTTPPort, common.DefaultHysteriaSocksPort}
	out := ports[:0]
	for _, p := range ports {
		if p > 0 {
			out = append(out, p)
		}
	}
	return out
}

func (a *app) loadSettings() settings {
	st := settings{Host: defaultHost, APIPort: defaultAPIPort, SocksPort: defaultSocks, HTTPPort: defaultHTTP, Mode: common.ModeSmart}
	if b, err := os.ReadFile(a.settingsPath()); err == nil {
		_ = json.Unmarshal(b, &st)
	}
	if st.Host == "" {
		st.Host = defaultHost
	}
	if st.APIPort == 0 {
		st.APIPort = defaultAPIPort
	}
	if st.Mode == "" {
		st.Mode = common.ModeSmart
	}
	if st.Protocol == "" {
		st.Protocol = common.ProtoAuto
	}
	if !common.TunReady(a.workDir) {
		// 环境不就绪时不要沿用上次的 TUN 选择：否则下次打开会直奔一个注定失败的连接。
		st.TunMode = false
	}
	return st
}

func (a *app) saveSettings() {
	// 界面没建起来时（理论上不该走到这）沿用存档里的值，
	// 而不是凭空造一个：否则一次无关的保存就会把用户的选择覆盖掉。
	clean := a.loadSettings().cleanOnBoot()
	if a.cleanBox != nil {
		clean = a.cleanBox.Checked()
	}
	st := settings{
		Host:      strings.TrimSpace(a.hostBox.Text()),
		User:      strings.TrimSpace(a.userBox.Text()),
		SocksPort: a.uiSocksPort(),
		HTTPPort:  a.uiHTTPPort(),
		AllowLAN:  a.uiListenAddr() == common.ListenAny,
		Mode:      a.uiMode(),
		Protocol:  a.uiProtocol(),
		TunMode:   a.tunBox != nil && a.tunBox.Checked(),
		// 线路只记 id：线路表每次登录由服务端下发（见 settings.InstanceID 的说明）。
		InstanceID: a.uiInstanceID(),

		RememberPass: a.rememberBox != nil && a.rememberBox.Checked(),
		AutoLogin:    a.autoLoginBox != nil && a.autoLoginBox.Checked(),
		PassEnc:      a.savedPassEnc,
		CloseAction:  a.closeAction,

		CleanOnBoot: &clean,
		AutoStart:   a.autoStartBox != nil && a.autoStartBox.Checked(),
		AutoConnect: a.autoConnBox != nil && a.autoConnBox.Checked(),
		// 「自动最小化」在保存时再核对一次依赖：依赖项没勾，就不落盘成 true。
		// 否则设置文件里会留下一个永远不生效的 true，下次启动读出来还是假的。
		MinimizeOnStart: minimizeAllowed(
			a.autoConnBox != nil && a.autoConnBox.Checked(),
			a.minimizeBox != nil && a.minimizeBox.Checked(),
		),
	}
	st.APIPort, _ = strconv.Atoi(strings.TrimSpace(a.apiPortBox.Text()))
	if st.APIPort == 0 {
		st.APIPort = defaultAPIPort
	}
	if err := os.MkdirAll(a.workDir, 0o755); err != nil {
		return
	}
	if b, err := json.MarshalIndent(st, "", "  "); err == nil {
		_ = os.WriteFile(a.settingsPath(), b, 0o644)
	}
	// 立刻把开关落到系统上：用户勾完就想生效，不该等到下次启动。
	a.syncStartupOptions(st)
}

// ---------- 速率 ----------

// updateRate 用客户端自己两次采样的差除以真实间隔来算速率。
//
// 之前直接显示服务端下发的速率：服务端按自己的 5 秒窗口算平均，客户端每 5 秒去取一次，
// 两个周期一旦错拍，就会连续读到同一个值——表现为一次显示 0、下一次翻倍，
// 用户看到的数字自然和实际流量对不上。改成自己量自己的，就不存在错拍。
// 再做一次轻度指数平滑：单次采样本身带抖动，不平滑会跳得看不清。
func (a *app) updateRate(up, down int64) {
	now := time.Now()
	if !a.rateReady {
		a.ratePrevUp, a.ratePrevDown, a.ratePrevAt, a.rateReady = up, down, now, true
		return
	}
	dt := now.Sub(a.ratePrevAt).Seconds()
	if dt < 0.4 {
		return
	}
	du := float64(up-a.ratePrevUp) / dt
	dd := float64(down-a.ratePrevDown) / dt
	if du < 0 || dd < 0 {
		// 计数回绕或服务端重启：重置基线，别显示负数。
		a.ratePrevUp, a.ratePrevDown, a.ratePrevAt = up, down, now
		return
	}
	const alpha = 0.45
	if a.rateUpEMA == 0 && a.rateDownEMA == 0 {
		a.rateUpEMA, a.rateDownEMA = du, dd
	} else {
		a.rateUpEMA = a.rateUpEMA*(1-alpha) + du*alpha
		a.rateDownEMA = a.rateDownEMA*(1-alpha) + dd*alpha
	}
	a.ratePrevUp, a.ratePrevDown, a.ratePrevAt = up, down, now
	a.upBar.SetFraction(rateFraction(a.rateUpEMA))
	a.downBar.SetFraction(rateFraction(a.rateDownEMA))
	a.rateLabel.SetText(fmt.Sprintf("↑ %s/s   ↓ %s/s",
		humanBytes(int64(a.rateUpEMA)), humanBytes(int64(a.rateDownEMA))))
}

// ---------- 关闭行为 ----------

// askClose 询问关闭方式，并允许记住选择。
// 自己画这个对话框而不用 MsgBox：MsgBox 承载不了「记住我的选择」这个勾选项。
func (a *app) askClose() {
	var win *walk.Dialog
	var remember *walk.CheckBox
	choice := ""
	if err := (declarative.Dialog{
		AssignTo: &win,
		Title:    "关闭 " + appName,
		Size:     declarative.Size{Width: 370, Height: 205},
		Layout:   declarative.VBox{},
		Children: []declarative.Widget{
			declarative.Label{Text: "要最小化到托盘继续运行，还是直接退出程序？"},
			declarative.Composite{
				Layout: declarative.HBox{},
				Children: []declarative.Widget{
					declarative.PushButton{
						Text:      "最小化到托盘",
						MinSize:   declarative.Size{Width: 135, Height: 34},
						OnClicked: func() { choice = closeToTray; win.Accept() },
					},
					declarative.PushButton{
						Text:      "退出程序",
						MinSize:   declarative.Size{Width: 110, Height: 34},
						OnClicked: func() { choice = closeToExit; win.Accept() },
					},
					declarative.HSpacer{},
				},
			},
			declarative.CheckBox{AssignTo: &remember, Text: "记住我的选择，下次不再询问"},
			declarative.PushButton{Text: "取消", OnClicked: func() { win.Cancel() }},
		},
	}).Create(a.mw); err != nil {
		// 连对话框都建不出来时，退回最安全的动作：留在托盘，别把用户的代理断掉。
		a.mw.Hide()
		return
	}
	win.Run()
	switch choice {
	case closeToTray:
		if remember.Checked() {
			a.setCloseAction(closeToTray)
		}
		a.mw.Hide()
	case closeToExit:
		if remember.Checked() {
			a.setCloseAction(closeToExit)
		}
		a.quit()
	}
}

func (a *app) setCloseAction(v string) {
	a.closeAction = v
	a.saveSettings()
}

// ---------- 凭据 ----------

// saveCredentials 按「记住密码」的勾选状态保存或清除密码。
// 存的是 DPAPI 加密结果（见 common.Protect），不是明文。
func (a *app) saveCredentials(user, pass string) {
	if a.rememberBox == nil || !a.rememberBox.Checked() || pass == "" {
		a.savedPassEnc = ""
		return
	}
	enc, err := common.Protect(pass)
	if err != nil {
		a.savedPassEnc = ""
		return
	}
	a.savedPassEnc = enc
}

func humanBytes(n int64) string {
	if n < 0 {
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
