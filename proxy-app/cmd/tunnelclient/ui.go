package main

import (
	"math"
	"sync"
	"time"
	"unsafe"

	"github.com/lxn/walk"
	declarative "github.com/lxn/walk/declarative"
	"github.com/lxn/win"
)

// 浅色主题与自绘动画控件。
//
// 为什么大部分界面元素要自绘：walk 是对 Win32 的薄封装，原生控件的配色完全
// 跟随系统主题——在浅色画布上会看到灰底按钮、灰底分组框，与设计不搭。而内核
// 只提供画布（Canvas）级的绘制能力，所以想做出「卡片 + 强调色 + 动效」的效果，
// 只能自己画。这里把用到的几种控件集中在一个文件里，避免散落到各处以减少重复。

// ---------- 配色 ----------
//
// 只保留一个强调色（蓝），成功/危险各一个语义色；其余全部是中性灰阶。
// 颜色数量少，界面才不像调色板。

var (
	colWindowBG  = walk.RGB(0xF4, 0xF6, 0xFA)
	colCard      = walk.RGB(0xFF, 0xFF, 0xFF)
	colText      = walk.RGB(0x1F, 0x24, 0x30)
	colTextDim   = walk.RGB(0x6B, 0x72, 0x80)
	colTextFaint = walk.RGB(0x9C, 0xA4, 0xB2)
	colAccent    = walk.RGB(0x2F, 0x6B, 0xFF)
	colAccentDim = walk.RGB(0x23, 0x54, 0xD6)
	colGreen     = walk.RGB(0x16, 0xB3, 0x64)
	colRed       = walk.RGB(0xE5, 0x48, 0x4D)
	colRedDim    = walk.RGB(0xC9, 0x3A, 0x3F)
	colGray      = walk.RGB(0xC7, 0xCC, 0xD6)
	colTrack     = walk.RGB(0xEC, 0xEF, 0xF4)
	colNotice    = walk.RGB(0x8A, 0x5A, 0x00)
)

// uiFamily 是界面字体。微软雅黑 UI 从 Win7 起随系统提供；
// 万一缺失，CreateFontIndirect 会自动替换，不会导致绘制失败。
const uiFamily = "Microsoft YaHei UI"

// themeSet 是绘制用的画刷集合。
//
// 这些画刷只创建一次、进程内一直复用：绘制函数每秒会被调用几十次，
// 每帧新建再释放画刷会造成大量无谓的 GDI 对象创建与销毁。
type themeSet struct {
	windowBG, card, track                         walk.Brush
	accent, accentDim, accentDisabled, accentSoft walk.Brush
	green, greenSoft                              walk.Brush
	red, redDim, redSoft                          walk.Brush
	gray                                          walk.Brush
}

var (
	themeOnce sync.Once
	themeVal  *themeSet
)

func theme() *themeSet {
	themeOnce.Do(func() {
		mk := func(c walk.Color) walk.Brush {
			b, err := walk.NewSolidColorBrush(c)
			if err != nil {
				// 拿不到画刷就退回空画刷：绘制函数会「什么都不画」，
				// 但绝不会因为空句柄而崩溃。
				return walk.NullBrush()
			}
			return b
		}
		themeVal = &themeSet{
			windowBG:       mk(colWindowBG),
			card:           mk(colCard),
			track:          mk(colTrack),
			accent:         mk(colAccent),
			accentDim:      mk(colAccentDim),
			accentDisabled: mk(walk.RGB(0xC3, 0xD3, 0xFF)),
			accentSoft:     mk(walk.RGB(0xDD, 0xE6, 0xFF)),
			green:          mk(colGreen),
			greenSoft:      mk(walk.RGB(0xD6, 0xF5, 0xE5)),
			red:            mk(colRed),
			redDim:         mk(colRedDim),
			redSoft:        mk(walk.RGB(0xFC, 0xE0, 0xE0)),
			gray:           mk(colGray),
		}
	})
	return themeVal
}

// ---------- 动画调度 ----------

// animated 是可以自行推进一帧的控件。
type animated interface {
	// advance 推进一帧并返回是否需要重绘。返回 false 表示本帧没有变化，
	// 调度器据此判断「已经没有东西在动」，从而把定时器停下来。
	advance() bool
	animatedWidget() *walk.CustomWidget
}

const frameInterval = 40 * time.Millisecond

// animator 用一条定时器统一驱动所有动画控件。
//
// 用单一定时器而不是每个控件各开一个 goroutine：一帧内所有控件同步推进，
// 而且能在「没有动画需求」时整体停下——客户端经常挂在托盘里好几个小时，
// 那时不该还有 25fps 的重绘在跑。
type animator struct {
	mw    *walk.MainWindow
	items []animated

	mu   sync.Mutex
	on   bool
	stop chan struct{}
}

// animatorRef 是当前窗口的调度器。
//
// 做成包级变量是为了让自绘控件能主动「唤醒」动画（例如流量突然从 0 开始），
// 而不必把调度器引用穿过每一个控件的构造参数。
var animatorRef *animator

func (an *animator) add(items ...animated) {
	an.items = append(an.items, items...)
}

// wake 在动画可能重新变得需要时启动定时器；已在运行则什么都不做。
func (an *animator) wake() {
	if an == nil || an.mw == nil {
		return
	}
	an.mu.Lock()
	defer an.mu.Unlock()
	if an.on {
		return
	}
	an.on = true
	stop := make(chan struct{})
	an.stop = stop
	go an.loop(stop)
}

func (an *animator) pause() {
	an.mu.Lock()
	defer an.mu.Unlock()
	if !an.on {
		return
	}
	an.on = false
	close(an.stop)
}

func (an *animator) loop(stop chan struct{}) {
	t := time.NewTicker(frameInterval)
	defer t.Stop()
	idle := 0
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			changed := false
			// 必须回到界面线程再重绘：walk 的控件不是线程安全的。
			an.mw.Synchronize(func() {
				if !an.mw.Visible() {
					// 挂在托盘里时不推进动画，省下全部重绘开销。
					return
				}
				for _, it := range an.items {
					if it.advance() {
						changed = true
						if w := it.animatedWidget(); w != nil {
							w.Invalidate()
						}
					}
				}
			})
			if changed {
				idle = 0
				continue
			}
			idle++
			if idle >= 12 { // 约半秒都没有变化，就停下定时器
				an.pause()
				return
			}
		}
	}
}

// wakeAnimator 由自绘控件调用，把可能已经停下的调度器重新唤醒。
func wakeAnimator() {
	if animatorRef != nil {
		animatorRef.wake()
	}
}

// ---------- 状态指示点 ----------

type dotState int

const (
	dotIdle dotState = iota
	dotConnecting
	dotConnected
	dotError
)

// statusDot 是连接状态的呼吸点。
//
// 用「在圆点后面叠一个浅色光晕、半径随时间变化」来表现动效：
// GDI 没有 alpha 通道，用透明度做淡出并不可行，而浅色实心光晕叠在白色卡片上
// 视觉效果几乎等价，且不依赖任何混合 API。
type statusDot struct {
	w     *walk.CustomWidget
	state dotState
	phase float64
}

func (d *statusDot) animatedWidget() *walk.CustomWidget { return d.w }

func (d *statusDot) SetState(s dotState) {
	if d.state == s {
		return
	}
	d.state = s
	d.phase = 0
	d.invalidate()
	if s == dotConnecting || s == dotConnected {
		wakeAnimator()
	}
}

func (d *statusDot) invalidate() {
	if d.w != nil {
		d.w.Invalidate()
	}
}

func (d *statusDot) advance() bool {
	switch d.state {
	case dotConnecting:
		d.phase += 1.0 / 26 // 约 1 秒一个脉冲
	case dotConnected:
		d.phase += 1.0 / 66 // 约 2.6 秒一次呼吸，刻意放慢，不抢注意力
	default:
		// 未连接与失败态是静止的：没有变化就没有必要重绘。
		return false
	}
	for d.phase >= 1 {
		d.phase -= 1
	}
	return true
}

func (d *statusDot) paint(c *walk.Canvas, _ walk.Rectangle) error {
	if d.w == nil {
		return nil
	}
	rc := d.w.ClientBoundsPixels()
	if rc.Width <= 0 || rc.Height <= 0 {
		return nil
	}
	th := theme()
	// PaintBuffered 模式不做背景擦除，必须自己把整块铺满，
	// 否则上一帧的图形会残留在下面。
	if err := c.FillRectanglePixels(th.card, rc); err != nil {
		return err
	}

	cx := float64(rc.Width) / 2
	cy := float64(rc.Height) / 2
	base := math.Min(float64(rc.Width), float64(rc.Height))/2 - 9
	if base < 5 {
		base = 5
	}

	var halo walk.Brush
	core := th.gray
	coreR := base * 0.74
	haloR := 0.0

	switch d.state {
	case dotConnecting:
		halo, core = th.accentSoft, th.accent
		coreR = base * (0.84 + 0.16*math.Sin(2*math.Pi*d.phase))
		haloR = base + 3 + d.phase*7
	case dotConnected:
		halo, core = th.greenSoft, th.green
		coreR = base * (0.90 + 0.10*math.Sin(2*math.Pi*d.phase))
		haloR = base + 4
	case dotError:
		halo, core = th.redSoft, th.red
		coreR = base * 0.86
		haloR = base + 3
	}

	if haloR > 0 {
		if err := c.FillEllipsePixels(halo, circleRect(cx, cy, haloR)); err != nil {
			return err
		}
	}
	return c.FillEllipsePixels(core, circleRect(cx, cy, coreR))
}

func circleRect(cx, cy, r float64) walk.Rectangle {
	return walk.Rectangle{
		X:      int(cx - r),
		Y:      int(cy - r),
		Width:  int(2*r + 0.5),
		Height: int(2*r + 0.5),
	}
}

// barFullRate 是速率条的「满格」速率。10MB/s 已经高于绝大多数实际使用场景，
// 拿它当满格基准，日常浏览时进度条不会一直顶在满格。
const barFullRate = 10 * 1024 * 1024

// rateFraction 把字节/秒换算成 0..1 的条长。
//
// 用平方根而不是线性：线性映射下 100KB/s 只有满格的 1%，几乎看不见，
// 而「此刻有没有流量」比「精确的比例」重要得多，平方根能把低速段拉开。
func rateFraction(bps float64) float64 {
	if bps <= 0 || math.IsNaN(bps) {
		return 0
	}
	f := bps / barFullRate
	if f >= 1 {
		return 1
	}
	return math.Sqrt(f)
}

// ---------- 速率条 ----------

// meterBar 是带缓动的速率条。
//
// 直接按每次采样画条会让它一跳一跳的（采样本身有抖动），所以显示值以指数方式
// 追向目标值：既跟得上真实变化，又不会帧间突跳。
type meterBar struct {
	w     *walk.CustomWidget
	fill  walk.Brush
	want  float64 // 目标比例 0..1
	shown float64 // 缓动后的显示值
}

func (m *meterBar) animatedWidget() *walk.CustomWidget { return m.w }

func (m *meterBar) SetFraction(f float64) {
	if math.IsNaN(f) {
		f = 0
	}
	if f < 0 {
		f = 0
	}
	if f > 1 {
		f = 1
	}
	m.want = f
	// 必须唤醒调度器：流量从 0 开始时，缓动得有人推着走。
	wakeAnimator()
}

func (m *meterBar) invalidate() {
	if m.w != nil {
		m.w.Invalidate()
	}
}

func (m *meterBar) advance() bool {
	diff := m.want - m.shown
	if math.Abs(diff) <= 0.0015 {
		if m.shown == m.want {
			return false
		}
		m.shown = m.want
		return true
	}
	m.shown += diff * 0.22
	if m.shown < 0 {
		m.shown = 0
	}
	if m.shown > 1 {
		m.shown = 1
	}
	return true
}

func (m *meterBar) paint(c *walk.Canvas, _ walk.Rectangle) error {
	if m.w == nil {
		return nil
	}
	rc := m.w.ClientBoundsPixels()
	if rc.Width <= 0 || rc.Height <= 0 {
		return nil
	}
	th := theme()
	if err := c.FillRectanglePixels(th.card, rc); err != nil {
		return err
	}
	// 两端做成半圆（胶囊形）：圆角椭圆尺寸取条高本身。
	pill := walk.Size{Width: rc.Height, Height: rc.Height}
	if err := c.FillRoundedRectanglePixels(th.track, rc, pill); err != nil {
		return err
	}
	if m.shown <= 0 {
		return nil
	}
	w := int(float64(rc.Width) * m.shown)
	// 宽度不能小于圆角直径，否则 RoundRect 会画出畸形的形状；
	// 同时也让极小的流量仍然「看得见」，而不是细到不可察觉。
	if w < rc.Height {
		w = rc.Height
	}
	if w > rc.Width {
		w = rc.Width
	}
	return c.FillRoundedRectanglePixels(m.fill, walk.Rectangle{X: rc.X, Y: rc.Y, Width: w, Height: rc.Height}, pill)
}

// ---------- 强调色按钮 ----------

type btnStyle int

const (
	btnPrimary btnStyle = iota
	btnDanger
)

// accentButton 是自绘的强调色按钮。
//
// 之所以不用原生 PushButton：原生按钮的颜色由系统决定，无法做成设计里的强调色，
// 而连接按钮是界面的主行动点，值得为它单独实现一次绘制与交互。
type accentButton struct {
	w       *walk.CustomWidget
	text    string
	style   btnStyle
	bg      walk.Brush
	enabled bool
	pressed bool
	font    *walk.Font
	onClick func()
}

func newAccentButton(text string, style btnStyle, bg walk.Brush, onClick func()) *accentButton {
	return &accentButton{
		text:    text,
		style:   style,
		bg:      bg,
		enabled: true,
		font:    mustFont(10, walk.FontBold),
		onClick: onClick,
	}
}

func mustFont(pt int, style walk.FontStyle) *walk.Font {
	f, err := walk.NewFont(uiFamily, pt, style)
	if err != nil {
		f, err = walk.NewFont("MS Shell Dlg 2", pt, style)
	}
	if err != nil {
		return nil
	}
	return f
}

func (b *accentButton) SetText(s string) {
	if b.text == s {
		return
	}
	b.text = s
	b.invalidate()
}

func (b *accentButton) SetStyle(s btnStyle) {
	if b.style == s {
		return
	}
	b.style = s
	b.invalidate()
}

func (b *accentButton) SetEnabled(v bool) {
	if b.enabled == v {
		return
	}
	b.enabled = v
	b.pressed = false
	b.invalidate()
}

func (b *accentButton) invalidate() {
	if b.w != nil {
		b.w.Invalidate()
	}
}

func (b *accentButton) paint(c *walk.Canvas, _ walk.Rectangle) error {
	if b.w == nil {
		return nil
	}
	rc := b.w.ClientBoundsPixels()
	if rc.Width <= 0 || rc.Height <= 0 {
		return nil
	}
	th := theme()
	bg := b.bg
	if bg == nil {
		bg = th.windowBG
	}
	if err := c.FillRectanglePixels(bg, rc); err != nil {
		return err
	}

	fill := th.accent
	textColor := colCard
	if b.style == btnDanger {
		fill = th.red
	}
	if b.enabled && b.pressed {
		if b.style == btnDanger {
			fill = th.redDim
		} else {
			fill = th.accentDim
		}
	}
	if !b.enabled {
		fill = th.accentDisabled
		textColor = colCard
		if b.style == btnDanger {
			fill = th.gray
		}
	}

	// 圆角半径固定 9px：按钮高度可能变化，但视觉上的圆角不该跟着变。
	corner := walk.Size{Width: 18, Height: 18}
	if err := c.FillRoundedRectanglePixels(fill, rc, corner); err != nil {
		return err
	}
	if b.text == "" || b.font == nil {
		return nil
	}
	return c.DrawTextPixels(b.text, b.font, textColor, rc,
		walk.TextCenter|walk.TextVCenter|walk.TextSingleLine)
}

func (b *accentButton) onMouseDown(x, y int, button walk.MouseButton) {
	if button != walk.LeftButton || !b.enabled {
		return
	}
	// 点击即获取焦点，这样随后的回车/空格也能触发按钮。
	if b.w != nil {
		_ = b.w.SetFocus()
	}
	if !b.pressed {
		b.pressed = true
		b.invalidate()
	}
}

func (b *accentButton) onMouseUp(x, y int, button walk.MouseButton) {
	if button != walk.LeftButton {
		return
	}
	wasPressed := b.pressed
	b.pressed = false
	b.invalidate()
	if !wasPressed || !b.enabled || b.w == nil {
		return
	}
	// 按下时鼠标被捕获，移到按钮外松手同样会收到回调——那不是一次点击。
	rc := b.w.ClientBoundsPixels()
	if x < 0 || y < 0 || x >= rc.Width || y >= rc.Height {
		return
	}
	if b.onClick != nil {
		b.onClick()
	}
}

func (b *accentButton) onKeyDown(key walk.Key) {
	if !b.enabled {
		return
	}
	if key == walk.KeyReturn || key == walk.KeySpace {
		if b.onClick != nil {
			b.onClick()
		}
	}
}

// ---------- declarative 构件的复用片段 ----------

func uiFont(pt int, bold bool) declarative.Font {
	return declarative.Font{Family: uiFamily, PointSize: pt, Bold: bold}
}

// card 生成一张白色卡片。用普通 Composite + 内边距代替 GroupBox：
// 原生分组框会画出系统风格的标题边框，在浅色卡片式界面里显得很旧。
func card(children ...declarative.Widget) declarative.Composite {
	return declarative.Composite{
		Background: declarative.SolidColorBrush{Color: colCard},
		Layout: declarative.VBox{
			Margins: declarative.Margins{Left: 12, Top: 8, Right: 12, Bottom: 9},
			Spacing: 4,
		},
		Children: children,
	}
}

// accentButtonWidget 把自绘按钮包成一个可放进 declarative 布局的控件。
//
// MinSize 与 MaxSize 必须成对给同一个高度，缺一不可：CustomWidget 的布局项是
// 「贪婪」的（默认理想高度 100px，且 GrowableVert），只设 MinSize 等于只给了下限，
// 它会一路撑满剩余空间——按钮就变成一条突兀的大色块。MaxSize 才是真正的上限。
func accentButtonWidget(b *accentButton, height int) declarative.CustomWidget {
	h := declarative.Size{Height: height}
	return declarative.CustomWidget{
		AssignTo:            &b.w,
		MinSize:             h,
		MaxSize:             h,
		PaintPixels:         b.paint,
		PaintMode:           declarative.PaintBuffered,
		InvalidatesOnResize: true,
		OnMouseDown:         b.onMouseDown,
		OnMouseUp:           b.onMouseUp,
		OnKeyDown:           b.onKeyDown,
	}
}

// labelAboveControl 把「说明文字 + 控件」叠成一格，用于替代网格里单独占一行的提示文字。
// 每个提示单独占一行会让卡片凭空长高两行，紧凑布局下这个代价不小。
func labelAboveControl(control, hint declarative.Widget) declarative.Composite {
	return declarative.Composite{
		Layout:   declarative.VBox{MarginsZero: true, Spacing: 2},
		Children: []declarative.Widget{control, hint},
	}
}

// hintText 生成一段会自动折行的说明文字。
//
// 这类文字长度不定，**必须**用 TextLabel 而不是 Label，否则会被右边缘整片切掉
// （用户反馈的「说明字体显示不全，最右边只显示了一半」）。原因是 walk 的 Label
// 底下的静态控件既不会按控件宽度重新折行，也从不汇报「给定宽度下需要多高」，
// 布局只能按「一行」给它高度，超出部分就没了。TextLabel 实现了
// HasHeightForWidth，布局会拿实际宽度算出要几行、把高度给足。
//
// MinSize.Width 必须 > 0，它是 walk 里「开启动态折行」的开关（见 TextLabel
// 字段上的注释）。这里取 200 只是把它打开——真正的宽度由布局给，
// TextLabel 是横向可伸缩的，会被撑到卡片可用宽度。
func hintText(s string) declarative.TextLabel {
	return declarative.TextLabel{
		Text:      s,
		Font:      uiFont(8, false),
		TextColor: colNotice,
		MinSize:   declarative.Size{Width: 200},
	}
}

func cardTitle(s string) declarative.Label {
	return declarative.Label{Text: s, Font: uiFont(10, true), TextColor: colText}
}

func fieldLabel(s string) declarative.Label {
	return declarative.Label{Text: s, Font: uiFont(9, false), TextColor: colTextDim}
}

func valueLabel(to **walk.Label, s string) declarative.Label {
	return declarative.Label{AssignTo: to, Text: s, Font: uiFont(9, false), TextColor: colText}
}

// barBlock 是「标题 + 数值 + 进度条」的一组，用于展示上传/下载速率。
func barBlock(title string, valueTo **walk.Label, bar *meterBar) declarative.Composite {
	return declarative.Composite{
		Layout: declarative.VBox{MarginsZero: true, Spacing: 3},
		Children: []declarative.Widget{
			declarative.Composite{
				Layout: declarative.HBox{MarginsZero: true},
				Children: []declarative.Widget{
					fieldLabel(title),
					declarative.HSpacer{},
					declarative.Label{AssignTo: valueTo, Text: "—", Font: uiFont(9, true), TextColor: colText},
				},
			},
			declarative.CustomWidget{
				AssignTo:            &bar.w,
				MinSize:             declarative.Size{Height: 8},
				MaxSize:             declarative.Size{Height: 8},
				PaintPixels:         bar.paint,
				PaintMode:           declarative.PaintBuffered,
				InvalidatesOnResize: true,
			},
		},
	}
}

// ---------- 窗口尺寸 ----------

// 登录只有一个表单，使用界面有四张卡片，两者需要的高度差很多。
// 窗口按当前面板调整尺寸：既不让登录界面留一大片空白，也避免使用界面
// 内容超出窗口、要用户手动拉大才能看全。
const (
	winWLogin, winHLogin = 418, 560
	winWMain, winHMain   = 466, 858
)

// spiGetWorkArea 是 SystemParametersInfo 的 SPI_GETWORKAREA。
// win 包没有导出这个常量，这里按 Win32 头文件补上。
const spiGetWorkArea = 0x0030

// applyPanelSize 把窗口调整到指定面板所需要的尺寸（入参为 1/96" 单位）。
func applyPanelSize(mw *walk.MainWindow, w96, h96 int) {
	if mw == nil {
		return
	}
	size := mw.SizeFrom96DPI(walk.Size{Width: w96, Height: h96})
	// 夹到桌面工作区高度：小屏笔记本上窗口若比工作区还高，最下面那张卡片
	// 和按钮会落到屏幕外、永远点不到——那比出现滚动条更糟。
	if maxH := workAreaHeight(); maxH > 0 && size.Height > maxH {
		size.Height = maxH
	}
	_ = mw.SetSizePixels(size)
}

// workAreaHeight 返回桌面工作区高度（原生像素，已扣除任务栏）。
// 读不到时返回 0，调用方据此跳过夹紧，而不是把窗口压成 0 高。
func workAreaHeight() int {
	var r win.RECT
	if !win.SystemParametersInfo(spiGetWorkArea, 0, unsafe.Pointer(&r), 0) {
		return 0
	}
	if h := int(r.Bottom - r.Top); h > 0 {
		// 留一点余量，免得窗口正好顶着任务栏上沿。
		return h - 16
	}
	return 0
}
