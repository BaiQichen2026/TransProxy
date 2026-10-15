package main

import (
	"math"
	"testing"
)

// 速率条的取值必须收敛在 0..1，任何越界都会让 RoundRect 画出畸形图形。
func TestRateFractionBounds(t *testing.T) {
	for _, c := range []struct {
		name string
		bps  float64
		want float64
	}{
		{"零", 0, 0},
		{"负数", -1, 0},
		{"NaN", math.NaN(), 0},
		{"半速", barFullRate / 4, 0.5},
		{"满格", barFullRate, 1},
		{"超过满格", barFullRate * 8, 1},
	} {
		if got := rateFraction(c.bps); math.Abs(got-c.want) > 1e-9 {
			t.Fatalf("%s: rateFraction(%v) = %v，期望 %v", c.name, c.bps, got, c.want)
		}
	}
}

// 低速段必须被拉开：线性映射下 1% 满格只画得出 1% 的条长，几乎看不见；
// 平方根映射要让它明显更可见。同时映射必须单调，否则条长与速率的对应关系会错乱。
func TestRateFractionLiftsLowRatesAndStaysMonotonic(t *testing.T) {
	const onePercent = barFullRate / 100
	if got := rateFraction(onePercent); got <= 0.05 {
		t.Fatalf("1%% 满格速率的条长 = %v，应明显大于线性映射的 0.01", got)
	}

	prev := -1.0
	for _, bps := range []float64{0, 1024, 100 * 1024, 1024 * 1024, 4 * 1024 * 1024, barFullRate} {
		got := rateFraction(bps)
		if got < prev {
			t.Fatalf("速率 %v 的条长 %v 小于更低速率的 %v，映射不单调", bps, got, prev)
		}
		prev = got
	}
}

// 缓动的收敛行为：必须逐步逼近目标，并在足够接近后吸附，否则动画永远不会停。
func TestMeterBarEasesAndSettles(t *testing.T) {
	m := &meterBar{}
	m.SetFraction(1)

	frames := 0
	for m.advance() {
		frames++
		if frames > 200 {
			t.Fatal("速率条缓动没有收敛，动画将永远无法停下")
		}
	}
	if m.shown != 1 {
		t.Fatalf("收敛后应吸附到目标 1，实际 %v", m.shown)
	}
	if frames < 3 {
		t.Fatalf("只用了 %d 帧就到位，说明没有缓动、是瞬间跳变", frames)
	}

	// 已经到位后再推进不应报告「有变化」，调度器才会停下来。
	if m.advance() {
		t.Fatal("已收敛的速率条不应继续报告变化")
	}
}

// hintText 必须开启动态折行。
//
// MinSize.Width > 0 是 walk 里打开折行的开关；一旦被"简化"成 0，TextLabel 会退回
// 单行行为，说明文字又会被右边缘整片切掉——也就是用户反馈过的
// 「说明字体显示不全，最右边只显示了一半」。这条测试就是拦住那次回退。
func TestHintTextEnablesWrapping(t *testing.T) {
	h := hintText("一段足够长的说明文字，用来确认它会被按控件宽度折行而不是直接切掉。")
	if h.MinSize.Width <= 0 {
		t.Fatalf("MinSize.Width = %d，折行没打开，长文字会被裁掉", h.MinSize.Width)
	}
	// 横向不能再设上限：那会重新把可用宽度卡死，等于白折行。
	if h.MaxSize.Width > 0 {
		t.Fatalf("MaxSize.Width = %d，会把宽度卡死导致右侧被裁", h.MaxSize.Width)
	}
}

// 「启动后自动最小化到托盘」必须依赖「启动后自动连接服务器」。
func TestMinimizeAllowedRequiresAutoConnect(t *testing.T) {
	for _, c := range []struct {
		autoConnect, minimize, want bool
	}{
		{false, false, false},
		{false, true, false}, // 关键项：没开自动连接时，勾了也不生效
		{true, false, false},
		{true, true, true},
	} {
		if got := minimizeAllowed(c.autoConnect, c.minimize); got != c.want {
			t.Fatalf("minimizeAllowed(autoConnect=%v, minimize=%v) = %v，期望 %v",
				c.autoConnect, c.minimize, got, c.want)
		}
	}
}
