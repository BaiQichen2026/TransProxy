// mkicon 由一张源图生成 Windows 客户端需要的图标资源：
//
//	app.ico                     多尺寸图标（16/24/32/48/64/128/256）
//	cmd/tunnelclient/rsrc.syso  编进 exe 的 Windows 资源（图标 + 清单）
//
// 为什么要生成 .syso 而不是放一个现成的：exe 的图标与托盘图标都来自 exe 内嵌的
// 资源（托盘由 cmd/tunnelclient 用 walk.NewIconFromResourceId(1) 从同一个资源里取），
// 换图标就必须重做资源段。资源 id 1 就是这里的图标组，改编号要同步改客户端。
// 仓库里不放二进制中间产物，改图标=换一张源图重跑本程序。
//
// 清单（app.manifest）必须一并写进资源：它声明了 Common Controls 6.0 依赖与
// DPI 感知，缺了它 walk 创建 ToolTip 会失败、程序在启动阶段直接崩溃。
package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
)

// icoSizes 是 ICO 里包含的尺寸。Windows 会按显示场景自行挑选：
// 16/24 用于列表与小图标，32/48 用于桌面与任务栏，256 用于大图标视图。
var icoSizes = []int{16, 24, 32, 48, 64, 128, 256}

// androidIcons 是 Android 各密度目录对应的启动图标边长。
// 基准是 mdpi 的 48dp，其余按密度倍数递增（hdpi 1.5×、xhdpi 2×、xxhdpi 3×、xxxhdpi 4×）。
// 每个密度都要给一份：只放一张让系统去缩放，小图标上会明显发虚。
var androidIcons = []struct {
	dir  string
	size int
}{
	{"mipmap-mdpi", 48},
	{"mipmap-hdpi", 72},
	{"mipmap-xhdpi", 96},
	{"mipmap-xxhdpi", 144},
	{"mipmap-xxxhdpi", 192},
}

// androidResDir 是 Android 资源目录（相对 proxy-app）。
const androidResDir = "android/app/src/main/res"

func main() {
	src := "app-icon.png"
	icoOut := "app.ico"
	sysoOut := filepath.Join("cmd", "tunnelclient", "rsrc.syso")
	manifest := "app.manifest"
	if len(os.Args) > 1 {
		src = os.Args[1]
	}
	if len(os.Args) > 2 {
		icoOut = os.Args[2]
	}
	if len(os.Args) > 3 {
		sysoOut = os.Args[3]
	}
	if len(os.Args) > 4 {
		manifest = os.Args[4]
	}

	base, err := loadSquare(src)
	if err != nil {
		fail(err)
	}

	// 各尺寸的位图。先各自编码成 DIB，ICO 与 syso 共用同一份数据，
	// 保证「exe 图标」和「图标文件」永远一致。
	dibs := make([][]byte, len(icoSizes))
	for i, s := range icoSizes {
		dibs[i] = encodeDIB(downscale(base, s))
	}

	if err := os.WriteFile(icoOut, buildICO(dibs), 0o644); err != nil {
		fail(err)
	}
	fmt.Printf("已生成 %s（%d 个尺寸）\n", icoOut, len(dibs))

	man, err := os.ReadFile(manifest)
	if err != nil {
		fail(fmt.Errorf("读取清单 %s 失败: %w", manifest, err))
	}
	if err := os.WriteFile(sysoOut, buildSyso(dibs, man), 0o644); err != nil {
		fail(err)
	}
	fmt.Printf("已生成 %s（图标 %d 个 + 1 个清单，共 %d 字节）\n",
		sysoOut, len(dibs), len(buildSyso(dibs, man)))

	if err := writeAndroidIcons(base); err != nil {
		fail(err)
	}
	fmt.Printf("已生成 Android 启动图标（%d 个密度）\n", len(androidIcons))
}

// writeAndroidIcons 把源图按各密度写入 mipmap-* 目录。
//
// 复用同一份源图与同一套缩放，保证手机和电脑上的图标是同一张脸——
// 分开维护的话，下次换图很容易只改一边。
func writeAndroidIcons(base *image.RGBA) error {
	for _, ic := range androidIcons {
		dir := filepath.Join(androidResDir, ic.dir)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("创建 %s 失败: %w", dir, err)
		}
		img := downscale(base, ic.size)

		var buf bytes.Buffer
		if err := png.Encode(&buf, img); err != nil {
			return fmt.Errorf("编码 %s 失败: %w", ic.dir, err)
		}
		// 同时给出 ic_launcher_round.png：部分启动器在圆形图标模式下会去找它，
		// 找不到就退回到方形图再自己裁，边缘容易出现难看的锯齿。
		// 这里不做圆形遮罩，交给系统按自己的形状规则处理，避免与各家 ROM 的
		// 显示方式打架（我们画的圆形对不上它就变成被切掉一圈）。
		for _, name := range []string{"ic_launcher.png", "ic_launcher_round.png"} {
			p := filepath.Join(dir, name)
			if err := os.WriteFile(p, buf.Bytes(), 0o644); err != nil {
				return fmt.Errorf("写入 %s 失败: %w", p, err)
			}
		}
	}
	return nil
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "生成图标失败:", err)
	os.Exit(1)
}

// loadSquare 读入源图，居中裁成正方形后返回。
//
// 裁成正方形是必须的：ICO 里每个尺寸都是正方形，直接把 794×681 缩到 256×256
// 会把画面横向压扁，人脸明显变形。宁可裁掉两侧多余的背景，也不要把人拉变形。
func loadSquare(path string) (*image.RGBA, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("打开源图失败: %w", err)
	}
	defer f.Close()
	src, err := png.Decode(f)
	if err != nil {
		return nil, fmt.Errorf("解析源图失败: %w", err)
	}
	b := src.Bounds()
	side := b.Dx()
	if b.Dy() < side {
		side = b.Dy()
	}
	if side <= 0 {
		return nil, fmt.Errorf("源图尺寸异常: %dx%d", b.Dx(), b.Dy())
	}
	ox := b.Min.X + (b.Dx()-side)/2
	oy := b.Min.Y + (b.Dy()-side)/2

	out := image.NewRGBA(image.Rect(0, 0, side, side))
	// 用转换而不是直接拷贝像素：源图可能是任意颜色模型（JPEG 转存的 PNG 是 YCbCr 等），
	// 直接按 RGBA 取会拿到预乘过的值，缩放时颜色会偏暗。
	// At().RGBA() 返回预乘值，这里换算回非预乘的 8 位分量。
	for y := 0; y < side; y++ {
		for x := 0; x < side; x++ {
			r, g, bb, a := src.At(ox+x, oy+y).RGBA()
			if a == 0 {
				continue
			}
			out.SetRGBA(x, y, color.RGBA{
				R: uint8((r * 0xffff / a) >> 8),
				G: uint8((g * 0xffff / a) >> 8),
				B: uint8((bb * 0xffff / a) >> 8),
				A: uint8(a >> 8),
			})
		}
	}
	return out, nil
}

// downscale 盒式缩放到 n×n。
//
// 必须在「预乘 alpha」的空间里求平均：直接平均非预乘的 RGB，
// 透明像素的黑色会被混进来，导致边缘出现一圈暗边。
// 当前源图是抠掉背景的透明图，透明区域占了一大半，所以这一步是必须的——
// 少了它，人物轮廓周围会糊出一圈灰黑色的脏边。
func downscale(src *image.RGBA, n int) *image.RGBA {
	b := src.Bounds()
	sw, sh := b.Dx(), b.Dy()
	out := image.NewRGBA(image.Rect(0, 0, n, n))
	for y := 0; y < n; y++ {
		y0, y1 := y*sh/n, (y+1)*sh/n
		if y1 <= y0 {
			y1 = y0 + 1
		}
		for x := 0; x < n; x++ {
			x0, x1 := x*sw/n, (x+1)*sw/n
			if x1 <= x0 {
				x1 = x0 + 1
			}
			var rs, gs, bs, as, cnt float64
			for sy := y0; sy < y1 && sy < sh; sy++ {
				for sx := x0; sx < x1 && sx < sw; sx++ {
					c := src.RGBAAt(sx, sy)
					a := float64(c.A) / 255
					rs += float64(c.R) * a
					gs += float64(c.G) * a
					bs += float64(c.B) * a
					as += a
					cnt++
				}
			}
			if cnt == 0 || as == 0 {
				continue
			}
			out.Set(x, y, color.RGBA{
				R: uint8(rs / as), G: uint8(gs / as), B: uint8(bs / as),
				A: uint8(as / cnt * 255),
			})
		}
	}
	return out
}

// encodeDIB 把图像编码成 ICO/资源里的 32 位 BGRA 位图条目（含 AND 掩码）。
func encodeDIB(img *image.RGBA) []byte {
	w, h := img.Bounds().Dx(), img.Bounds().Dy()
	maskRow := ((w + 31) / 32) * 4

	var buf bytes.Buffer
	put32 := func(v uint32) { _ = binary.Write(&buf, binary.LittleEndian, v) }
	i32 := func(v int) { put32(uint32(int32(v))) }

	// BITMAPINFOHEADER：高度写两倍，因为后面还跟着 AND 掩码。
	i32(40)
	i32(w)
	i32(h * 2)
	_ = binary.Write(&buf, binary.LittleEndian, uint16(1))  // planes
	_ = binary.Write(&buf, binary.LittleEndian, uint16(32)) // bpp
	put32(0)                                                // BI_RGB
	put32(uint32(w*h*4 + maskRow*h))
	i32(0)
	i32(0)
	put32(0)
	put32(0)

	// 位图数据自下而上，通道顺序为 BGRA。
	for y := h - 1; y >= 0; y-- {
		for x := 0; x < w; x++ {
			c := img.RGBAAt(x, y)
			buf.Write([]byte{c.B, c.G, c.R, c.A})
		}
	}
	// AND 掩码全 0：不透明度完全由 alpha 通道决定。
	buf.Write(make([]byte, maskRow*h))
	return buf.Bytes()
}

// buildICO 拼出 .ico 文件。容器格式与 .syso 里的图标资源是两套东西：
// 这里用「目录 + 整段位图」，资源里则是「GRPICONDIR + 独立的 RT_ICON」。
func buildICO(dibs [][]byte) []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, uint16(0))
	binary.Write(&buf, binary.LittleEndian, uint16(1))
	binary.Write(&buf, binary.LittleEndian, uint16(len(dibs)))

	offset := 6 + 16*len(dibs)
	for i, s := range icoSizes {
		dim := byte(s)
		if s >= 256 {
			dim = 0 // 256 在格式里用 0 表示
		}
		buf.WriteByte(dim)
		buf.WriteByte(dim)
		buf.WriteByte(0) // 调色板数
		buf.WriteByte(0) // 保留
		binary.Write(&buf, binary.LittleEndian, uint16(1))
		binary.Write(&buf, binary.LittleEndian, uint16(32))
		binary.Write(&buf, binary.LittleEndian, uint32(len(dibs[i])))
		binary.Write(&buf, binary.LittleEndian, uint32(offset))
		offset += len(dibs[i])
	}
	for _, d := range dibs {
		buf.Write(d)
	}
	return buf.Bytes()
}
