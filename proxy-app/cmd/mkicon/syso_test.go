package main

import (
	"encoding/binary"
	"testing"
)

// 这个测试盯的是资源树的「形状」，不是内容。
//
// 起因是一个很难查的真实故障：生成器一度在名称/ID 层下面又套了一层目录，
// 资源树变成四层。用脚本解析这棵树完全正常（每一层都自洽），
// 但链接出来的 exe 被 Windows 判为「不是有效的应用程序」，
// 连 go test 都建不出可执行的测试二进制。
//
// 仅靠「解析得出来」是验不出这种错的——所以这里断言的是**结构**：
// 严格三层，且第三层的目录项必须直接指向数据描述项。

const (
	testDirHeaderSize = 16
	testDirEntrySize  = 8
	testDataEntrySize = 16
)

type parsedEntry struct {
	id      uint32
	isDir   bool
	target  uint32
	dataOff uint32
	dataLen uint32
}

// parseDir 解析一个 IMAGE_RESOURCE_DIRECTORY，返回它的目录项。
func parseDir(t *testing.T, sec []byte, off uint32) []parsedEntry {
	t.Helper()
	if int(off)+testDirHeaderSize > len(sec) {
		t.Fatalf("目录偏移 0x%X 越界", off)
	}
	named := binary.LittleEndian.Uint16(sec[off+12:])
	ids := binary.LittleEndian.Uint16(sec[off+14:])
	if named != 0 {
		t.Fatalf("不该出现具名项（NumberOfNamedEntries=%d）", named)
	}
	out := make([]parsedEntry, 0, ids)
	for i := 0; i < int(ids); i++ {
		eo := int(off) + testDirHeaderSize + i*testDirEntrySize
		if eo+testDirEntrySize > len(sec) {
			t.Fatalf("目录项越界（目录 0x%X 第 %d 项）", off, i)
		}
		e := parsedEntry{
			id:     binary.LittleEndian.Uint32(sec[eo:]),
			target: binary.LittleEndian.Uint32(sec[eo+4:]),
		}
		if e.target&0x80000000 != 0 {
			e.isDir = true
			e.target &^= 0x80000000
		} else {
			do := int(e.target)
			if do+testDataEntrySize > len(sec) {
				t.Fatalf("数据描述项偏移 0x%X 越界", e.target)
			}
			e.dataOff = binary.LittleEndian.Uint32(sec[do:])
			e.dataLen = binary.LittleEndian.Uint32(sec[do+4:])
		}
		out = append(out, e)
	}
	return out
}

// sysoSection 从生成的 COFF 目标文件里取出 .rsrc 段的内容。
func sysoSection(t *testing.T, syso []byte) []byte {
	t.Helper()
	if len(syso) < 20+40 {
		t.Fatal("目标文件太短")
	}
	if m := binary.LittleEndian.Uint16(syso[0:]); m != 0x8664 {
		t.Fatalf("机器类型不对：0x%X", m)
	}
	if n := binary.LittleEndian.Uint16(syso[2:]); n != 1 {
		t.Fatalf("应当只有一个段，实际 %d 个", n)
	}
	sh := syso[20:]
	if string(sh[0:5]) != ".rsrc" {
		t.Fatalf("段名不对：%q", sh[0:8])
	}
	rawSize := binary.LittleEndian.Uint32(sh[16:])
	rawPtr := binary.LittleEndian.Uint32(sh[20:])
	end := int(rawPtr + rawSize)
	if end > len(syso) {
		t.Fatalf("段数据超出文件（ptr=%d size=%d 文件=%d）", rawPtr, rawSize, len(syso))
	}
	return syso[rawPtr:end]
}

func relocCount(t *testing.T, syso []byte) int {
	t.Helper()
	sh := syso[20:]
	return int(binary.LittleEndian.Uint16(sh[32:]))
}

// 资源树必须是严格三层：类型 → 名称/ID → 语言 → 数据描述项。
func TestSysoResourceTreeIsExactlyThreeLevels(t *testing.T) {
	dibs := make([][]byte, len(icoSizes))
	for i := range dibs {
		dibs[i] = []byte{byte(i), byte(i + 1), byte(i + 2)}
	}
	manifest := []byte("<assembly>test</assembly>")

	sec := sysoSection(t, buildSyso(dibs, manifest))

	root := parseDir(t, sec, 0)
	if len(root) != 3 {
		t.Fatalf("根目录应当有 3 个资源类型，实际 %d 个", len(root))
	}
	// 类型必须升序，且正是图标 / 图标组 / 清单
	wantTypes := []uint32{rtIcon, rtGroupIcon, rtManifest}
	for i, e := range root {
		if e.id != wantTypes[i] {
			t.Errorf("根目录第 %d 项应为类型 %d，实际 %d", i, wantTypes[i], e.id)
		}
		if !e.isDir {
			t.Errorf("类型 %d 应当指向子目录", e.id)
		}
	}

	totalLeaves := 0
	for _, typeEntry := range root {
		// 第二层：类型目录 → 名称/ID
		lvl2 := parseDir(t, sec, typeEntry.target)
		if len(lvl2) == 0 {
			t.Fatalf("类型 %d 下没有任何名称/ID 目录项", typeEntry.id)
		}
		for i := 1; i < len(lvl2); i++ {
			if lvl2[i].id <= lvl2[i-1].id {
				t.Errorf("类型 %d 的 ID 未升序：%v", typeEntry.id, lvl2)
			}
		}
		for _, nameEntry := range lvl2 {
			if !nameEntry.isDir {
				// 这正是「少一层」的错：名称/ID 层直接指向了数据描述项。
				t.Fatalf("类型 %d 的 ID %d 直接指向数据描述项——资源树缺少语言层",
					typeEntry.id, nameEntry.id)
			}
			// 第三层：名称/ID 目录 → 语言，这一层的项必须直接指向数据描述项。
			lvl3 := parseDir(t, sec, nameEntry.target)
			if len(lvl3) != 1 {
				t.Fatalf("类型 %d 的 ID %d 下应当只有 1 种语言，实际 %d 个",
					typeEntry.id, nameEntry.id, len(lvl3))
			}
			lang := lvl3[0]
			if lang.id != resLang {
				t.Errorf("语言 ID 应为 0x%X，实际 0x%X", resLang, lang.id)
			}
			if lang.isDir {
				// 这正是「多一层」的错：语言层下面还有目录，资源树成了四层。
				t.Fatalf("类型 %d 的 ID %d 的语言层下还有子目录——资源树多了一层"+
					"（会导致链接产物无法加载）", typeEntry.id, nameEntry.id)
			}
			if lang.dataLen == 0 {
				t.Errorf("类型 %d 的 ID %d 资源长度为 0", typeEntry.id, nameEntry.id)
			}
			if int(lang.dataOff)+int(lang.dataLen) > len(sec) {
				t.Errorf("类型 %d 的 ID %d 资源数据越界（off=%d len=%d 段长=%d）",
					typeEntry.id, nameEntry.id, lang.dataOff, lang.dataLen, len(sec))
			}
			totalLeaves++
		}
	}
	if want := len(dibs) + 2; totalLeaves != want {
		t.Fatalf("叶子资源数应当为 %d（%d 个图标 + 图标组 + 清单），实际 %d",
			want, len(dibs), totalLeaves)
	}
}

// 每个数据描述项的 OffsetToData 都必须有一条重定位，否则链接后它仍是段内偏移、
// 而不是 RVA——资源就会指到错误的内存位置。
func TestSysoRelocationsCoverEveryDataEntry(t *testing.T) {
	dibs := make([][]byte, len(icoSizes))
	for i := range dibs {
		dibs[i] = []byte{byte(i)}
	}
	syso := buildSyso(dibs, []byte("m"))
	sec := sysoSection(t, syso)

	// 收集所有数据描述项的偏移
	want := map[uint32]bool{}
	var walk func(off uint32, depth int)
	walk = func(off uint32, depth int) {
		if depth > 3 {
			t.Fatalf("资源树超过三层（起点 0x%X）", off)
		}
		for _, e := range parseDir(t, sec, off) {
			if e.isDir {
				walk(e.target, depth+1)
			} else {
				want[e.target] = true
			}
		}
	}
	walk(0, 1)

	if len(want) == 0 {
		t.Fatal("没找到任何数据描述项")
	}

	sh := syso[20:]
	nrel := relocCount(t, syso)
	if nrel != len(want) {
		t.Fatalf("重定位数 %d 与数据描述项数 %d 不相等", nrel, len(want))
	}
	relPtr := binary.LittleEndian.Uint32(sh[24:])
	got := map[uint32]bool{}
	for i := 0; i < nrel; i++ {
		p := relPtr + uint32(i*10)
		off := binary.LittleEndian.Uint32(syso[p:])
		sym := binary.LittleEndian.Uint32(syso[p+4:])
		typ := binary.LittleEndian.Uint16(syso[p+8:])
		if typ != 0x0003 {
			t.Errorf("重定位类型应为 3 (ADDR32NB)，实际 %d", typ)
		}
		if sym != 0 {
			t.Errorf("重定位应当引用符号 0（.rsrc 段符号），实际 %d", sym)
		}
		got[off] = true
	}
	for off := range want {
		if !got[off] {
			t.Errorf("数据描述项 0x%X 缺少重定位，链接后它不会是 RVA", off)
		}
	}
}

// 清单必须原样写进资源：它声明 Common Controls 6.0 依赖与 DPI 感知，
// 少一个字节都可能让 walk 在启动阶段崩溃。
func TestSysoManifestIsByteIdentical(t *testing.T) {
	dibs := make([][]byte, len(icoSizes))
	for i := range dibs {
		dibs[i] = []byte{byte(i)}
	}
	manifest := []byte("<?xml version=\"1.0\"?><assembly/>")
	sec := sysoSection(t, buildSyso(dibs, manifest))

	for _, e := range parseDir(t, sec, 0) {
		if e.id != rtManifest {
			continue
		}
		lvl2 := parseDir(t, sec, e.target)
		lvl3 := parseDir(t, sec, lvl2[0].target)
		leaf := lvl3[0]
		got := sec[leaf.dataOff : leaf.dataOff+leaf.dataLen]
		if string(got) != string(manifest) {
			t.Fatalf("清单内容不一致：\n 得到 %q\n 期望 %q", got, manifest)
		}
		return
	}
	t.Fatal("资源树里找不到清单")
}
