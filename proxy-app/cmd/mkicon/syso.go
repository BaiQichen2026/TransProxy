package main

import (
	"bytes"
	"encoding/binary"
)

// Windows 资源类型编号（winuser.h）。
const (
	rtIcon      = 3  // 单个图标位图
	rtGroupIcon = 14 // 图标组（把上面这些位图串成一个「多尺寸图标」）
	rtManifest  = 24 // 应用程序清单
)

// 资源语言。用 en-US：windres / rsrc 的默认值，也是最通用的选择。
const resLang = 0x0409

// 目录头部固定 16 字节，目录项固定 8 字节，数据描述项固定 16 字节（PE/COFF 规范写死）。
const (
	dirHeaderSize = 16
	dirEntrySize  = 8
	dataEntrySize = 16
)

// buildSyso 生成一个只含 .rsrc 段的 COFF 目标文件，交给 Go 链接器编进 exe。
//
// 为什么手写而不调 rsrc / windres：这套构建环境里没有装这些工具，
// 而且仓库一贯主张「图标由代码生成、不放二进制中间产物」。
//
// 整个文件的关键只有一处：IMAGE_RESOURCE_DATA_ENTRY.OffsetToData 按规范必须是
// RVA（相对镜像基址），但链接之前根本不知道 .rsrc 会被安排在哪个 RVA。
// 所以这里先填「段内偏移」，并在该字段上挂一条 IMAGE_REL_AMD64_ADDR32NB 重定位，
// 符号指向 .rsrc 段本身：链接器会把段 RVA 加上去，正好得到最终 RVA。
// COFF 没有独立的加数字段，加数就是字段里原有的值——也就是说
// 「先填段内偏移、再挂重定位」正是这个格式的惯用法，不是权宜之计。
//
// 资源树是固定三层，不能再多也不能再少：
//
//	类型(RT_ICON/RT_GROUP_ICON/RT_MANIFEST)
//	  名称/ID（图标资源 ID）
//	    语言（本文件统一 0x0409）——这一层的目录项直接指向数据描述项
//
// 这里曾经多套了一层（名称/ID 层之下又放了一个语言层目录，等于四层）。
// 症状很隐蔽：资源树本身看着自洽、用脚本解析也能解出来，
// 但链接出来的 exe 被 Windows 判为「不是有效的应用程序」，双击毫无反应；
// 连 `go test ./cmd/tunnelclient` 都建不出可执行的测试二进制
// （报 "not a valid Win32 application"）。
// 实测确认：把这个多出来的层级去掉、严格三层之后，两者立刻恢复正常。
func buildSyso(dibs [][]byte, manifest []byte) []byte {
	n := len(dibs)
	if n == 0 {
		panic("没有图标数据")
	}

	groupData := buildGroupIcon(dibs)

	type resRef struct {
		id      uint32
		payload []byte
		// 布局阶段算出的段内偏移
		idDirOff uint32 // 名称/ID 层目录
		entryOff uint32 // 数据描述项
		dataOff  uint32 // 资源数据
	}

	icons := make([]resRef, n)
	for i := range dibs {
		icons[i] = resRef{id: uint32(i + 1), payload: dibs[i]}
	}
	group := resRef{id: 1, payload: groupData}
	man := resRef{id: 1, payload: manifest}

	// ---------- 1) 规划段内布局 ----------

	cursor := uint32(0)
	alloc := func(size int) uint32 {
		off := cursor
		cursor += uint32(size)
		return off
	}
	typeDirSize := func(entries int) int { return dirHeaderSize + entries*dirEntrySize }
	idDirSize := dirHeaderSize + dirEntrySize // 每个名称/ID 层目录只有一条目（一种语言）

	rootOff := alloc(typeDirSize(3))
	iconTypeOff := alloc(typeDirSize(n))
	groupTypeOff := alloc(typeDirSize(1))
	manTypeOff := alloc(typeDirSize(1))

	for i := range icons {
		icons[i].idDirOff = alloc(idDirSize)
	}
	group.idDirOff = alloc(idDirSize)
	man.idDirOff = alloc(idDirSize)

	// 数据描述项连排，方便核对重定位位置。
	for i := range icons {
		icons[i].entryOff = alloc(dataEntrySize)
	}
	group.entryOff = alloc(dataEntrySize)
	man.entryOff = alloc(dataEntrySize)

	// 资源数据统一对齐到 8 字节：里面有 32 位整数与位图行，对齐更稳妥。
	align8 := func() {
		if r := cursor % 8; r != 0 {
			cursor += 8 - r
		}
	}
	align8()
	for i := range icons {
		icons[i].dataOff = alloc(len(icons[i].payload))
		align8()
	}
	group.dataOff = alloc(len(group.payload))
	align8()
	man.dataOff = alloc(len(man.payload))
	align8()

	section := make([]byte, cursor)
	put16 := func(off uint32, v uint16) { binary.LittleEndian.PutUint16(section[off:], v) }
	put32 := func(off uint32, v uint32) { binary.LittleEndian.PutUint32(section[off:], v) }

	// ---------- 2) 写目录树 ----------

	writeDirHeader := func(off uint32, idEntries uint16) {
		put16(off+0, 0)  // Characteristics
		put32(off+4, 0)  // TimeDateStamp
		put16(off+8, 0)  // MajorVersion
		put16(off+10, 0) // MinorVersion
		put16(off+12, 0) // NumberOfNamedEntries：全用数字 ID，没有具名项
		put16(off+14, idEntries)
	}
	// 目录项：高位置 1 表示指向子目录，否则指向数据描述项。
	writeDirEntry := func(off, id, target uint32, isDir bool) {
		put32(off+0, id)
		if isDir {
			target |= 0x80000000
		}
		put32(off+4, target)
	}
	writeDataEntry := func(r resRef) {
		// OffsetToData 先写段内偏移，重定位会把它变成最终 RVA。
		put32(r.entryOff+0, r.dataOff)
		put32(r.entryOff+4, uint32(len(r.payload)))
		put32(r.entryOff+8, 0) // CodePage：不使用代码页
		put32(r.entryOff+12, 0)
	}

	// 第一层：根目录 → 三种资源类型，按编号升序（查找假定同层有序）。
	writeDirHeader(rootOff, 3)
	writeDirEntry(rootOff+dirHeaderSize+0*dirEntrySize, rtIcon, iconTypeOff, true)
	writeDirEntry(rootOff+dirHeaderSize+1*dirEntrySize, rtGroupIcon, groupTypeOff, true)
	writeDirEntry(rootOff+dirHeaderSize+2*dirEntrySize, rtManifest, manTypeOff, true)

	// 第二层：类型目录 → 名称/ID
	writeDirHeader(iconTypeOff, uint16(n))
	for i, r := range icons {
		writeDirEntry(iconTypeOff+dirHeaderSize+uint32(i)*dirEntrySize, r.id, r.idDirOff, true)
	}
	writeDirHeader(groupTypeOff, 1)
	writeDirEntry(groupTypeOff+dirHeaderSize, group.id, group.idDirOff, true)
	writeDirHeader(manTypeOff, 1)
	writeDirEntry(manTypeOff+dirHeaderSize, man.id, man.idDirOff, true)

	// 第三层：名称/ID 目录 → 语言；这一层的目录项直接指向数据描述项（高位为 0）。
	for _, r := range icons {
		writeDirHeader(r.idDirOff, 1)
		writeDirEntry(r.idDirOff+dirHeaderSize, resLang, r.entryOff, false)
		writeDataEntry(r)
	}
	writeDirHeader(group.idDirOff, 1)
	writeDirEntry(group.idDirOff+dirHeaderSize, resLang, group.entryOff, false)
	writeDataEntry(group)
	writeDirHeader(man.idDirOff, 1)
	writeDirEntry(man.idDirOff+dirHeaderSize, resLang, man.entryOff, false)
	writeDataEntry(man)

	// ---------- 3) 写资源数据 ----------
	for _, r := range icons {
		copy(section[r.dataOff:], r.payload)
	}
	copy(section[group.dataOff:], group.payload)
	copy(section[man.dataOff:], man.payload)

	// ---------- 4) 拼 COFF 目标文件 ----------
	// 每个数据描述项的 OffsetToData 字段挂一条重定位，都指向 .rsrc 段符号。
	relocs := make([]uint32, 0, n+2)
	for _, r := range icons {
		relocs = append(relocs, r.entryOff)
	}
	relocs = append(relocs, group.entryOff, man.entryOff)

	const (
		coffHeaderSize    = 20
		sectionHeaderSize = 40
		symEntrySize      = 18
	)
	rawPtr := uint32(coffHeaderSize + sectionHeaderSize)
	relocPtr := rawPtr + uint32(len(section))
	relocSize := uint32(10 * len(relocs))
	symPtr := relocPtr + relocSize
	strTableSize := uint32(4) // 只有长度字段，没有名字
	total := symPtr + symEntrySize + strTableSize

	out := make([]byte, total)
	le := binary.LittleEndian

	// COFF 头
	le.PutUint16(out[0:], 0x8664) // IMAGE_FILE_MACHINE_AMD64
	le.PutUint16(out[2:], 1)      // 一个段
	le.PutUint32(out[4:], 0)      // TimeDateStamp：留 0，保证输出可复现
	le.PutUint32(out[8:], symPtr)
	le.PutUint32(out[12:], 1) // 一个符号
	le.PutUint16(out[16:], 0) // 无可选头
	le.PutUint16(out[18:], 0x0104)

	// 段头
	sh := out[coffHeaderSize:]
	copy(sh[0:8], ".rsrc\x00\x00\x00")
	// VirtualSize 写 0：COFF 目标文件里这是惯例，含义是「与 SizeOfRawData 相同」，
	// 既有可用的资源文件也是这么写的。
	// （注：实测过把它填成真实长度，链接产物同样能正常加载——它并不是问题的关键，
	//   这里按惯例写 0 只是为了跟既有产物保持一致。）
	le.PutUint32(sh[8:], 0)                     // VirtualSize：0 表示「同 SizeOfRawData」
	le.PutUint32(sh[12:], 0)                    // VirtualAddress：由链接器决定
	le.PutUint32(sh[16:], uint32(len(section))) // SizeOfRawData
	le.PutUint32(sh[20:], rawPtr)               // PointerToRawData
	le.PutUint32(sh[24:], relocPtr)             // PointerToRelocations
	le.PutUint32(sh[28:], 0)                    // PointerToLinenumbers
	le.PutUint16(sh[32:], uint16(len(relocs)))  // NumberOfRelocations
	le.PutUint16(sh[34:], 0)                    // NumberOfLinenumbers
	le.PutUint32(sh[36:], 0x40000040)           // 已初始化数据 + 可读

	copy(out[rawPtr:], section)

	// 重定位表
	for i, off := range relocs {
		p := relocPtr + uint32(i*10)
		le.PutUint32(out[p:], off)      // 字段在段内的偏移
		le.PutUint32(out[p+4:], 0)      // 符号表下标：0 = .rsrc 段符号
		le.PutUint16(out[p+8:], 0x0003) // IMAGE_REL_AMD64_ADDR32NB
	}

	// 符号表：一个 .rsrc 段符号（存储类 3 = 静态）
	p := symPtr
	copy(out[p:p+8], ".rsrc\x00\x00\x00")
	le.PutUint32(out[p+8:], 0)  // Value
	le.PutUint16(out[p+12:], 1) // SectionNumber（段号从 1 开始）
	le.PutUint16(out[p+14:], 0) // Type
	out[p+16] = 3               // StorageClass = IMAGE_SYM_CLASS_STATIC
	out[p+17] = 0               // NumberOfAuxSymbols

	le.PutUint32(out[symPtr+symEntrySize:], strTableSize)

	return out
}

// buildGroupIcon 生成 RT_GROUP_ICON 的内容（GRPICONDIR）。
//
// 它和 .ico 文件头长得很像，区别在最后：.ico 的条目用一个 32 位**文件偏移**
// 指向位图，而资源里必须在同一次资源提交中把位图放成独立的 RT_ICON，
// 所以条目末尾是一个 16 位**资源 ID**。这正是「多尺寸图标」在资源里的表达方式。
func buildGroupIcon(dibs [][]byte) []byte {
	var buf bytes.Buffer
	w16 := func(v uint16) { _ = binary.Write(&buf, binary.LittleEndian, v) }
	w32 := func(v uint32) { _ = binary.Write(&buf, binary.LittleEndian, v) }

	w16(0)                 // 保留
	w16(1)                 // 类型：1 = 图标
	w16(uint16(len(dibs))) // 条目数
	for i, s := range icoSizes {
		dim := byte(s)
		if s >= 256 {
			dim = 0 // 256 用 0 表示
		}
		buf.WriteByte(dim) // 宽
		buf.WriteByte(dim) // 高
		buf.WriteByte(0)   // 调色板数
		buf.WriteByte(0)   // 保留
		w16(1)             // 平面数
		w16(32)            // 位深
		w32(uint32(len(dibs[i])))
		w16(uint16(i + 1)) // 对应 RT_ICON 的资源 ID（从 1 开始）
	}
	return buf.Bytes()
}
