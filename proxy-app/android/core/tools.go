//go:build tools

// 这个文件永远不参与编译（靠上面的 build tag 排除），它存在的唯一目的是
// 让 `go mod tidy` 不要把 gomobile 需要的依赖清掉。
//
// 背景：gomobile bind 会检查当前模块的依赖图里有没有 golang.org/x/mobile，
// 但我们的代码并不 import 它（它是构建工具，不是运行时依赖）。
// 早先这份 go.mod 里恰好留着它，所以一直能用；一旦跑过 `go mod tidy`，
// 它就被当成无用依赖删掉，bind 直接报 "missing golang.org/x/mobile dependency"。
//
// 按官方新建议写 `tool golang.org/x/mobile/cmd/gobind` 试过，结果卡死在
// gomobile 的 `go list -deps -compiled` 那一步（x/mobile 含 cgo 代码，
// 被拉进 android 目标的依赖图后就走不通了）。这里用更老但更稳的写法：
// 一个 build tag 排除的文件做空导入，tidy 就会保留依赖。
package core

import (
	_ "golang.org/x/mobile/bind"
)
