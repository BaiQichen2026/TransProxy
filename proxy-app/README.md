# TransProxy

自用的加密隧道代理：一个服务端 + Windows 客户端。目的不是通用翻墙工具，而是一套
「自己完全掌握、行为可解释」的访问加速链路。

服务端是总节点（控制面），客户端目前只有 Windows 版（Android 版在开发中）。

---

## 1. 架构总览

```
                 ┌──────────────── 服务端 43.108.99.4 (Seoul) ────────────────┐
   Windows 客户端 │  xray      TCP 443    VLESS + XTLS-Vision + REALITY       │
   ──────────────►│  hysteria  UDP 8443   QUIC / salamander 混淆              │──► 外网
                 │  transctl  TCP 8443   控制面 HTTPS（账号/流量/改密）        │
                 └───────────────────────────────────────────────────────────┘
```

两条通道（「双通道」）：

| 通道 | 协议 | 端口 | 特点 |
|---|---|---|---|
| A | VLESS + XTLS-Vision + REALITY | TCP 443 | 最隐蔽，流量看起来就是正常 TLS |
| B | Hysteria2（QUIC） | UDP 8443 | 抗丢包，弱网下更稳 |

关键设计：**两条通道只在内核的 `proxy` 出站上分岔**，入站、分流规则、TUN 接管完全共用。
REALITY 由内核直接建隧道；Hysteria2 则是「旁挂」——内核把流量交给本机一个 SOCKS 端口，
由旁边的 hysteria 进程负责真正的隧道。

这样做的好处是分流逻辑只有一份，不可能出现「换条通道行为就变了」。

域名：`proxy.example.com`（REALITY 伪装 SNI 借的是 `www.samsung.com`）。

---

## 2. 目录与组件

```
proxy-app/
  cmd/tunnelclient/     Windows 客户端（walk GUI）
  cmd/tunneladmin/      管理面板（本地操作用户，经 transctl 落到服务器）
  cmd/transctl/         服务端命令行（账号/参数的唯一入口）
  cmd/mkicon/           图标生成
  internal/common/      客户端与服务端共用的逻辑
  internal/ctl/         服务端控制面
```

`internal/common` 里几个容易看错的文件：

| 文件 | 职责 |
|---|---|
| `profile.go` | 生成客户端配置；两条通道的 `proxy` 出站就在这里分岔 |
| `runner.go` | 拉起/停止内核进程（xray 与 hysteria 共用同一套生命周期） |
| `tunsetup.go` | TUN 模式下由客户端自己配地址/DNS/路由（不用内核的自动配置） |
| `winproxy.go` | 系统代理的读写与还原 |
| `proxyrestore.go` | **系统代理的落盘备份与异常退出后的还原**（见第 5 节） |

---

## 3. 端口约定

刻意避开常见客户端的默认端口，否则撞端口会让新内核绑定失败，
而端口探测却因为旧进程占着而「成功」，表现为一堆莫名其妙的错乱。

| 用途 | 端口 | 备注 |
|---|---|---|
| 控制面 API | TCP 8443 | 客户端登录/取参数/查流量/改密，以及监控接口 |
| hysteria 服务端 | UDP 8443 | 与上面同号但不同协议，互不冲突 |
| 内核统计 API | TCP 10085 | 只在 127.0.0.1 上，供控制面读流量、增删用户 |
| 客户端 SOCKS 入站 | 17900 | 避开 10808（v2rayN）、7890（Clash） |
| 客户端 HTTP 入站 | 17901 | 同上 |
| hysteria 客户端 SOCKS | 17902 | 本机内部端口，xray 的 proxy 出站指向它 |
| 监控端 | TCP 18443 | 只绑监控端所在内网的 192.0.2.10，见第 11 节 |

> 注意：端口是**保存在客户端本地设置**里的，改默认值只影响首次运行；
> 已有 `client-settings.json` 的机器会继续用旧值。

---

## 4. 客户端行为要点

- **仅代理境外**：`geoip:cn` / `geosite:cn` 与内网直连，IPv6 一律走本机。
  路由用 `domainStrategy: AsIs`，避免用本地 DNS 解析域名导致被污染后误判为直连。
- **智能优选**：选「智能优选」时先试通道 A，探测不通过再自动退到通道 B。
  明确指定通道时只试那一条，失败就如实报错，不偷偷切换。
- **先探测再改系统设置**：连接时先用本地代理探一次（`generate_204`），
  确认隧道真的通了，再动系统代理或路由表。避免「端口在监听但其实不通」被当成连接成功。
- **TUN 模式**：内核只负责建虚拟网卡，地址/DNS/路由由客户端自己用 netsh/route 配置，
  这样每一步都能回读校验、能报出具体原因。`direct` 出站必须绑物理网卡地址
  （`sendThrough`），否则国内直连流量会被接管路由送回 TUN 形成死循环。

---

## 5. 关键设计：系统代理的还原

这一节记录的是一个**真实踩过的严重故障**及其修复，改动集中在 `internal/common/proxyrestore.go`。

### 5.1 故障现象

「客户端一退出（或重启后没打开客户端），整台机器什么网站都打不开」——连不需要
翻墙的站点也打不开，包括 TraeWork。

### 5.2 根因

非 TUN 模式下，客户端会把系统代理改成 `127.0.0.1:<本机 HTTP 端口>`。
还原逻辑本来是有的，但**快照只存在内存里**：

```
ProxyEnable = 1
ProxyServer = 127.0.0.1:10809
```

只要进程没走到正常退出那一步——被任务管理器结束、崩溃、或**开着客户端直接关机重启**——
注册表就会一直留着这两项。而重启后没有任何进程在该端口上监听，于是所有程序的
流量都被送进一个死地址，整机断网。这解释了一个很反直觉的现象：
**必须先把客户端打开才有网**（客户端一起来，端口才有人监听）。

### 5.3 修复：三道保障

1. **落盘备份**（`SaveProxyBackup`）
   改动系统代理**之前**，把原始设置写到工作目录 `proxy-backup.json`。
   顺序强制：备份必须早于改注册表——反过来会留下「已经改了但没备份」的窗口，
   此刻一旦断电，原始设置就再也找不回来。

2. **登录时一次性还原**（`RegisterProxyRecovery`）
   同时登记 `HKCU\...\RunOnce\TransProxyRestoreProxy`，指向
   `"<exe>" -restore-proxy -dir "<工作目录>"`。
   下次开机登录时自动还原并自我清理。**即使客户端再也不会被打开，开机也会自动修好**，
   不会留下「必须开着客户端才有网」的死局。
   用 `RunOnce` 而不是计划任务：不需要管理员权限，且系统执行后自动删除。
   > 这一条受界面上的「开机自动清理系统代理」开关控制（默认开启）。
   > 关掉后就没有开机兜底了，异常退出需要手动打开客户端才能恢复上网——
   > 界面上把代价写清楚了，别默认用户会去读文档。

3. **兜底防线**（`pointsAtDeadOwnProxy`）
   即使没有备份、或备份损坏读不懂，只要系统代理指向**我们自己的端口**且该端口
   已无监听者，就判定为我方留下的死状态并清掉。
   限定「自己的端口」是必要的——否则会误关用户自己的代理
   （例如用户的 v2rayN 恰好还没启动时，它的端口同样是「没有监听者」）。

还原流程：

```
正常断开/退出   还原 → 清备份 → 撤销登录启动项
异常退出        下次启动时补还原，界面提示「检测到上次未正常退出」
开机且不开客户端  登录启动项自动还原
备份损坏/缺失    走兜底防线，按死代理处理
```

### 5.4 相关约定

- 备份文件损坏时**仍然继续走兜底逻辑**，而不是静默返回。
  静默返回正是「用户一直断网却没有任何提示」的成因。
- `-restore-proxy` 走的是最简路径：不建界面、不联网、不申请提权，只改注册表然后退出。
  越简单越不容易再出问题。
- 开关名 `FlagRestoreProxy` 只定义一次，命令行解析与写进启动项两处都引用它，
  避免写岔导致登录项静默失效。
- **注册表一律走 API（`x/sys/windows/registry`），不调 `reg.exe`**。
  `reg.exe` 是控制台程序，由 GUI 进程拉起时 Windows 会给它开一个控制台窗口；
  连接、断开、开机还原都要读写这几个值，于是黑框会反复闪——这正是用户反馈过的
  「大黑框很烦」。走 API 则完全没有子进程。
  同理，其它子进程（xray、netsh、route）一律加 `CREATE_NO_WINDOW`。

### 5.5 启动选项

界面上「启动选项」卡片里四个开关，都直接对应系统状态，勾完即时生效
（`syncStartupOptions`，启动时与保存设置时各同步一次）：

| 开关 | 落在哪里 | 关掉的代价 |
|---|---|---|
| 开机自动清理系统代理 | `HKCU\...\RunOnce` | 异常退出后需手动打开客户端才能恢复上网 |
| 开机自动启动本软件 | `HKCU\...\Run` | 无 |
| 启动后自动连接服务器 | 本地 `client-settings.json` | 无（只影响便利性） |
| 启动后自动最小化到托盘 | 本地 `client-settings.json` | 无（只影响便利性） |

几个刻意的设计：

- `CleanOnBoot` 在存档里是**指针**（`*bool`），不是普通 bool。
  需要区分「没设置过」和「明确关掉」：这个功能是异常退出后的兜底，
  首次运行必须按开启处理；普通 bool 的零值恰好是 false，
  会让老用户升级上来的默认行为从「开」悄悄变成「关」。
- 自启项与还原项用**两个不同的键**（`Run` vs `RunOnce`）。
  把自启写进 `RunOnce`，用户重启一次之后就再也不自启了，而且完全看不出原因。
- 自启命令显式带 `-dir`。不带的话程序会退回默认工作目录，
  一旦用户装到别处（例如 D 盘并用 `-dir` 指定），自启起来的就是另一套配置、
  另一份代理备份，两个实例互相看不见对方的系统代理，排查极其费劲。
- 同步时**无条件重写**而不是「只在勾选变化时改」，为了兜住两种历史遗留：
  注册表被手工清理过；程序被挪了目录，自启项里留下一条指向旧路径的命令
  （系统每次开机都会去执行一个不存在的文件，界面却还显示「已开启」）。
- 「启动后自动连接」用完即清零（`autoConnectPending`）。
  不清的话，用户之后手动登出再登录会被莫名其妙地自动连上，而他并没有点过连接。
  它依赖「记住密码」——没有可用的密码就无从自动登录，勾选时就会当场提示。
- 「启动后自动最小化到托盘」**依赖**「启动后自动连接」（`minimizeAllowed`）。
  没勾自动连接时这个复选框是禁用的，依赖项被取消时它也会跟着取消：
  单独最小化等于把程序藏起来却什么都没连，用户既看不到界面、也不知道连没连上。
  读取设置与保存设置两处都走同一个判定函数，避免出现「存进去了、启动时又不认」。
  实现上不是「建好窗口再 Hide()」，而是给 `MainWindow` 传 `Visible: false`——
  后者会让 declarative 根本不调 `Show()`，连一闪都不会有。
  注意配套改动：TUN 提权的确认框挂在主窗口上，窗口隐藏时对话框也会跟着看不见，
  所以 `initTun` 在弹窗前会先把窗口亮出来。
- 无需管理员权限：这四项都在 `HKCU` / 本地文件里。

### 5.6 故障排查

怀疑又遇到同类问题时，按顺序看这三处：

```powershell
# 1) 系统代理是否指向一个已经没人监听的端口
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer
Get-NetTCPConnection -LocalPort <上面的端口> -State Listen   # 无输出=没人监听

# 2) 是否有待还原的备份（有则下次启动会自动还原）
dir "%LOCALAPPDATA%\TransProxy\proxy-backup.json"

# 3) 登录启动项是否还在
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce" /v TransProxyRestoreProxy
```

**紧急恢复直连**（立刻能用网，之后可再连客户端）：

```powershell
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f
```

### 5.6 更早的一个同类事故

TUN 模式的清理代码曾经执行 `route delete 0.0.0.0` 而不带掩码，命中并删除了系统
默认路由（`0.0.0.0/0`），导致断开后整机断网。现在清理逻辑强制带掩码，
并对掩码为 `0.0.0.0` 的路由直接跳过，断开后还会用 `HasDefaultRoute()` 自检并警告。

---

## 6. 安全约定

- SSH 只允许密钥登录（服务器 `admin@proxy.example.com`）。
- 客户端登录密码用 DPAPI 加密后落盘，不存明文；明文只在内存里存活，
  供 Hysteria2 认证使用。
- `hysteria.yaml`（含账号密码与混淆密钥）以 0600 权限落盘。
- 客户端连接身份（UUID）在改密码时会一并更换，旧参数立即失效。
- 账号鉴权失败一律返回同一句「账号或密码错误」，避免被用来枚举有效账号。

---

## 7. 客户端界面与动效

界面是浅色卡片式，配色只保留一个强调色（蓝）加成功/危险两个语义色。
几个自绘控件（呼吸状态点、缓动速率条、强调色按钮）在 `cmd/tunnelclient/ui.go`，
原因与取舍都写在那个文件的注释里。要点：

- 自绘控件用**单一定时器**统一驱动动画，空闲约半秒即自动停表——
  客户端常挂在托盘里几小时，那时不该还有重绘在跑。
- 自定义控件的布局项是「贪婪」的：`MinSize` 与 `MaxSize` **必须成对给**，
  只给下限会让按钮一路撑满剩余空间、变成一条突兀的大色块。
- 两个面板（登录 / 使用中）内容高度差很多，窗口按当前面板调整尺寸并夹到桌面工作区；
  首次显示前窗口还不知道自己落在哪块显示器上，所以尺寸要等显示后再纠正一次。

---

## 8. 开发与验证

```powershell
# 图标资源（改了 app-icon.png 之后必须重跑，否则 exe 与 APK 还是旧图标）
go run ./cmd/mkicon

# 构建（Go 工具链在 tools/go-dist/go/bin）
go fmt ./... ; go vet ./... ; go test ./...
go build -trimpath -ldflags "-H windowsgui -s -w" -o ..\dist\TransProxyClient.exe ./cmd/tunnelclient
```

`cmd/mkicon` 由一张源图 `app-icon.png` 生成三样东西，三处图标永远同源：

| 产物 | 用途 |
|---|---|
| `app.ico` | 多尺寸图标文件（16/24/32/48/64/128/256） |
| `cmd/tunnelclient/rsrc.syso` | 编进 exe 的 Windows 资源：图标 + `app.manifest` |
| `android/app/src/main/res/mipmap-*/ic_launcher*.png` | Android 各密度启动图标 |

`.syso` 是手写的 COFF 目标文件（`cmd/mkicon/syso.go`），因为这套环境里没有
`rsrc` / `windres`，也不该为此多引一个外部工具。要点是资源目录三层的
`OffsetToData` 必须写成 RVA，而链接前不知道段会被放在哪，所以先填段内偏移、
再挂一条 `IMAGE_REL_AMD64_ADDR32NB` 重定位指向 `.rsrc` 段——链接器会把段 RVA 加上去。

`app.manifest` **必须**一并写进资源：它声明了 Common Controls 6.0 依赖与 DPI 感知，
缺了它 walk 创建 ToolTip 会失败、程序在启动阶段直接崩溃。

无人值守自检（走完整链路后自动清理）：

```powershell
.\dist\TransProxyClient.exe -selftest -user <账号> -pass <密码> -proto reality
.\dist\TransProxyClient.exe -selftest -user <账号> -pass <密码> -proto hysteria
```

结果同时写入 `%TEMP%\transproxy-client-selftest.txt`。

---

## 9. 踩过的坑（避免重犯）

| 坑 | 现象 | 处置 |
|---|---|---|
| REALITY 伪装站点证书链过大 | `REALITY: processed invalid connection` | 换用 `www.samsung.com`；不要用 `www.microsoft.com`（5879 字节） |
| `route delete` 不带掩码 | 删掉系统默认路由，整机断网 | 强制带掩码；掩码为 0.0.0.0 的一律跳过；断开后自检 |
| 自绘控件只给 `MinSize` | 按钮变成巨大的色块 | `MinSize` 与 `MaxSize` 成对给 |
| 窗口创建时按 96 DPI 换算 | 登录窗口比预期小一圈 | 显示后再按 1/96" 单位纠正一次尺寸 |
| 依赖内核统计「在线连接」 | 永远显示 0 | 内核不提供该统计，改用「最近活动时间」 |
| 服务端 30s 窗口 vs 客户端 5s 轮询 | 速率忽 0 忽翻倍 | 客户端自己按两次采样差算速率，并做指数平滑 |
| hysteria 认证不返回 `id` | 流量统计出现空键 `{"":{...}}` | 认证响应必须带 `id`（账号名） |
| 端口撞车 | 内核绑定失败但探测「成功」 | 避开 10808/10809/7890；用 17900/17901/17902 |
| 用 `reg.exe` 读写系统代理 | 每次连接/断开/开机都闪一个黑框 | 改用 `x/sys/windows/registry`，无子进程 |
| 用 `reg.exe` 登记登录启动项 | 开机登录瞬间弹黑框，正是用户投诉的那个 | 同上 |
| 构建漏了 `-H windowsgui` | 程序后面挂着关不掉的 cmd 黑框，关掉它进程一起死 | 构建命令固定带 `-H windowsgui` |
| 无条件申请管理员权限 | 一次启动连弹两三个 UAC | 只在设置里确实开着 TUN 时才提权 |
| 自启/还原混用同一个注册表键 | 只自启一次，第二次开机就不动了 | 自启用 `Run`，还原用 `RunOnce` |
| 认证路径只读内存副本 | 刚用命令行建的账号登录报密码错，几秒后又正常 | `Snapshot`/`Find` 先 `syncFromDisk` |
| 用 `Label` 放长说明文字 | 文字被卡片右边缘整片切掉，只显示一半 | 改用 `TextLabel`，并让 `MinSize.Width > 0` 开启动态折行 |
| 托盘图标用 `walk.IconApplication()` | 换了 exe 图标，托盘还是那个系统默认图标 | 它返回的是 Windows 内置的 `IDI_APPLICATION`，跟 exe 里的图标无关；改成 `walk.NewIconFromResourceId(1)` |
| 从浏览器下载的 exe 带 MOTW | 每次启动都弹「打开文件 - 安全警告：无法验证发布者」 | 该弹窗发生在代码加载**之前**，拦不掉第一次；程序能跑起来后自清 `Zone.Identifier`，从第二次起不再弹。彻底消除只能靠代码签名证书 |
| 下载页只给 `Last-Modified`、不给 `Cache-Control` | 发了新版，用户点下载拿到的还是上一版 | 安装包响应必须显式 `Cache-Control: no-store, must-revalidate`。浏览器会按「经验缓存」把整份安装包留下（新鲜期约文件年龄的十分之一），再次下载时根本不问服务器；而页面清单是实时读的、新旧包体积又只差几十 KB，界面上完全看不出哪里不对 |
| 用 `cp` 替换运行中的控制面二进制 | 服务起不来，`systemctl` 报 `status=203/EXEC` | `cp` 不保留权限位，目标变成 0644。改用 `install -m 0755`，或先 `cp` 到同目录临时名再 `mv -f` 覆盖（rename 才是原子的） |

---

## 10. Android 客户端

架构与 Windows 端同源：**内核只处理包，分流规则由同一份配置语义决定**。
差别在于 Android 上虚拟网卡不是内核自己建的，而是由 VpnService 建好后把 fd 交给内核
（这是 Xray 官方支持的 Android 通路，走环境变量 `xray.tun.fd`）。

```
android/
  core/        Go 内核封装 → 经 gomobile 编译成 xraycore.aar
  app/         Android 应用（VpnService + 界面）；不依赖 AndroidX/Kotlin
  app/libs/xraycore.aar
  app/src/main/assets/{geoip.dat,geosite.dat}
```

两个必须记住的点：

- **防回环**：`Builder.addDisallowedApplication(自己)` 不能少。内核发出的连接一旦被
  再送进隧道就是无限套娃，现象是「一连就断网、日志里什么都没有」。
- **分流数据要落盘**：`geoip.dat` / `geosite.dat` 是在**解析配置阶段**就被读进来的。
  设备上没有这两个文件，配置会被直接拒绝。所以它们随 APK 打包，
  首次连接时由 `AssetInstaller` 释放到私有目录，并把 `xray.location.asset` 指过去。

### 构建

先用 gomobile 出 AAR，再用 Gradle 出 APK：

```powershell
# 1) 内核 AAR（每个 ABI 各编一次）
gomobile bind -target=android/amd64 -androidapi 24 -javapkg com.transproxy `
  -o android/core/build/xraycore.aar transproxy/core
# 真机还需要：-target=android/arm64 与 android/arm

# 2) 把 AAR 放到 android/app/libs/ 后
cd android
gradle assembleDebug
```

### 构建环境上的四个坑（都已踩过）

| 坑 | 现象 | 处置 |
|---|---|---|
| **路径含空格** | `cgo: C compiler "…\TRAE" not found` | 把 `ANDROID_NDK_HOME` 指向 8.3 **短路径**（`TRAE~1` 形式），空格会把 clang 路径截断 |
| **javac 默认 GBK** | 导出 API 的中文注释成非法字节，编译失败 | 设 `JAVA_TOOL_OPTIONS=-Dfile.encoding=UTF-8` |
| **路径超 260 字符** | cmdline-tools 解压中途失败 | 用 `tar` 解压（内部走 `\\?\`，不受 MAX_PATH 限制） |
| **AGP 8 不生成 BuildConfig** | `找不到符号 BuildConfig` | `buildFeatures { buildConfig = true }` |
| **换掉 AAR 后增量打包** | arm64 的 APK 从 91MB 涨到 154MB（体积翻倍但功能正常） | 增量打包把旧的 `libgojni.so` 残留在 APK 里。换 AAR 后必须 `gradle clean assembleDebug`。核对方法：APK 里 `lib/<abi>/` 应当只有一个 `.so` |
| **AAR 缺某个 ABI** | 对应 APK 构建「成功」但里面没有 `.so`，装上必崩 | 日志里会有 `There are no .so files available to package in the APK for <abi>`。只发布 AAR 里真正包含的 ABI，别把空壳包发出去 |
| **`go mod tidy` 清掉 gomobile 的依赖** | `gomobile bind` 报 `missing golang.org/x/mobile dependency` | 我们并不 import 它，tidy 会当无用依赖删掉。用 `tools.go`（`//go:build tools` + 空导入）钉住。**别用** `go get -tool`：加了 `tool` 指令后 gomobile 会卡死在 `go list -deps -compiled`（x/mobile 含 cgo，进了 android 目标的依赖图就走不通），现象是 CPU 归零、无限等待 |
| **hysteria 的 TLS 服务器名传成了 REALITY 的 SNI** | 握手失败：`CRYPTO_ERROR 0x150 (remote): tls: internal error` | 要用**入口域名**（证书上的域名），不是 `params.sni`（那是 `www.samsung.com`，REALITY 借用的站点）。见第 10 节 |

另外 gomobile 会把导出函数名**首字母转小写**：Go 侧的 `BuildConfig/Logs/Start`
在 Java 里是 `buildConfig/logs/start`。

### 传输通道（通道A / 通道B）

界面上一个按钮在两条通道间切换，改完重连生效。两条通道**只在内核的 proxy 出站上分岔**，
入站、分流规则、TUN 接管完全共用，因此不会出现「两条通道行为不一致」。

| | 通道A · REALITY | 通道B · Hysteria2 |
|---|---|---|
| 内核出站 | 自己建 VLESS + REALITY 隧道 | 指向本机 `127.0.0.1:17902` 的 SOCKS5 |
| 隧道由谁建 | 内核 | 同进程内的 hysteria 客户端库 |
| 特点 | 最隐蔽 | 抗丢包 |

**Android 与 Windows 的关键差异**：Windows 是「旁挂」——拉一个 `hysteria.exe` 进程；
Android 不允许拉起外部进程，所以 hysteria 客户端以库的形式跑在同一进程内，
再由我们自己起一个最小 SOCKS5 入口（`internal/.../hysteria.go`）。
对内核来说两条通道形状完全一样。

两个容易踩的点：

- **TLS 服务器名要用入口域名，不是 REALITY 的伪装 SNI**。`params.sni` 是
  `www.samsung.com`（REALITY 借用的站点），而 hysteria 的证书是入口域名的。
  传错的表现是握手以「服务端内部错误」告终，很难从现象反推。
- **通道B 的认证需要「账号:密码」原文**（服务端用 bcrypt 比对），不像通道A 用的是 UUID。
  这份凭据随参数串走，但**只有勾了「记住密码」才会落盘**（见 `Prefs.sanitizeForStorage`）。
  没勾时通道B 在进程被系统回收后无法自动恢复，界面上会把原因说清楚。

联网验证（要连真实服务器，默认跳过）：

```powershell
$env:HY_TEST_USER="临时账号"; $env:HY_TEST_PASS="密码"
go test -run TestLiveHysteriaTunnel -v ./...   # 在 proxy-app/android/core 下执行
```

它会走完整链路：登录拿参数 → 握手 → 经 SOCKS5 建 TCP 连 example.com → 再走 UDP 做一次 DNS 查询。
测完记得把临时账号删掉。

### 后台保活

VPN 一旦放后台被系统回收，用户就会遇到「连上一会儿就断了」。这里做了四层：

1. **前台服务 + 常驻通知**（`startForeground`，类型 `specialUse`）。
   注意通知**必须指定 channelId**，否则 Android 8+ 会判为 Bad notification
   并抛 `RemoteServiceException` 把整个进程带崩——这个坑踩过一次。
2. **`START_STICKY` + 空 Intent 自愈**。系统回收进程后重启服务时给的是空 Intent，
   那时隧道已经断了。所以连接成功时把参数存进 SharedPreferences，
   服务被重启时凭它自动重建隧道；用户主动断开则清掉，避免「点了断开又自己连上」。
3. **电池优化白名单**。国内 ROM 会额外清理后台，仅在界面上提供入口
   （`ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS`）并显示当前状态。
4. **崩溃循环保护**。连续自动重启超过 4 次就放弃并清掉参数，
   否则「起来就崩」会一直耗电。

### 构建产物

按 ABI 拆包（内核 .so 每个架构约 64MB，合成一个包会到 150MB 以上）：

| 产物 | 大小 | 用途 |
|---|---|---|
| `app-arm64-v8a-debug.apk` | ~93MB | **真机装这个**（已发布到下载页） |
| `app-x86_64-debug.apk` | ~95MB | 模拟器 |
| `app-universal-debug.apk` | ~159MB | 通吃，不想挑架构时装这个 |
| `app-armeabi-v7a-debug.apk` | ~29MB | ⚠️ **空壳，不要发布** |

最后一行要特别小心：AAR 里只编了 arm64 与 x86_64，armeabi-v7a 的 APK 能构建成功、
体积也「正常」，但里面根本没有 `libgojni.so`，装上必崩。构建日志里会有
`There are no .so files available to package in the APK for armeabi-v7a`。

### 已知待办

- [ ] 密码目前存在应用私有 SharedPreferences（受应用沙箱保护），
      尚未用 Keystore 再加一层
- [ ] 整机流量（tun-in → proxy）尚未取到直接日志证据，
      建议在真机上开浏览器访问 `google.com` 做一次人工确认


---

## 11. 监控（访问记录）

目标是回答「哪个账号在什么时候访问了哪些站点」。数据全部来自内核自己的访问日志，
不需要改内核、也不需要旁路抓包。

### 11.1 能拿到什么、拿不到什么

内核的访问日志行尾带 `email: <账号名>`（渲染配置时写进了每个 VLESS 用户的 email 字段），
所以按账号归属是原生能力：

```
2026/09/19 04:11:19.362675 from 27.187.241.248:41478 accepted tcp:accounts.google.com:443 [reality-in >> direct] email: qichen
```

| 维度 | 是否可得 | 说明 |
|---|---|---|
| 账号、时间、目标主机名、端口、TCP/UDP、命中直连还是代理、来源 IP | ✅ | 直接解析日志 |
| 完整 URL / 路径 / **搜索关键词** | ❌ | HTTPS 全程加密，日志里只到 TLS SNI。要拿到必须做中间人解密，那会让 REALITY 的伪装彻底失效，不做 |
| 通道B（Hysteria2）的流量 | ❌ | 那条流量在 hysteria 进程里就终止了，不经过内核 |
| 明文 DNS 查询（UDP 53） | 主动丢弃 | 日志里只有「查询发给了哪个解析器」（例如 `1.1.1.1:53`），没有「查了什么域名」——内核不解开 DNS 报文。这类记录回答不了任何监控问题，却占了全部记录的 15%，所以在采集阶段就丢掉（`isNoise`）。UDP 443（QUIC）是真实访问，照常保留 |

**记录粒度是「连接」不是「请求」**：同一域名被访问多次就是多条记录。

### 11.2 服务端

| 组件 | 位置 | 作用 |
|---|---|---|
| 日志落文件 | `/var/log/xray/access.log` | 内核写；由 `XrayAccessLog` 常量控制。必须落文件而不是 stdout，因为要按偏移增量读 |
| 采集器 | `internal/ctl/monitor.go` | 每 2 秒增量读日志、解析、按天写入 `<data>/access/YYYY-MM-DD.jsonl`；超过 64MB 清空内核日志；保留 14 天 |
| 监控接口 | `internal/ctl/admin.go` | `/api/v1/admin/{overview,events,top}` |
| 管理员令牌 | `<data>/admin-token` | 首次启动生成，`transctl admintoken` 可打印 |

接口约定（全部用 `X-Admin-Token` 头鉴权，也可用 `Authorization: Bearer`）：

```
GET  /api/v1/admin/overview                          账号清单 + 用量 + 采集状态
GET  /api/v1/admin/events?since=&user=&host=&limit=  增量访问记录（since 为 Unix 微秒）
GET  /api/v1/admin/top?days=&user=&limit=            域名 TopN + 每账号条数

POST /api/v1/admin/user/create  {name,password,note,quotaBytes}
POST /api/v1/admin/user/update  {name,note?,quotaBytes?,enabled?,newPassword?}
POST /api/v1/admin/user/delete  {name}
```

账号管理接口会**即时改动运行中的内核**（`AddUserRuntime` / `RemoveUserRuntime`），
不需要重启，因此不会打断其他在线用户。几点必须知道的：

- **账号名严格限 `[A-Za-z0-9_-]{1,32}`**。这不是美观问题：名字会被拼进临时文件路径
  （`AddUserRuntime` 写 `/tmp/transctl-adu-<名字>.json`），放任 `../` 等于开放任意路径写入。
- 禁用账号 = 从内核摘掉，正在用的设备会立刻断线；重新启用会装回新身份。
- 重置密码会更换 UUID，旧连接参数立即失效，本人需重新登录。
- 删除账号先摘内核再删库，避免留下「库里没有、内核里还能连」的幽灵用户。

> **时间单位是 Unix 微秒**，与客户端接口（`/api/v1/traffic` 的 `lastActive` 按秒）不同。
> 用微秒是必须的：一次 DNS 突发会在同一**毫秒**内产生好几条一模一样的记录，
> 按毫秒存下来监控端做增量去重时会把它们当重复丢掉（实测 611 条被并成 371 条）。

### 11.3 监控端

监控端在 10.x 内网、服务端在公网，服务端连不到监控端，所以方向是 **监控端 主动拉**。

部署在 `/vol1/1000/transproxy/`（源码在仓库 `monitor/`）：

| 文件 | 作用 |
|---|---|
| `monitor.py` | 全部逻辑：拉取 + 本地存储 + 网页 + 账号管理转发（纯标准库，无依赖） |
| `config.json` | 服务端地址、管理员令牌、监听地址、页面口令哈希（0600） |
| `data/events.jsonl` | 本地记录，14 天滚动 |
| `logs/{monitor,stdout}.log` | 业务日志与未捕获异常 |
| `/etc/systemd/system/transproxy-monitor.service` | 开机自启 |

访问：`http://192.0.2.10:18443/`（HTTP Basic 认证，用户名 `admin`）。

面板能做的事：

- 看：账号用量与最近活动、域名 TopN、可搜索的访问记录（今天 / 7 天 / 14 天）
- 管：**新建账号、改备注与额度、重置密码、停用/启用、删除**，改完即时生效
- 改：**右上角「修改密码」可随时更换面板自己的登录口令**

账号操作由监控端转发给节点，**管理员令牌只存在 监控端上，不下发到浏览器**。
所以浏览器侧只需要面板口令，即使面板页面被人看到，也拿不到直接操作节点的能力。

面板口令存在 `config.json` 的 `password_hash` 里（PBKDF2-HMAC-SHA256，加盐 20 万次迭代，0600）。在网页里改会
**同时更新内存与磁盘，立即生效**；万一忘记了，在监控端上走命令行补救：

```bash
cd /vol1/1000/transproxy
python3 monitor.py --set-password                     # 交互式无回显输入新密码
sudo systemctl restart transproxy-monitor            # 必须重启才生效（服务内存里还是旧口令）
```

> 口令不从命令行参数传入：监控端上进程的 argv 对同机所有用户可见，还会留在 shell 历史里。
> 需要在脚本里非交互执行时用管道：`echo '新密码' | python3 monitor.py --set-password`。
> 库里若还是旧的无盐 SHA-256 记录，下一次成功登录会自动升级为 PBKDF2。

> 网页改动不需要重启（改的是同一个进程内存里的字典），命令行改动需要重启——
> 这个差异是刻意的：网页路径能保证「改完立刻可用」，命令行路径只能改文件。

运维：

```bash
sudo systemctl status|restart|stop transproxy-monitor   # 服务
sudo systemctl disable --now transproxy-monitor         # 彻底关掉
curl -u admin:<口令> http://192.0.2.10:18443/api/data?days=7   # 直接取数据
```

### 11.4 刻意做的取舍

- **两套令牌严格分开**：用户令牌只能读自己的流量，管理员令牌才能读所有人的记录。
  混用会导致「客户端被逆向 → 全站浏览记录泄露」。
- **访问记录落在控制面的数据目录**（`<data>/access/`），不是数据库。
  每天几万条、保留 14 天，单文件足够，且出问题能直接 `cat` 看。
- **管理员令牌不写进日志**：启动时只打日志到 journald，令牌要用 `admintoken` 命令取。
- 面板页面与接口都要求认证；监听只绑监控端所在内网的指定地址，不对全网开放。

---

## 12. 待办

- [ ] 服务器侧对 Windows 客户端做一次端到端回归
- [ ] 监控：通道B（Hysteria2）的访问记录尚未覆盖
- [ ] Windows 客户端登录界面按钮偏大、与窗口尺寸不匹配
