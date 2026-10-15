package ctl

import (
	"fmt"
	"html"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// 下载页。
//
// 设计目标是「不想被扫描器扫到」，不是「强鉴权」：
//   - 页面挂在一个随机深层路径下，根路径与其它路径一律 404，不暴露任何入口；
//   - 目录不可枚举，只按白名单文件名提供文件；
//   - 响应带 noindex，避免被搜索引擎收录。
//
// 需要清楚：知道这个路径的人都能下载。对安装包来说这是可接受的，
// 真要设防应当加令牌，但那样分发就得逐个发链接、反而更难用。
//
// 访问方式：
//   GET /<DownloadPath>/        下载页
//   GET /<DownloadPath>/<文件名> 安装包

// allowedPackages 是下载目录里唯一允许暴露的文件类型，值是响应用的 Content-Type。
//
// 用白名单而不是「排除某些后缀」：目录里会同时躺着日志、账号库、备份，
// 黑名单总有漏的那一刻，白名单不会。
var allowedPackages = map[string]string{
	".apk": "application/vnd.android.package-archive",
	".exe": "application/vnd.microsoft.portable-executable",
}

// packageKind 判断文件名是不是可下载的安装包，并返回它的 Content-Type。
// 后缀一律小写比较，免得 Windows 上传的 .EXE 被漏掉。
func packageKind(name string) (string, bool) {
	ext := strings.ToLower(filepath.Ext(name))
	ct, ok := allowedPackages[ext]
	return ct, ok
}

// downloadPrefix 返回归一化后的路径前缀，形如 "/k7x2..."；未配置时返回空串。
func (s *Service) downloadPrefix() string {
	p := strings.Trim(strings.TrimSpace(s.Settings.DownloadPath), "/")
	if p == "" {
		return ""
	}
	return "/" + p
}

// handleDownload 是下载页与安装包共用的入口。
// 任何不匹配的路径都返回 404（而不是 403），免得告诉扫描器「这里有东西但你没权限」。
func (s *Service) handleDownload(w http.ResponseWriter, r *http.Request) {
	prefix := s.downloadPrefix()
	if prefix == "" || !strings.HasPrefix(r.URL.Path, prefix) {
		http.NotFound(w, r)
		return
	}
	rest := strings.TrimPrefix(strings.TrimPrefix(r.URL.Path, prefix), "/")
	if rest == "" {
		s.serveDownloadPage(w, r)
		return
	}
	s.serveDownloadFile(w, r, rest)
}

func (s *Service) serveDownloadPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Robots-Tag", "noindex, nofollow, noarchive")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(s.downloadHTML()))
}

func (s *Service) serveDownloadFile(w http.ResponseWriter, r *http.Request, name string) {
	// 只允许下载目录下的单层文件名：挡掉 ../、绝对路径与子目录。
	if name == "" || strings.ContainsAny(name, `/\`) || strings.Contains(name, "..") {
		http.NotFound(w, r)
		return
	}
	// 与页面的展示口径保持一致：只放行白名单里的安装包后缀。
	// 下载目录里可能躺着备份、日志之类的东西，不能因为「知道文件名」就下得走。
	ctype, ok := packageKind(name)
	if !ok {
		http.NotFound(w, r)
		return
	}
	dir := strings.TrimSpace(s.Settings.DownloadDir)
	if dir == "" {
		http.NotFound(w, r)
		return
	}
	full := filepath.Join(dir, name)
	st, err := os.Stat(full)
	if err != nil || st.IsDir() {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition",
		fmt.Sprintf("attachment; filename=%q", name))

	// 安装包必须显式禁缓存。
	//
	// 只靠 http.ServeFile 给出的 Last-Modified，浏览器会按「经验缓存」把整份安装包
	// 留在本地（新鲜期大约是文件年龄的十分之一，对几天前的包就是好几个小时）。
	// 用户再次点下载时浏览器**根本不问服务器**，直接把本地那份旧包给出去：
	// 我们发了新版，用户拿到的还是上一版，而页面清单又是实时读的、大小也只差几十 KB，
	// 从界面上完全看不出哪儿不对。线上真的这样坑过一次，所以这里必须 no-store。
	w.Header().Set("Cache-Control", "no-store, must-revalidate")
	w.Header().Set("Pragma", "no-cache")

	http.ServeFile(w, r, full)
}

// listPackages 返回可下载的安装包，按文件名排序。
// 只认白名单后缀，避免把同目录下别的东西（例如备份文件）意外暴露出去。
func (s *Service) listPackages() []string {
	dir := strings.TrimSpace(s.Settings.DownloadDir)
	if dir == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if _, ok := packageKind(e.Name()); ok {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out
}

// downloadHTML 生成下载页。
//
// 页面内容固定在代码里而不是外部模板：部署只涉及一个文件，
// 不会出现「模板忘了传」这类问题。
func (s *Service) downloadHTML() string {
	prefix := s.downloadPrefix()

	var items strings.Builder
	pkgs := s.listPackages()
	if len(pkgs) == 0 {
		items.WriteString(`<li class="empty">暂无可下载的安装包</li>`)
	}
	for _, name := range pkgs {
		// 文件名来自服务器本地目录，仍然转义一次再放进 HTML，
		// 免得将来有人把带特殊字符的文件名丢进来。
		n := html.EscapeString(name)
		items.WriteString(fmt.Sprintf(
			`<li><a href="%s/%s">%s</a><span class="meta">%s</span></li>`,
			prefix, n, n, humanSize(fileSize(filepath.Join(s.Settings.DownloadDir, name)))))
	}

	// 机型提示：真机几乎都是 arm64，模拟器才是 x86_64。
	hint := ""
	if len(pkgs) > 0 {
		hint = `<p class="hint">Windows 电脑装 <code>.exe</code>；` +
			`手机装 <code>arm64-v8a</code> 那个 apk，模拟器装 <code>x86_64</code>。` +
			`装不上的话换另一个试试。</p>`
	}

	out := strings.ReplaceAll(downloadTemplate, "{{ITEMS}}", items.String())
	return replaceOnce(out, "{{HINT}}", hint)
}

// replaceOnce 只替换第一处，避免样式里恰好出现同样的占位串时被误伤。
func replaceOnce(s, old, new string) string {
	i := strings.Index(s, old)
	if i < 0 {
		return s
	}
	return s[:i] + new + s[i+len(old):]
}

func fileSize(path string) int64 {
	st, err := os.Stat(path)
	if err != nil {
		return 0
	}
	return st.Size()
}

func humanSize(n int64) string {
	if n <= 0 {
		return ""
	}
	units := []string{"B", "KB", "MB", "GB"}
	f := float64(n)
	i := 0
	for f >= 1024 && i < len(units)-1 {
		f /= 1024
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d B", n)
	}
	return fmt.Sprintf("%.1f %s", f, units[i])
}

const downloadTemplate = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow,noarchive">
<title>TransProxy</title>
<style>
  :root { color-scheme: light; }
  body { margin:0; padding:28px 20px 48px; background:#f4f6fa; color:#1f2430;
         font:16px/1.7 -apple-system,"Segoe UI","Microsoft YaHei UI",sans-serif; }
  .wrap { max-width:620px; margin:0 auto; }
  h1 { font-size:26px; margin:0 0 4px; }
  .sub { color:#6b7280; margin:0 0 26px; }
  h2 { font-size:16px; margin:28px 0 8px; }
  .card { background:#fff; border-radius:10px; padding:16px 18px; margin:0 0 14px; }
  ul { list-style:none; padding:0; margin:0; }
  li { display:flex; align-items:baseline; justify-content:space-between;
       gap:12px; padding:12px 0; border-bottom:1px solid #eef1f6; }
  li:last-child { border-bottom:0; }
  li a { color:#2f6bff; text-decoration:none; font-weight:600; word-break:break-all; }
  .meta { color:#9ca4b2; font-size:13px; white-space:nowrap; }
  .empty { color:#9ca4b2; justify-content:flex-start; }
  .hint { color:#6b7280; font-size:13px; margin:10px 0 0; }
  code { background:#eef1f6; border-radius:4px; padding:1px 5px; font-size:13px; }
  p { margin:8px 0; }
  .notice p { color:#8a5a00; }
  strong { color:#1f2430; }
</style>
</head>
<body>
<div class="wrap">
  <h1>TransProxy</h1>
  <p class="sub">免费学习版 · 加密隧道代理</p>

  <h2>下载</h2>
  <div class="card">
    <ul>{{ITEMS}}</ul>
    {{HINT}}
  </div>

  <h2>免费声明</h2>
  <div class="card notice">
    <p>本软件<strong>完全免费</strong>，没有任何收费项目，也不存在「付费版」「高级版」。</p>
    <p>若有人以本软件名义向你收取费用，均与作者无关。</p>
  </div>

  <h2>免责声明</h2>
  <div class="card notice">
    <p>本软件仅供<strong>学习与网络技术研究</strong>使用。</p>
    <p>使用者应自行确保其使用行为符合所在地法律法规，并自行承担因使用本软件产生的一切后果。</p>
    <p>作者不对任何直接或间接损失负责，也不对使用者的具体用途作任何担保。</p>
  </div>

  <h2>关于账号</h2>
  <div class="card">
    <p>本软件<strong>不提供注册</strong>，也没有开放申请入口。账号由维护者按需分配。</p>
    <p>确有使用需要，请联系作者。<strong>本页面不提供任何联系方式</strong>，请通过你已知的渠道联系。</p>
  </div>
</div>
</body>
</html>
`
