package ctl

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newDownloadService(t *testing.T) (*Service, string) {
	t.Helper()
	dir := t.TempDir()
	// 放两个安装包（Android 与 Windows），以及几个不该被暴露的文件
	if err := os.WriteFile(filepath.Join(dir, "app-arm64-v8a.apk"), []byte("APKDATA"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "TransProxyClient.exe"), []byte("EXEDATA"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "secret.txt"), []byte("SHOULD-NOT-LEAK"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := NewService(nil, ServerSettings{
		DownloadPath: "k7x2mq9f4v1p8n3z",
		DownloadDir:  dir,
	}, nil)
	return s, dir
}

// 根路径与错误路径都必须 404：不给扫描器留下「这里有个站」的印象。
// 用 404 而不是 403，是因为 403 等于承认「路径存在但你没权限」。
func TestDownloadHidesEverythingElse(t *testing.T) {
	s, _ := newDownloadService(t)
	h := s.Handler()

	for _, p := range []string{
		"/",
		"/index.html",
		"/download",
		"/dl",
		"/k7x2mq9f4v1p8n3",   // 少一个字符
		"/k7x2mq9f4v1p8n3z2", // 多一个字符
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s 应返回 404，实际 %d", p, rec.Code)
		}
	}
}

// 下载页必须带上用户要求的那几段声明，且不得出现联系方式。
func TestDownloadPageStatements(t *testing.T) {
	s, _ := newDownloadService(t)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/k7x2mq9f4v1p8n3z/", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("下载页应返回 200，实际 %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"免费", "免责", "不提供注册", "请联系作者", "不提供任何联系方式"} {
		if !strings.Contains(body, want) {
			t.Fatalf("下载页缺少声明：%q", want)
		}
	}
	// 页面要能列出安装包
	if !strings.Contains(body, "app-arm64-v8a.apk") {
		t.Fatal("下载页没有列出 Android 安装包")
	}
	if !strings.Contains(body, "TransProxyClient.exe") {
		t.Fatal("下载页没有列出 Windows 客户端")
	}
	// 非安装包文件不应出现在页面上
	if strings.Contains(body, "secret.txt") {
		t.Fatal("下载页不该列出非安装包文件")
	}
	// 不该被搜索引擎收录
	if rec.Header().Get("X-Robots-Tag") == "" {
		t.Fatal("下载页缺少 noindex 头")
	}
}

// 安装包响应必须显式禁缓存。
//
// 只给 Last-Modified 时，浏览器会把下载过的安装包整份缓存下来，再次下载时根本不问
// 服务器，用户拿到的还是上一版；而页面清单是实时读的、新旧包的体积又只差几十 KB，
// 所以从界面上完全看不出哪里不对。线上真被这个问题坑过一次。
func TestDownloadFileDisablesCaching(t *testing.T) {
	s, _ := newDownloadService(t)
	for _, name := range []string{"TransProxyClient.exe", "app-arm64-v8a.apk"} {
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec,
			httptest.NewRequest(http.MethodGet, "/k7x2mq9f4v1p8n3z/"+name, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s 应返回 200，实际 %d", name, rec.Code)
		}
		cc := rec.Header().Get("Cache-Control")
		if !strings.Contains(cc, "no-store") {
			t.Fatalf("%s 的 Cache-Control 必须含 no-store，否则浏览器会拿旧的；实际 %q", name, cc)
		}
	}
}

func TestDownloadServesApk(t *testing.T) {
	s, _ := newDownloadService(t)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec,
		httptest.NewRequest(http.MethodGet, "/k7x2mq9f4v1p8n3z/app-arm64-v8a.apk", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("下载安装包应返回 200，实际 %d", rec.Code)
	}
	got, _ := io.ReadAll(rec.Body)
	if string(got) != "APKDATA" {
		t.Fatalf("下载内容不对：%q", got)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "android.package-archive") {
		t.Fatalf("apk 的 Content-Type 不对：%q", ct)
	}
}

func TestDownloadServesExe(t *testing.T) {
	s, _ := newDownloadService(t)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec,
		httptest.NewRequest(http.MethodGet, "/k7x2mq9f4v1p8n3z/TransProxyClient.exe", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("下载 Windows 客户端应返回 200，实际 %d", rec.Code)
	}
	got, _ := io.ReadAll(rec.Body)
	if string(got) != "EXEDATA" {
		t.Fatalf("下载内容不对：%q", got)
	}
	// 直接给 application/octet-stream 也行，只要不是被浏览器当成网页打开。
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "portable-executable") &&
		!strings.Contains(ct, "octet-stream") {
		t.Fatalf("exe 的 Content-Type 不对：%q", ct)
	}
}

// 只暴露白名单后缀：目录里其它文件即便知道文件名也不该能下载。
func TestDownloadRejectsNonPackage(t *testing.T) {
	s, _ := newDownloadService(t)
	for _, name := range []string{
		"secret.txt", "users.json",
		"app-arm64-v8a.apk.bak", "TransProxyClient.exe.bak", "TransProxyClient.zip",
	} {
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec,
			httptest.NewRequest(http.MethodGet, "/k7x2mq9f4v1p8n3z/"+name, nil))
		if rec.Code != http.StatusNotFound {
			t.Fatalf("%s 应返回 404，实际 %d", name, rec.Code)
		}
		if strings.Contains(rec.Body.String(), "SHOULD-NOT-LEAK") {
			t.Fatalf("%s 泄露了目录内的非安装包文件", name)
		}
	}
}

// 路径穿越必须被挡住：这是这类静态下载接口最容易出的漏洞。
func TestDownloadBlocksTraversal(t *testing.T) {
	s, _ := newDownloadService(t)
	h := s.Handler()

	for _, p := range []string{
		"/k7x2mq9f4v1p8n3z/../users.json",
		"/k7x2mq9f4v1p8n3z/..%2fusers.json",
		"/k7x2mq9f4v1p8n3z/....//users.json",
		"/k7x2mq9f4v1p8n3z/sub/../../../etc/passwd",
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, p, nil))
		body := rec.Body.String()
		if rec.Code == http.StatusOK {
			t.Fatalf("%s 不应成功（返回 200）", p)
		}
		if strings.Contains(body, "SHOULD-NOT-LEAK") || strings.Contains(body, "root:") {
			t.Fatalf("%s 泄露了目录外内容", p)
		}
	}
}

// 没配置路径时整个下载功能应当等于不存在，而不是挂在根路径上。
func TestDownloadDisabledWhenPathEmpty(t *testing.T) {
	s := NewService(nil, ServerSettings{DownloadDir: t.TempDir()}, nil)
	rec := httptest.NewRecorder()
	s.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("未配置路径时根路径应 404，实际 %d", rec.Code)
	}
	if s.downloadPrefix() != "" {
		t.Fatal("未配置路径时前缀应为空")
	}
}
