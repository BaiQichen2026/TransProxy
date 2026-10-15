package common

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

// ParseShareLink 解析 vless:// 分享链接，只识别 REALITY 方案用到的字段。
//
// 公钥参数同时接受 pbk 与 pwd 两种写法：新版 Xray 把 REALITY 客户端的公钥字段
// 由 publicKey 更名为 password，分享链接层面也随之出现了 pwd 这个新参数名。
func ParseShareLink(link string) (Profile, error) {
	raw := strings.TrimSpace(link)
	if raw == "" {
		return Profile{}, fmt.Errorf("链接为空")
	}
	if !strings.HasPrefix(raw, "vless://") {
		return Profile{}, fmt.Errorf("只支持 vless:// 开头的分享链接")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return Profile{}, fmt.Errorf("链接无法解析: %w", err)
	}

	p := Default()
	p.UUID = u.User.Username()
	if p.UUID == "" {
		return Profile{}, fmt.Errorf("链接缺少用户 UUID")
	}
	p.ServerAddr = u.Hostname()
	if p.ServerAddr == "" {
		return Profile{}, fmt.Errorf("链接缺少服务器地址")
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil {
			return Profile{}, fmt.Errorf("端口无法解析: %v", err)
		}
		p.ServerPort = n
	}

	q := u.Query()
	if v := q.Get("sni"); v != "" {
		p.SNI = v
	}
	if v := q.Get("pbk"); v != "" {
		p.PublicKey = v
	}
	if v := q.Get("pwd"); v != "" {
		p.PublicKey = v
	}
	if v := q.Get("sid"); v != "" {
		p.ShortID = v
	}
	if v := q.Get("fp"); v != "" {
		p.Fingerprint = v
	}
	if v := q.Get("flow"); v != "" {
		p.Flow = v
	}
	if u.Fragment != "" {
		p.Remark = u.Fragment
	}
	return p, nil
}
