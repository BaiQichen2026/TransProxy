package ctl

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// 账号管理接口（管理员专用，供监控面板调用）。
//
// 这些操作会真正改动运行中的内核：新增/删除用户、改密码换 UUID，
// 都通过 AddUserRuntime / RemoveUserRuntime 即时生效，不需要重启内核，
// 因此不会打断其他在线用户。
//
// 监控面板不直接调这些接口，而是由 监控端上的服务代转：管理员令牌只留在服务端与
// 监控端上，绝不下发到浏览器。

// userNamePattern 限定账号名的字符集。
//
// 这不是美观问题而是安全问题：账号名会被拼进临时文件名
// （AddUserRuntime 写 /tmp/transctl-adu-<名字>.json），
// 放任 `../` 之类的名字等于开放任意路径写入。
var userNamePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,32}$`)

type userCreateReq struct {
	Name       string `json:"name"`
	Password   string `json:"password"`
	Note       string `json:"note"`
	QuotaBytes int64  `json:"quotaBytes"`
	// AllowNodes 是新账号被授权使用的中转线路 id 列表，空 = 只能用默认线路。
	AllowNodes []string `json:"allowNodes"`
}

func (s *Service) handleAdminUserCreate(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		errJSON(w, 405, "只支持 POST")
		return
	}
	var req userCreateReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		errJSON(w, 400, "请求格式错误")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Note = strings.TrimSpace(req.Note)
	if !userNamePattern.MatchString(req.Name) {
		errJSON(w, 400, "账号名只能包含字母、数字、下划线和短横线，长度 1-32")
		return
	}
	if req.QuotaBytes < 0 {
		errJSON(w, 400, "额度不能为负数")
		return
	}
	// 授权线路先校验再落库：写错的 id 不会报任何错，只会静默地变成
	// 「授了权但用不了」，在管理界面上极难看出来。
	routes, err := s.Relays.NormalizeAllowNodes(req.AllowNodes)
	if err != nil {
		errJSON(w, 400, err.Error())
		return
	}
	if _, err := s.Store.Add(req.Name, req.Password, req.Note, req.QuotaBytes); err != nil {
		errJSON(w, 400, err.Error())
		return
	}
	if len(routes) > 0 {
		if err := s.Store.Modify(req.Name, func(u *User) { u.AllowNodes = routes }); err != nil {
			errJSON(w, 500, "账号已创建但写入线路授权失败: "+err.Error())
			return
		}
	}
	// 新账号必须立刻装进运行中的内核，否则用户拿到的连接参数会连不上。
	nu, _ := s.Store.Snapshot(req.Name)
	if err := s.ApplyUser(&nu); err != nil {
		errJSON(w, 500, "账号已创建但同步内核失败: "+err.Error())
		return
	}
	s.Log("监控接口：已创建账号 %s", req.Name)
	writeJSON(w, 200, map[string]any{"ok": true, "message": fmt.Sprintf("账号 %s 已创建", req.Name)})
}

type userUpdateReq struct {
	Name        string  `json:"name"`
	Note        *string `json:"note"`
	QuotaBytes  *int64  `json:"quotaBytes"`
	Enabled     *bool   `json:"enabled"`
	NewPassword string  `json:"newPassword"`
	// AllowNodes 必须用指针：要能区分「这次没提交这个字段（保持原样）」与
	// 「提交了空数组（取消全部授权）」。用切片的话后者会被当成前者，权限永远收不回来。
	AllowNodes *[]string `json:"allowNodes"`
}

func (s *Service) handleAdminUserUpdate(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		errJSON(w, 405, "只支持 POST")
		return
	}
	var req userUpdateReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		errJSON(w, 400, "请求格式错误")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if _, ok := s.Store.Snapshot(req.Name); !ok {
		errJSON(w, 404, "账号不存在")
		return
	}
	if req.QuotaBytes != nil && *req.QuotaBytes < 0 {
		errJSON(w, 400, "额度不能为负数")
		return
	}

	// 授权线路先校验，写错的 id 直接拒掉而不是静默失效。
	var routes []string
	if req.AllowNodes != nil {
		var err error
		routes, err = s.Relays.NormalizeAllowNodes(*req.AllowNodes)
		if err != nil {
			errJSON(w, 400, err.Error())
			return
		}
	}

	msg := []string{}
	// 改密码会换 UUID，是一条独立路径。
	if req.NewPassword != "" {
		if err := s.Store.SetPassword(req.Name, req.NewPassword); err != nil {
			errJSON(w, 400, err.Error())
			return
		}
		msg = append(msg, "密码已重置（旧连接参数立即失效）")
	}
	// 备注 / 额度 / 启用状态 / 线路授权
	if req.Note != nil || req.QuotaBytes != nil || req.Enabled != nil || req.AllowNodes != nil {
		err := s.Store.Modify(req.Name, func(u *User) {
			if req.Note != nil {
				u.Note = strings.TrimSpace(*req.Note)
			}
			if req.QuotaBytes != nil {
				u.QuotaBytes = *req.QuotaBytes
			}
			if req.Enabled != nil {
				u.Enabled = *req.Enabled
			}
			if req.AllowNodes != nil {
				u.AllowNodes = routes
			}
		})
		if err != nil {
			errJSON(w, 400, err.Error())
			return
		}
		if req.Enabled != nil {
			if *req.Enabled {
				msg = append(msg, "已启用")
			} else {
				msg = append(msg, "已停用")
			}
		}
		if req.Note != nil {
			msg = append(msg, "备注已更新")
		}
		if req.QuotaBytes != nil {
			msg = append(msg, "额度已更新")
		}
		if req.AllowNodes != nil {
			if len(routes) == 0 {
				msg = append(msg, "已取消全部中转线路授权")
			} else {
				msg = append(msg, "已授权线路："+strings.Join(routes, "、"))
			}
		}
	}
	if len(msg) == 0 {
		errJSON(w, 400, "没有需要修改的字段")
		return
	}

	// 把最新状态同步进内核：启用时是新身份装进去，停用时是摘掉。
	nu, ok := s.Store.Snapshot(req.Name)
	var err error
	if ok && nu.Enabled {
		err = s.ApplyUser(&nu)
	} else {
		err = s.DropUser(req.Name)
	}
	if err != nil {
		errJSON(w, 500, "已修改但同步内核失败: "+err.Error())
		return
	}
	s.Log("监控接口：已修改账号 %s（%s）", req.Name, strings.Join(msg, "、"))
	writeJSON(w, 200, map[string]any{
		"ok": true, "message": fmt.Sprintf("账号 %s：%s", req.Name, strings.Join(msg, "、")),
	})
}

type userDeleteReq struct {
	Name string `json:"name"`
}

func (s *Service) handleAdminUserDelete(w http.ResponseWriter, r *http.Request) {
	if !s.requireAdmin(w, r) {
		return
	}
	if r.Method != http.MethodPost {
		errJSON(w, 405, "只支持 POST")
		return
	}
	var req userDeleteReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8192)).Decode(&req); err != nil {
		errJSON(w, 400, "请求格式错误")
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if _, ok := s.Store.Snapshot(req.Name); !ok {
		errJSON(w, 404, "账号不存在")
		return
	}
	// 先从内核摘掉再删库：反过来的话，删库成功但摘除失败会留下一个
	// 「账号库里没有、内核里还能连」的幽灵用户。
	if err := s.DropUser(req.Name); err != nil {
		errJSON(w, 500, "从内核移除失败: "+err.Error())
		return
	}
	if err := s.Store.Remove(req.Name); err != nil {
		errJSON(w, 500, err.Error())
		return
	}
	s.Log("监控接口：已删除账号 %s", req.Name)
	writeJSON(w, 200, map[string]any{"ok": true, "message": fmt.Sprintf("账号 %s 已删除", req.Name)})
}
