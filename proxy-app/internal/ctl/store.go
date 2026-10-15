package ctl

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// User 是一个账号。
//
// UUID 是喂给内核的身份标识（VLESS 用它做认证），对用户不可见、也不需要用户知道；
// 用户只需要记住账号密码。改密码时会顺带换掉 UUID，等价于把旧会话彻底作废。
type User struct {
	Name       string    `json:"name"`
	Password   string    `json:"passwordHash"`
	UUID       string    `json:"uuid"`
	QuotaBytes int64     `json:"quotaBytes"`
	UsedBytes  int64     `json:"usedBytes"`
	Enabled    bool      `json:"enabled"`
	Note       string    `json:"note,omitempty"`
	CreatedAt  time.Time `json:"createdAt"`

	// AllowNodes 列出该账号**被授权使用的落地线路**（线路 id，例如 "edge-a"）。
	//
	// 空表示只能用本机那条默认线路。默认值刻意是「不给」：新增一条落地线路时，
	// 绝不会因为「忘了配」而让所有人自动用上它 —— 想放开必须显式授权。
	AllowNodes []string `json:"allowNodes,omitempty"`

	// LastActive 是该账号最近一次被观测到有流量的时间。
	// 内核没有提供可用的「在线数」统计（策略里也没有对应开关，实测 statsonline 始终查不到键），
	// 所以用这个指标代替：它同样能回答「现在有人在用吗」，而且是真实数据。
	LastActive time.Time `json:"lastActive,omitempty"`

	// lastUp/lastDown 记录上一次从内核读到的计数器原始值，用于计算增量。
	// 内核重启后计数器归零，靠这两个值识别出“归零”并重新起算。
	lastUp   int64 `json:"-"`
	lastDown int64 `json:"-"`
}

// AllowsNode 报告该账号是否被授权使用指定线路。
func (u *User) AllowsNode(id string) bool {
	for _, n := range u.AllowNodes {
		if n == id {
			return true
		}
	}
	return false
}

// Remaining 返回剩余额度；QuotaBytes 为 0 表示不限量。
func (u *User) Remaining() int64 {
	if u.QuotaBytes <= 0 {
		return -1
	}
	r := u.QuotaBytes - u.UsedBytes
	if r < 0 {
		return 0
	}
	return r
}

// Store 是账号库，落盘为单个 JSON 文件。
// 用户规模很小，用文件 + 互斥锁足够，且便于直接查看和备份。
type Store struct {
	path string

	mu     sync.Mutex
	Secret string  `json:"serverSecret"`
	Users  []*User `json:"users"`

	// sig 记录本进程上次读写文件时的签名，用于发现外部进程（管理命令）的改动。
	sig string
}

// TokenSecret 返回令牌签名密钥的当前值。
//
// 必须走这个方法而不是直接读字段：账号库文件被外部进程（管理命令）改动时，
// syncFromDisk 会在持锁状态下替换这个值，而 HTTP 处理器是并发读它的——
// 直接读字段就是一次数据竞争（go test -race 会报）。
func (s *Store) TokenSecret() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Secret
}

// LoadStore 读取账号库，文件不存在时创建空库并生成令牌签名密钥。
func LoadStore(path string) (*Store, error) {
	s := &Store{path: path, sig: fileSig(path)}
	b, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			return nil, err
		}
		s.Secret = randomHex(32)
		if err := s.save(); err != nil {
			return nil, err
		}
		return s, nil
	}
	if err := json.Unmarshal(b, s); err != nil {
		return nil, fmt.Errorf("账号库不是合法 JSON: %w", err)
	}
	if s.Secret == "" {
		s.Secret = randomHex(32)
		if err := s.save(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *Store) save() error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	// 先写临时文件再改名，避免写一半被中断导致账号库损坏。
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, s.path); err != nil {
		return err
	}
	s.sig = fileSig(s.path)
	return nil
}

// fileSig 返回文件的轻量签名，用来判断文件是否被其他进程改过。
func fileSig(path string) string {
	fi, err := os.Stat(path)
	if err != nil {
		return ""
	}
	return fmt.Sprintf("%d-%d", fi.Size(), fi.ModTime().UnixNano())
}

// Save 加锁落盘。
func (s *Store) Save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.save()
}

// Find 按账号名查找，找不到返回 nil。
func (s *Store) Find(name string) *User {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.syncFromDisk()
	for _, u := range s.Users {
		if u.Name == name {
			return u
		}
	}
	return nil
}

// List 返回账号快照副本，避免调用方在锁外读到正在被修改的结构。
func (s *Store) List() []User {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]User, 0, len(s.Users))
	for _, u := range s.Users {
		c := *u
		out = append(out, c)
	}
	return out
}

// Add 新建账号。
func (s *Store) Add(name, password, note string, quotaBytes int64) (*User, error) {
	if name == "" {
		return nil, errors.New("账号名不能为空")
	}
	if len(password) < 6 {
		return nil, errors.New("密码至少 6 位")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.syncFromDisk()
	for _, u := range s.Users {
		if u.Name == name {
			return nil, fmt.Errorf("账号 %s 已存在", name)
		}
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	u := &User{
		Name:       name,
		Password:   string(hash),
		UUID:       NewUUID(),
		QuotaBytes: quotaBytes,
		Enabled:    true,
		Note:       note,
		CreatedAt:  time.Now(),
	}
	s.Users = append(s.Users, u)
	return u, s.save()
}

// Remove 删除账号。
func (s *Store) Remove(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.syncFromDisk()
	for i, u := range s.Users {
		if u.Name == name {
			s.Users = append(s.Users[:i], s.Users[i+1:]...)
			return s.save()
		}
	}
	return fmt.Errorf("账号 %s 不存在", name)
}

// Modify 就地修改某个账号并落盘，回调在持锁状态下执行。
// 改备注、额度、启用状态这类「改几个字段」的操作走这里；
// 改密码要连带换 UUID，用 SetPassword。
func (s *Store) Modify(name string, fn func(u *User)) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.syncFromDisk()
	for _, u := range s.Users {
		if u.Name == name {
			fn(u)
			return s.save()
		}
	}
	return fmt.Errorf("账号 %s 不存在", name)
}

// SetPassword 改密码，并同时更换 UUID。
// 换 UUID 的目的是让旧密码期间发出的所有连接参数立即失效，这对“改密码”这个动作才是完整的。
func (s *Store) SetPassword(name, newPassword string) error {
	if len(newPassword) < 6 {
		return errors.New("新密码至少 6 位")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.syncFromDisk()
	for _, u := range s.Users {
		if u.Name != name {
			continue
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
		if err != nil {
			return err
		}
		u.Password = string(hash)
		u.UUID = NewUUID()
		return s.save()
	}
	return fmt.Errorf("账号 %s 不存在", name)
}

// CheckPassword 校验密码。
func (u *User) CheckPassword(password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(password)) == nil
}

// syncFromDisk 在持锁状态下检查文件是否被别的进程改过，改过就重新加载。
//
// 管理命令（transctl）与后台控制服务是独立进程，会直接改写同一个文件；
// 监控面板的账号管理接口又是在控制服务进程里改同一份数据。
// 不重新加载的话，服务侧会用陈旧的内存副本覆盖掉别人的改动——
// 现象是「刚用命令行加的账号，被网页上的一次操作静默抹掉」。
//
// 调用方必须已持有 s.mu。
func (s *Store) syncFromDisk() {
	sig := fileSig(s.path)
	if sig == s.sig {
		return
	}
	if b, err := os.ReadFile(s.path); err == nil {
		var fresh Store
		if json.Unmarshal(b, &fresh) == nil && fresh.Secret != "" {
			s.Secret = fresh.Secret
			s.Users = fresh.Users
		}
	}
	s.sig = sig
}

// Update 在持锁状态下遍历账号并允许原地修改，回调返回 true 表示有改动需要落盘。
// 流量累加这类「读-改-写」必须走这里，否则并发下会丢增量。
func (s *Store) Update(fn func(u *User) bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.syncFromDisk()

	dirty := false
	for _, u := range s.Users {
		if fn(u) {
			dirty = true
		}
	}
	if !dirty {
		return nil
	}
	return s.save()
}

// Read 在持锁状态下只读遍历账号。
func (s *Store) Read(fn func(u *User)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.Users {
		fn(u)
	}
}

// Import 以指定 UUID 建立账号，用于把已有的裸 UUID 用户迁移成账号。
// 保留原 UUID 可以让此前发出去的节点信息在迁移后继续有效。
func (s *Store) Import(name, password, uuid, note string, quotaBytes int64) (*User, error) {
	if name == "" || uuid == "" {
		return nil, errors.New("账号名与 UUID 均不能为空")
	}
	if len(password) < 6 {
		return nil, errors.New("密码至少 6 位")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.syncFromDisk()
	for _, u := range s.Users {
		if u.Name == name {
			return nil, fmt.Errorf("账号 %s 已存在", name)
		}
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	u := &User{
		Name: name, Password: string(hash), UUID: uuid, QuotaBytes: quotaBytes,
		Enabled: true, Note: note, CreatedAt: time.Now(),
	}
	s.Users = append(s.Users, u)
	return u, s.save()
}

// Snapshot 返回账号副本，供 HTTP 处理器这类在锁外读取的场景使用。
// 直接返回内部指针会造成与流量轮询协程之间的数据竞争。
//
// 必须先 syncFromDisk：登录、令牌校验这些认证路径全靠它取账号，
// 而账号可能是刚被管理命令（独立进程）加进来的。之前这里没有同步，
// 只靠 5 秒一次的流量轮询顺带刷新内存副本，于是出现「刚加好的账号登录报
// 『账号或密码错误』、过几秒又好了」——认证结果取决于后台轮询的时机，
// 这种不确定性没有任何理由存在于认证路径上。
func (s *Store) Snapshot(name string) (User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.syncFromDisk()
	for _, u := range s.Users {
		if u.Name == name {
			return *u, true
		}
	}
	return User{}, false
}

// NewUUID 生成 v4 UUID。
func NewUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
