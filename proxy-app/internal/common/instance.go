package common

// 多线路（多实例）。
//
// 客户端**不预置任何节点信息**：出口地址、端口、UUID、REALITY 公钥、shortId、SNI、
// hysteria 口令，全部由服务端在登录响应里下发。这套「线路表」是同一思路的延伸 ——
// 服务端多发一项，客户端就多一条可选线路，客户端里不需要硬编码任何节点。
//
// 好处是加线路、改线路的显示名都不用重新发客户端；代价是客户端登录不上就拿不到
// 参数，但这本来就是既有架构的前提。

// 线路角色。
//
// 【当前拓扑：服务端下发的永远是 RoleExit】每个实例都是自己的出口 —— 选「分支节点A」
// 就是从分支节点A的 IP 出网，两条通道都不经过另一台机器。所以界面上对每一条线路
// 都该说「出口」，不该说「入口/中转」。
//
// RoleRelay 是早先「中转到总节点」方案的取值，那个方案已废弃。这里保留它、
// 并保留 IsRelay()，是因为它是 wire 上的合法取值：以后若真出现
// 「第一跳 + 出口在别处」的形态，客户端不必改协议就能渲染。
const (
	// RoleExit：这条线路自己就是出口（当前唯一会被下发的取值）。
	RoleExit = "exit"
	// RoleRelay：这条线路只是第一跳，真正出网的是 Via 指向的那条。
	//
	// 客户端不需要为它做任何特殊处理 —— 参数已经由服务端按拓扑组装好了，
	// 这个字段只用于界面提示与排障。
	RoleRelay = "relay"
)

// DefaultInstanceID 是「没有选中任何线路」时代用的 id。
const DefaultInstanceID = "default"

// Instance 是一条可选线路：线路本身的描述 + 这条线路的连接参数。
type Instance struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Role string `json:"role,omitempty"`
	// Via 是这条线路最终从哪条线路出网，只对 RoleRelay 有意义。
	// 当前拓扑下一直是空的（每条线路自己出网）。
	Via string `json:"via,omitempty"`

	// Params 内嵌是为了让 JSON 保持扁平：客户端拿到的每一项，字段形状与原来的
	// params 完全一致。这样「按线路取参数」只是换一个来源，其余代码一行都不用动。
	Params
}

// IsRelay 报告这条线路是否需要再跳一次才能出网。
//
// 当前拓扑下恒为 false（服务端下发的都是 RoleExit）。留着是因为服务端仍可能
// 下发 relay —— 那时界面就得如实说「经某线路出网」，否则用户会以为出口变了。
func (i Instance) IsRelay() bool { return i.Role == RoleRelay }

// Choose 按 id 选线路。
//
// 兜底分两层，两层都不报错（宁可安静地退回默认线路，也不要把用户卡在
// 「选了条不存在的线路然后怎么都连不上」上）：
//   - id 非空但找不到：说明服务端撤掉了这条线路或改了 id，退回默认线路；
//   - id 为空：用服务端给的列表第一项 —— 服务端把本机线路排在第一位。
//
// 列表为空时（老服务端、或单线路部署）合成一条默认线路，行为与过去完全一致。
func (r *LoginResult) Choose(id string) Instance {
	if id != "" {
		for _, ins := range r.Instances {
			if ins.ID == id {
				return ins
			}
		}
	}
	if len(r.Instances) > 0 {
		return r.Instances[0]
	}
	return Instance{ID: DefaultInstanceID, Name: "默认线路", Role: RoleExit, Params: r.Params}
}

// ProfileFor 按所选线路合成连接配置。
func (r *LoginResult) ProfileFor(instanceID, mode string, socksPort, httpPort int) Profile {
	return FromParams(r.Choose(instanceID).Params, r.UUID, mode, socksPort, httpPort)
}
