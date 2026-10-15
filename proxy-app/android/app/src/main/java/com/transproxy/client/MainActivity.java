package com.transproxy.client;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.graphics.Color;
import android.net.Uri;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.PowerManager;
import android.provider.Settings;
import android.text.InputType;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import com.transproxy.core.Core;

import org.json.JSONObject;

/**
 * 界面。结构与 Windows 端一致：登录面板 → 使用面板。
 *
 * 刻意不用 XML 布局，全部用代码搭：控件不多，代码搭出来的层级一眼能看懂，
 * 也少一处「布局文件写错、运行时才崩」的出错面。
 */
public class MainActivity extends Activity implements TransVpnService.Listener {

    private static final int REQ_VPN = 1001;
    private static final long POLL_MS = 5000;

    // 登录面板
    private LinearLayout loginPanel;
    private EditText hostBox, portBox, userBox, passBox;
    private CheckBox rememberBox;
    private TextView loginTip;

    // 使用面板
    private LinearLayout mainPanel;
    private TextView accountLabel, stateLabel, stateDetail, trafficLabel, rateLabel, logLabel;
    private Button connectBtn;
    private CheckBox autoConnBox;
    /** 线路选择按钮（点击循环切换）。 */
    private Button lineBtn;
    /** 线路说明：这条线路是直连出口，还是经中转从别的线路出网。 */
    private TextView lineHint;

    private ControlApi.Session session;
    private boolean connected;
    /**
     * 本次启动是否要「自动登录后顺手连上」。
     *
     * 只在启动那一次有效，用完立刻清零：否则用户之后手动登出再登录，
     * 会被莫名其妙地自动连上，而他自己并没有点过连接。
     */
    private boolean autoConnectPending;
    /**
     * 本会话内的明文密码，只存在于内存。
     *
     * 通道B 的认证需要「账号:密码」原文（服务端做 bcrypt 比对），而登录成功后
     * 输入框会被清空，所以必须在这里留一份。它不会主动落盘——
     * 写盘的是「记住密码」那条独立路径，且详情见 Prefs.sanitizeForStorage。
     */
    private String sessionPass;

    private final Handler ui = new Handler(Looper.getMainLooper());
    private long lastUp, lastDown, lastAt;

    @Override
    protected void onCreate(Bundle b) {
        super.onCreate(b);
        TransVpnService.listener = this;
        setContentView(buildUi());
        loadPrefs();
    }

    @Override
    protected void onDestroy() {
        if (TransVpnService.listener == this) {
            TransVpnService.listener = null;
        }
        ui.removeCallbacksAndMessages(null);
        super.onDestroy();
    }

    // ---------- 界面搭建 ----------

    private int dp(float v) {
        return (int) TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v,
                getResources().getDisplayMetrics());
    }

    private View buildUi() {
        ScrollView scroll = new ScrollView(this);
        scroll.setBackgroundColor(Color.parseColor("#F4F6FA"));

        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        int pad = dp(16);
        root.setPadding(pad, pad, pad, pad);
        scroll.addView(root);

        loginPanel = new LinearLayout(this);
        loginPanel.setOrientation(LinearLayout.VERTICAL);
        root.addView(loginPanel);
        buildLoginPanel();

        mainPanel = new LinearLayout(this);
        mainPanel.setOrientation(LinearLayout.VERTICAL);
        mainPanel.setVisibility(View.GONE);
        root.addView(mainPanel);
        buildMainPanel();

        return scroll;
    }

    private TextView title(String text, float size) {
        TextView t = new TextView(this);
        t.setText(text);
        t.setTextSize(size);
        t.setTextColor(Color.parseColor("#1F2430"));
        t.setPadding(0, dp(4), 0, dp(4));
        return t;
    }

    private TextView label(String text) {
        TextView t = new TextView(this);
        t.setText(text);
        t.setTextSize(13);
        t.setTextColor(Color.parseColor("#6B7280"));
        t.setPadding(0, dp(8), 0, dp(2));
        return t;
    }

    private EditText field(String value, boolean password) {
        EditText e = new EditText(this);
        e.setText(value);
        e.setTextSize(15);
        if (password) {
            e.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        }
        return e;
    }

    private void buildLoginPanel() {
        loginPanel.addView(title(getString(R.string.app_name), 26));
        TextView sub = label("免费学习版 · 加密隧道代理");
        loginPanel.addView(sub);

        loginPanel.addView(label("服务器地址"));
        hostBox = field(Prefs.host(this), false);
        loginPanel.addView(hostBox);

        loginPanel.addView(label("控制端口"));
        portBox = field(String.valueOf(Prefs.port(this)), false);
        loginPanel.addView(portBox);

        loginPanel.addView(label("账号"));
        userBox = field(Prefs.user(this), false);
        loginPanel.addView(userBox);

        loginPanel.addView(label("密码"));
        passBox = field(Prefs.remember(this) ? Prefs.pass(this) : "", true);
        loginPanel.addView(passBox);

        rememberBox = new CheckBox(this);
        rememberBox.setText("记住密码");
        rememberBox.setChecked(Prefs.remember(this));
        loginPanel.addView(rememberBox);

        Button login = new Button(this);
        login.setText("登录");
        login.setTextSize(16);
        login.setOnClickListener(v -> doLogin());
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.topMargin = dp(14);
        loginPanel.addView(login, lp);

        loginTip = label("请输入服务端分配的账号密码");
        loginPanel.addView(loginTip);

        // 显示内核版本。除了让用户知道用的是哪个内核，它还有个实际作用：
        // 这里会真正调用一次内核的导出函数——如果 so 没打进 APK、或者架构不匹配，
        // 这一行会立刻暴露出 UnsatisfiedLinkError，而不是等到点连接才失败。
        TextView ver = label("内核：" + safeVersion());
        loginPanel.addView(ver);

        loginPanel.addView(notice());
    }

    private static String safeVersion() {
        try {
            return Core.version();
        } catch (Throwable t) {
            return "加载失败（" + t.getClass().getSimpleName() + "：" + t.getMessage() + "）";
        }
    }

    private void buildMainPanel() {
        accountLabel = label("");
        mainPanel.addView(accountLabel);

        stateLabel = title("未连接", 22);
        mainPanel.addView(stateLabel);

        stateDetail = label("");
        mainPanel.addView(stateDetail);

        connectBtn = new Button(this);
        connectBtn.setText("连接");
        connectBtn.setTextSize(16);
        connectBtn.setOnClickListener(v -> toggleConnect());
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.topMargin = dp(12);
        mainPanel.addView(connectBtn, lp);

        mainPanel.addView(label("流量"));
        trafficLabel = new TextView(this);
        trafficLabel.setTextSize(14);
        trafficLabel.setTextColor(Color.parseColor("#1F2430"));
        mainPanel.addView(trafficLabel);

        rateLabel = new TextView(this);
        rateLabel.setTextSize(14);
        rateLabel.setTextColor(Color.parseColor("#1F2430"));
        mainPanel.addView(rateLabel);

        mainPanel.addView(label("代理规则"));
        Button modeBtn = new Button(this);
        modeBtn.setText(modeLabelApplied());
        modeBtn.setOnClickListener(v -> toggleMode(modeBtn));
        mainPanel.addView(modeBtn);

        mainPanel.addView(label("传输通道"));
        Button protoBtn = new Button(this);
        protoBtn.setText(protoLabel());
        protoBtn.setOnClickListener(v -> toggleProto(protoBtn));
        mainPanel.addView(protoBtn);

        mainPanel.addView(label("线路"));
        lineBtn = new Button(this);
        lineBtn.setText(lineLabel());
        lineBtn.setOnClickListener(v -> toggleLine(lineBtn));
        mainPanel.addView(lineBtn);
        // 说明放在控件下方：用户最关心「从哪儿出网」。服务端下发的每条线路都是
        // 自己的出口（选分支节点A就是从分支节点A的 IP 出网），所以这里正常显示「直连出口」。
        lineHint = label("");
        lineHint.setTextSize(12);
        mainPanel.addView(lineHint);

        mainPanel.addView(label("本机代理端口"));
        Button lanBtn = new Button(this);
        lanBtn.setText(lanLabel());
        lanBtn.setOnClickListener(v -> toggleAllowLan(lanBtn));
        mainPanel.addView(lanBtn);

        // 后台保活：前台服务已经做了，但国内不少 ROM 还会额外清理后台，
        // 申请电池优化白名单是唯一能让系统放行的手段，所以把入口摆在显眼处。
        mainPanel.addView(label("后台运行"));
        Button bgBtn = new Button(this);
        bgBtn.setText(bgLabel());
        bgBtn.setOnClickListener(v -> requestBackgroundAllowed(bgBtn));
        mainPanel.addView(bgBtn);

        mainPanel.addView(label("启动选项"));
        autoConnBox = new CheckBox(this);
        autoConnBox.setText("启动后自动连接服务器");
        autoConnBox.setChecked(Prefs.autoConnect(this));
        autoConnBox.setOnCheckedChangeListener((v, on) -> {
            Prefs.setAutoConnect(this, on);
            if (on && !Prefs.remember(this)) {
                // 没有记住密码就无法自动登录，现在说清楚，别等用户下次打开时
                // 干等半天发现没连上再来找原因。
                toast("还需要在登录页勾选「记住密码」，否则无法自动登录");
            }
        });
        mainPanel.addView(autoConnBox);
        // 说明写在控件下方，而不是用一个含糊的标题：这三个字概括不了「自动登录+自动连接」。
        TextView autoConnHint = label("打开后自动登录并直接连上，使用上次成功的参数，不需要再点「连接」。需先勾选「记住密码」。");
        autoConnHint.setTextSize(11);
        mainPanel.addView(autoConnHint);

        Button pw = new Button(this);
        pw.setText("修改密码");
        pw.setOnClickListener(v -> changePassword());
        LinearLayout.LayoutParams lp2 = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp2.topMargin = dp(12);
        mainPanel.addView(pw, lp2);

        Button logout = new Button(this);
        logout.setText("退出登录");
        logout.setOnClickListener(v -> confirmLogout());
        LinearLayout.LayoutParams lp3 = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp3.topMargin = dp(8);
        mainPanel.addView(logout, lp3);

        mainPanel.addView(label("内核日志（排查问题用）"));
        logLabel = new TextView(this);
        logLabel.setTextSize(11);
        logLabel.setTextColor(Color.parseColor("#6B7280"));
        logLabel.setTypeface(android.graphics.Typeface.MONOSPACE);
        mainPanel.addView(logLabel);

        mainPanel.addView(notice());
    }

    private TextView notice() {
        TextView t = new TextView(this);
        t.setText(getString(R.string.notice_1) + "\n" + getString(R.string.notice_2));
        t.setTextSize(12);
        t.setTextColor(Color.parseColor("#8A5A00"));
        t.setPadding(0, dp(18), 0, dp(8));
        return t;
    }

    private String modeLabelApplied() {
        return "代理规则：" + ("global".equals(Prefs.mode(this)) ? "全局代理" : "智能分流（仅代理境外）");
    }

    private void toggleMode(Button b) {
        boolean global = "global".equals(Prefs.mode(this));
        Prefs.get(this).edit().putString(Prefs.KEY_MODE, global ? "smart" : "global").apply();
        b.setText(modeLabelApplied());
        toast("规则已切换，重连后生效");
    }

    // ---------- 传输通道 ----------

    /** 服务端是否下发了可用的通道B。三项参数缺一不可，缺了连不上。 */
    private boolean hysteriaAvailable() {
        JSONObject p = activeParams();
        if (p == null) {
            return false;
        }
        return p.optBoolean("hysteriaEnabled")
                && p.optInt("hysteriaPort") > 0
                && !p.optString("hysteriaObfs").isEmpty();
    }

    private String protoLabel() {
        if (Prefs.PROTO_HYSTERIA.equals(Prefs.proto(this))) {
            if (!hysteriaAvailable()) {
                return "通道B · Hysteria2（服务端未启用，将退回通道A）";
            }
            return "通道B · Hysteria2（抗丢包）";
        }
        return "通道A · REALITY（最隐蔽）";
    }

    private void toggleProto(Button b) {
        if (Prefs.PROTO_HYSTERIA.equals(Prefs.proto(this))) {
            Prefs.get(this).edit().putString(Prefs.KEY_PROTO, Prefs.PROTO_REALITY).apply();
            b.setText(protoLabel());
            toast("已切回通道A，重连后生效");
            return;
        }
        if (!hysteriaAvailable()) {
            toast("服务端未启用通道B，无法切换");
            return;
        }
        Prefs.get(this).edit().putString(Prefs.KEY_PROTO, Prefs.PROTO_HYSTERIA).apply();
        b.setText(protoLabel());
        toast("已切到通道B，重连后生效");
    }

    // ---------- 线路（多实例） ----------

    /**
     * 当前选中的线路 id。
     *
     * 存档里的 id 若已被服务端撤掉（或从没选过），退回第一项 —— 与
     * ControlApi.Session.paramsFor 的兜底一致：宁可换一条能用的，也不要把用户卡住。
     */
    private String currentInstanceId() {
        if (session == null) {
            return Prefs.instanceId(this);
        }
        String saved = Prefs.instanceId(this);
        for (int i = 0; i < session.lineCount(); i++) {
            JSONObject ins = session.line(i);
            if (ins != null && saved.equals(ins.optString("id"))) {
                return saved;
            }
        }
        JSONObject first = session.line(0);
        return first == null ? "" : first.optString("id");
    }

    /** 当前生效的连接参数（所选线路那份）。 */
    private JSONObject activeParams() {
        if (session == null || session.params == null) {
            return null;
        }
        return session.paramsFor(currentInstanceId());
    }

    private String lineLabel() {
        JSONObject ins = activeParams();
        if (ins == null) {
            return "默认线路";
        }
        String name = ins.optString("name");
        return name.isEmpty() ? "默认线路" : name;
    }

    /**
     * 线路说明：说清「从哪儿出网」。
     *
     * 当前服务端下发的都是 exit（每条线路都是自己的出口），所以正常显示「直连出口」。
     * relay 分支是把这个协议字段当真时的渲染方式，理由同 Windows 端 enterMain：
     * 万一以后出现「第一跳 + 出口在别处」的形态，界面必须如实说，不能让用户以为出口变了。
     */
    private String lineHintText() {
        JSONObject ins = activeParams();
        if (ins == null) {
            return "";
        }
        if (!"relay".equals(ins.optString("role"))) {
            return "直连出口";
        }
        String via = ins.optString("via");
        for (int i = 0; i < session.lineCount(); i++) {
            JSONObject x = session.line(i);
            if (x != null && via.equals(x.optString("id"))) {
                via = x.optString("name");
                break;
            }
        }
        return "入口在中转节点，仍从「" + via + "」出网";
    }

    /** 按登录结果刷新线路按钮与说明。 */
    private void refreshLineUi() {
        if (lineBtn != null) {
            lineBtn.setText(lineLabel());
        }
        if (lineHint != null) {
            lineHint.setText(lineHintText());
        }
    }

    /** 在可选线路之间循环切换。 */
    private void toggleLine(Button b) {
        if (session == null || session.lineCount() <= 1) {
            toast("服务端只提供了这一条线路");
            return;
        }
        String now = currentInstanceId();
        int cur = 0;
        for (int i = 0; i < session.lineCount(); i++) {
            JSONObject ins = session.line(i);
            if (ins != null && now.equals(ins.optString("id"))) {
                cur = i;
                break;
            }
        }
        JSONObject next = session.line((cur + 1) % session.lineCount());
        Prefs.setInstanceId(this, next == null ? "" : next.optString("id"));
        refreshLineUi();
        b.setText(lineLabel());
        toast("已切换到「" + lineLabel() + "」，重连后生效");
    }

    // ---------- 本机代理端口 ----------

    private String lanLabel() {
        if (Prefs.allowLan(this)) {
            return "监听地址：允许局域网（0.0.0.0:" + Prefs.DEFAULT_SOCKS + "）";
        }
        return "监听地址：仅本机（127.0.0.1:" + Prefs.DEFAULT_SOCKS + "）";
    }

    /**
     * 在「仅本机」与「允许局域网」之间切换。
     * 服务端连接不受影响，但监听地址是启动时写进内核配置的，改动要重连才生效。
     */
    private void toggleAllowLan(Button b) {
        boolean on = !Prefs.allowLan(this);
        Prefs.setAllowLan(this, on);
        b.setText(lanLabel());
        if (on) {
            toast("已允许局域网访问，重连后生效。该端口无密码，请确认网络可信");
        } else {
            toast("已改为仅本机访问，重连后生效");
        }
    }

    // ---------- 退出登录 ----------

    private void confirmLogout() {
        new android.app.AlertDialog.Builder(this)
                .setTitle("退出登录")
                .setMessage("将断开当前连接，并清除本机记住的密码。确定退出吗？")
                .setPositiveButton("退出登录", (d, w) -> doLogout())
                .setNegativeButton("取消", null)
                .show();
    }

    private void doLogout() {
        // 先断隧道再清会话：反过来的话轮询可能拿着已失效的令牌继续请求。
        sendServiceAction(TransVpnService.ACTION_STOP, null);
        connected = false;
        session = null;
        sessionPass = null;
        lastAt = 0;
        lastUp = 0;
        lastDown = 0;
        ui.removeCallbacksAndMessages(null);

        // 记住的密码必须一起清掉：否则下次打开会自动登录，等于没退出。
        Prefs.clearPass(this);
        Prefs.get(this).edit()
                .putBoolean(Prefs.KEY_REMEMBER, false)
                .apply();
        if (rememberBox != null) {
            rememberBox.setChecked(false);
        }
        if (passBox != null) {
            passBox.setText("");
        }

        mainPanel.setVisibility(View.GONE);
        loginPanel.setVisibility(View.VISIBLE);
        loginTip.setText("已退出登录，请重新输入密码");
        setState("idle", "");
        toast("已退出登录");
    }

    // ---------- 后台保活 ----------

    private boolean ignoringBatteryOptimizations() {
        PowerManager pm = (PowerManager) getSystemService(Context.POWER_SERVICE);
        return pm != null && pm.isIgnoringBatteryOptimizations(getPackageName());
    }

    private String bgLabel() {
        return ignoringBatteryOptimizations()
                ? "后台运行：已允许（不会被清理）"
                : "点此允许后台运行（防止被系统清理）";
    }

    private void requestBackgroundAllowed(Button b) {
        if (ignoringBatteryOptimizations()) {
            toast("已在后台运行白名单中，放后台不会被清理");
            b.setText(bgLabel());
            return;
        }
        try {
            Intent i = new Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS);
            i.setData(Uri.parse("package:" + getPackageName()));
            startActivity(i);
        } catch (Exception e) {
            // 个别 ROM 没有这个页面，退回到应用详情页让用户手动设置。
            try {
                Intent i = new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS);
                i.setData(Uri.parse("package:" + getPackageName()));
                startActivity(i);
            } catch (Exception e2) {
                toast("无法打开设置页，请手动在系统设置里允许后台运行");
            }
        }
        // 从设置页返回时刷新按钮文字
        ui.postDelayed(() -> b.setText(bgLabel()), 1500);
    }

    private void loadPrefs() {
        // 先记下本次启动是否要自动连接，再触发自动登录。
        // 顺序不能反：登录成功时若标记还没准备好，就永远不会自动连上了。
        autoConnectPending = Prefs.autoConnect(this);
        autoLoginIfRemembered();
    }

    /** 记住密码时直接带着密码进使用界面，省得每次重输。 */
    private void autoLoginIfRemembered() {
        if (Prefs.remember(this) && !Prefs.user(this).isEmpty() && !Prefs.pass(this).isEmpty()) {
            ui.postDelayed(this::doLogin, 300);
        }
    }

    // ---------- 登录 ----------

    private void doLogin() {
        final String host = hostBox.getText().toString().trim();
        final String user = userBox.getText().toString().trim();
        final String pass = passBox.getText().toString();
        int port;
        try {
            port = Integer.parseInt(portBox.getText().toString().trim());
        } catch (Exception e) {
            loginTip.setText("控制端口必须是数字");
            return;
        }
        if (host.isEmpty() || user.isEmpty() || pass.isEmpty()) {
            loginTip.setText("请填写服务器地址、账号与密码");
            return;
        }
        try {
            ControlApi.validateHost(host);
        } catch (Exception e) {
            loginTip.setText(e.getMessage());
            return;
        }
        loginTip.setText("正在登录…");

        new Thread(() -> {
            try {
                ControlApi.Session s = ControlApi.login(host, port, user, pass);
                ui.post(() -> {
                    session = s;
                    // 通道B 认证要用到原文，而输入框之后可能被清空，所以在这里留一份。
                    sessionPass = pass;
                    savePrefs(host, port, user, pass);
                    enterMain();
                    // 启动后自动连接：只在本次启动的自动登录时生效。
                    // 立刻清标记，之后用户手动登出再登录就不会被自动接管了。
                    if (autoConnectPending) {
                        autoConnectPending = false;
                        toggleConnect();
                    }
                });
            } catch (Exception e) {
                ui.post(() -> loginTip.setText("登录失败：" + e.getMessage()));
            }
        }, "login").start();
    }

    private void savePrefs(String host, int port, String user, String pass) {
        boolean remember = rememberBox.isChecked();
        Prefs.get(this).edit()
                .putString(Prefs.KEY_HOST, host)
                .putInt(Prefs.KEY_PORT, port)
                .putString(Prefs.KEY_USER, user)
                .putBoolean(Prefs.KEY_REMEMBER, remember)
                .apply();
        // 密码走单独的入口：那里会加密，并在加密不可用时选择「不保存」而不是明文落盘。
        Prefs.setPass(this, remember ? pass : "");
    }

    private void enterMain() {
        accountLabel.setText("账号：" + session.username
                + (session.note == null || session.note.isEmpty() ? "" : "（" + session.note + "）"));
        loginPanel.setVisibility(View.GONE);
        mainPanel.setVisibility(View.VISIBLE);
        setState(connected ? "connected" : "idle", "");
        // 线路按钮与说明要按这次的登录结果重建：线路表每次登录都可能变。
        refreshLineUi();
        startPolling();
    }

    // ---------- 连接 ----------

    private void toggleConnect() {
        if (connected) {
            sendServiceAction(TransVpnService.ACTION_STOP, null);
            connected = false;
            setState("idle", "已断开");
            return;
        }
        if (session == null) {
            return;
        }
        // VpnService.prepare 返回非 null 表示用户还没授权过 VPN，需要弹窗征求同意。
        Intent prep = VpnService.prepare(this);
        if (prep != null) {
            startActivityForResult(prep, REQ_VPN);
        } else {
            startTunnel();
        }
    }

    @Override
    protected void onActivityResult(int req, int result, Intent data) {
        super.onActivityResult(req, result, data);
        if (req == REQ_VPN) {
            if (result == RESULT_OK) {
                startTunnel();
            } else {
                setState("error", "用户拒绝了 VPN 授权，无法接管流量");
            }
        }
    }

    private void startTunnel() {
        try {
            String params = session.toCoreParams(Prefs.mode(this), Prefs.DEFAULT_SOCKS,
                    Prefs.allowLan(this), Prefs.proto(this), sessionPass, currentInstanceId());
            sendServiceAction(TransVpnService.ACTION_START, params);
            connected = true;
            setState("connecting", "正在建立隧道…");
        } catch (Exception e) {
            setState("error", String.valueOf(e.getMessage()));
        }
    }

    private void sendServiceAction(String action, String params) {
        Intent i = new Intent(this, TransVpnService.class);
        i.setAction(action);
        if (params != null) {
            i.putExtra(TransVpnService.EXTRA_PARAMS, params);
        }
        startService(i);
    }

    @Override
    public void onState(String state, String detail) {
        ui.post(() -> setState(state, detail));
    }

    private void setState(String state, String detail) {
        switch (state) {
            case "connected":
                stateLabel.setText("已连接");
                stateDetail.setText(detail);
                connectBtn.setText("断开");
                break;
            case "connecting":
                stateLabel.setText("正在连接…");
                stateDetail.setText(detail);
                break;
            case "error":
                stateLabel.setText("连接失败");
                stateDetail.setText(detail);
                connectBtn.setText("连接");
                connected = false;
                break;
            default:
                stateLabel.setText("未连接");
                stateDetail.setText(detail);
                connectBtn.setText("连接");
                break;
        }
    }

    // ---------- 流量轮询 ----------

    private void startPolling() {
        ui.removeCallbacksAndMessages(null);
        ui.post(poll);
    }

    private final Runnable poll = new Runnable() {
        @Override
        public void run() {
            if (session != null) {
                new Thread(() -> {
                    try {
                        JSONObject t = ControlApi.traffic(
                                Prefs.host(MainActivity.this), Prefs.port(MainActivity.this), session.token);
                        ui.post(() -> render(t));
                    } catch (Exception ignored) {
                        // 轮询失败不打扰用户：可能只是网络抖动，下一次就好了。
                    }
                }, "poll").start();
            }
            // 顺带把内核日志刷出来，出问题时光看界面就能判断。
            // 注意 gomobile 会把导出函数名首字母转小写，Go 侧的 Logs 在这里是 logs。
            String logs = Core.logs();
            if (logs != null && !logs.isEmpty()) {
                String[] parts = logs.split("\n");
                int from = Math.max(0, parts.length - 8);
                StringBuilder sb = new StringBuilder();
                for (int i = from; i < parts.length; i++) {
                    sb.append(parts[i]).append('\n');
                }
                logLabel.setText(sb.toString());
            }
            ui.postDelayed(this, POLL_MS);
        }
    };

    private void render(JSONObject t) {
        long up = t.optLong("sessionUp");
        long down = t.optLong("sessionDown");
        long used = t.optLong("usedBytes");
        long quota = t.optLong("quotaBytes");
        trafficLabel.setText("本次上传 " + human(up) + "　本次下载 " + human(down)
                + "\n累计用量 " + human(used)
                + "　剩余额度 " + (quota > 0 ? human(t.optLong("remainingBytes")) + " / " + human(quota) : "不限量"));

        long now = System.currentTimeMillis();
        if (lastAt > 0) {
            double dt = (now - lastAt) / 1000.0;
            if (dt > 0.5) {
                long du = (long) ((up - lastUp) / dt);
                long dd = (long) ((down - lastDown) / dt);
                // 速率由客户端自己按两次采样的差算：服务端按自己的窗口统计，
                // 两边周期一旦错拍，读到的数字就会忽 0 忽翻倍。
                if (du >= 0 && dd >= 0) {
                    rateLabel.setText("实时速率 ↑ " + human(du) + "/s　↓ " + human(dd) + "/s");
                }
            }
        }
        lastAt = now;
        lastUp = up;
        lastDown = down;
    }

    private static String human(long n) {
        if (n < 0) {
            return "不限";
        }
        String[] u = {"B", "KB", "MB", "GB", "TB"};
        double f = n;
        int i = 0;
        while (f >= 1024 && i < u.length - 1) {
            f /= 1024;
            i++;
        }
        return i == 0 ? n + " B" : String.format(java.util.Locale.US, "%.2f %s", f, u[i]);
    }

    // ---------- 改密 ----------

    private void changePassword() {
        final EditText oldB = new EditText(this);
        oldB.setHint("原密码");
        oldB.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);
        final EditText newB = new EditText(this);
        newB.setHint("新密码（至少 6 位）");
        newB.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_PASSWORD);

        LinearLayout box = new LinearLayout(this);
        box.setOrientation(LinearLayout.VERTICAL);
        box.setPadding(dp(16), dp(8), dp(16), dp(8));
        box.addView(oldB);
        box.addView(newB);

        new android.app.AlertDialog.Builder(this)
                .setTitle("修改密码")
                .setView(box)
                .setPositiveButton("确定", (d, w) -> {
                    String op = oldB.getText().toString();
                    String np = newB.getText().toString();
                    if (op.isEmpty() || np.length() < 6) {
                        toast("请填写原密码，新密码至少 6 位");
                        return;
                    }
                    new Thread(() -> {
                        try {
                            ControlApi.changePassword(Prefs.host(this), Prefs.port(this),
                                    session.token, op, np);
                            // 改密会更换账号的连接身份，旧令牌立即失效，必须重新登录。
                            ControlApi.Session s = ControlApi.login(
                                    Prefs.host(this), Prefs.port(this), session.username, np);
                            ui.post(() -> {
                                session = s;
                                sessionPass = np;
                                boolean remember = Prefs.remember(this);
                                Prefs.setPass(this, remember ? np : "");
                                toast("密码已修改，已用新身份重新登录");
                            });
                        } catch (Exception e) {
                            ui.post(() -> toast("修改失败：" + e.getMessage()));
                        }
                    }, "chpw").start();
                })
                .setNegativeButton("取消", null)
                .show();
    }

    private void toast(String s) {
        Toast.makeText(this, s, Toast.LENGTH_SHORT).show();
    }
}
