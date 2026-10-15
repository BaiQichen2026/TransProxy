package com.transproxy.client;

import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONObject;

/**
 * 本地设置。
 *
 * 关于密码：勾了「记住密码」时会保存，但**不是明文**——用 Android Keystore 里
 * 的 AES-GCM 密钥加密后再存（见 SecretBox）。与 Windows 端用 DPAPI 加密是同一个思路：
 * SharedPreferences 只是应用私有的普通文件，明文躺在里面，备份导出或设备取证
 * 就能直接读走。
 *
 * 加密不可用时（极少数设备）宁可什么都不存，也绝不退回明文。
 */
public final class Prefs {

    private static final String FILE = "transproxy";
    /** 密文前缀。带这个前缀的才是加密过的，没有的按历史明文处理。 */
    private static final String ENC_PREFIX = "v1:";

    public static final String KEY_HOST = "host";
    public static final String KEY_PORT = "port";
    public static final String KEY_USER = "user";
    public static final String KEY_PASS = "pass";
    public static final String KEY_MODE = "mode";
    public static final String KEY_SOCKS = "socksPort";
    public static final String KEY_REMEMBER = "remember";
    public static final String KEY_ALLOW_LAN = "allowLan";
    public static final String KEY_PROTO = "protocol";

    public static final String DEFAULT_HOST = "proxy.example.com";
    public static final int DEFAULT_PORT = 8443;
    /** 调试用 SOCKS 端口：留着它就能绕开 VPN 单独验证隧道本身是否通。 */
    public static final int DEFAULT_SOCKS = 17900;
    /**
     * 通道B（Hysteria2）在本机监听的 SOCKS 端口。
     * 与调试端口刻意错开：切换通道时两者可能短暂共存。
     */
    public static final int DEFAULT_HY_SOCKS = 17902;

    public static final String PROTO_REALITY = "reality";
    public static final String PROTO_HYSTERIA = "hysteria";

    private Prefs() {
    }

    public static SharedPreferences get(Context ctx) {
        return ctx.getSharedPreferences(FILE, Context.MODE_PRIVATE);
    }

    public static String host(Context ctx) {
        return get(ctx).getString(KEY_HOST, DEFAULT_HOST);
    }

    public static int port(Context ctx) {
        return get(ctx).getInt(KEY_PORT, DEFAULT_PORT);
    }

    public static String user(Context ctx) {
        return get(ctx).getString(KEY_USER, "");
    }

    /**
     * 读取保存的密码。解不开或没存过都返回空串，调用方按「需要重新输入」处理。
     *
     * 兼容早期版本：那时存的是明文，读到没有前缀的值就顺手升级成密文，
     * 免得明文一直躺在磁盘上。
     */
    public static String pass(Context ctx) {
        String raw = get(ctx).getString(KEY_PASS, "");
        if (raw == null || raw.isEmpty()) {
            return "";
        }
        if (!raw.startsWith(ENC_PREFIX)) {
            setPass(ctx, raw);
            return raw;
        }
        String plain = SecretBox.decrypt(raw.substring(ENC_PREFIX.length()));
        return plain == null ? "" : plain;
    }

    /**
     * 保存密码（加密后存）。传空串等于清除。
     *
     * 加密失败时不保存任何东西——这点是刻意的：悄悄退回明文，
     * 会让「记住密码」在用户不知情的情况下变成明文落盘。
     */
    public static void setPass(Context ctx, String value) {
        String v = value == null ? "" : value;
        if (v.isEmpty()) {
            get(ctx).edit().remove(KEY_PASS).apply();
            return;
        }
        String enc = SecretBox.encrypt(v);
        if (enc == null) {
            get(ctx).edit().remove(KEY_PASS).apply();
            return;
        }
        get(ctx).edit().putString(KEY_PASS, ENC_PREFIX + enc).apply();
    }

    public static void clearPass(Context ctx) {
        get(ctx).edit().remove(KEY_PASS).apply();
    }

    /**
     * 返回通道B 认证需要的「账号:密码」，条件不满足时返回空串。
     *
     * 之所以从已保存的账号密码推导，而不是把凭据留在参数串里：
     * 参数串会被落盘用于「被杀后自动恢复隧道」，如果里面也放一份明文密码，
     * 那就等于在加密存储之外又留了一份明文拷贝，加密就白做了。
     */
    public static String storedAuth(Context ctx) {
        if (!remember(ctx)) {
            return "";
        }
        String u = user(ctx), p = pass(ctx);
        if (u.isEmpty() || p.isEmpty()) {
            return "";
        }
        return u + ":" + p;
    }

    public static boolean remember(Context ctx) {
        return get(ctx).getBoolean(KEY_REMEMBER, false);
    }

    public static String mode(Context ctx) {
        return get(ctx).getString(KEY_MODE, "smart");
    }

    /** 选定的传输通道：reality（通道A）或 hysteria（通道B）。 */
    public static String proto(Context ctx) {
        return get(ctx).getString(KEY_PROTO, PROTO_REALITY);
    }

    /**
     * 是否允许局域网内的其它设备借本机端口上网。
     * 打开后 SOCKS 入站绑到 0.0.0.0；该入站没有认证，只在可信网络里开。
     */
    public static boolean allowLan(Context ctx) {
        return get(ctx).getBoolean(KEY_ALLOW_LAN, false);
    }

    public static void setAllowLan(Context ctx, boolean on) {
        get(ctx).edit().putBoolean(KEY_ALLOW_LAN, on).apply();
    }

    // ---------- 启动后自动连接 ----------

    public static final String KEY_AUTO_CONNECT = "autoConnect";

    /**
     * 是否在打开应用后自动登录并连上服务器。
     *
     * 依赖「记住密码」：没有可用的密码就无法自动登录，所以开关打开但没勾记住密码时
     * 不会有任何效果（界面上会提示）。
     */
    public static boolean autoConnect(Context ctx) {
        return get(ctx).getBoolean(KEY_AUTO_CONNECT, false);
    }

    public static void setAutoConnect(Context ctx, boolean on) {
        get(ctx).edit().putBoolean(KEY_AUTO_CONNECT, on).apply();
    }

    // ---------- 线路（多实例） ----------

    public static final String KEY_INSTANCE = "instanceId";

    /**
     * 用户上次选中的线路 id，空表示默认线路。
     *
     * 只存 id，不存线路参数：线路表每次登录都由服务端下发，
     * 这样服务端加线路、改线路名、换线路地址都不用动本地这份设置。
     */
    public static String instanceId(Context ctx) {
        return get(ctx).getString(KEY_INSTANCE, "");
    }

    public static void setInstanceId(Context ctx, String id) {
        get(ctx).edit().putString(KEY_INSTANCE, id == null ? "" : id).apply();
    }

    // ---------- 隧道自动恢复 ----------
    //
    // 进程被系统回收后，START_STICKY 会把服务重新拉起来，但那时没有 Intent、
    // 隧道也已经断了。所以连接成功时把参数存下来，重启时凭它自己恢复；
    // 用户主动断开时清掉，避免「明明点了断开，过一会儿又自己连上」。

    public static final String KEY_ACTIVE_PARAMS = "activeParams";
    public static final String KEY_RESTART_COUNT = "restartCount";
    public static final String KEY_RESTART_AT = "restartAt";

    public static String activeParams(Context ctx) {
        String s = get(ctx).getString(KEY_ACTIVE_PARAMS, "");
        return s == null ? "" : s;
    }

    public static void setActiveParams(Context ctx, String params) {
        get(ctx).edit().putString(KEY_ACTIVE_PARAMS, params).apply();
    }

    /**
     * 写盘前剔除不该落盘的凭据。**无论是否勾选记住密码都剔除**。
     *
     * 通道B 的认证需要「账号:密码」明文（服务端用 bcrypt 比对），它随内核参数
     * 一起放在同一个串里。而这个串会被存下来用于「进程被杀后自动恢复隧道」。
     *
     * 为什么不按「勾了记住密码就允许存」来放宽：密码本身已经由 SecretBox 加密后
     * 存在别处，这里再放一份明文，等于让加密白做——攻击者只要读这个串就够了。
     * 恢复隧道时用 {@link #storedAuth} 现算即可，不需要在这里留第二份拷贝。
     *
     * 代价是：未勾选记住密码时，通道B 在进程被系统回收后无法自动恢复。
     * 这是刻意的取舍，界面上的错误提示会把原因说清楚。
     */
    public static String sanitizeForStorage(Context ctx, String paramsJson) {
        try {
            JSONObject o = new JSONObject(paramsJson);
            if (o.has("hyAuth")) {
                o.remove("hyAuth");
                return o.toString();
            }
            return paramsJson;
        } catch (Exception e) {
            // 解析不出来说明这串参数本来也不可用，宁可不存也不要冒险落盘。
            return "";
        }
    }

    public static void clearActiveParams(Context ctx) {
        get(ctx).edit()
                .remove(KEY_ACTIVE_PARAMS)
                .remove(KEY_RESTART_COUNT)
                .remove(KEY_RESTART_AT)
                .apply();
    }

    /**
     * 记一次自动重启并返回累计次数。
     * 超过阈值就说明是「起来就崩」的循环，再重启只会持续耗电，
     * 所以调用方应当放弃自动恢复并提示用户。
     */
    public static int noteRestart(Context ctx) {
        long now = System.currentTimeMillis();
        long last = get(ctx).getLong(KEY_RESTART_AT, 0);
        int count = get(ctx).getInt(KEY_RESTART_COUNT, 0);
        // 距上次重启超过 5 分钟就重新计数：正常的「偶尔被杀一次」不该被误判成崩溃循环。
        if (now - last > 5 * 60 * 1000L) {
            count = 0;
        }
        count++;
        get(ctx).edit()
                .putInt(KEY_RESTART_COUNT, count)
                .putLong(KEY_RESTART_AT, now)
                .apply();
        return count;
    }
}
