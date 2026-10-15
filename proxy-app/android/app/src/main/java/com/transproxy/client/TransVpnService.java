package com.transproxy.client;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;

import com.transproxy.core.Core;

import org.json.JSONObject;

/**
 * VPN 服务：建立虚拟网卡，把它交给内核，由内核决定每条连接走直连还是走隧道。
 *
 * 与 Windows 端的分工完全一致——内核只负责处理包，分流规则由配置决定。
 * 区别在于虚拟网卡不是内核自己建的：Android 只允许通过 VpnService 建网卡，
 * 建好后把 fd 交给内核。
 */
public class TransVpnService extends VpnService {

    public static final String ACTION_START = "com.transproxy.client.START";
    public static final String ACTION_STOP = "com.transproxy.client.STOP";
    public static final String EXTRA_PARAMS = "params";

    private static final String CHANNEL_ID = "transproxy";
    private static final int NOTIFY_ID = 1001;

    /** 虚拟网卡自身的地址与 MTU。 */
    private static final String TUN_ADDRESS = "26.26.26.1";
    private static final int TUN_PREFIX = 24;
    private static final int TUN_MTU = 1400;
    /** DNS 用境外地址：这样 DNS 查询本身也会走隧道，避免被本地污染。 */
    private static final String TUN_DNS = "1.1.1.1";

    /** 供界面观察状态。单 Activity 应用，用静态引用最省事。 */
    public interface Listener {
        void onState(String state, String detail);
    }

    public static volatile Listener listener;

    private ParcelFileDescriptor tun;
    private Thread worker;

    /** 崩溃循环的阈值：连续自动重启超过这个次数就放弃，免得一直耗电。 */
    private static final int MAX_AUTO_RESTART = 4;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        // 系统在我们被杀之后把服务重新拉起来时，intent 是 null。
        // 此刻通知可能还挂着、隧道却已经断了——必须凭上次存下的参数自己恢复，
        // 否则用户看到的就是「放后台一会儿 VPN 就没了」。
        if (intent == null || intent.getAction() == null) {
            String saved = Prefs.activeParams(this);
            if (saved.isEmpty()) {
                stopSelf();
                return START_NOT_STICKY;
            }
            int n = Prefs.noteRestart(this);
            if (n > MAX_AUTO_RESTART) {
                // 起来就崩的循环：继续重启只会持续耗电，收手并把参数清掉，
                // 让用户重新点一次连接（那时能看到真实报错）。
                Prefs.clearActiveParams(this);
                stopSelf();
                return START_NOT_STICKY;
            }
            startForegroundSafely();
            startVpn(saved);
            return START_STICKY;
        }

        String action = intent.getAction();
        if (ACTION_STOP.equals(action)) {
            stopVpn();
            return START_NOT_STICKY;
        }
        if (ACTION_START.equals(action)) {
            String params = intent.getStringExtra(EXTRA_PARAMS);
            startForegroundSafely();
            startVpn(params);
            return START_STICKY;
        }
        return START_STICKY;
    }

    private void startForegroundSafely() {
        NotificationManager nm = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && nm != null) {
            NotificationChannel ch = new NotificationChannel(
                    CHANNEL_ID, getString(R.string.app_name), NotificationManager.IMPORTANCE_LOW);
            ch.setShowBadge(false);
            nm.createNotificationChannel(ch);
        }
        Intent open = new Intent(this, MainActivity.class);
        int piFlags = PendingIntent.FLAG_UPDATE_CURRENT;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            piFlags |= PendingIntent.FLAG_IMMUTABLE;
        }
        PendingIntent pi = PendingIntent.getActivity(this, 0, open, piFlags);

        Notification.Builder nb = new Notification.Builder(this)
                .setContentTitle(getString(R.string.app_name))
                .setContentText(getString(R.string.vpn_channel))
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .setContentIntent(pi)
                .setOngoing(true);
        // Android 8 起通知必须归属某个渠道，否则推送会被判为「Bad notification」
        // 并抛出 RemoteServiceException 把整个进程带崩——这里漏过一次，别再漏。
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nb.setChannelId(CHANNEL_ID);
        }
        Notification n = nb.build();

        // 前台服务要尽快进入前台，否则 Android 14+ 会直接抛异常。
        // 即便如此也不让通知问题把应用弄崩：VPN 已经建好了，能跑就跑，
        // 只是长时间在后台有被系统回收的风险。
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startForeground(NOTIFY_ID, n,
                        android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
            } else {
                startForeground(NOTIFY_ID, n);
            }
        } catch (Throwable t) {
            notifyState("connecting", "前台通知创建失败（不影响连接）：" + t.getMessage());
        }
    }

    private void startVpn(final String paramsJson) {
        if (worker != null) {
            // 重复点连接时先收掉旧的，避免两个内核同时抢同一个 TUN。
            stopVpn();
        }
        notifyState("connecting", "正在建立隧道…");

        worker = new Thread(() -> {
            try {
                // 1) 分流数据必须先落到磁盘：内核解析配置时就要读它。
                String assetDir = AssetInstaller.ensure(TransVpnService.this);

                // 2) 生成内核配置。分流规则在 Go 侧，与 Windows 端同一套语义。
                String config = Core.buildConfig(paramsJson);

                // 2.5) 通道B 要先把它自己那条隧道建起来。
                // 刻意放在启动内核之前：握手失败（认证不对、UDP 被运营商阻断）
                // 会在这一步直接抛出真实原因，而不是变成「连上了却什么都打不开」。
                startHysteriaIfNeeded(paramsJson);

                // 3) 建虚拟网卡。
                Builder b = new Builder()
                        .setSession(getString(R.string.app_name))
                        .setMtu(TUN_MTU)
                        .addAddress(TUN_ADDRESS, TUN_PREFIX)
                        .addRoute("0.0.0.0", 0)
                        .addDnsServer(TUN_DNS);

                // 只路由 IPv4：本客户端不代理 IPv6，IPv6 保持直连，
                // 与 Windows 端「IPv6 走本机」的语义一致。

                // 这一句是防回环的关键：把自己排掉之后，内核发出的连接
                // （到服务器的隧道本身）就不会再被送进隧道，否则会无限套娃。
                // 少了它，表现是「一连就断网、且日志里看不到任何出错」。
                try {
                    b.addDisallowedApplication(getPackageName());
                } catch (Exception e) {
                    throw new Exception("无法把自己排除在 VPN 之外，会导致流量回环：" + e.getMessage());
                }

                ParcelFileDescriptor pfd = b.establish();
                if (pfd == null) {
                    throw new Exception("建立虚拟网卡失败（可能是用户拒绝了 VPN 授权）");
                }
                tun = pfd;

                // 4) 把 fd 交给内核并启动。
                Core.start(config, pfd.getFd(), assetDir);
                // 连接成功后才记下参数：这样「被杀后自动恢复」只会在原本连得上的
                // 情况下发生；参数有问题导致连不上时，上面会抛错并清掉记录，
                // 不会陷入反复重试。
                // 写盘前要过一道 sanitize：通道B 的认证凭据不该在用户
                // 没勾「记住密码」时被悄悄落盘。
                Prefs.setActiveParams(TransVpnService.this,
                        Prefs.sanitizeForStorage(TransVpnService.this, paramsJson));
                notifyState("connected", "隧道已建立 · " + TUN_ADDRESS + "/" + TUN_PREFIX);
            } catch (Throwable t) {
                closeTun();
                notifyState("error", String.valueOf(t.getMessage()));
                stopVpn();
            }
        }, "transproxy-start");
        worker.start();
    }

    /**
     * 通道B 需要先在本进程内把 hysteria 客户端跑起来，并等它就绪。
     *
     * Android 不允许拉起外部进程，所以通道B 不像 Windows 那样旁挂一个
     * hysteria.exe，而是把客户端库跑在同一进程里，再由它在本机开一个 SOCKS
     * 入口；内核的 proxy 出站指向那个入口。对内核来说两条通道形状完全一样。
     */
    private void startHysteriaIfNeeded(String paramsJson) throws Exception {
        JSONObject p = new JSONObject(paramsJson);
        if (!Prefs.PROTO_HYSTERIA.equals(p.optString("protocol"))) {
            return;
        }
        String auth = p.optString("hyAuth");
        if (auth.isEmpty()) {
            // 自动恢复这条路径上参数串里的凭据已被剔除（见 Prefs.sanitizeForStorage），
            // 用加密保存的账号密码现算。用户勾了记住密码就能接上，
            // 没勾则本地没有可用的密码，只能让用户重新登录。
            auth = Prefs.storedAuth(TransVpnService.this);
        }
        if (auth.isEmpty()) {
            throw new Exception("通道B 需要重新登录：本机没有可用的密码。"
                    + "若希望被杀后能自动恢复，请在登录界面勾选「记住密码」再连接。");
        }
        // 端口必须是通道B 自己的那个（服务端下发的 hysteriaPort，8443/UDP），
        // 不能沿用 params.port —— 那是通道A 的 REALITY 入站端口（443/TCP）。
        // 这里曾经传错成 port，结果是「通道B 永远连不上」：UDP 443 上根本没人监听，
        // 握手包发出去没有任何回应，客户端只能一直重试到超时，
        // 而界面上通道B 却显示「可用」（那处判断用的是 hysteriaPort），现象与原因完全对不上。
        // 参数缺失/非法由上一步的 Core.buildConfig 校验并报出，这里不再重复兜底。
        int hyPort = p.optInt("hysteriaPort");
        if (hyPort <= 0) {
            throw new Exception("服务端未下发通道B 端口，无法建立连接");
        }
        // TLS 服务器名必须是**证书上的域名**，不能传 params 里的 sni —— 那是
        // REALITY 借用的伪装站点（www.samsung.com），hysteria 的证书跟它毫无关系。
        //
        // 直连线路下「证书域名」就等于连接地址；但中转线路下两者是分开的：
        // 连的是中转节点（可能就是个 IP），证书却仍是出口节点域名的。
        // 所以服务端会单独下发 hysteriaSNI，缺省才回退到连接地址。
        // 漏了这一步的表现是「中转线路的通道B 永远握不上手」，报错只提证书、不提 SNI。
        String hySNI = p.optString("hysteriaSNI");
        if (hySNI.isEmpty()) {
            hySNI = p.optString("address");
        }
        Core.startHysteria(
                p.optString("address"),
                hyPort,
                hySNI,
                auth,
                p.optString("hysteriaObfs"),
                p.optInt("hysteriaSocksPort", Prefs.DEFAULT_HY_SOCKS));
    }

    private void stopVpn() {
        // 用户主动断开（或启动失败）时清掉记录，否则 START_STICKY 会在进程被回收后
        // 又凭旧参数自己连上——用户会看到「点了断开却自动重连」。
        Prefs.clearActiveParams(this);
        try {
            if (Core.running()) {
                Core.stop();
            }
        } catch (Throwable ignored) {
            // 停止阶段的异常没有恢复价值，继续往下清理。
        }
        closeTun();
        worker = null;
        notifyState("idle", "已断开");
        stopForegroundCompat();
        stopSelf();
    }

    private void closeTun() {
        if (tun != null) {
            try {
                tun.close();
            } catch (Exception ignored) {
                // 关不掉也不影响退出，系统会回收。
            }
            tun = null;
        }
    }

    private void stopForegroundCompat() {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                stopForeground(STOP_FOREGROUND_REMOVE);
            } else {
                stopForeground(true);
            }
        } catch (Throwable ignored) {
            // 没进过前台时调用会抛，忽略即可。
        }
    }

    private void notifyState(String state, String detail) {
        Listener l = listener;
        if (l != null) {
            l.onState(state, detail);
        }
    }

    @Override
    public void onRevoke() {
        // 用户在其他地方撤回了 VPN 授权，或系统要求关闭。
        // 这里必须真的把内核停掉：只关网卡会让内核继续跑着一个谁也进不来的隧道。
        stopVpn();
        super.onRevoke();
    }

    @Override
    public void onDestroy() {
        closeTun();
        try {
            if (Core.running()) {
                Core.stop();
            }
        } catch (Throwable ignored) {
            // 销毁阶段不再处理。
        }
        super.onDestroy();
    }
}
