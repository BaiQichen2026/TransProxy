package com.transproxy.client;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;

/**
 * 控制面客户端：与服务端 8443 的 HTTPS 接口通信。
 *
 * 只做三件事：登录、查流量、改密码。连接参数（UUID、REALITY 公钥等）都由登录响应下发，
 * 客户端不预置任何节点信息——这样换服务器、改密码都不用重新发客户端。
 */
public final class ControlApi {

    private ControlApi() {
    }

    /** 登录成功后拿到的东西。 */
    public static final class Session {
        public String token;
        public String username;
        public String note;
        public String uuid;
        /** 服务端下发的连接参数，原样透传给内核的配置生成。 */
        public JSONObject params;
        /** 服务端下发的可选线路；为 null 表示只有默认线路（老服务端）。 */
        public JSONArray instances;

        /** lineCount 返回可选线路数；0 表示服务端没下发线路表。 */
        public int lineCount() {
            return instances == null ? 0 : instances.length();
        }

        public JSONObject line(int i) {
            return instances == null ? null : instances.optJSONObject(i);
        }

        /**
         * 按 id 取线路参数。
         *
         * 兜底规则与 Windows 端 common.Choose() 完全一致：id 找不到（服务端撤了这条线路）
         * 或为空时退回列表第一项；连列表都没有就用默认参数。**任何情况都不报错** ——
         * 宁可换一条能用的线路，也不要把用户卡在「怎么都连不上」上。
         *
         * 线路项本身就是扁平对象（线路信息与连接参数在同一层），所以可以直接当参数用。
         */
        public JSONObject paramsFor(String instanceId) {
            if (instances != null) {
                if (instanceId != null && !instanceId.isEmpty()) {
                    for (int i = 0; i < instances.length(); i++) {
                        JSONObject ins = instances.optJSONObject(i);
                        if (ins != null && instanceId.equals(ins.optString("id"))) {
                            return ins;
                        }
                    }
                }
                JSONObject first = instances.optJSONObject(0);
                if (first != null) {
                    return first;
                }
            }
            return params;
        }

        /**
         * 把服务端参数与本地选择合成内核需要的参数串。
         *
         * @param allowLan 为真时本机 SOCKS 端口绑到 0.0.0.0，局域网内其它设备可用
         * @param protocol 通道选择（reality / hysteria）
         * @param password 通道B 认证需要账号密码原文，所以必须传进来；
         *                 它会以 hyAuth 的形式进入参数串，落盘策略见 Prefs.sanitizeForStorage
         * @param instanceId 选中的线路 id，空表示默认线路
         */
        public String toCoreParams(String mode, int socksPort, boolean allowLan,
                                   String protocol, String password,
                                   String instanceId) throws Exception {
            JSONObject o = new JSONObject(paramsFor(instanceId).toString());
            o.put("uuid", uuid);
            o.put("mode", mode);
            o.put("protocol", protocol);
            if (socksPort > 0) {
                o.put("socksPort", socksPort);
            }
            o.put("allowLan", allowLan);
            // 通道B 在本机监听的 SOCKS 端口由本端决定，服务端不关心。
            o.put("hysteriaSocksPort", Prefs.DEFAULT_HY_SOCKS);
            // 通道B 的认证是「账号:密码」原文：服务端拿它做 bcrypt 比对，
            // 没有原文就没法认证（这点与通道A 不同，那边用的是 UUID）。
            if (Prefs.PROTO_HYSTERIA.equals(protocol) && password != null && !password.isEmpty()) {
                o.put("hyAuth", username + ":" + password);
            }
            if (!o.has("spiderX")) {
                o.put("spiderX", "/");
            }
            // 调试包把内核日志开到 info：出问题时界面上能直接看到每条连接
            // 命中的出站（tun-in -> proxy / direct），不必再重打包。
            // 正式包保持 warning，避免日志缓冲被正常连接刷爆。
            o.put("logLevel", BuildConfig.DEBUG ? "info" : "warning");
            return o.toString();
        }
    }

    /**
     * 登录。host 必须是域名。
     *
     * 这里刻意**不做**「填了 IP 就跳过证书校验」这种降级：这条连接承载账号密码、
     * 令牌与连接身份，一旦不校验证书，同网段的攻击者用一张自签证书就能全部截走，
     * 还能返回伪造的连接参数把流量引到自己的服务器。而服务端证书是签给域名的，
     * 填 IP 必然校验失败——所以正确的做法是提前拒绝 IP，让用户改填域名。
     */
    public static Session login(String host, int port, String user, String pass) throws Exception {
        validateHost(host);
        JSONObject body = new JSONObject();
        body.put("username", user);
        body.put("password", pass);

        JSONObject r = post(base(host, port) + "/api/v1/login", null, body);
        Session s = new Session();
        s.token = r.optString("token");
        s.username = r.optString("username");
        s.note = r.optString("note");
        s.uuid = r.optString("uuid");
        s.params = r.optJSONObject("params");
        // 线路表允许缺失：老服务端不下发，此时客户端只提供默认线路。
        s.instances = r.optJSONArray("instances");
        if (s.token.isEmpty() || s.params == null) {
            throw new Exception("服务端未返回令牌或连接参数");
        }
        return s;
    }

    /** 查询本账号流量。 */
    public static JSONObject traffic(String host, int port, String token) throws Exception {
        return get(base(host, port) + "/api/v1/traffic", token);
    }

    /** 修改密码。改完密码后服务端会更换该账号的连接身份，必须重新登录。 */
    public static void changePassword(String host, int port, String token,
                                      String oldPass, String newPass) throws Exception {
        JSONObject body = new JSONObject();
        body.put("oldPassword", oldPass);
        body.put("newPassword", newPass);
        post(base(host, port) + "/api/v1/password", token, body);
    }

    private static String base(String host, int port) {
        return "https://" + host + ":" + port;
    }

    /** 校验服务器地址：只接受域名，理由见 login 的说明。 */
    public static void validateHost(String host) throws Exception {
        String h = host == null ? "" : host.trim();
        if (h.isEmpty()) {
            throw new Exception("请填写服务器域名");
        }
        if (isIpLiteral(h)) {
            throw new Exception("请填写域名而不是 IP 地址：证书是按域名签发的，用 IP 连接无法验证服务器身份");
        }
        if (h.indexOf('.') < 0) {
            throw new Exception("服务器地址看起来不像域名：" + h);
        }
    }

    private static boolean isIpLiteral(String host) {
        if (host.indexOf(':') >= 0) {
            return true; // IPv6 字面量
        }
        String[] parts = host.split("\\.");
        if (parts.length != 4) {
            return false;
        }
        for (String p : parts) {
            try {
                int v = Integer.parseInt(p);
                if (v < 0 || v > 255) {
                    return false;
                }
            } catch (NumberFormatException e) {
                return false;
            }
        }
        return true;
    }

    private static JSONObject post(String url, String token, JSONObject body) throws Exception {
        HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
        c.setRequestMethod("POST");
        c.setConnectTimeout(15000);
        c.setReadTimeout(20000);
        c.setDoOutput(true);
        c.setRequestProperty("Content-Type", "application/json");
        if (token != null) {
            c.setRequestProperty("Authorization", "Bearer " + token);
        }
        byte[] payload = body.toString().getBytes(StandardCharsets.UTF_8);
        try (OutputStream os = c.getOutputStream()) {
            os.write(payload);
        }
        return read(c);
    }

    private static JSONObject get(String url, String token) throws Exception {
        HttpURLConnection c = (HttpURLConnection) new URL(url).openConnection();
        c.setRequestMethod("GET");
        c.setConnectTimeout(15000);
        c.setReadTimeout(20000);
        if (token != null) {
            c.setRequestProperty("Authorization", "Bearer " + token);
        }
        return read(c);
    }

    private static JSONObject read(HttpURLConnection c) throws Exception {
        int code = c.getResponseCode();
        InputStream is = (code >= 200 && code < 300) ? c.getInputStream() : c.getErrorStream();
        StringBuilder sb = new StringBuilder();
        if (is != null) {
            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(is, StandardCharsets.UTF_8))) {
                String line;
                while ((line = br.readLine()) != null) {
                    sb.append(line);
                }
            }
        }
        String text = sb.toString();
        if (code < 200 || code >= 300) {
            // 服务端出错时返回 {"error": "..."}，把它原样带给用户，比只报 HTTP 码有用。
            try {
                JSONObject o = new JSONObject(text);
                String msg = o.optString("error");
                if (!msg.isEmpty()) {
                    throw new Exception(msg);
                }
            } catch (Exception ignored) {
                // 不是 JSON 就退回通用错误
            }
            throw new Exception("服务端返回 HTTP " + code);
        }
        return new JSONObject(text);
    }
}
