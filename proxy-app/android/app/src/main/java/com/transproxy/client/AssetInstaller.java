package com.transproxy.client;

import android.content.Context;

import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * 把随 APK 打包的分流数据释放到应用私有目录。
 *
 * 这一步不能省：内核在「解析配置」阶段就要读 geoip.dat / geosite.dat，
 * 而不是等到转发时。它按路径找文件（由 xray.location.asset 指定），
 * 没法直接读 APK 里的 asset，所以必须先落到磁盘。
 *
 * 之所以放在 filesDir 而不是 cacheDir：缓存目录可能被系统随时清掉，
 * 清掉之后内核会因为找不到文件而启动失败。
 */
public final class AssetInstaller {

    private AssetInstaller() {
    }

    /** 需要释放的文件。 */
    private static final String[] FILES = {"geoip.dat", "geosite.dat"};

    /**
     * 确保数据文件已在私有目录中就位，返回该目录路径。
     * 同尺寸即视为已存在，避免每次连接都重写 30MB。
     */
    public static String ensure(Context ctx) throws Exception {
        File dir = new File(ctx.getFilesDir(), "xray");
        if (!dir.exists() && !dir.mkdirs()) {
            throw new Exception("无法创建数据目录：" + dir);
        }
        for (String name : FILES) {
            File dst = new File(dir, name);
            long assetSize = assetSize(ctx, name);
            if (dst.exists() && dst.length() == assetSize && assetSize > 0) {
                continue;
            }
            copy(ctx, name, dst);
        }
        return dir.getAbsolutePath();
    }

    private static long assetSize(Context ctx, String name) {
        try (InputStream in = ctx.getAssets().open(name)) {
            // AssetManager 不直接给未压缩条目的大小，只能数一遍；
            // 这一步只在每次连接时跑一次，代价可以接受。
            byte[] buf = new byte[64 * 1024];
            long total = 0;
            int n;
            while ((n = in.read(buf)) > 0) {
                total += n;
            }
            return total;
        } catch (Exception e) {
            return -1;
        }
    }

    private static void copy(Context ctx, String name, File dst) throws Exception {
        File tmp = new File(dst.getParentFile(), name + ".tmp");
        try (InputStream in = ctx.getAssets().open(name);
             OutputStream out = new FileOutputStream(tmp)) {
            byte[] buf = new byte[64 * 1024];
            int n;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
            }
            out.flush();
        }
        // 先写临时文件再改名：中途失败不会留下一个半截的数据文件，
        // 否则下次会因「尺寸对不上」反复重拷，或者更糟——被当成完整文件加载。
        if (dst.exists() && !dst.delete()) {
            throw new Exception("无法覆盖旧数据文件：" + dst);
        }
        if (!tmp.renameTo(dst)) {
            throw new Exception("无法落地数据文件：" + dst);
        }
    }
}
