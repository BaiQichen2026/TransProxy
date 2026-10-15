package com.transproxy.client;

import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import java.nio.charset.StandardCharsets;
import java.security.KeyStore;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

/**
 * 用 Android Keystore 里的 AES-GCM 密钥加解密本地保存的敏感值（目前是账号密码）。
 *
 * 为什么要单独做这一层：SharedPreferences 只是一个应用私有的普通文件，
 * 明文密码躺在里面，等于把「记住密码」变成「把密码写在硬盘上」——
 * 备份导出、设备被取证、应用数据被拷走，任何一个场景都会直接泄露。
 * 密钥由系统密钥库托管、不会随加密结果离开本设备，拷走密文也解不开。
 *
 * 这层不追求防住「已经拿到本应用身份并且能调用 Keystore」的对手——那种情况下
 * 任何本地存储都保不住。它拦住的是「文件被拷走」这一类。
 *
 * 失败时一律返回 null 而不是退回明文：拿不到加密能力时，「什么都不存」
 * 永远优于「明文存一份」。调用方据此把密码丢弃、让用户重新输入。
 */
final class SecretBox {

    private static final String KEYSTORE = "AndroidKeyStore";
    private static final String ALIAS = "transproxy.local.v1";
    private static final String TRANSFORM = "AES/GCM/NoPadding";
    /** GCM 的推荐 IV 长度。 */
    private static final int IV_LEN = 12;
    private static final int TAG_BITS = 128;

    private SecretBox() {
    }

    /** 加密；失败返回 null。 */
    static String encrypt(String plain) {
        if (plain == null || plain.isEmpty()) {
            return null;
        }
        try {
            Cipher c = Cipher.getInstance(TRANSFORM);
            c.init(Cipher.ENCRYPT_MODE, key());
            byte[] iv = c.getIV();
            byte[] ct = c.doFinal(plain.getBytes(StandardCharsets.UTF_8));
            // IV 直接前置在密文里：GCM 的 IV 不是秘密，但每次加密都必须是新的，
            // 解密的双方都得拿到它，所以和密文放在一起最省事。
            byte[] out = new byte[iv.length + ct.length];
            System.arraycopy(iv, 0, out, 0, iv.length);
            System.arraycopy(ct, 0, out, iv.length, ct.length);
            return Base64.encodeToString(out, Base64.NO_WRAP);
        } catch (Exception e) {
            return null;
        }
    }

    /** 解密；失败返回 null。 */
    static String decrypt(String stored) {
        if (stored == null || stored.isEmpty()) {
            return null;
        }
        try {
            byte[] all = Base64.decode(stored, Base64.NO_WRAP);
            if (all.length <= IV_LEN) {
                return null;
            }
            Cipher c = Cipher.getInstance(TRANSFORM);
            c.init(Cipher.DECRYPT_MODE, key(), new GCMParameterSpec(TAG_BITS, all, 0, IV_LEN));
            byte[] pt = c.doFinal(all, IV_LEN, all.length - IV_LEN);
            return new String(pt, StandardCharsets.UTF_8);
        } catch (Exception e) {
            // 解不开的原因很多：换过锁屏、从备份恢复、系统升级导致密钥失效……
            // 一律当作「没有存过密码」，让用户重新登录一次。
            // 绝不能因为解不开就让应用崩在启动路径上。
            return null;
        }
    }

    private static SecretKey key() throws Exception {
        KeyStore ks = KeyStore.getInstance(KEYSTORE);
        ks.load(null);
        if (ks.containsAlias(ALIAS)) {
            return ((KeyStore.SecretKeyEntry) ks.getEntry(ALIAS, null)).getSecretKey();
        }
        KeyGenerator kg = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE);
        kg.init(new KeyGenParameterSpec.Builder(ALIAS,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                // 刻意不要求用户认证：自动登录发生在应用启动时，
                // 那一刻不可能让用户先按指纹。
                .setUserAuthenticationRequired(false)
                .build());
        return kg.generateKey();
    }
}
