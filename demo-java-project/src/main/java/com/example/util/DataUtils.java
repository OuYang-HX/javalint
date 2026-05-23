package com.example.util;

import java.io.FileInputStream;
import java.io.ObjectInputStream;
import java.sql.Connection;
import java.sql.Statement;
import javax.crypto.Cipher;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;

public class DataUtils {
    private Connection dbConnection;

    // ⚠️ 直接使用 ObjectInputStream.readObject()
    public static Object deserialize(String path) {
        try (FileInputStream fis = new FileInputStream(path);
             ObjectInputStream ois = new ObjectInputStream(fis)) {
            return ois.readObject();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // 安全方法
    public static String sanitize(String input) {
        if (input == null) return null;
        return input.replaceAll("[<>\"']", "");
    }

    // ⚠️ 命令注入风险
    public static int runCommand(String userInput) {
        try {
            // 危险：用户输入直接拼入命令
            Runtime runtime = Runtime.getRuntime();
            return runtime.exec("sh -c " + userInput).waitFor();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // 安全的命令执行（硬编码命令 + 参数分离）
    public static int safeListFiles() {
        try {
            ProcessBuilder pb = new ProcessBuilder("ls", "-la", "/tmp");
            return pb.start().waitFor();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // ⚠️ 弱加密：DES 已被认为不安全
    public static byte[] encryptDES(String plaintext, String keyStr) {
        try {
            // ⚠️ 危险：DES 密钥长度仅56位，容易被暴力破解
            DESKeySpec desKey = new DESKeySpec(keyStr.getBytes());
            SecretKeySpec secretKey = new SecretKeySpec(desKey.getKey(), "DES");
            Cipher cipher = Cipher.getInstance("DES");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return cipher.doFinal(plaintext.getBytes());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // ⚠️ ECB模式加密：不提供语义安全性
    public static byte[] encryptAES_ECB(String plaintext, String keyStr) {
        try {
            // ⚠️ 危险：AES/ECB 模式不安全，相同明文块产生相同密文块
            SecretKeySpec key = new SecretKeySpec(keyStr.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(plaintext.getBytes());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // ⚠️ 硬编码密钥
    private static final String SECRET_KEY = "MySuperSecretKey12345";
    private static final String DB_PASSWORD = "admin123";

    public static byte[] encryptWithHardcodedKey(String plaintext) {
        try {
            // ⚠️ 危险：密钥硬编码在源代码中
            SecretKeySpec key = new SecretKeySpec(SECRET_KEY.getBytes(), "AES");
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key);
            return cipher.doFinal(plaintext.getBytes());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // ⚠️ 不安全的哈希：MD5 已被破解
    public static String hashMD5(String input) {
        try {
            // ⚠️ 危险：MD5 已被证明存在碰撞攻击
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] digest = md.digest(input.getBytes());
            return bytesToHex(digest);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // ⚠️ 不安全的哈希：SHA-1 已被破解
    public static String hashSHA1(String input) {
        try {
            // ⚠️ 危险：SHA-1 已被证明存在碰撞攻击
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            byte[] digest = md.digest(input.getBytes());
            return bytesToHex(digest);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // ✅ 安全：使用 SHA-256
    public static String hashSHA256(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(input.getBytes());
            return bytesToHex(digest);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // ⚠️ SQL注入：在工具类中也存在
    public java.util.List<String> searchLogs(String filter) {
        String sql = "SELECT log_message FROM system_logs WHERE level = '" + filter + "'";
        try (Statement stmt = dbConnection.createStatement()) {
            ResultSet rs = stmt.executeQuery(sql);
            java.util.List<String> logs = new java.util.ArrayList<>();
            while (rs.next()) {
                logs.add(rs.getString("log_message"));
            }
            return logs;
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // ⚠️ 不安全的随机数：用于安全场景的 java.util.Random
    public static String generateToken() {
        // ⚠️ 危险：java.util.Random 不是密码学安全的，生成的 token 可预测
        java.util.Random random = new java.util.Random();
        return Long.toHexString(random.nextLong());
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}