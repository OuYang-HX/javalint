package com.example.service;

import java.io.*;
import java.net.URL;
import java.net.HttpURLConnection;

public class FileService {
    private String baseDir = "/var/app/data/";

    // ⚠️ 路径穿越：用户输入直接拼入文件路径
    public String readFile(String fileName) {
        String fullPath = baseDir + fileName;
        try {
            // ⚠️ 危险：fileName 可能是 "../../etc/passwd"
            FileInputStream fis = new FileInputStream(fullPath);
            BufferedReader reader = new BufferedReader(new InputStreamReader(fis));
            StringBuilder content = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\n");
            }
            reader.close();
            return content.toString();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    // ✅ 安全：路径规范化 + 白名单校验
    public String readFileSafe(String fileName) {
        try {
            java.io.File file = new java.io.File(baseDir, fileName);
            String canonicalPath = file.getCanonicalPath();
            String canonicalBase = new java.io.File(baseDir).getCanonicalPath();
            if (!canonicalPath.startsWith(canonicalBase)) {
                throw new SecurityException("Path traversal detected");
            }
            BufferedReader reader = new BufferedReader(new FileReader(file));
            StringBuilder content = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\n");
            }
            reader.close();
            return content.toString();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    // ⚠️ 任意文件写入
    public boolean writeFile(String filePath, String content) {
        try {
            // ⚠️ filePath 和 content 都来自用户输入
            FileOutputStream fos = new FileOutputStream(filePath);
            fos.write(content.getBytes());
            fos.close();
            return true;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    // ⚠️ SSRF：用户输入直接用作URL
    public byte[] fetchUrl(String targetUrl) {
        try {
            // ⚠️ 危险：targetUrl 可能是内网地址 http://169.254.169.254/latest/meta-data/
            URL url = new URL(targetUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            InputStream is = conn.getInputStream();
            return is.readAllBytes();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}