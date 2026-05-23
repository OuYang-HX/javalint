package com.example.service;

import java.io.*;
import java.net.*;
import java.util.logging.Logger;

public class ReportService {
    private static final Logger logger = Logger.getLogger(ReportService.class.getName());

    // ⚠️ SSRF：用户输入直接用作URL发起HTTP请求
    public String fetchUrl(String targetUrl) {
        try {
            // ⚠️ 危险：targetUrl 可能是 http://internal-server/admin
            URL url = new URL(targetUrl);
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            conn.setRequestMethod("GET");
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(conn.getInputStream()));
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            reader.close();
            return response.toString();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    // ⚠️ 日志注入：用户输入未过滤写入日志
    public void logAccess(String userInput) {
        // ⚠️ 危险：userInput 可能包含换行符伪造日志条目
        // 例如: "admin\nINFO: User admin logged in successfully"
        logger.info("User accessed: " + userInput);
    }

    // ⚠️ 不安全的XML解析（XXE）
    public String parseXmlReport(String xmlInput) {
        try {
            // ⚠️ 危险：默认的 DocumentBuilderFactory 允许外部实体
            javax.xml.parsers.DocumentBuilderFactory factory =
                javax.xml.parsers.DocumentBuilderFactory.newInstance();
            javax.xml.parsers.DocumentBuilder builder = factory.newDocumentBuilder();
            org.w3c.dom.Document doc = builder.parse(
                new org.xml.sax.InputSource(new StringReader(xmlInput)));
            return doc.getDocumentElement().getTextContent();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    // ✅ 安全：禁用外部实体的XML解析
    public String parseXmlSafe(String xmlInput) {
        try {
            javax.xml.parsers.DocumentBuilderFactory factory =
                javax.xml.parsers.DocumentBuilderFactory.newInstance();
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            javax.xml.parsers.DocumentBuilder builder = factory.newDocumentBuilder();
            org.w3c.dom.Document doc = builder.parse(
                new org.xml.sax.InputSource(new StringReader(xmlInput)));
            return doc.getDocumentElement().getTextContent();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    // ⚠️ 模板注入：用户输入拼入模板字符串
    public String generateReport(String template, String userInput) {
        // ⚠️ 危险：如果模板引擎支持表达式，userInput 可能注入代码
        String filled = template.replace("${input}", userInput);
        return filled;
    }
}