package com.example.controller;

import com.example.model.User;
import com.example.service.UserService;
import com.example.service.ReportService;
import com.example.service.FileService;
import com.example.service.AuthService;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class UserController {
    private UserService userService;
    private ReportService reportService;
    private FileService fileService;
    private AuthService authService;

    // ⚠️ SQL注入：调用了有风险的 findByUsername，传入来自请求的参数
    public User handleGetUser(String requestParam) {
        User user = userService.findByUsername(requestParam);
        return user;
    }

    // ⚠️ SQL注入：deleteUser + 请求参数
    public int handleDeleteUser(String headerValue) {
        return userService.deleteUser(headerValue);
    }

    // ⚠️ 危险反序列化
    public Object handleImport(String filePath) {
        return userService.loadObject(filePath);
    }

    // 安全调用
    public User handleGetById(Long id) {
        return userService.findById(id);
    }

    // ⚠️ 路径穿越：用户输入直接拼成文件路径
    public String handleDownload(String fileName) {
        return fileService.readFile(fileName);
    }

    // ⚠️ 二次注入：用户输入先存入DB，再从DB读出拼SQL
    public User handleSearch(String keyword) {
        return userService.searchUser(keyword);
    }

    // ⚠️ SSRF：用户输入直接用作URL
    public String handleProxy(String targetUrl) {
        return reportService.fetchUrl(targetUrl);
    }

    // ⚠️ XPath注入
    public User handleXPathQuery(String userName) {
        return userService.findByXPath(userName);
    }

    // ⚠️ LDAP注入
    public boolean handleLogin(String loginName, String loginPassword) {
        return authService.ldapAuth(loginName, loginPassword);
    }

    // ⚠️ 日志注入：用户输入未过滤写入日志
    public void handleLog(String userInput) {
        reportService.logAccess(userInput);
    }

    // ⚠️ 不安全的反射：用户输入决定实例化的类
    public Object handlePlugin(String className) {
        return authService.loadPlugin(className);
    }
}