package com.example.service;

import com.example.model.User;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

public class UserService {
    private Connection dbConnection;

    public User findById(Long id) {
        // ✅ 安全：使用参数化查询
        String sql = "SELECT * FROM users WHERE id = ?";
        try (PreparedStatement stmt = dbConnection.prepareStatement(sql)) {
            stmt.setLong(1, id);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return new User(rs.getLong("id"), rs.getString("username"), rs.getString("email"));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    // ⚠️ SQL注入风险：字符串拼接
    public User findByUsername(String username) {
        String sql = "SELECT * FROM users WHERE username = '" + username + "'";
        try (Statement stmt = dbConnection.createStatement()) {
            ResultSet rs = stmt.executeQuery(sql);
            if (rs.next()) {
                return new User(rs.getLong("id"), rs.getString("username"), rs.getString("email"));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    // ⚠️ SQL注入风险：字符串拼接 + execute
    public int deleteUser(String username) {
        String sql = "DELETE FROM users WHERE username = '" + username + "'";
        try (Statement stmt = dbConnection.createStatement()) {
            return stmt.execute(sql) ? 1 : 0;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return 0;
    }

    // ⚠️ 危险反序列化
    public Object loadObject(String filename) {
        try (java.io.FileInputStream fis = new java.io.FileInputStream(filename);
             java.io.ObjectInputStream ois = new java.io.ObjectInputStream(fis)) {
            return ois.readObject();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    // ✅ 安全方法
    public List<User> findAll() {
        List<User> users = new ArrayList<>();
        String sql = "SELECT * FROM users";
        try (PreparedStatement stmt = dbConnection.prepareStatement(sql)) {
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                users.add(new User(rs.getLong("id"), rs.getString("username"), rs.getString("email")));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return users;
    }

    // ⚠️ 二次注入：参数先存入DB，方法内部又从DB取出拼SQL
    // 用户输入在存储时未转义，从DB读出后直接拼入新的SQL
    public User searchUser(String keyword) {
        // 第一步：把 keyword 存入数据库（看似安全，因为用了 PreparedStatement）
        String insertSql = "INSERT INTO search_history (keyword) VALUES (?)";
        try (PreparedStatement stmt = dbConnection.prepareStatement(insertSql)) {
            stmt.setString(1, keyword);
            stmt.executeUpdate();
        } catch (Exception e) {
            e.printStackTrace();
        }

        // 第二步：从数据库读取最近搜索词，拼入新SQL — ⚠️ 二次注入
        // 从DB取出的数据可能包含恶意SQL片段，因为存储时未转义
        String recentKeyword = getRecentKeyword();
        String querySql = "SELECT * FROM users WHERE username = '" + recentKeyword + "'";
        try (Statement stmt = dbConnection.createStatement()) {
            ResultSet rs = stmt.executeQuery(querySql);
            if (rs.next()) {
                return new User(rs.getLong("id"), rs.getString("username"), rs.getString("email"));
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    private String getRecentKeyword() {
        String sql = "SELECT keyword FROM search_history ORDER BY id DESC LIMIT 1";
        try (PreparedStatement stmt = dbConnection.prepareStatement(sql)) {
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) return rs.getString("keyword");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return "";
    }

    // ⚠️ XPath注入：用户输入直接拼入XPath表达式
    public User findByXPath(String userName) {
        try {
            javax.xml.xpath.XPathFactory factory = javax.xml.xpath.XPathFactory.newInstance();
            javax.xml.xpath.XPath xpath = factory.newXPath();
            // ⚠️ 危险：用户输入直接拼入XPath
            String expression = "/users/user[username='" + userName + "']";
            javax.xml.xpath.XPathExpression expr = xpath.compile(expression);
            return null; // 简化，实际会返回解析结果
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    // ⚠️ 批量注入：LIKE查询 + 多个用户输入拼接
    public List<User> searchByMultipleCriteria(String name, String email) {
        String sql = "SELECT * FROM users WHERE username LIKE '%" + name + "%' AND email LIKE '%" + email + "%'";
        try (Statement stmt = dbConnection.createStatement()) {
            ResultSet rs = stmt.executeQuery(sql);
            List<User> users = new ArrayList<>();
            while (rs.next()) {
                users.add(new User(rs.getLong("id"), rs.getString("username"), rs.getString("email")));
            }
            return users;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return new ArrayList<>();
    }
}