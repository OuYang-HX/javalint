package com.example.service;

import java.util.Hashtable;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

public class AuthService {
    private DirContext ldapContext;

    // ⚠️ LDAP注入：用户输入直接拼入LDAP查询
    public boolean ldapAuth(String loginName, String loginPassword) {
        try {
            // ⚠️ 危险：loginName 可能是 *)(|(cn=*)(password=*))
            String filter = "(&(uid=" + loginName + ")(userPassword=" + loginPassword + "))";
            SearchControls controls = new SearchControls();
            controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            NamingEnumeration<SearchResult> results =
                ldapContext.search("ou=users,dc=example,dc=com", filter, controls);
            return results.hasMore();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    // ✅ 安全：LDAP参数化查询
    public boolean ldapAuthSafe(String loginName, String loginPassword) {
        try {
            String filter = "(&(uid={0})(userPassword={1}))";
            SearchControls controls = new SearchControls();
            controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            Object[] args = {loginName, loginPassword};
            NamingEnumeration<SearchResult> results =
                ldapContext.search("ou=users,dc=example,dc=com", filter, args, controls);
            return results.hasMore();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return false;
    }

    // ⚠️ 不安全的反射：用户输入决定实例化的类
    public Object loadPlugin(String className) {
        try {
            // ⚠️ 危险：className 可能是 "java.lang.Runtime" 或恶意类
            Class<?> clazz = Class.forName(className);
            return clazz.getDeclaredConstructor().newInstance();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    // ⚠️ JNDI注入：用户输入作为 JNDI lookup 名称
    public Object lookupResource(String jndiName) {
        try {
            // ⚠️ 危险：jndiName 可能指向恶意 RMI 服务
            Hashtable<String, String> env = new Hashtable<>();
            env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.rmi.registry.RegistryContextFactory");
            env.put(Context.PROVIDER_URL, "rmi://localhost:1099");
            Context ctx = new InitialDirContext(env);
            return ctx.lookup(jndiName);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }
}