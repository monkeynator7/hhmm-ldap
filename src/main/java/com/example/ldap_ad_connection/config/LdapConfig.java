package com.example.ldap_ad_connection.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.core.support.LdapContextSource;

import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import java.util.Hashtable;

@Configuration
public class LdapConfig {

    @Value("${spring.ldap.urls}")
    private String ldapUrl;

    @Value("${spring.ldap.base}")
    private String ldapBase;

    @Value("${spring.ldap.username}")
    private String ldapUsername;

    @Value("${spring.ldap.password}")
    private String ldapPassword;

    @Value("${app.ldap.connection-timeout}")
    private int connectionTimeout;

    public String getLdapUrl() {
        return ldapUrl;
    }

    @Bean
    public LdapContextSource contextSource() {
        LdapContextSource contextSource = new LdapContextSource();
        contextSource.setUrl(ldapUrl);
        contextSource.setBase(ldapBase);
        contextSource.setUserDn(ldapUsername);
        contextSource.setPassword(ldapPassword);
        contextSource.setPooled(true);
        contextSource.setReferral("follow");
        
        // Configuración adicional para entorno corporativo
//        Hashtable<String, Object> baseEnvironment = new Hashtable<>();
//        baseEnvironment.put("com.sun.jndi.ldap.connect.timeout", String.valueOf(connectionTimeout));
//        baseEnvironment.put("com.sun.jndi.ldap.read.timeout", "30000");
//        contextSource.setBaseEnvironment(baseEnvironment);
        
        return contextSource;
    }

    @Bean
    public LdapTemplate ldapTemplate() {
        LdapTemplate ldapTemplate = new LdapTemplate(contextSource());
        ldapTemplate.setIgnorePartialResultException(true);
        ldapTemplate.setIgnoreNameNotFoundException(true);
        return ldapTemplate;
    }

    public DirContext getNativeLdapConnection() throws NamingException {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, ldapUrl);
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, ldapUsername);
        env.put(Context.SECURITY_CREDENTIALS, ldapPassword);
        env.put(Context.REFERRAL, "follow");
        env.put("com.sun.jndi.ldap.connect.timeout", String.valueOf(connectionTimeout));
        env.put("com.sun.jndi.ldap.read.timeout", "30000");
        
        return new InitialDirContext(env);
    }

    public DirContext getNativeLdapConnection(String username, String password) throws NamingException {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, ldapUrl);
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, formatUserPrincipal(username));
        env.put(Context.SECURITY_CREDENTIALS, password);
        env.put(Context.REFERRAL, "follow");
        env.put("com.sun.jndi.ldap.connect.timeout", String.valueOf(connectionTimeout));
        env.put("com.sun.jndi.ldap.read.timeout", "30000");
        
        return new InitialDirContext(env);
    }

    private String formatUserPrincipal(String username) {
        if (username.contains("@")) {
            return username;
        }
        return username + "@alemana.cl";
    }
}