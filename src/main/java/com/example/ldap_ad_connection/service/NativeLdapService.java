package com.example.ldap_ad_connection.service;

import com.example.ldap_ad_connection.config.LdapConfig;
import com.example.ldap_ad_connection.model.ADUser;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.ldap.core.AttributesMapper;
import org.springframework.ldap.core.LdapTemplate;
import org.springframework.ldap.filter.AndFilter;
import org.springframework.ldap.filter.EqualsFilter;
import org.springframework.ldap.query.LdapQuery;
import org.springframework.ldap.query.LdapQueryBuilder;
import org.springframework.ldap.query.SearchScope;
import org.springframework.stereotype.Service;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.*;
import java.util.ArrayList;
import java.util.List;

@Slf4j
@Service
public class NativeLdapService {

    @Autowired
    private LdapConfig ldapConfig;

    @Autowired
    private LdapTemplate ldapTemplate;

    @Value("${app.ldap.user-search-base}")
    private String userSearchBase;

    @Value("${app.ldap.group-search-base}")
    private String groupSearchBase;

    @Value("${app.ldap.required-group}")
    private String requiredGroup;

    @Value("${app.ldap.domain}")
    private String domain;

    public boolean authenticateUser(String username, String password) {
        DirContext context = null;
        try {
            context = ldapConfig.getNativeLdapConnection(username, password);
            log.info("Autenticación exitosa para usuario: {}", username);
            return true;
        } catch (NamingException e) {
            log.error("Error en autenticación para usuario {}: {}", username, e.getMessage());
            return false;
        } finally {
            if (context != null) {
                try {
                    context.close();
                } catch (NamingException e) {
                    log.error("Error cerrando conexión LDAP: {}", e.getMessage());
                }
            }
        }
    }

    public AuthResult authenticateUserWithDetails(String username, String password) {
        AuthResult result = new AuthResult();
        result.setUsername(username);
        
        try {
            // Primero verificar autenticación
            boolean isAuthenticated = authenticateUser(username, password);
            result.setAuthenticated(isAuthenticated);
            
            if (isAuthenticated) {
                // Obtener información del usuario
                ADUser user = findUserByUsername(username);
                if (user != null) {
                    result.setUser(user);
                    result.setAccountEnabled(user.isEnabled());
                    result.setAccountLocked(user.isAccountLocked());
                    
                    // Verificar membresía en grupo requerido
                    boolean hasRequiredGroup = checkUserGroupMembership(username, requiredGroup);
                    result.setHasRequiredGroup(hasRequiredGroup);
                    result.setUserGroups(getUserGroups(username));
                    
                    if (hasRequiredGroup) {
                        result.setMessage("Autenticación exitosa y usuario pertenece al grupo requerido");
                    } else {
                        result.setMessage("Usuario autenticado pero no pertenece al grupo requerido");
                    }
                }
            } else {
                result.setMessage("Credenciales inválidas");
            }
            
        } catch (Exception e) {
            log.error("Error durante autenticación detallada: {}", e.getMessage());
            result.setAuthenticated(false);
            result.setMessage("Error durante el proceso de autenticación: " + e.getMessage());
        }
        
        return result;
    }

    public boolean checkUserGroupMembership(String username, String groupDn) throws NamingException {
        List<String> userGroups = getUserGroups(username);
        return userGroups.contains(groupDn);
    }

    public List<String> getUserGroups(String username) throws NamingException {
        List<String> groups = new ArrayList<>();
        DirContext context = null;

        try {
            context = ldapConfig.getNativeLdapConnection();

            String filter = "(&(objectClass=user)(sAMAccountName=" + username + "))";
            SearchControls controls = new SearchControls();
            controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            controls.setReturningAttributes(new String[]{"memberOf"});

            NamingEnumeration<SearchResult> results = context.search(userSearchBase, filter, controls);

            if (results.hasMore()) {
                SearchResult result = results.next();
                Attribute memberOf = result.getAttributes().get("memberOf");
                
                if (memberOf != null) {
                    for (int i = 0; i < memberOf.size(); i++) {
                        groups.add((String) memberOf.get(i));
                    }
                }
            }

        } finally {
            if (context != null) {
                context.close();
            }
        }

        return groups;
    }

    public List<ADUser> searchUsers(String searchTerm) throws NamingException {
        List<ADUser> users = new ArrayList<>();
        DirContext context = null;

        try {
            context = ldapConfig.getNativeLdapConnection();

            String filter = "(&(objectClass=user)(|(cn=*" + searchTerm + "*)(sAMAccountName=*" + searchTerm + "*)(mail=*" + searchTerm + "*)(displayName=*" + searchTerm + "*)))";
            
            SearchControls controls = new SearchControls();
            controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            controls.setReturningAttributes(new String[]{
                "cn", "sAMAccountName", "userPrincipalName", "mail", 
                "displayName", "givenName", "sn", "memberOf", "userAccountControl", "distinguishedName"
            });

            NamingEnumeration<SearchResult> results = context.search(userSearchBase, filter, controls);

            while (results.hasMore()) {
                SearchResult result = results.next();
                Attributes attributes = result.getAttributes();
                users.add(mapAttributesToUser(attributes, result.getNameInNamespace()));
            }

        } finally {
            if (context != null) {
                context.close();
            }
        }

        return users;
    }

    public List<ADUser> findAllUsers() {
        LdapQuery query = LdapQueryBuilder.query()
                .base(userSearchBase)
                .searchScope(SearchScope.SUBTREE)
                .where("objectClass").is("user")
                .and("objectClass").is("person");

        return ldapTemplate.search(query, new ADUserAttributesMapper());
    }

    public ADUser findUserByUsername(String username) {
        AndFilter filter = new AndFilter();
        filter.and(new EqualsFilter("objectClass", "user"));
        filter.and(new EqualsFilter("sAMAccountName", username));

        List<ADUser> users = ldapTemplate.search(
            userSearchBase, 
            filter.encode(), 
            new ADUserAttributesMapper()
        );

        return users.isEmpty() ? null : users.get(0);
    }

    public List<ADUser> findUsersInGroup(String groupDn) throws NamingException {
        List<ADUser> users = new ArrayList<>();
        DirContext context = null;

        try {
            context = ldapConfig.getNativeLdapConnection();

            String filter = "(&(objectClass=user)(memberOf=" + groupDn + "))";
            
            SearchControls controls = new SearchControls();
            controls.setSearchScope(SearchControls.SUBTREE_SCOPE);
            controls.setReturningAttributes(new String[]{
                "cn", "sAMAccountName", "userPrincipalName", "mail", 
                "displayName", "givenName", "sn", "memberOf", "userAccountControl", "distinguishedName"
            });

            NamingEnumeration<SearchResult> results = context.search(userSearchBase, filter, controls);

            while (results.hasMore()) {
                SearchResult result = results.next();
                Attributes attributes = result.getAttributes();
                users.add(mapAttributesToUser(attributes, result.getNameInNamespace()));
            }

        } finally {
            if (context != null) {
                context.close();
            }
        }

        return users;
    }

    private ADUser mapAttributesToUser(Attributes attributes, String dn) throws NamingException {
        ADUser user = new ADUser();
        
        Attribute attr = attributes.get("cn");
        if (attr != null) user.setCommonName((String) attr.get());
        
        attr = attributes.get("sAMAccountName");
        if (attr != null) user.setSamAccountName((String) attr.get());
        
        attr = attributes.get("userPrincipalName");
        if (attr != null) user.setUserPrincipalName((String) attr.get());
        
        attr = attributes.get("mail");
        if (attr != null) user.setEmail((String) attr.get());
        
        attr = attributes.get("displayName");
        if (attr != null) user.setDisplayName((String) attr.get());
        
        attr = attributes.get("givenName");
        if (attr != null) user.setFirstName((String) attr.get());
        
        attr = attributes.get("sn");
        if (attr != null) user.setLastName((String) attr.get());
        
        attr = attributes.get("userAccountControl");
        if (attr != null) user.setUserAccountControl((String) attr.get());
        
        attr = attributes.get("distinguishedName");
        if (attr != null) user.setDistinguishedName((String) attr.get());

        return user;
    }

    private static class ADUserAttributesMapper implements AttributesMapper<ADUser> {
        @Override
        public ADUser mapFromAttributes(Attributes attributes) throws NamingException {
            ADUser user = new ADUser();
            
            Attribute attr = attributes.get("cn");
            if (attr != null) user.setCommonName((String) attr.get());
            
            attr = attributes.get("sAMAccountName");
            if (attr != null) user.setSamAccountName((String) attr.get());
            
            attr = attributes.get("userPrincipalName");
            if (attr != null) user.setUserPrincipalName((String) attr.get());
            
            attr = attributes.get("mail");
            if (attr != null) user.setEmail((String) attr.get());
            
            attr = attributes.get("displayName");
            if (attr != null) user.setDisplayName((String) attr.get());
            
            attr = attributes.get("givenName");
            if (attr != null) user.setFirstName((String) attr.get());
            
            attr = attributes.get("sn");
            if (attr != null) user.setLastName((String) attr.get());
            
            attr = attributes.get("userAccountControl");
            if (attr != null) user.setUserAccountControl((String) attr.get());
            
            attr = attributes.get("distinguishedName");
            if (attr != null) user.setDistinguishedName((String) attr.get());

            return user;
        }
    }

    public static class AuthResult {
        private boolean authenticated;
        private String username;
        private ADUser user;
        private boolean hasRequiredGroup;
        private boolean accountEnabled;
        private boolean accountLocked;
        private List<String> userGroups;
        private String message;

        // Getters and Setters
        public boolean isAuthenticated() { return authenticated; }
        public void setAuthenticated(boolean authenticated) { this.authenticated = authenticated; }
        
        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        
        public ADUser getUser() { return user; }
        public void setUser(ADUser user) { this.user = user; }
        
        public boolean isHasRequiredGroup() { return hasRequiredGroup; }
        public void setHasRequiredGroup(boolean hasRequiredGroup) { this.hasRequiredGroup = hasRequiredGroup; }
        
        public boolean isAccountEnabled() { return accountEnabled; }
        public void setAccountEnabled(boolean accountEnabled) { this.accountEnabled = accountEnabled; }
        
        public boolean isAccountLocked() { return accountLocked; }
        public void setAccountLocked(boolean accountLocked) { this.accountLocked = accountLocked; }
        
        public List<String> getUserGroups() { return userGroups; }
        public void setUserGroups(List<String> userGroups) { this.userGroups = userGroups; }
        
        public String getMessage() { return message; }
        public void setMessage(String message) { this.message = message; }
    }
}