package com.example.ldap_ad_connection.controller;

import com.example.ldap_ad_connection.dto.AuthRequest;
import com.example.ldap_ad_connection.model.ADUser;
import com.example.ldap_ad_connection.service.NativeLdapService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.naming.NamingException;
import javax.validation.Valid;
import java.util.List;

@Slf4j
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    
    @Autowired
    private NativeLdapService ldapService;
    
    @Value("${app.ldap.required-group}")
    private String requiredGroup;
    
    @PostMapping("/authenticate")
    public ResponseEntity<AuthResponse> authenticateUser(@Valid @RequestBody AuthRequest authRequest) {
        log.info("Solicitud de autenticación para usuario: {}", authRequest.getUsername());
        
        NativeLdapService.AuthResult authResult = ldapService.authenticateUserWithDetails(
            authRequest.getUsername(), 
            authRequest.getPassword()
        );
        
        AuthResponse response = new AuthResponse();
        response.setAuthenticated(authResult.isAuthenticated());
        response.setUsername(authResult.getUsername());
        response.setUser(authResult.getUser());
        response.setHasRequiredGroup(authResult.isHasRequiredGroup());
        response.setAccountEnabled(authResult.isAccountEnabled());
        response.setAccountLocked(authResult.isAccountLocked());
        response.setUserGroups(authResult.getUserGroups());
        response.setMessage(authResult.getMessage());
        
        if (authResult.isAuthenticated() && authResult.isHasRequiredGroup()) {
            return ResponseEntity.ok(response);
        } else if (authResult.isAuthenticated() && !authResult.isHasRequiredGroup()) {
            return ResponseEntity.status(403).body(response);
        } else {
            return ResponseEntity.status(401).body(response);
        }
    }
    
    @PostMapping("/honorarios")
    public ResponseEntity<AuthResponse> authenticateHonorariosUser(
            @RequestParam String username,
            @RequestParam String password) {
        
        log.info("Autenticación específica para grupo Honorarios - Usuario: {}", username);
        
        NativeLdapService.AuthResult authResult = ldapService.authenticateUserWithDetails(username, password);
        
        AuthResponse response = new AuthResponse();
        response.setAuthenticated(authResult.isAuthenticated());
        response.setUsername(authResult.getUsername());
        response.setHasRequiredGroup(authResult.isHasRequiredGroup());
        response.setAccountEnabled(authResult.isAccountEnabled());
        response.setAccountLocked(authResult.isAccountLocked());
        response.setMessage(authResult.getMessage());
        
        if (authResult.isAuthenticated() && authResult.isHasRequiredGroup()) {
            response.setMessage("Autenticación exitosa para sistema de honorarios");
            return ResponseEntity.ok(response);
        } else if (authResult.isAuthenticated() && !authResult.isHasRequiredGroup()) {
            response.setMessage("Usuario autenticado pero no tiene acceso al sistema de honorarios");
            return ResponseEntity.status(403).body(response);
        } else {
            response.setMessage("Credenciales inválidas para sistema de honorarios");
            return ResponseEntity.status(401).body(response);
        }
    }
    
    @GetMapping("/group/users")
    public ResponseEntity<List<ADUser>> getUsersInHonorariosGroup() {
        try {
            List<ADUser> users = ldapService.findUsersInGroup(requiredGroup);
            return ResponseEntity.ok(users);
        } catch (NamingException e) {
            log.error("Error obteniendo usuarios del grupo: {}", e.getMessage());
            return ResponseEntity.internalServerError().build();
        }
    }
    
    @GetMapping("/health")
    public ResponseEntity<HealthResponse> healthCheck() {
        try {
            // Intentar una conexión simple para verificar salud del servicio
            boolean connectionTest = ldapService.authenticateUser(
                ldapService.findUserByUsername("test") != null ? "test" : "administrator", 
                "test"
            );
            
            HealthResponse response = new HealthResponse();
            response.setStatus("UP");
            response.setMessage("LDAP Service is running - Connection test completed");
            response.setDomain("alemana.cl");
            response.setRequiredGroup(requiredGroup);
            
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            HealthResponse response = new HealthResponse();
            response.setStatus("DOWN");
            response.setMessage("LDAP Service health check failed: " + e.getMessage());
            return ResponseEntity.status(503).body(response);
        }
    }
    
    // Clases de respuesta interna
    public static class AuthResponse {
        private boolean authenticated;
        private String username;
        private ADUser user;
        private boolean hasRequiredGroup;
        private boolean accountEnabled;
        private boolean accountLocked;
        private List<String> userGroups;
        private String message;
        
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
    
    public static class HealthResponse {
        private String status;
        private String message;
        private String domain;
        private String requiredGroup;
        
        public String getStatus() { return status; }
        public void setStatus(String status) { this.status = status; }
        
        public String getMessage() { return message; }
        public void setMessage(String message) { this.message = message; }
        
        public String getDomain() { return domain; }
        public void setDomain(String domain) { this.domain = domain; }
        
        public String getRequiredGroup() { return requiredGroup; }
        public void setRequiredGroup(String requiredGroup) { this.requiredGroup = requiredGroup; }
    }
}