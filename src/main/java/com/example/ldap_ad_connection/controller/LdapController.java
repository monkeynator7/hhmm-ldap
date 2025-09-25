package com.example.ldap_ad_connection.controller;

import com.example.ldap_ad_connection.model.ADUser;
import com.example.ldap_ad_connection.service.NativeLdapService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import javax.naming.NamingException;
import java.util.List;

@Slf4j
@RestController
@RequestMapping("/api/ldap")
public class LdapController {

    @Autowired
    private NativeLdapService ldapService;

    @GetMapping("/users")
    public ResponseEntity<List<ADUser>> getAllUsers() {
        try {
            List<ADUser> users = ldapService.findAllUsers();
            return ResponseEntity.ok(users);
        } catch (Exception e) {
            log.error("Error obteniendo todos los usuarios: {}", e.getMessage());
            return ResponseEntity.internalServerError().build();
        }
    }

    @GetMapping("/users/search")
    public ResponseEntity<List<ADUser>> searchUsers(@RequestParam String term) {
        try {
            List<ADUser> users = ldapService.searchUsers(term);
            return ResponseEntity.ok(users);
        } catch (NamingException e) {
            log.error("Error buscando usuarios: {}", e.getMessage());
            return ResponseEntity.badRequest().build();
        }
    }

    @GetMapping("/users/{username}")
    public ResponseEntity<ADUser> getUserByUsername(@PathVariable String username) {
        try {
            ADUser user = ldapService.findUserByUsername(username);
            if (user != null) {
                return ResponseEntity.ok(user);
            } else {
                return ResponseEntity.notFound().build();
            }
        } catch (Exception e) {
            log.error("Error obteniendo usuario {}: {}", username, e.getMessage());
            return ResponseEntity.internalServerError().build();
        }
    }

    @GetMapping("/users/{username}/groups")
    public ResponseEntity<List<String>> getUserGroups(@PathVariable String username) {
        try {
            List<String> groups = ldapService.getUserGroups(username);
            return ResponseEntity.ok(groups);
        } catch (NamingException e) {
            log.error("Error obteniendo grupos del usuario {}: {}", username, e.getMessage());
            return ResponseEntity.badRequest().build();
        }
    }
}