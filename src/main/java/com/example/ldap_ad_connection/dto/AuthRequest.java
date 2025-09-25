package com.example.ldap_ad_connection.dto;

import lombok.Data;
import javax.validation.constraints.NotBlank;

@Data
public class AuthRequest {
    
    @NotBlank(message = "Username is required")
    private String username;
    
    @NotBlank(message = "Password is required")
    private String password;
    
    private boolean checkGroupMembership = true;
}