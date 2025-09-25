package com.example.ldap_ad_connection.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;

import javax.naming.Name;
import java.util.List;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class ADUser {
    private Name dn;
    private String commonName;
    private String samAccountName;
    private String userPrincipalName;
    private String email;
    private String displayName;
    private String firstName;
    private String lastName;
    private List<String> groups;
    private String userAccountControl;
    private String distinguishedName;

    public boolean isEnabled() {
        try {
            if (userAccountControl != null) {
                int uac = Integer.parseInt(userAccountControl);
                return (uac & 2) == 0;
            }
            return false;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    public boolean isAccountLocked() {
        try {
            if (userAccountControl != null) {
                int uac = Integer.parseInt(userAccountControl);
                return (uac & 16) != 0;
            }
            return false;
        } catch (NumberFormatException e) {
            return false;
        }
    }
}
