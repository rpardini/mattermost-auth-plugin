package org.jenkinsci.plugins.mattermost;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.userdetails.UserDetails;

import java.util.Arrays;

public class MattermostUserDetails implements UserDetails {
    private final GrantedAuthority[] authorities;
    private final String username;

    public MattermostUserDetails(String username, GrantedAuthority[] grantedAuthorities) {
        this.username = username;
        this.authorities = Arrays.copyOf(grantedAuthorities, grantedAuthorities.length);
    }

    @Override
    public GrantedAuthority[] getAuthorities() {
        return Arrays.copyOf(this.authorities, this.authorities.length);
    }

    @Override
    public String getPassword() {
        return null;
    }

    @Override
    public String getUsername() {
        return this.username;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
