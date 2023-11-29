package org.bloomreach.xm.cms.oidc.support;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;

import java.util.Collection;

public class NamedOidcUser extends DefaultOidcUser {
    private static final long serialVersionUID = 1L;
    private final String userName;

    public NamedOidcUser(
            final Collection<? extends GrantedAuthority> authorities,
            final OidcIdToken idToken,
            final OidcUserInfo userInfo,
            final String userName) {
        super(authorities, idToken, userInfo);
        this.userName = userName;
    }

    @Override
    public String getName() {
        return this.userName;
    }
}
