package org.bloomreach.xm.cms.oidc.support;

import lombok.Getter;
import org.hippoecm.frontend.model.UserCredentials;

import java.io.Serializable;

@Getter
public class SSOUserState implements Serializable {

    private static final long serialVersionUID = 1L;

    public static final String OIDC_ID = SSOUserState.class.getName() + ".oidc.id";

    private final UserCredentials credentials;
    private final String sessionId;

    public SSOUserState(final UserCredentials credentials, final String sessionId) {
        this.credentials = credentials;
        this.sessionId = sessionId;
    }
}
