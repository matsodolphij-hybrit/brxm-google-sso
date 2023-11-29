package org.hybrit.repository.provider;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.apache.jackrabbit.api.security.user.UserManager;
import org.apache.jackrabbit.value.StringValue;
import org.bloomreach.xm.cms.oidc.filter.UserSessionFilter;
import org.bloomreach.xm.cms.oidc.support.SSOUserState;
import org.hippoecm.repository.security.DelegatingSecurityProvider;
import org.hippoecm.repository.security.RepositorySecurityProvider;
import org.hippoecm.repository.security.user.DelegatingHippoUserManager;
import org.hippoecm.repository.security.user.HippoUserManager;

import javax.jcr.*;
import java.util.Arrays;

import static org.bloomreach.xm.cms.oidc.filter.UserSessionFilter.*;
import static org.bloomreach.xm.cms.oidc.support.SSOUserState.OIDC_ID;

@Slf4j
public class OpenIdDelegatingSecurityProvider extends DelegatingSecurityProvider {

    private HippoUserManager userManager;

    public OpenIdDelegatingSecurityProvider() {
        super(new RepositorySecurityProvider());
    }

    @Override
    public UserManager getUserManager() throws RepositoryException {
        if (userManager == null) {
            userManager =
                    new DelegatingHippoUserManager((HippoUserManager) super.getUserManager()) {
                        @Override
                        public boolean authenticate(final SimpleCredentials simpleCredentials)
                                throws RepositoryException {
                            if (validateAuthentication(simpleCredentials)) {
                                final String userId = simpleCredentials.getUserID();
                                if (!hasUser(userId)) {
                                    // This where we create a new user with a role of admin. This is where you can set another role if your SSO provider allows this.
                                    syncUser(
                                            createUser(userId), getGroupManager().getGroup("admin"), simpleCredentials);
                                }
                                return true;
                            } else {
                                return false;
                            }
                        }
                    };
        }
        return userManager;
    }

    @Override
    public UserManager getUserManager(Session session) throws RepositoryException {
        return new DelegatingHippoUserManager((HippoUserManager) super.getUserManager(session)) {
            @Override
            public boolean authenticate(final SimpleCredentials simpleCredentials)
                    throws RepositoryException {
                if (validateAuthentication(simpleCredentials)) {
                    final String userId = simpleCredentials.getUserID();
                    if (!hasUser(userId)) {
                        // This where we create a new user with a role of admin. This is where you can set another role if your SSO provider allows this.s
                        syncUser(createUser(userId), getGroupManager().getGroup("admin"), simpleCredentials);
                    }
                    return true;
                } else {
                    return false;
                }
            }
        };
    }

    protected boolean validateAuthentication(final SimpleCredentials simpleCredentials) {
        final SSOUserState userState = UserSessionFilter.getCurrentSSOUserState();
        if (userState != null) {
            return StringUtils.isNotEmpty(userState.getCredentials().getUsername());
        } else {
            final String oidcID = (String) simpleCredentials.getAttribute(OIDC_ID);
            if (StringUtils.isNotBlank(oidcID)) {
                log.debug("Authentication allowed to: {}", oidcID);
                return true;
            }
        }
        return false;
    }

    protected void syncUser(final Node user, final Node group, final SimpleCredentials credentials)
            throws RepositoryException {
        // By setting this property we make sure that this user will be logged in using our custom OpenIdDelegatingSecurityProvider class.
        user.setProperty(
                "hipposys:securityprovider",
                "openid");
        user.setProperty("hipposys:active", true);
        user.setProperty("hipposys:firstname", (String) credentials.getAttribute(FIRSTNAME_ATTRIBUTE));
        user.setProperty("hipposys:lastname", (String) credentials.getAttribute(LASTNAME_ATTRIBUTE));
        user.setProperty("hipposys:email", (String) credentials.getAttribute(EMAIL_ATTRIBUTE));

        // add the user to the correct group based on the role
        final Value[] values = group.getProperties("hipposys:members").nextProperty().getValues();
        final Value[] newValues = Arrays.copyOf(values, values.length + 1);
        newValues[values.length] = new StringValue(user.getName());
        group.setProperty("hipposys:members", newValues);
    }
}
