package org.bloomreach.xm.cms.oidc.filter;

import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.bloomreach.xm.cms.oidc.support.NamedOidcUser;
import org.bloomreach.xm.cms.oidc.support.SSOUserState;
import org.hippoecm.frontend.model.UserCredentials;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import javax.jcr.SimpleCredentials;
import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Slf4j
public class UserSessionFilter implements Filter {

    public static final String FIRSTNAME_ATTRIBUTE = "firstname";
    public static final String LASTNAME_ATTRIBUTE = "lastname";
    public static final String EMAIL_ATTRIBUTE = "email";
    private static final String SSO_USER_STATE = SSOUserState.class.getName();
    private static final ThreadLocal<SSOUserState> tlCurrentSSOUserState = new ThreadLocal<>();

    @Override
    public void init(FilterConfig filterConfig) {
    }

    /**
     * Creates a new secured session if the user is authorized. {@inheritDoc}
     */
    @Override
    public void doFilter(
            final ServletRequest servletRequest,
            final ServletResponse servletResponse,
            final FilterChain filterChain)
            throws IOException, ServletException {

        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (!authentication.isAuthenticated()) {
            filterChain.doFilter(servletRequest, servletResponse);
        }

        final HttpSession session = ((HttpServletRequest) servletRequest).getSession();
        SSOUserState userState = (SSOUserState) session.getAttribute(SSO_USER_STATE);

        if (userState == null || !userState.getSessionId().equals(session.getId())) {
            userState = new SSOUserState(new UserCredentials(createSimpleCredentials(authentication)), session.getId());
            session.setAttribute(SSO_USER_STATE, userState);
        }

        if (userState.getSessionId().equals(session.getId())) {
            servletRequest.setAttribute(UserCredentials.class.getName(), userState.getCredentials());
        }

        try {
            tlCurrentSSOUserState.set(userState);
            filterChain.doFilter(servletRequest, servletResponse);
        } finally {
            tlCurrentSSOUserState.remove();
        }
    }

    public static SSOUserState getCurrentSSOUserState() {
        return tlCurrentSSOUserState.get();
    }

    @Override
    public void destroy() {
        tlCurrentSSOUserState.remove();
    }

    private SimpleCredentials createSimpleCredentials(final Authentication authentication) {
        final NamedOidcUser userInfo = (NamedOidcUser) authentication.getPrincipal();
        final SimpleCredentials simpleCredentials =
                new SimpleCredentials(userInfo.getEmail(), "dummy".toCharArray());

        simpleCredentials.setAttribute(FIRSTNAME_ATTRIBUTE, userInfo.getGivenName());
        simpleCredentials.setAttribute(LASTNAME_ATTRIBUTE, getFullSurname(userInfo));
        simpleCredentials.setAttribute(EMAIL_ATTRIBUTE, userInfo.getEmail());
        simpleCredentials.setAttribute(SSOUserState.OIDC_ID, userInfo.getEmail());
        return simpleCredentials;
    }

    private String getFullSurname(final NamedOidcUser userInfo) {
        return StringUtils.isNotBlank(userInfo.getMiddleName())
                ? userInfo.getMiddleName() + " " + userInfo.getFamilyName()
                : userInfo.getFamilyName();
    }
}
