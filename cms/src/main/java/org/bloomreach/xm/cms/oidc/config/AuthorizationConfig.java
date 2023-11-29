package org.bloomreach.xm.cms.oidc.config;

import lombok.extern.slf4j.Slf4j;
import org.bloomreach.xm.cms.oidc.filter.UserSessionFilter;
import org.bloomreach.xm.cms.oidc.support.NamedOidcUser;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;

import java.util.HashSet;
import java.util.Set;

@Slf4j
@Configuration
@EnableWebSecurity
@PropertySource("classpath:application-azure-ad.properties")
public class AuthorizationConfig {

    @Value("${sso.enabled}")
    boolean ssoEnabled;

    @Bean
    SecurityFilterChain filterChain(final HttpSecurity http)
            throws Exception {
        if (ssoEnabled) {
            return http
                    .csrf(AbstractHttpConfigurer::disable)
                    .headers()
                    .frameOptions()
                    .sameOrigin() // this configuration makes sure that the experience manager does not break.
                    .and()
                    .authorizeRequests()
                    .and()
                    .authorizeRequests(r -> r.anyRequest().authenticated())
                    .oauth2Login(
                            oauth2 ->
                                    oauth2.userInfoEndpoint(ep -> ep.oidcUserService(customOidcUserService())))
                    .addFilterAfter(new UserSessionFilter(), FilterSecurityInterceptor.class)
                    .build();
        } else {
            return defaultBRXMLogin(http);
        }
    }

    private OAuth2UserService<OidcUserRequest, OidcUser> customOidcUserService() {
        final OidcUserService delegate = new OidcUserService();

        return (userRequest) -> {
            OidcUser oidcUser = delegate.loadUser(userRequest);
            // Google SSO does not configure authorities. Other providers like Azure AD and OKTA can specify authorities.
            // These authorities can be used to set a BRXM role. We will set admin role by default for this User.
            final Set<GrantedAuthority> mappedAuthorities = new HashSet<>(oidcUser.getAuthorities());

            oidcUser =
                    new NamedOidcUser(
                            mappedAuthorities,
                            oidcUser.getIdToken(),
                            oidcUser.getUserInfo(),
                            oidcUser.getEmail());

            return oidcUser;
        };
    }

    private SecurityFilterChain defaultBRXMLogin(final HttpSecurity http) throws Exception {
        return http.authorizeRequests()
                .antMatchers("/**")
                .permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .csrf()
                .disable()
                .headers()
                .frameOptions()
                .sameOrigin()
                .and()
                .build();
    }
}
