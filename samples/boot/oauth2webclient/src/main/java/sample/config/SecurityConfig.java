/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sample.config;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import javax.servlet.http.HttpServletRequest;

/**
 * @author Joe Grandja
 */
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    protected final Log logger = LogFactory.getLog(getClass());

    @Autowired
    private ClientRegistrationRepository clientRegistrationRepository;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        logger.info("Going to configure and use CustomAuthorizationRequestResolver.");
        http
                .authorizeRequests().mvcMatchers("/", "/public/**").permitAll()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .and()
                .oauth2Client()
                .and()
                //.oauth2Login()
                //.and()
                /*.authorizeRequests(authorizeRequests ->
                        authorizeRequests
                                .mvcMatchers("/", "/public/**").permitAll()
                                .anyRequest().authenticated()
                )*/
                //.formLogin(withDefaults())
                //.oauth2Client(withDefaults())
                //.oauth2Login(withDefaults())
                .oauth2Login(x -> {
                            x.authorizationEndpoint()
                                    .authorizationRequestResolver(
                                            new CustomAuthorizationRequestResolver(this.clientRegistrationRepository)
                                    );
                        }
                );
    }

    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails userDetails = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(userDetails);
    }

    public class CustomAuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {
        private final OAuth2AuthorizationRequestResolver defaultAuthorizationRequestResolver;

        public CustomAuthorizationRequestResolver(
                ClientRegistrationRepository clientRegistrationRepository) {

            this.defaultAuthorizationRequestResolver =
                    new DefaultOAuth2AuthorizationRequestResolver(
                            clientRegistrationRepository, "/oauth2/authorization");
        }

        @Override
        public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
            OAuth2AuthorizationRequest authorizationRequest = this.defaultAuthorizationRequestResolver.resolve(request);
            String a = request.getHeader("X-Forwarded-Prefix");
            return authorizationRequest != null ? customAuthorizationRequest(authorizationRequest) : null;
        }

        @Override
        public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
            OAuth2AuthorizationRequest authorizationRequest = this.defaultAuthorizationRequestResolver.resolve(
                    request, clientRegistrationId
            );

            return authorizationRequest != null ? customAuthorizationRequest(authorizationRequest) : null;
        }

        private OAuth2AuthorizationRequest customAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest) {
            //Map<String, Object> additionalParameters =
            //		new LinkedHashMap<>(authorizationRequest.getAdditionalParameters());
            //additionalParameters.put("prompt", "consent");  6

            final String redirectUriHardcoded = "https://example.com/myDevApp/login/oauth2/code/client-id";
            final boolean forceRedirect = false;
            logger.info(
                    "Going to (" + forceRedirect + ") force change redirect_uri from:\n" +
                            authorizationRequest.getRedirectUri() + "\n" +
                            "to this hardcoded one:\n" +
                            redirectUriHardcoded
            );
            final OAuth2AuthorizationRequest.Builder from = OAuth2AuthorizationRequest.from(authorizationRequest);
            if(forceRedirect) {
                from.redirectUri(redirectUriHardcoded);
            }
            return from
                    //.additionalParameters(additionalParameters)
                    .build();
        }
    }
}
