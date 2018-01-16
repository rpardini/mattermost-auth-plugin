/*
 * The MIT License
 *
 * Copyright (c) 2016  Michael Bischoff & GeriMedica - www.gerimedica.nl
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package org.jenkinsci.plugins.mattermost;

import com.google.api.client.auth.oauth2.AuthorizationCodeFlow;
import com.google.api.client.auth.oauth2.BearerToken;
import com.google.api.client.auth.oauth2.ClientParametersAuthentication;
import com.google.api.client.auth.openidconnect.IdTokenResponse;
import com.google.api.client.http.*;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.GenericJson;
import com.google.api.client.json.JsonFactory;
import com.google.api.client.json.JsonObjectParser;
import com.google.api.client.json.jackson2.JacksonFactory;
import edu.umd.cs.findbugs.annotations.SuppressFBWarnings;
import hudson.Extension;
import hudson.model.Descriptor;
import hudson.model.User;
import hudson.security.SecurityRealm;
import hudson.tasks.Mailer;
import hudson.util.FormValidation;
import hudson.util.HttpResponses;
import hudson.util.Secret;
import jenkins.model.Jenkins;
import org.acegisecurity.*;
import org.acegisecurity.context.SecurityContextHolder;
import org.acegisecurity.providers.UsernamePasswordAuthenticationToken;
import org.acegisecurity.providers.anonymous.AnonymousAuthenticationToken;
import org.kohsuke.stapler.*;
import org.kohsuke.stapler.HttpResponse;

import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.util.Collections;

/**
 * Login with Mattermost
 *
 * @author Michael Bischoff
 * @author Ricardo Pardini
 */
public class MattermostSecurityRealm extends SecurityRealm {

    private transient static final JsonFactory JSON_FACTORY = new JacksonFactory();

    private final String clientId;
    private final Secret clientSecret;
    private final String mattermostServerUrl;
    private final boolean disableSslVerification;

    @DataBoundConstructor
    public MattermostSecurityRealm(String clientId, String clientSecret, String mattermostServerUrl, boolean disableSslVerification) {
        this.clientId = clientId;
        this.clientSecret = Secret.fromString(clientSecret);
        this.mattermostServerUrl = mattermostServerUrl;
        this.disableSslVerification = disableSslVerification;
    }

    private HttpTransport constructHttpTransport(boolean disableSslVerification) {
        NetHttpTransport.Builder builder = new NetHttpTransport.Builder();

        if (disableSslVerification) {
            try {
                builder.doNotValidateCertificate();
            } catch (GeneralSecurityException ex) {
                // we do not handle this exception...
            }
        }

        return builder.build();
    }

    @SuppressWarnings("unused")
    public String getClientId() {
        return clientId;
    }

    @SuppressWarnings("unused")
    public Secret getClientSecret() {
        return clientSecret;
    }

    @SuppressWarnings("unused")
    public String getMattermostServerUrl() {
        return mattermostServerUrl;
    }

    @SuppressWarnings("unused")
    public boolean isDisableSslVerification() {
        return disableSslVerification;
    }

    /**
     * Login begins with our {@link #doCommenceLogin(String, String)} method.
     */
    @Override
    public String getLoginUrl() {
        return "securityRealm/commenceLogin";
    }

    /*
     * Acegi has this notion that first an {@link org.acegisecurity.Authentication} object is created
     * by collecting user information and then the act of authentication is done
     * later (by {@link org.acegisecurity.AuthenticationManager}) to verify it. But in case of OpenID,
     * we create an {@link org.acegisecurity.Authentication} only after we verified the user identity,
     * so {@link org.acegisecurity.AuthenticationManager} becomes no-op.
     */
    @Override
    public SecurityComponents createSecurityComponents() {
        return new SecurityComponents(
                new AuthenticationManager() {
                    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
                        if (authentication instanceof AnonymousAuthenticationToken)
                            return authentication;
                        throw new BadCredentialsException("Unexpected authentication type: " + authentication);
                    }
                }
        );
    }

    /**
     * handles the the securityRealm/commenceLogin resource
     */
    @SuppressWarnings({"unused", "WeakerAccess"})
    public HttpResponse doCommenceLogin(@QueryParameter String from, @Header("Referer") final String referer) throws IOException {
        final String redirectOnFinish = determineRedirectTarget(from, referer);

        final AuthorizationCodeFlow flow = new AuthorizationCodeFlow.Builder(
                BearerToken.queryParameterAccessMethod(),
                constructHttpTransport(this.disableSslVerification),
                JSON_FACTORY,
                new GenericUrl(this.mattermostServerUrl + "/oauth/access_token"),
                new ClientParametersAuthentication(clientId, clientSecret.getPlainText()),
                clientId,
                this.mattermostServerUrl + "/oauth/authorize"
        )
                .setScopes(Collections.singletonList("openid email"))
                .build();

        return new MattermostSession(flow, from, buildOAuthRedirectUrl()) {
            @Override
            public HttpResponse onSuccess(String authorizationCode) {
                try {

                    String redirectUri = buildOAuthRedirectUrl();
                    IdTokenResponse response = flow.newTokenRequest(authorizationCode).setRedirectUri(redirectUri).executeUnparsed().parseAs(IdTokenResponse.class);

                    // access token can always be obtained directly.
                    String accessToken = response.getAccessToken();

                    GenericJson userInfo = getUserInfo(flow, accessToken);
                    String username = (String) userInfo.get("username");

                    if (username == null) {
                        return HttpResponses.error(500, "no field 'username' was supplied in the token payload to be used as the username");
                    }

                    flow.createAndStoreCredential(response, null);

                    UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, "", new GrantedAuthority[]{SecurityRealm.AUTHENTICATED_AUTHORITY});
                    SecurityContextHolder.getContext().setAuthentication(token);

                    User u = User.get(token.getName());

                    String email = (String) userInfo.get("email");
                    if (email != null) {
                        u.addProperty(new Mailer.UserProperty(email));
                    }

                    String fullName = userInfo.get("first_name") + " " + userInfo.get("last_name");
                    u.setFullName(fullName);

                    return new HttpRedirect(redirectOnFinish);

                } catch (IOException e) {
                    return HttpResponses.error(500, e);
                }

            }
        }.doCommenceLogin();
    }


    private GenericJson getUserInfo(final AuthorizationCodeFlow flow, final String accessToken) throws IOException {
        HttpRequestFactory requestFactory = flow.getTransport().createRequestFactory(new HttpRequestInitializer() {
            @Override
            public void initialize(HttpRequest request) {
                request.getHeaders().setAuthorization("Bearer " + accessToken);
            }
        });
        HttpRequest request = requestFactory.buildGetRequest(new GenericUrl(this.mattermostServerUrl + "/api/v4/users/me"));
        request.setParser(new JsonObjectParser(flow.getJsonFactory()));
        request.setThrowExceptionOnExecuteError(false);
        com.google.api.client.http.HttpResponse response = request.execute();
        if (response.isSuccessStatusCode()) {
            return response.parseAs(GenericJson.class);
        }
        throw new HttpResponseException(response);
    }


    @SuppressFBWarnings("NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE")
    private String determineRedirectTarget(@QueryParameter String from, @Header("Referer") String referer) {
        String target;
        if (from != null) {
            target = from;
        } else if (referer != null) {
            target = referer;
        } else {
            target = Jenkins.getInstance().getRootUrl();
        }
        return target;
    }

    @SuppressFBWarnings("NP_NULL_ON_SOME_PATH_FROM_RETURN_VALUE")
    private String buildOAuthRedirectUrl() throws NullPointerException {
        String rootUrl = Jenkins.getInstance().getRootUrl();
        if (rootUrl == null) {
            throw new NullPointerException("Jenkins root url should not be null");
        } else {
            return rootUrl + "securityRealm/finishLogin";
        }
    }

    /**
     * This is where the user comes back to at the end of the OpenID redirect ping-pong.
     */
    @SuppressWarnings("unused")
    public HttpResponse doFinishLogin(StaplerRequest request) throws IOException {
        return MattermostSession.getCurrent().doFinishLogin(request);
    }

    @SuppressWarnings("unused")
    @Extension
    public static final class DescriptorImpl extends Descriptor<SecurityRealm> {
        public String getDisplayName() {
            return "Login with Mattermost";
        }

        public FormValidation doCheckClientId(@QueryParameter String clientId) {
            if (clientId == null || clientId.trim().length() == 0) {
                return FormValidation.error("Client id is required.");
            }
            return FormValidation.ok();
        }

        public FormValidation doCheckClientSecret(@QueryParameter String clientSecret) {
            if (clientSecret == null || clientSecret.trim().length() == 0) {
                return FormValidation.error("Client secret is required.");
            }
            return FormValidation.ok();
        }

        public FormValidation doCheckTokenServerUrl(@QueryParameter String mattermostServerUrl) {
            if (mattermostServerUrl == null) {
                return FormValidation.error("Mattermost Server Url Key is required.");
            }
            try {
                new URL(mattermostServerUrl);
                return FormValidation.ok();
            } catch (MalformedURLException e) {
                return FormValidation.error(e, "Not a valid url.");
            }
        }

    }
}
