/*
 *  Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 *  WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 *  in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.sso.saml.cloud.processor;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.cache.AuthenticationRequestCacheEntry;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkLoginResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkRuntimeException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundConstants;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundUtil;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationRequest;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.saml.cloud.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.cloud.context.SAMLMessageContext;
import org.wso2.carbon.identity.sso.saml.cloud.exception.SAMLRuntimeException;
import org.wso2.carbon.identity.sso.saml.cloud.response.SAMLCloudFrameworkLogoutResponse;
import org.wso2.carbon.identity.sso.saml.cloud.util.SAMLSSOUtil;
import org.wso2.carbon.registry.core.utils.UUIDGenerator;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import javax.servlet.http.Cookie;

public abstract class AuthnRequestProcessor extends IdentityProcessor {

    private static Log log = LogFactory.getLog(AuthnRequestProcessor.class);

    @Override
    public String getName() {
        return SAMLSSOConstants.SAMLFormFields.SAML_SSO;
    }

    @Override
    public String getCallbackPath(IdentityMessageContext context) {
        return IdentityUtil.getServerURL("identity", false, false);
    }

    @Override
    public String getRelyingPartyId() {
        return null;
    }

    protected FrameworkLoginResponse.FrameworkLoginResponseBuilder buildResponseForFrameworkLogin(
            IdentityMessageContext context) {
        IdentityRequest identityRequest = context.getRequest();
        Map<String, String[]> parameterMap = identityRequest.getParameterMap();

        AuthenticationRequest authenticationRequest = new AuthenticationRequest();
        authenticationRequest.appendRequestQueryParams(parameterMap);
        for (Object entry : identityRequest.getHeaderMap().keySet()) {
            authenticationRequest.addHeader((String) entry, identityRequest.getHeaderMap().get(entry));
        }
        authenticationRequest.setRelyingParty(((SAMLMessageContext) context).getIssuer());
        authenticationRequest.setType(getName());
        authenticationRequest.setPassiveAuth(Boolean.parseBoolean(
                String.valueOf(context.getParameter(InboundConstants.PassiveAuth))));
        authenticationRequest.setForceAuth(Boolean.parseBoolean(
                String.valueOf(context.getParameter(InboundConstants.ForceAuth))));
        authenticationRequest.setTenantDomain(((SAMLMessageContext) context).getTenantDomain());
        try {
            authenticationRequest.setCommonAuthCallerPath(URLEncoder.encode(getCallbackPath(context),
                    StandardCharsets.UTF_8.name()));
        } catch (UnsupportedEncodingException e) {
            throw FrameworkRuntimeException.error("Error occurred while URL encoding callback path " +
                    getCallbackPath(context), e);
        }

        AuthenticationRequestCacheEntry authRequest = new AuthenticationRequestCacheEntry(authenticationRequest);
        String sessionDataKey = UUIDGenerator.generateUUID();
        FrameworkUtils.addAuthenticationRequestToCache(sessionDataKey, authRequest);

        InboundUtil.addContextToCache(sessionDataKey, context);

        FrameworkLoginResponse.FrameworkLoginResponseBuilder responseBuilder =
                new FrameworkLoginResponse.FrameworkLoginResponseBuilder(context);
        responseBuilder.setAuthName(getName());
        responseBuilder.setContextKey(sessionDataKey);
        responseBuilder.setCallbackPath(getCallbackPath(context));
        responseBuilder.setRelyingParty(((SAMLMessageContext) context).getIssuer());
        //type parameter is using since framework checking it, but future it'll use AUTH_NAME
        responseBuilder.setAuthType(getName());
        String commonAuthURL = IdentityUtil.getServerURL(FrameworkConstants.COMMONAUTH, true, true);
        responseBuilder.setRedirectURL(commonAuthURL);
        return responseBuilder;
    }

    protected SAMLCloudFrameworkLogoutResponse.SAMLCloudFrameworkLogoutResponseBuilder buildResponseForCloudLogout(
            IdentityMessageContext context) {
        IdentityRequest identityRequest = context.getRequest();
        Map parameterMap = identityRequest.getParameterMap();
        AuthenticationRequest authenticationRequest = new AuthenticationRequest();
        authenticationRequest.appendRequestQueryParams(parameterMap);
        for (Object entry : identityRequest.getHeaderMap().keySet()) {
            authenticationRequest.addHeader((String) entry, identityRequest.getHeaderMap().get(entry));
        }

        authenticationRequest.setRelyingParty(((SAMLMessageContext) context).getIssuer());
        authenticationRequest.setType(this.getName());

        try {
            authenticationRequest.setCommonAuthCallerPath(URLEncoder.encode(getCallbackPath(context),
                                                                            StandardCharsets.UTF_8.name()));
        } catch (UnsupportedEncodingException e) {
            throw SAMLRuntimeException.error("Error occurred while URL encoding callback path " +
                                                  this.getCallbackPath(context), e);
        }

        authenticationRequest.addRequestQueryParam(FrameworkConstants.RequestParams.LOGOUT,
                                                   new String[]{Boolean.TRUE.toString()});
        AuthenticationRequestCacheEntry authRequest = new AuthenticationRequestCacheEntry(authenticationRequest);
        String sessionId = null;
        Cookie ssoTokenIdCookie = SAMLSSOUtil.getTokenIdCookie(context);
        if (ssoTokenIdCookie != null) {
            sessionId = ssoTokenIdCookie.getValue();
        } else {
            String message = String.format("SSO Token ID cookie cannot be found Tenant Domain : %s, Issuer : %s ",
                                           ((SAMLMessageContext) context).getTenantDomain(),
                                           ((SAMLMessageContext) context).getIssuer());
            log.warn(message);
            throw SAMLRuntimeException.error(message);
        }
        FrameworkUtils.addAuthenticationRequestToCache(sessionId, authRequest);
        InboundUtil.addContextToCache(sessionId, context);
        SAMLCloudFrameworkLogoutResponse.SAMLCloudFrameworkLogoutResponseBuilder
                responseBuilder = new SAMLCloudFrameworkLogoutResponse.SAMLCloudFrameworkLogoutResponseBuilder(context);
        responseBuilder.setAuthName(this.getName());
        responseBuilder.setContextKey(sessionId);
        responseBuilder.setCallbackPath(this.getCallbackPath(context));
        responseBuilder.setRelyingParty(((SAMLMessageContext) context).getIssuer());
        responseBuilder.setAuthType(this.getName());
        String commonAuthURL = IdentityUtil.getServerURL(FrameworkConstants.COMMONAUTH, true, true);
        responseBuilder.setRedirectURL(commonAuthURL);
        return responseBuilder;
    }
}
