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
package org.wso2.carbon.identity.sso.saml.cloud.handler.auth;


import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.saml2.core.Response;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.sso.saml.cloud.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.cloud.context.SAMLMessageContext;
import org.wso2.carbon.identity.sso.saml.cloud.request.SAMLIdpInitRequest;
import org.wso2.carbon.identity.sso.saml.cloud.response.SAMLErrorResponse;
import org.wso2.carbon.identity.sso.saml.cloud.response.SAMLLoginResponse;
import org.wso2.carbon.identity.sso.saml.cloud.response.SAMLResponse;
import org.wso2.carbon.identity.sso.saml.cloud.util.SAMLSSOUtil;
import org.wso2.carbon.registry.core.utils.UUIDGenerator;
import org.wso2.carbon.user.api.UserStoreException;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class IDPInitAuthHandler extends AuthHandler {
    private static Log log = LogFactory.getLog(IDPInitAuthHandler.class);

    @Override
    public boolean canHandle(SAMLMessageContext messageContext) {
        if (messageContext.getRequest() instanceof SAMLIdpInitRequest) {
            return true;
        }
        return false;
    }

    public SAMLResponse.SAMLResponseBuilder validateAuthnResponseFromFramework(SAMLMessageContext messageContext,
                                                                               AuthenticationResult authnResult,
                                                                               IdentityRequest identityRequest)throws IdentityException,IOException{

        SAMLResponse.SAMLResponseBuilder builder;
        if (authnResult == null || !authnResult.isAuthenticated()) {

            if (log.isDebugEnabled() && authnResult != null) {
                log.debug("Unauthenticated User.");
            }

            if (!authnResult.isAuthenticated()) {
                String destination = messageContext.getDestination();
                String errorResp = SAMLSSOUtil.buildErrorResponse(SAMLSSOConstants.StatusCodes.AUTHN_FAILURE,
                        "User authentication failed", destination);
                builder = new SAMLErrorResponse.SAMLErrorResponseBuilder(messageContext);
                ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setErrorResponse(errorResp);
                ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setStatus(SAMLSSOConstants
                        .Notification.EXCEPTION_STATUS);
                ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setMessageLog(SAMLSSOConstants
                        .Notification.EXCEPTION_MESSAGE);
                ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setAcsUrl(((SAMLIdpInitRequest)
                        messageContext.getRequest()).getAcs());
                return builder;
            } else {
                throw IdentityException.error("Session data is not found for authenticated user");
            }

        } else {
            messageContext.setTenantDomain(authnResult.getSubject().getTenantDomain());
            SAMLSSOUtil.setIsSaaSApplication(authnResult.isSaaSApp());
            try {
                SAMLSSOUtil.setUserTenantDomain(authnResult.getSubject().getTenantDomain());
            } catch (UserStoreException e) {
                builder = new SAMLErrorResponse.SAMLErrorResponseBuilder(messageContext);
                return builder;
            } catch (IdentityException e) {
                builder = new SAMLErrorResponse.SAMLErrorResponseBuilder(messageContext);
                return builder;
            }

            String relayState = identityRequest.getParameter(SAMLSSOConstants.RELAY_STATE);
            if (StringUtils.isBlank(relayState)) {
                relayState = messageContext.getRelayState();
            }

            builder = authenticate(messageContext, authnResult.isAuthenticated(), authnResult
                    .getAuthenticatedAuthenticators(), SAMLSSOConstants.AuthnModes.USERNAME_PASSWORD);
            if (builder instanceof SAMLLoginResponse.SAMLLoginResponseBuilder) { // authenticated
                ((SAMLLoginResponse.SAMLLoginResponseBuilder) builder).setRelayState(relayState);
                ((SAMLLoginResponse.SAMLLoginResponseBuilder) builder).setAcsUrl(messageContext
                        .getAssertionConsumerURL());
                ((SAMLLoginResponse.SAMLLoginResponseBuilder) builder).setSubject(messageContext.getUser()
                        .getAuthenticatedSubjectIdentifier());
                ((SAMLLoginResponse.SAMLLoginResponseBuilder) builder).setAuthenticatedIdPs(messageContext
                        .getAuthenticationResult().getAuthenticatedIdPs());
                ((SAMLLoginResponse.SAMLLoginResponseBuilder) builder).setTenantDomain(messageContext
                        .getTenantDomain());
                return builder;
            } else { // authentication FAILURE
                ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setStatus(SAMLSSOConstants
                        .Notification.EXCEPTION_STATUS);
                ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setMessageLog(SAMLSSOConstants
                        .Notification.EXCEPTION_MESSAGE);
                ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setAcsUrl(messageContext
                        .getSamlssoServiceProviderDO().getDefaultAssertionConsumerUrl());
                return builder;
            }

        }
    }

    private SAMLResponse.SAMLResponseBuilder authenticate(SAMLMessageContext messageContext, boolean isAuthenticated,
                                                          String authenticators, String authMode) throws
            IdentityException {

        SAMLSSOServiceProviderDO serviceProviderConfigs = SAMLSSOUtil.getServiceProviderConfig(messageContext);
        messageContext.setSamlssoServiceProviderDO(serviceProviderConfigs);
        SAMLResponse.SAMLResponseBuilder builder;

        if (serviceProviderConfigs == null) {
            String msg = "A Service Provider with the Issuer '" + messageContext.getIssuer() + "' is not " +
                    "registered." + " Service Provider should be registered in advance.";
            if (log.isDebugEnabled()) {
                log.debug(msg);
            }
            builder = new SAMLErrorResponse.SAMLErrorResponseBuilder(messageContext);
            ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setErrorResponse(buildErrorResponse
                    (null, SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR, msg, null));
            return builder;
        }

        if (!serviceProviderConfigs.isIdPInitSSOEnabled()) {
            String msg = "IdP initiated SSO not enabled for service provider '" + messageContext.getIssuer() + "'.";
            if (log.isDebugEnabled()) {
                log.debug(msg);
            }
            builder = new SAMLErrorResponse.SAMLErrorResponseBuilder(messageContext);
            ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setErrorResponse(buildErrorResponse
                    (null, SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR, msg, null));
            return builder;
        }

        if (serviceProviderConfigs.isEnableAttributesByDefault() && serviceProviderConfigs
                .getAttributeConsumingServiceIndex() != null) {
            messageContext.setAttributeConsumingServiceIndex(Integer.parseInt(serviceProviderConfigs
                    .getAttributeConsumingServiceIndex()));
        }


        String acsUrl = StringUtils.isNotBlank(((SAMLIdpInitRequest) messageContext.getRequest()).getAcs()) ? (
                (SAMLIdpInitRequest) messageContext.getRequest()).getAcs() : serviceProviderConfigs
                .getDefaultAssertionConsumerUrl();
        if (StringUtils.isBlank(acsUrl) || !serviceProviderConfigs.getAssertionConsumerUrlList().contains
                (acsUrl)) {
            String msg = "ALERT: Invalid Assertion Consumer URL value '" + acsUrl + "' in the " +
                    "AuthnRequest message from  the issuer '" + serviceProviderConfigs.getIssuer() +
                    "'. Possibly " + "an attempt for a spoofing attack";
            if (log.isDebugEnabled()) {
                log.debug(msg);
            }
            builder = new SAMLErrorResponse.SAMLErrorResponseBuilder(messageContext);
            ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setErrorResponse(buildErrorResponse
                    (null, SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR, msg, acsUrl));
            ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setAcsUrl(acsUrl);
            return builder;
        }
        // TODO : persist the session
        if (isAuthenticated) {
            builder = new SAMLLoginResponse.SAMLLoginResponseBuilder(messageContext);
            String respString = ((SAMLLoginResponse.SAMLLoginResponseBuilder) builder).buildResponse();

            if (log.isDebugEnabled()) {
                log.debug("Authentication successfully processed. The SAMLResponse is :" + respString);
            }
            return builder;
        } else {
            List<String> statusCodes = new ArrayList<String>();
            statusCodes.add(SAMLSSOConstants.StatusCodes.AUTHN_FAILURE);
            statusCodes.add(SAMLSSOConstants.StatusCodes.IDENTITY_PROVIDER_ERROR);
            if (log.isDebugEnabled()) {
                log.debug("Error processing the authentication request.");
            }
            builder = new SAMLErrorResponse.SAMLErrorResponseBuilder(messageContext);
            ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setErrorResponse(SAMLSSOUtil.buildErrorResponse
                    (null, statusCodes, "Authentication Failure, invalid username or password.", null));
            ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setAcsUrl(serviceProviderConfigs.getLoginPageURL());
            return builder;
        }
    }

    /**
     * @param id
     * @param status
     * @param statMsg
     * @return
     * @throws Exception
     */
    private String buildErrorResponse(String id, String status, String statMsg, String destination) throws
            IdentityException {

        List<String> statusCodeList = new ArrayList<String>();
        statusCodeList.add(status);
        return SAMLSSOUtil.buildErrorResponse(id, statusCodeList, statMsg, destination);
    }
}
