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


import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.core.Response;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.core.util.IdentityUtil;
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

public class IDPInitLoginProcessor extends IdentityProcessor {
    private static Log log = LogFactory.getLog(SSOLoginProcessor.class);

    @Override
    public String getName() {
        return "IDPInitLoginProcessor";
    }

    public int getPriority() {
        return 3;
    }

    @Override
    public String getCallbackPath(IdentityMessageContext context) {
        return IdentityUtil.getServerURL("identity", false, false);
    }

    @Override
    public boolean canHandle(IdentityRequest identityRequest) {
        IdentityMessageContext context = getContextIfAvailable(identityRequest);
        if (context != null) {
            if (context.getRequest() instanceof SAMLIdpInitRequest) {
                return true;
            }
        }
        return false;
    }

    @Override
    public SAMLResponse.SAMLResponseBuilder process(IdentityRequest identityRequest) throws FrameworkException {

//        IDPInitMessageContext messageContext = (IDPInitMessageContext) getContextIfAvailable(identityRequest);
//        AuthenticationResult authnResult = processResponseFromFrameworkLogin(messageContext, identityRequest);
//        SAMLResponse.SAMLResponseBuilder builder;
//
//
//        if (authnResult == null || !authnResult.isAuthenticated()) {
//
//            if (log.isDebugEnabled() && authnResult != null) {
//                log.debug("Unauthenticated User.");
//            }
//            String destination = messageContext.getRequest().getAcs();
//            // No Passive option implemented for IDPinit Login
//            try {
//                if (!authnResult.isAuthenticated()) {
//                    String errorResp = SAMLSSOUtil.buildErrorResponse(SAMLSSOConstants.StatusCodes.AUTHN_FAILURE,
//                            "User authentication failed", destination);
//                    builder = new SAMLErrorResponse.SAMLErrorResponseBuilder(messageContext);
//                    ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setErrorResponse(errorResp);
//                    ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setStatus(SAMLSSOConstants
//                            .Notification.EXCEPTION_STATUS);
//                    ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setMessageLog(SAMLSSOConstants
//                            .Notification.EXCEPTION_MESSAGE);
//                    ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setAcsUrl(destination);
//                    return builder;
//                } else {
//                    throw IdentityException.error("Session data is not found for authenticated user");
//                }
//            } catch (IdentityException | IOException e) {
//                //TODO
//                //Handle This exception
//            }
//
//        } else {
//            SAMLSSOUtil.setIsSaaSApplication(authnResult.isSaaSApp());
//            try {
//                SAMLSSOUtil.setUserTenantDomain(authnResult.getSubject().getTenantDomain());
//            } catch (UserStoreException e) {
//                builder = new SAMLErrorResponse.SAMLErrorResponseBuilder(messageContext);
//                return builder;
//            } catch (IdentityException e) {
//                builder = new SAMLErrorResponse.SAMLErrorResponseBuilder(messageContext);
//                return builder;
//            }
//
//            String relayState = identityRequest.getParameter(SAMLSSOConstants.RELAY_STATE);
//            if (StringUtils.isBlank(relayState)) {
//                relayState = messageContext.getRequest().getRelayState();
//            }
//
//
////            if (identityRequest.getParameter(SAMLSSOConstants.RELAY_STATE) != null) {
////                relayState = identityRequest.getParameter(SAMLSSOConstants.RELAY_STATE);
////            } else {
////                relayState = messageContext.getRelayState();
////            }
//
////            startTenantFlow(authnReqDTO.getTenantDomain());
//
////            if (sessionId == null) {
////                sessionId = UUIDGenerator.generateUUID();
////            }
//            try {
//                builder = authenticate(messageContext, authnResult.isAuthenticated(), authnResult
//                        .getAuthenticatedAuthenticators(), SAMLSSOConstants.AuthnModes.USERNAME_PASSWORD);
//                if (builder instanceof SAMLLoginResponse.SAMLLoginResponseBuilder) { // authenticated
////
////                storeTokenIdCookie(sessionId, req, resp, authnReqDTO.getTenantDomain());
////                removeSessionDataFromCache(req.getParameter(SAMLSSOConstants.SESSION_DATA_KEY));
//                    ((SAMLLoginResponse.SAMLLoginResponseBuilder) builder).setRelayState(relayState);
//                    ((SAMLLoginResponse.SAMLLoginResponseBuilder) builder).setAcsUrl(messageContext
//                            .getSamlssoServiceProviderDO().getDefaultAssertionConsumerUrl());
//                    ((SAMLLoginResponse.SAMLLoginResponseBuilder) builder).setSubject(authnResult.getSubject()
//                            .getAuthenticatedSubjectIdentifier());
//                    ((SAMLLoginResponse.SAMLLoginResponseBuilder) builder).setAuthenticatedIdPs(authnResult
//                            .getAuthenticatedIdPs());
//                    ((SAMLLoginResponse.SAMLLoginResponseBuilder) builder).setTenantDomain(messageContext
//                            .getTenantDomain());
//                    return builder;
//                } else { // authentication FAILURE
//                    ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setStatus(SAMLSSOConstants
//                            .Notification.EXCEPTION_STATUS);
//                    ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setMessageLog(SAMLSSOConstants
//                            .Notification.EXCEPTION_MESSAGE);
//                    ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setAcsUrl(messageContext
//                            .getSamlssoServiceProviderDO().getDefaultAssertionConsumerUrl());
//                    return builder;
//                }
//            } catch (IdentityException e) {
//
//            }
//        }
        return null;
    }

    @Override
    public String getRelyingPartyId() {
        return null;
    }

    private SAMLResponse.SAMLResponseBuilder authenticate(SAMLMessageContext messageContext, boolean isAuthenticated, String authenticators, String authMode) throws IdentityException {
        SAMLResponse.SAMLResponseBuilder builder;
//        try {
//            SAMLSSOServiceProviderDO serviceProviderConfigs = SAMLSSOUtil.getServiceProviderConfig(messageContext);
//            if (serviceProviderConfigs == null) {
//                String msg = "A Service Provider with the Issuer '" + messageContext.getIssuer() + "' is not " +
//                        "registered." + " Service Provider should be registered in advance.";
//                if(log.isDebugEnabled()){
//                    log.debug(msg);
//                }
//                builder = new SAMLErrorResponse.SAMLErrorResponseBuilder(messageContext);
//                ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setErrorResponse(buildErrorResponse
//                        (messageContext.getId(), SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR, msg, null));
//                return builder;
//                return buildErrorResponse(authnReqDTO.getId(),
//                        SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR, msg, null);
//            }
//            messageContext.setSamlssoServiceProviderDO(serviceProviderConfigs);
//            if (!serviceProviderConfigs.isIdPInitSSOEnabled()) {
//                String msg = "IdP initiated SSO not enabled for service provider '" + authnReqDTO.getIssuer() + "'.";
//                log.debug(msg);
//                return buildErrorResponse(null,
//                        SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR, msg, null);
//            }
//
//            if (serviceProviderConfigs.isEnableAttributesByDefault() && serviceProviderConfigs
//                    .getAttributeConsumingServiceIndex() != null) {
//                authnReqDTO.setAttributeConsumingServiceIndex(Integer
//                        .parseInt(serviceProviderConfigs
//                                .getAttributeConsumingServiceIndex()));
//            }
//
//            // reading the service provider configs
//            populateServiceProviderConfigs(serviceProviderConfigs, authnReqDTO);
//
//            String acsUrl = authnReqDTO.getAssertionConsumerURL();
//            if (StringUtils.isBlank(acsUrl) || !serviceProviderConfigs.getAssertionConsumerUrlList().contains
//                    (acsUrl)) {
//                String msg = "ALERT: Invalid Assertion Consumer URL value '" + acsUrl + "' in the " +
//                        "AuthnRequest message from  the issuer '" + serviceProviderConfigs.getIssuer() +
//                        "'. Possibly " + "an attempt for a spoofing attack";
//                log.error(msg);
//                return buildErrorResponse(authnReqDTO.getId(),
//                        SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR, msg, acsUrl);
//            }
//
//            // if subject is specified in AuthnRequest only that user should be
//            // allowed to logged-in
//            if (authnReqDTO.getSubject() != null && authnReqDTO.getUser() != null) {
//                String authenticatedSubjectIdentifier =
//                        authnReqDTO.getUser().getAuthenticatedSubjectIdentifier();
//                if (authenticatedSubjectIdentifier != null &&
//                        !authenticatedSubjectIdentifier.equals(authnReqDTO.getSubject())) {
//                    String msg = "Provided username does not match with the requested subject";
//                    log.warn(msg);
//
//                    List<String> statusCodes = new ArrayList<>();
//                    statusCodes.add(SAMLSSOConstants.StatusCodes.AUTHN_FAILURE);
//                    statusCodes.add(SAMLSSOConstants.StatusCodes.IDENTITY_PROVIDER_ERROR);
//
//                    return buildErrorResponse(authnReqDTO.getId(),
//                            statusCodes, msg, authnReqDTO.getAssertionConsumerURL());
//                }
//            }
//
//            // persist the session
//            SSOSessionPersistenceManager sessionPersistenceManager = SSOSessionPersistenceManager
//                    .getPersistenceManager();
//
//            SAMLSSORespDTO samlssoRespDTO = null;
//            String sessionIndexId = null;
//
//            if (isAuthenticated) {
//                if (sessionId != null && sessionPersistenceManager.isExistingTokenId(sessionId)) {
//                    sessionIndexId = sessionPersistenceManager.getSessionIndexFromTokenId(sessionId);
//                } else {
//                    sessionIndexId = UUIDGenerator.generateUUID();
//                    sessionPersistenceManager.persistSession(sessionId, sessionIndexId);
//                }
//
//                if (authMode.equals(SAMLSSOConstants.AuthnModes.USERNAME_PASSWORD)) {
//                    SAMLSSOServiceProviderDO spDO = new SAMLSSOServiceProviderDO();
//                    spDO.setIssuer(authnReqDTO.getIssuer());
//                    spDO.setAssertionConsumerUrl(authnReqDTO.getAssertionConsumerURL());
//                    spDO.setCertAlias(authnReqDTO.getCertAlias());
//                    spDO.setSloResponseURL(authnReqDTO.getSloResponseURL());
//                    spDO.setSloRequestURL(authnReqDTO.getSloRequestURL());
//                    spDO.setTenantDomain(authnReqDTO.getTenantDomain());
//                    spDO.setDoSingleLogout(authnReqDTO.isDoSingleLogout());
//                    spDO.setIdPInitSLOEnabled(authnReqDTO.isIdPInitSLOEnabled());
//                    spDO.setAssertionConsumerUrls(authnReqDTO.getAssertionConsumerURLs());
//                    spDO.setIdpInitSLOReturnToURLs(authnReqDTO.getIdpInitSLOReturnToURLs());
//                    spDO.setSigningAlgorithmUri(authnReqDTO.getSigningAlgorithmUri());
//                    spDO.setDigestAlgorithmUri(authnReqDTO.getDigestAlgorithmUri());
//                    sessionPersistenceManager.persistSession(sessionIndexId,
//                            authnReqDTO.getUser().getAuthenticatedSubjectIdentifier(), spDO,
//                            authnReqDTO.getRpSessionId(), authnReqDTO.getIssuer(),
//                            authnReqDTO.getAssertionConsumerURL());
//                }
//
//                // Build the response for the successful scenario
//                ResponseBuilder respBuilder = SAMLSSOUtil.getResponseBuilder();
//                Response response = respBuilder.buildResponse(authnReqDTO, sessionIndexId);
//                samlssoRespDTO = new SAMLSSORespDTO();
//                String samlResp = SAMLSSOUtil.marshall(response);
//
//                if (log.isDebugEnabled()) {
//                    log.debug(samlResp);
//                }
//
//                samlssoRespDTO.setRespString(SAMLSSOUtil.encode(samlResp));
//                samlssoRespDTO.setSessionEstablished(true);
//                samlssoRespDTO.setAssertionConsumerURL(authnReqDTO.getAssertionConsumerURL());
//                samlssoRespDTO.setLoginPageURL(authnReqDTO.getLoginPageURL());
//                samlssoRespDTO.setSubject(authnReqDTO.getUser());
//            }
//
//            if (samlssoRespDTO.getRespString() != null) {
//                if (log.isDebugEnabled()) {
//                    log.debug(samlssoRespDTO.getRespString());
//                }
//            }
//            return samlssoRespDTO;
//        } catch (Exception e) {
//            log.error("Error processing the authentication request", e);
//            builder = new SAMLErrorResponse.SAMLErrorResponseBuilder(messageContext);
//            ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setErrorResponse(buildErrorResponse
//                    (messageContext.getId(), SAMLSSOConstants.StatusCodes
//                            .AUTHN_FAILURE, "Authentication Failure, invalid username or password.", null));
//            return builder;
//        }
        return null;
    }
}
