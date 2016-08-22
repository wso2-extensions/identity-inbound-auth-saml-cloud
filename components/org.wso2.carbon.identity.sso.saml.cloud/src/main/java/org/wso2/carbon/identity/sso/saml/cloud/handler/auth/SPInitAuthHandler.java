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
import org.opensaml.saml2.core.RequestAbstractType;
import org.opensaml.xml.security.x509.X509Credential;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.sso.saml.cloud.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.cloud.builders.signature.DefaultSSOSigner;
import org.wso2.carbon.identity.sso.saml.cloud.context.SAMLMessageContext;
import org.wso2.carbon.identity.sso.saml.cloud.exception.IdentitySAML2SSOException;
import org.wso2.carbon.identity.sso.saml.cloud.request.SAMLSpInitRequest;
import org.wso2.carbon.identity.sso.saml.cloud.response.SAMLErrorResponse;
import org.wso2.carbon.identity.sso.saml.cloud.response.SAMLLoginResponse;
import org.wso2.carbon.identity.sso.saml.cloud.response.SAMLResponse;
import org.wso2.carbon.identity.sso.saml.cloud.util.SAMLSSOUtil;
import org.wso2.carbon.identity.sso.saml.cloud.validators.SAML2HTTPRedirectDeflateSignatureValidator;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class SPInitAuthHandler extends AuthHandler {

    private static Log log = LogFactory.getLog(SPInitAuthHandler.class);

    @Override
    public boolean canHandle(SAMLMessageContext messageContext) {
        if (messageContext.getRequest() instanceof SAMLSpInitRequest) {
            return true;
        }
        return false;
    }

    public SAMLResponse.SAMLResponseBuilder validateAuthnResponseFromFramework(SAMLMessageContext messageContext,
                                                                               AuthenticationResult authnResult,
                                                                               IdentityRequest identityRequest)
            throws IdentityException, IOException {
        AuthnRequest authnReq = messageContext.getAuthnRequest();
        SAMLResponse.SAMLResponseBuilder builder;
        if (authnResult == null || !authnResult.isAuthenticated()) {

            if (log.isDebugEnabled() && authnResult != null) {
                log.debug("Unauthenticated User.");
            }

            if (authnReq.isPassive()) { //if passive

                String destination = authnReq.getAssertionConsumerServiceURL();
                List<String> statusCodes = new ArrayList<String>();
                statusCodes.add(SAMLSSOConstants.StatusCodes.NO_PASSIVE);
                statusCodes.add(SAMLSSOConstants.StatusCodes.IDENTITY_PROVIDER_ERROR);
                String errorResponse = SAMLSSOUtil.buildErrorResponse(messageContext.getId(), statusCodes,
                        "Cannot process response from framework Subject in Passive Mode", destination);
                builder = new SAMLLoginResponse.SAMLLoginResponseBuilder(messageContext);
                ((SAMLLoginResponse.SAMLLoginResponseBuilder) builder).setRelayState(messageContext.getRelayState
                        ());
                ((SAMLLoginResponse.SAMLLoginResponseBuilder) builder).setRespString(errorResponse);
                ((SAMLLoginResponse.SAMLLoginResponseBuilder) builder).setAcsUrl(messageContext
                        .getAssertionConsumerURL());
                ((SAMLLoginResponse.SAMLLoginResponseBuilder) builder).setSubject(messageContext.getSubject());
                ((SAMLLoginResponse.SAMLLoginResponseBuilder) builder).setAuthenticatedIdPs(null);
                ((SAMLLoginResponse.SAMLLoginResponseBuilder) builder).setTenantDomain(messageContext
                        .getTenantDomain());
                return builder;

            } else { // if forceAuthn or normal flow
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
                    ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setAcsUrl(authnReq
                            .getAssertionConsumerServiceURL());
                    return builder;
                } else {
                    throw IdentityException.error("Session data is not found for authenticated user");
                }
            }
        } else {
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
        SAMLSSOServiceProviderDO serviceProviderConfigs = messageContext.getSamlssoServiceProviderDO();
        SAMLResponse.SAMLResponseBuilder builder;
        if (serviceProviderConfigs.isDoValidateSignatureInRequests()) {
            List<String> idpUrlSet = SAMLSSOUtil.getDestinationFromTenantDomain(messageContext.getTenantDomain());

            if (messageContext.getDestination() == null || !idpUrlSet.contains(messageContext.getDestination())) {
                String msg = "Destination validation for Authentication Request failed. " + "Received: [" +
                        messageContext.getDestination() + "]." + " Expected one in the list: [" + StringUtils
                        .join(idpUrlSet, ',') + "]";
                if (log.isDebugEnabled()) {
                    log.debug(msg);
                }
                builder = new SAMLErrorResponse.SAMLErrorResponseBuilder(messageContext);
                ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setErrorResponse(buildErrorResponse
                        (messageContext.getId(), SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR, msg, null));
                return builder;
            }

            // validate the signature
            boolean isSignatureValid = validateAuthnRequestSignature(messageContext);

            if (!isSignatureValid) {
                String msg = "Signature validation for Authentication Request failed.";
                if (log.isDebugEnabled()) {
                    log.debug(msg);
                }
                builder = new SAMLErrorResponse.SAMLErrorResponseBuilder(messageContext);
                ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setErrorResponse(buildErrorResponse
                        (messageContext.getId(), SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR, msg, null));
                return builder;
            }
        } else {
            //Validate the assertion consumer url,  only if request is not signed.
            String acsUrl = messageContext.getAssertionConsumerURL();
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
                        (messageContext.getId(), SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR, msg, acsUrl));
                return builder;
            }
        }

        // if subject is specified in AuthnRequest only that user should be allowed to logged-in
        if (messageContext.getSubject() != null && messageContext.getUser() != null) {
            String authenticatedSubjectIdentifier = messageContext.getUser().getAuthenticatedSubjectIdentifier();
            if (authenticatedSubjectIdentifier != null && !authenticatedSubjectIdentifier.equals(messageContext
                    .getSubject())) {
                String msg = "Provided username does not match with the requested subject";
                if (log.isDebugEnabled()) {
                    log.debug(msg);
                }
                builder = new SAMLErrorResponse.SAMLErrorResponseBuilder(messageContext);
                ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setErrorResponse(buildErrorResponse
                        (messageContext.getId(), SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR, msg,
                                serviceProviderConfigs.getDefaultAssertionConsumerUrl()));
                return builder;
            }
        }
        // TODO persist the session
        if (isAuthenticated) {
            builder = new SAMLLoginResponse.SAMLLoginResponseBuilder(messageContext);
            String respString = ((SAMLLoginResponse.SAMLLoginResponseBuilder) builder).buildResponse();

            if (log.isDebugEnabled()) {
                log.debug("Authentication successfully processed. The SAMLResponse is :" + respString);
            }
            return builder;
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Error processing the authentication request");
            }

            builder = new SAMLErrorResponse.SAMLErrorResponseBuilder(messageContext);
            ((SAMLErrorResponse.SAMLErrorResponseBuilder) builder).setErrorResponse(buildErrorResponse
                    (messageContext.getId(), SAMLSSOConstants.StatusCodes
                            .AUTHN_FAILURE, "Authentication Failure, invalid username or password.", null));
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

    /**
     * Validates the request message's signature. Validates the signature of
     * both HTTP POST Binding and HTTP Redirect Binding.
     *
     * @param messageContext
     * @return
     */
    private boolean validateAuthnRequestSignature(SAMLMessageContext messageContext) {

        if (log.isDebugEnabled()) {
            log.debug("Validating SAML Request signature");
        }

        SAMLSSOServiceProviderDO serviceProvider = messageContext.getSamlssoServiceProviderDO();
        String domainName = messageContext.getTenantDomain();
        if (StringUtils.isBlank(domainName)) {
            domainName = MultitenantConstants.SUPER_TENANT_DOMAIN_NAME;
        }
        String alias = serviceProvider.getCertAlias();
        RequestAbstractType request = null;
        try {
            String decodedReq = null;

            if (messageContext.getRequest().isRedirect()) {
                decodedReq = SAMLSSOUtil.decode(((SAMLSpInitRequest) messageContext.getRequest()).getSamlRequest());
            } else {
                decodedReq = SAMLSSOUtil.decodeForPost(((SAMLSpInitRequest) messageContext.getRequest())
                        .getSamlRequest());
            }
            request = (RequestAbstractType) SAMLSSOUtil.unmarshall(decodedReq);
        } catch (IdentityException e) {
            if (log.isDebugEnabled()) {
                log.debug("Signature Validation failed for the SAMLRequest : Failed to unmarshall the SAML " +
                        "Assertion", e);
            }
        }

        try {
            if (messageContext.getRequest().isRedirect()) {
                // DEFLATE signature in Redirect Binding
                return validateDeflateSignature((SAMLSpInitRequest) messageContext.getRequest(), messageContext
                        .getIssuer(), alias, domainName);
            } else {
                // XML signature in SAML Request message for POST Binding
                return validateXMLSignature(request, alias, domainName);
            }
        } catch (IdentityException e) {
            if (log.isDebugEnabled()) {
                log.debug("Signature Validation failed for the SAMLRequest : Failed to validate the SAML Assertion", e);
            }
            return false;
        }
    }


    /**
     * Signature validation for HTTP Redirect Binding
     * @param request
     * @param issuer
     * @param alias
     * @param domainName
     * @return
     * @throws IdentityException
     */
    private boolean validateDeflateSignature(SAMLSpInitRequest request, String issuer,
                                                   String alias, String domainName) throws IdentityException {
        try {
            return new SAML2HTTPRedirectDeflateSignatureValidator().validateSignature(request, issuer,
                    alias, domainName);

        } catch (org.opensaml.xml.security.SecurityException e) {
            log.error("Error validating deflate signature", e);
            return false;
        } catch (IdentitySAML2SSOException e) {
            log.warn("Signature validation failed for the SAML Message : Failed to construct the X509CredentialImpl for the alias " +
                    alias, e);
            return false;
        }
    }


    /**
     * Validate the signature of an assertion
     *
     * @param request    SAML Assertion, this could be either a SAML Request or a
     *                   LogoutRequest
     * @param alias      Certificate alias against which the signature is validated.
     * @param domainName domain name of the subject
     * @return true, if the signature is valid.
     */
    private boolean validateXMLSignature(RequestAbstractType request, String alias,
                                               String domainName) throws IdentityException {

        if (request.getSignature() != null) {
            try {
                X509Credential cred = SAMLSSOUtil.getX509CredentialImplForTenant(domainName, alias);
                return new DefaultSSOSigner().validateXMLSignature(request, cred, alias);
            } catch (IdentitySAML2SSOException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Signature validation failed for the SAML Message : Failed to construct the " +
                            "X509CredentialImpl for the alias " + alias, e);
                }
            } catch (IdentityException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Signature Validation Failed for the SAML Assertion : Signature is invalid.", e);
                }
            }
        }
        return false;
    }
}
