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

package org.wso2.carbon.identity.sso.saml.cloud.builders.assertion;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml1.core.NameIdentifier;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.saml2.core.AttributeValue;
import org.opensaml.saml2.core.Audience;
import org.opensaml.saml2.core.AudienceRestriction;
import org.opensaml.saml2.core.AuthnContext;
import org.opensaml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml2.core.AuthnStatement;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.NameID;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmation;
import org.opensaml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml2.core.impl.AssertionBuilder;
import org.opensaml.saml2.core.impl.AttributeBuilder;
import org.opensaml.saml2.core.impl.AttributeStatementBuilder;
import org.opensaml.saml2.core.impl.AudienceBuilder;
import org.opensaml.saml2.core.impl.AudienceRestrictionBuilder;
import org.opensaml.saml2.core.impl.AuthnContextBuilder;
import org.opensaml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml2.core.impl.AuthnStatementBuilder;
import org.opensaml.saml2.core.impl.ConditionsBuilder;
import org.opensaml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml2.core.impl.SubjectBuilder;
import org.opensaml.saml2.core.impl.SubjectConfirmationBuilder;
import org.opensaml.saml2.core.impl.SubjectConfirmationDataBuilder;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSStringBuilder;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.core.util.IdentityCoreConstants;
import org.wso2.carbon.identity.sso.saml.SAMLSSOService;
import org.wso2.carbon.identity.sso.saml.cache.SessionDataCache;
import org.wso2.carbon.identity.sso.saml.cache.SessionDataCacheEntry;
import org.wso2.carbon.identity.sso.saml.cache.SessionDataCacheKey;
import org.wso2.carbon.identity.sso.saml.cloud.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.cloud.builders.SignKeyDataHolder;
import org.wso2.carbon.identity.sso.saml.cloud.util.SAMLSSOUtil;
import org.wso2.carbon.identity.sso.saml.cloud.context.SAMLMessageContext;
import org.wso2.carbon.identity.sso.saml.dto.QueryParamDTO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOReqValidationResponseDTO;
import org.wso2.carbon.identity.sso.saml.dto.SAMLSSOSessionDTO;
import org.wso2.carbon.identity.sso.saml.session.SSOSessionPersistenceManager;
import org.wso2.carbon.registry.core.utils.UUIDGenerator;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.StringTokenizer;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

import static org.wso2.carbon.identity.sso.saml.cloud.util.SAMLSSOUtil.getTokenIdCookie;

public class DefaultSAMLAssertionBuilder implements SAMLAssertionBuilder {

    private static Log log = LogFactory.getLog(DefaultSAMLAssertionBuilder.class);

    private String userAttributeSeparator = IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR_DEFAULT;

    @Override
    public void init() throws IdentityException {
        //Overridden method, no need to implement the body
    }

    @Override
    public Assertion buildAssertion(SAMLMessageContext context, DateTime notOnOrAfter, String sessionId) throws
            IdentityException {

        try {
            AuthenticationResult authnResult = context.getAuthenticationResult();
            DateTime currentTime = new DateTime();
            Assertion samlAssertion = new AssertionBuilder().buildObject();
            SAMLSSOServiceProviderDO samlssoServiceProviderDO = context.getSamlssoServiceProviderDO();
            samlAssertion.setID(SAMLSSOUtil.createID());
            samlAssertion.setVersion(SAMLVersion.VERSION_20);
            samlAssertion.setIssuer(SAMLSSOUtil.getIssuer());
            samlAssertion.setIssueInstant(currentTime);
            Subject subject = new SubjectBuilder().buildObject();

            NameID nameId = new NameIDBuilder().buildObject();

            nameId.setValue(authnResult.getSubject().getAuthenticatedSubjectIdentifier());
            if (samlssoServiceProviderDO.getNameIDFormat() != null) {
                nameId.setFormat(samlssoServiceProviderDO.getNameIDFormat());
            } else {
                nameId.setFormat(NameIdentifier.EMAIL);
            }

            subject.setNameID(nameId);

            SubjectConfirmation subjectConfirmation = new SubjectConfirmationBuilder()
                    .buildObject();
            subjectConfirmation.setMethod(SAMLSSOConstants.SUBJECT_CONFIRM_BEARER);
            SubjectConfirmationData scData = new SubjectConfirmationDataBuilder().buildObject();
            scData.setRecipient(context.getAssertionConsumerURL());
            scData.setNotOnOrAfter(notOnOrAfter);
            if (!context.isIdpInitSSO()) {
                scData.setInResponseTo(context.getId());
            }
            subjectConfirmation.setSubjectConfirmationData(scData);
            subject.getSubjectConfirmations().add(subjectConfirmation);

            if (samlssoServiceProviderDO.getRequestedRecipients() != null && samlssoServiceProviderDO
                    .getRequestedRecipients().length > 0) {
                for (String recipient : samlssoServiceProviderDO.getRequestedRecipients()) {
                    subjectConfirmation = new SubjectConfirmationBuilder()
                            .buildObject();
                    subjectConfirmation.setMethod(SAMLSSOConstants.SUBJECT_CONFIRM_BEARER);
                    scData = new SubjectConfirmationDataBuilder().buildObject();
                    scData.setRecipient(recipient);
                    scData.setNotOnOrAfter(notOnOrAfter);
                    if (!context.isIdpInitSSO()) {
                        scData.setInResponseTo(context.getId());
                    }
                    subjectConfirmation.setSubjectConfirmationData(scData);
                    subject.getSubjectConfirmations().add(subjectConfirmation);
                }
            }

            samlAssertion.setSubject(subject);

            AuthnStatement authStmt = new AuthnStatementBuilder().buildObject();
            authStmt.setAuthnInstant(new DateTime());

            AuthnContext authContext = new AuthnContextBuilder().buildObject();
            AuthnContextClassRef authCtxClassRef = new AuthnContextClassRefBuilder().buildObject();
            authCtxClassRef.setAuthnContextClassRef(AuthnContext.PASSWORD_AUTHN_CTX);
            authContext.setAuthnContextClassRef(authCtxClassRef);
            authStmt.setAuthnContext(authContext);

            SSOSessionPersistenceManager sessionPersistenceManager =
                    SSOSessionPersistenceManager.getPersistenceManager();
            String sessionIndexId;

            Cookie ssoTokenIdCookie = getTokenIdCookie(context);
            if (ssoTokenIdCookie != null) {
                sessionId = ssoTokenIdCookie.getValue();
            }
            if (sessionId == null) {
                sessionId = UUIDGenerator.generateUUID();
            }
            if (sessionId != null && sessionPersistenceManager.isExistingTokenId(sessionId)) {
                sessionIndexId = sessionPersistenceManager.getSessionIndexFromTokenId(sessionId);
            } else {
                sessionIndexId = UUIDGenerator.generateUUID();
                sessionPersistenceManager.persistSession(sessionId, sessionIndexId);
            }
            if (samlssoServiceProviderDO.isDoSingleLogout()) {
                authStmt.setSessionIndex(sessionId);
                addSessionToCache(context, sessionId);
                sessionPersistenceManager.persistSession(sessionIndexId,
                                                         context.getAuthenticationResult().getSubject()
                                                                .getAuthenticatedSubjectIdentifier(),
                                                         context.getSamlssoServiceProviderDO(),
                                                         context.getRpSessionId(), context.getIssuer(),
                                                         context.getAssertionConsumerURL());
            }
            samlAssertion.getAuthnStatements().add(authStmt);

            /*
                * If <AttributeConsumingServiceIndex> element is in the <AuthnRequest> and according to
                * the spec 2.0 the subject MUST be in the assertion
                */
            Map<String, String> claims = SAMLSSOUtil.getAttributes(context);
            if (claims != null && !claims.isEmpty()) {
                AttributeStatement attrStmt = buildAttributeStatement(claims);
                if (attrStmt != null) {
                    samlAssertion.getAttributeStatements().add(attrStmt);
                }
            }

            AudienceRestriction audienceRestriction = new AudienceRestrictionBuilder()
                    .buildObject();
            Audience issuerAudience = new AudienceBuilder().buildObject();
            issuerAudience.setAudienceURI(context.getIssuerWithDomain());
            audienceRestriction.getAudiences().add(issuerAudience);
            if (samlssoServiceProviderDO.getRequestedAudiences() != null) {
                for (String requestedAudience : samlssoServiceProviderDO.getRequestedAudiences()) {
                    Audience audience = new AudienceBuilder().buildObject();
                    audience.setAudienceURI(requestedAudience);
                    audienceRestriction.getAudiences().add(audience);
                }
            }
            Conditions conditions = new ConditionsBuilder().buildObject();
            conditions.setNotBefore(currentTime);
            conditions.setNotOnOrAfter(notOnOrAfter);
            conditions.getAudienceRestrictions().add(audienceRestriction);
            samlAssertion.setConditions(conditions);

            if (samlssoServiceProviderDO.isDoSignAssertions()) {
                SAMLSSOUtil.setSignature(samlAssertion, samlssoServiceProviderDO.getSigningAlgorithmUri(),
                        samlssoServiceProviderDO.getDigestAlgorithmUri(), new SignKeyDataHolder(context
                                .getAuthenticationResult().getSubject().getAuthenticatedSubjectIdentifier()));
            }

            return samlAssertion;
        } catch (Exception e) {
            log.error("Error when reading claim values for generating SAML Response", e);
            throw IdentityException.error(
                    "Error when reading claim values for generating SAML Response", e);
        }
    }

    private void addSessionToCache(SAMLMessageContext context, String sessionId) throws IdentityException {
        SessionDataCacheKey cacheKey = new SessionDataCacheKey(sessionId);
        SessionDataCacheEntry cacheEntry = new SessionDataCacheEntry();
        SAMLSSOSessionDTO sessionDTO = createSamlssoSessionDTO(context, sessionId);
        cacheEntry.setSessionDTO(sessionDTO);
        SessionDataCache.getInstance().addToCache(cacheKey, cacheEntry);
    }

    private SAMLSSOSessionDTO createSamlssoSessionDTO(SAMLMessageContext context, String sessionId)
            throws IdentityException {
        SAMLSSOSessionDTO sessionDTO = new SAMLSSOSessionDTO();
        sessionDTO.setHttpQueryString(context.getRequest().getQueryString());
        sessionDTO.setRelayState(context.getRelayState());
        sessionDTO.setSessionId(sessionId);
        sessionDTO.setLogoutReq(true);
        sessionDTO.setInvalidLogout(false);
        sessionDTO.setDestination(context.getDestination());
        sessionDTO.setIssuer(context.getIssuer());
        sessionDTO.setRequestID(context.getId());
        sessionDTO.setSubject(context.getSubject());
        sessionDTO.setRelyingPartySessionId(context.getRpSessionId());
        sessionDTO.setAssertionConsumerURL(context.getAssertionConsumerURL());
        sessionDTO.setTenantDomain(context.getTenantDomain());
        SAMLSSOService samlSSOService = new SAMLSSOService();
        String slo = context.getRequest().getParameter(SAMLSSOConstants.QueryParameter.SLO.toString());
        SAMLSSOReqValidationResponseDTO signInRespDTO;
        if (context.isIdpInitSSO()) {
            signInRespDTO = samlSSOService.validateIdPInitSSORequest(
                    context.getRelayState(), context.getRequest().getQueryString(),
                    getQueryParams(context.getRequest()), SAMLSSOUtil.getDefaultLogoutEndpoint(), sessionId,
                    context.getRpSessionId(), context.getRequest().getParameter(SAMLSSOConstants.AUTH_MODE),
                    (slo != null));
        } else {
            String samlRequest = context.getRequest().getParameter(SAMLSSOConstants.SAML_REQUEST);
            signInRespDTO = samlSSOService.validateSPInitSSORequest(
                    samlRequest, context.getRequest().getQueryString(), sessionId, context.getRpSessionId(),
                    context.getRequest().getParameter(SAMLSSOConstants.AUTH_MODE), false);
        }
        sessionDTO.setValidationRespDTO(signInRespDTO);
        sessionDTO.setRequestMessageString(signInRespDTO.getRequestMessageString());
        sessionDTO.setPassiveAuth(context.isPassive());
        sessionDTO.setIdPInitSSO(context.isIdpInitSSO());
        sessionDTO.setAttributeConsumingServiceIndex(context.getAttributeConsumingServiceIndex());
        sessionDTO.setForceAuth(signInRespDTO.isForceAuthn());
        return sessionDTO;
    }

    private AttributeStatement buildAttributeStatement(Map<String, String> claims) {

        String claimSeparator = claims.get(IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR);
        if (StringUtils.isNotBlank(claimSeparator)) {
            userAttributeSeparator = claimSeparator;
        }
        claims.remove(IdentityCoreConstants.MULTI_ATTRIBUTE_SEPARATOR);

        AttributeStatement attStmt = new AttributeStatementBuilder().buildObject();
        Iterator<Map.Entry<String, String>> iterator = claims.entrySet().iterator();
        boolean atLeastOneNotEmpty = false;
        for (int i = 0; i < claims.size(); i++) {
            Map.Entry<String, String> claimEntry = iterator.next();
            String claimUri = claimEntry.getKey();
            String claimValue = claimEntry.getValue();
            if (claimUri != null && !claimUri.trim().isEmpty() && claimValue != null && !claimValue.trim().isEmpty()) {
                atLeastOneNotEmpty = true;
                Attribute attribute = new AttributeBuilder().buildObject();
                attribute.setName(claimUri);
                //setting NAMEFORMAT attribute value to basic attribute profile
                attribute.setNameFormat(SAMLSSOConstants.NAME_FORMAT_BASIC);
                // look
                // https://wiki.shibboleth.net/confluence/display/OpenSAML/OSTwoUsrManJavaAnyTypes
                XSStringBuilder stringBuilder = (XSStringBuilder) Configuration.getBuilderFactory().
                        getBuilder(XSString.TYPE_NAME);
                XSString stringValue;

                //Need to check if the claim has multiple values
                if (userAttributeSeparator != null && claimValue.contains(userAttributeSeparator)) {
                    StringTokenizer st = new StringTokenizer(claimValue, userAttributeSeparator);
                    while (st.hasMoreElements()) {
                        String attValue = st.nextElement().toString();
                        if (attValue != null && attValue.trim().length() > 0) {
                            stringValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString
                                    .TYPE_NAME);
                            stringValue.setValue(attValue);
                            attribute.getAttributeValues().add(stringValue);
                        }
                    }
                } else {
                    stringValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
                    stringValue.setValue(claimValue);
                    attribute.getAttributeValues().add(stringValue);
                }

                attStmt.getAttributes().add(attribute);
            }
        }
        if (atLeastOneNotEmpty) {
            return attStmt;
        } else {
            return null;
        }
    }

    private QueryParamDTO[] getQueryParams(IdentityRequest request) {

        List<QueryParamDTO> queryParamDTOs =  new ArrayList<>();
        for(SAMLSSOConstants.QueryParameter queryParameter : SAMLSSOConstants.QueryParameter.values()) {
            queryParamDTOs.add(new QueryParamDTO(queryParameter.toString(),
                                                 request.getParameter(queryParameter.toString())));
        }

        return queryParamDTOs.toArray(new QueryParamDTO[queryParamDTOs.size()]);
    }
}
