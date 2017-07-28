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

package org.wso2.carbon.identity.sso.saml.cloud.response;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.common.SAMLVersion;
import org.opensaml.saml2.core.LogoutResponse;
import org.opensaml.saml2.core.Status;
import org.opensaml.saml2.core.StatusCode;
import org.opensaml.saml2.core.StatusMessage;
import org.opensaml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml2.core.impl.StatusMessageBuilder;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.sso.saml.cloud.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.cloud.context.SAMLMessageContext;
import org.wso2.carbon.identity.sso.saml.cloud.util.SAMLSSOUtil;

public class SAMLLogoutResponse extends SAMLResponse {

    private String respString;
    private String relayState;
    private String acsUrl;
    private String subject;
    private String authenticatedIdPs;
    private String tenantDomain;

    protected SAMLLogoutResponse(IdentityResponseBuilder builder) {
        super(builder);
        this.respString = ((SAMLLogoutResponseBuilder) builder).respString;
        this.relayState = ((SAMLLogoutResponseBuilder) builder).relayState;
        this.acsUrl = ((SAMLLogoutResponseBuilder) builder).acsUrl;
        this.authenticatedIdPs = ((SAMLLogoutResponseBuilder) builder).authenticatedIdPs;
        this.tenantDomain = ((SAMLLogoutResponseBuilder) builder).tenantDomain;
        this.subject = ((SAMLLogoutResponseBuilder) builder).subject;
    }

    public String getRespString() {
        return respString;
    }

    public String getSubject() {
        return subject;
    }

    public String getRelayState() {
        return relayState;
    }

    public String getAcsUrl() {
        return acsUrl;
    }

    public String getAuthenticatedIdPs() {
        return authenticatedIdPs;
    }

    public String getTenantDomain() {
        return tenantDomain;
    }

    public SAMLMessageContext getContext(){
        return (SAMLMessageContext)this.context;
    }

    public static class SAMLLogoutResponseBuilder extends SAMLResponseBuilder {

        private static Log log = LogFactory.getLog(SAMLLogoutResponseBuilder.class);

        private String respString;
        private String relayState;
        private String acsUrl;
        private String subject;
        private String authenticatedIdPs;
        private String tenantDomain;

        public SAMLLogoutResponseBuilder(IdentityMessageContext context) {
            super(context);
        }

        public SAMLLogoutResponse build(){
            return new SAMLLogoutResponse(this);
        }

        public String buildResponse() throws IdentityException {
            SAMLMessageContext messageContext = (SAMLMessageContext)this.context;
            SAMLSSOServiceProviderDO serviceProviderDO = messageContext.getSamlssoServiceProviderDO();
            if (log.isDebugEnabled()) {
                log.debug("Building SAML Response for the consumer '" + messageContext.getAssertionConsumerURL() + "'");
            }
            LogoutResponse response = new org.opensaml.saml2.core.impl.LogoutResponseBuilder().buildObject();
            response.setIssuer(SAMLSSOUtil.getIssuer());
            response.setID(SAMLSSOUtil.createID());
            if (!messageContext.isIdpInitSSO()) {
                response.setInResponseTo(messageContext.getId());
            }
            response.setDestination(messageContext.getAssertionConsumerURL());
            response.setStatus(buildStatus(SAMLSSOConstants.StatusCodes.SUCCESS_CODE, null));
            response.setVersion(SAMLVersion.VERSION_20);

//            if (serviceProviderDO.isDoSignResponse()) {
//                SAMLSSOUtil.setSignature(response, serviceProviderDO.getSigningAlgorithmUri(), serviceProviderDO
//                        .getDigestAlgorithmUri(), new SignKeyDataHolder(messageContext.getAuthenticationResult()
//                        .getSubject().getAuthenticatedSubjectIdentifier()));
//            }
            this.setResponse(response);
            String respString = SAMLSSOUtil.encode(SAMLSSOUtil.marshall(response));
            this.setRespString(respString);
            return respString;
        }

        public SAMLLogoutResponseBuilder setRespString(String respString) {
            this.respString = respString;
            return this;
        }

        public SAMLLogoutResponseBuilder setSubject(String subject) {
            this.subject = subject;
            return this;
        }

        public SAMLLogoutResponseBuilder setRelayState(String relayState) {
            this.relayState = relayState;
            return this;
        }

        public SAMLLogoutResponseBuilder setAcsUrl(String acsUrl) {
            this.acsUrl = acsUrl;
            return this;
        }

        public SAMLLogoutResponseBuilder setAuthenticatedIdPs(String authenticatedIdPs) {
            this.authenticatedIdPs = authenticatedIdPs;
            return this;
        }

        public SAMLLogoutResponseBuilder setTenantDomain(String tenantDomain) {
            this.tenantDomain = tenantDomain;
            return this;
        }

        private Status buildStatus(String status, String statMsg) {

            Status stat = new StatusBuilder().buildObject();

            // Set the status code
            StatusCode statCode = new StatusCodeBuilder().buildObject();
            statCode.setValue(status);
            stat.setStatusCode(statCode);

            // Set the status Message
            if (statMsg != null) {
                StatusMessage statMesssage = new StatusMessageBuilder().buildObject();
                statMesssage.setMessage(statMsg);
                stat.setStatusMessage(statMesssage);
            }

            return stat;
        }
    }
}
