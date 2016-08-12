/*
 * Copyright (c) 2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 *  Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.wso2.carbon.identity.sso.saml.cloud.validators;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.sso.saml.cloud.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.cloud.context.SAMLMessageContext;
import org.wso2.carbon.identity.sso.saml.cloud.exception.SAML2ClientException;
import org.wso2.carbon.identity.sso.saml.cloud.request.SAMLIdpInitRequest;
import org.wso2.carbon.identity.sso.saml.cloud.util.SAMLSSOUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantConstants;


public class IdPInitSSOAuthnRequestValidator implements SSOAuthnRequestValidator{

    private static Log log = LogFactory.getLog(IdPInitSSOAuthnRequestValidator.class);

    private SAMLMessageContext messageContext;
    private String spEntityID;


    public IdPInitSSOAuthnRequestValidator(SAMLMessageContext messageContext) throws IdentityException {
        this.messageContext = messageContext;
        this.spEntityID = ((SAMLIdpInitRequest)messageContext.getRequest()).getSpEntityID();
    }

    /**
     * Validates the authentication request according to IdP Initiated SAML SSO Web Browser Specification
     *
     * @return SAMLSSOSignInResponseDTO
     * @throws org.wso2.carbon.identity.base.IdentityException
     */
    public boolean validate() throws IdentityException {

        try {

            // spEntityID MUST NOT be null
            if (StringUtils.isNotBlank(spEntityID)) {
                this.messageContext.setIssuer(spEntityID);
            } else {
                if(log.isDebugEnabled()) {
                    log.debug("spEntityID parameter not found in request");
                }
                messageContext.setValid(false);
                throw SAML2ClientException.error(SAMLSSOUtil.buildErrorResponse(SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR,
                        "spEntityID parameter not found in request", null));
            }

            if (!SAMLSSOUtil.isSAMLIssuerExists(spEntityID, SAMLSSOUtil.getTenantDomainFromThreadLocal())) {
                String message = "A Service Provider with the Issuer '" + spEntityID + "' is not registered. Service " +
                                 "Provider should be registered in advance";
                String errorResp = SAMLSSOUtil.buildErrorResponse(SAMLSSOConstants.StatusCodes.REQUESTOR_ERROR,
                                                                  message, null);
                if (log.isDebugEnabled()) {
                    log.debug(message);
                }
                messageContext.setValid(false);
                throw SAML2ClientException.error(SAMLSSOUtil.buildErrorResponse(SAMLSSOConstants.StatusCodes
                        .REQUESTOR_ERROR, message, null));
            }

            if (StringUtils.isBlank(SAMLSSOUtil.getTenantDomainFromThreadLocal())) {
                SAMLSSOUtil.setTenantDomainInThreadLocal(MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
            }

            messageContext.setValid(true);

            if (log.isDebugEnabled()) {
                log.debug("IdP Initiated SSO request validation is successful");
            }
            return true;
        } catch (Exception e) {
            throw IdentityException.error("Error validating the IdP Initiated SSO request", e);
        }
    }

}
