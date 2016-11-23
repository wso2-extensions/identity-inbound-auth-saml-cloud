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
package org.wso2.carbon.identity.sso.saml.cloud.handler.validator;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.core.AuthnRequest;
import org.opensaml.xml.XMLObject;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.sso.saml.cloud.context.SAMLMessageContext;
import org.wso2.carbon.identity.sso.saml.cloud.request.SAMLSpInitRequest;
import org.wso2.carbon.identity.sso.saml.cloud.util.SAMLSSOUtil;
import org.wso2.carbon.identity.sso.saml.cloud.validators.SPInitSSOAuthnRequestValidator;
import org.wso2.carbon.identity.sso.saml.cloud.validators.SSOAuthnRequestValidator;
import org.wso2.carbon.user.api.UserStoreException;

import java.io.IOException;

public class SPInitSAMLValidator extends SAMLValidator {

    private static final Log log = LogFactory.getLog(SPInitSAMLValidator.class);

    @Override
    public boolean canHandle(SAMLMessageContext messageContext) {
        if (messageContext.getRequest() instanceof SAMLSpInitRequest) {
            return true;
        }
        return false;
    }

    public boolean validateRequest(SAMLMessageContext messageContext) throws IdentityException, IOException {
        SAMLSpInitRequest identityRequest = (SAMLSpInitRequest)messageContext.getRequest();
        String decodedRequest;
        if (identityRequest.isRedirect()) {
            decodedRequest = SAMLSSOUtil.decode(identityRequest.getSamlRequest());
        } else {
            decodedRequest = SAMLSSOUtil.decodeForPost(identityRequest.getSamlRequest());
        }
        XMLObject request = SAMLSSOUtil.unmarshall(decodedRequest);
        if (request instanceof AuthnRequest) {
            messageContext.setDestination(((AuthnRequest) request).getDestination());
            messageContext.setId(((AuthnRequest) request).getID());
            messageContext.setAssertionConsumerUrl(((AuthnRequest) request).getAssertionConsumerServiceURL());
            messageContext.setIsPassive(((AuthnRequest) request).isPassive());
            messageContext.setTenantDomain(messageContext.getRequest().getTenantDomain());
            try {
                SAMLSSOUtil.setTenantDomainInThreadLocal(messageContext.getRequest().getTenantDomain());
            } catch (UserStoreException e) {
                log.error("Error occurred while setting tenant domain to thread local.");
            }
            SSOAuthnRequestValidator reqValidator = new SPInitSSOAuthnRequestValidator(messageContext);
            return reqValidator.validate((AuthnRequest)request);
        }
        return false;
    }
}
