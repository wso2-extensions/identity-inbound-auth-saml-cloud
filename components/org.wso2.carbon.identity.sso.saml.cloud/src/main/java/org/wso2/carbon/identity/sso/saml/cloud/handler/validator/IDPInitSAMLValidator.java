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


import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.sso.saml.cloud.context.SAMLMessageContext;
import org.wso2.carbon.identity.sso.saml.cloud.request.SAMLIdpInitRequest;
import org.wso2.carbon.identity.sso.saml.cloud.request.SAMLSpInitRequest;
import org.wso2.carbon.identity.sso.saml.cloud.util.SAMLSSOUtil;
import org.wso2.carbon.identity.sso.saml.cloud.validators.IdPInitSSOAuthnRequestValidator;
import org.wso2.carbon.identity.sso.saml.cloud.validators.SSOAuthnRequestValidator;

import java.io.IOException;

public class IDPInitSAMLValidator extends SAMLValidator {

    @Override
    public boolean canHandle(SAMLMessageContext messageContext) {
        if (messageContext.getRequest() instanceof SAMLIdpInitRequest) {
            return true;
        }
        return false;
    }

    public boolean validateRequest(SAMLMessageContext messageContext) throws IdentityException, IOException {
        if(!((SAMLIdpInitRequest)messageContext.getRequest()).isLogout()){
            messageContext.setTenantDomain(SAMLSSOUtil.getTenantDomainFromThreadLocal());
            return new IdPInitSSOAuthnRequestValidator(messageContext).validate();
        }
        return false;
    }
}
