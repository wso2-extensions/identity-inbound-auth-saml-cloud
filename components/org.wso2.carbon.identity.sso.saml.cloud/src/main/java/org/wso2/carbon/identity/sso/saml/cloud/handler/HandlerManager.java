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

package org.wso2.carbon.identity.sso.saml.cloud.handler;

import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticationResult;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.handler.HandlerComparator;
import org.wso2.carbon.identity.sso.saml.cloud.context.SAMLMessageContext;
import org.wso2.carbon.identity.sso.saml.cloud.exception.SAML2Exception;
import org.wso2.carbon.identity.sso.saml.cloud.exception.SAMLRuntimeException;
import org.wso2.carbon.identity.sso.saml.cloud.handler.auth.AuthHandler;
import org.wso2.carbon.identity.sso.saml.cloud.handler.validator.SAMLValidator;
import org.wso2.carbon.identity.sso.saml.cloud.internal.IdentitySAMLSSOServiceComponentHolder;
import org.wso2.carbon.identity.sso.saml.cloud.response.SAMLResponse;

import java.util.Collections;
import java.util.List;

public class HandlerManager {

    private static volatile HandlerManager instance = new HandlerManager();

    private HandlerManager() {

    }

    public static HandlerManager getInstance() {
        return instance;
    }

    public boolean validateRequest(SAMLMessageContext messageContext) throws FrameworkException {

        List<SAMLValidator> validators = IdentitySAMLSSOServiceComponentHolder.getInstance().getSamlValidators();
        Collections.sort(validators, new HandlerComparator());
        for (SAMLValidator reqvalidator : validators) {
            if (reqvalidator.canHandle(messageContext)) {
                try {
                    return reqvalidator.validateRequest(messageContext);
                } catch (IdentityException e) {
                    throw new SAML2Exception("Authentication Request Validation Failed.", e);
                }
            }
        }
        throw SAMLRuntimeException.error("Cannot find SAML Request validator to validate this request");
    }

    public SAMLResponse.SAMLResponseBuilder getResponse(SAMLMessageContext messageContext, AuthenticationResult
            authnResult, IdentityRequest identityRequest) {
        List<AuthHandler> handlers = IdentitySAMLSSOServiceComponentHolder.getInstance().getAuthHandlers();
        Collections.sort(handlers,new HandlerComparator());
        for(AuthHandler authHandler : handlers){
            if(authHandler.canHandle(messageContext)){
                return authHandler.validateAuthnResponseFromFramework(messageContext, authnResult, identityRequest);
            }
        }
        throw SAMLRuntimeException.error("Cannot find handler to validate the authentication response");
    }
}
