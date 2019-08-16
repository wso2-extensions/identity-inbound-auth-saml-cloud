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
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkLoginResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.sso.saml.cloud.context.SAMLMessageContext;
import org.wso2.carbon.identity.sso.saml.cloud.handler.HandlerManager;
import org.wso2.carbon.identity.sso.saml.cloud.request.SAMLIdpInitRequest;

import java.util.HashMap;

public class IDPInitAuthnRequestProcessor extends AuthnRequestProcessor {

    private static final Log log = LogFactory.getLog(IDPInitAuthnRequestProcessor.class);

    @Override
    public int getPriority() {
        return 4;
    }

    @Override
    public boolean canHandle(IdentityRequest identityRequest) {
        if (identityRequest instanceof SAMLIdpInitRequest) {
            return true;
        }
        return false;
    }

    @Override
    public FrameworkLoginResponse.FrameworkLoginResponseBuilder process(IdentityRequest identityRequest) throws
            FrameworkException {
        SAMLMessageContext messageContext = new SAMLMessageContext((SAMLIdpInitRequest) identityRequest, new
                HashMap<String, String>());
        HandlerManager.getInstance().validateRequest(messageContext);
        return buildResponseForFrameworkLogin(messageContext);
    }
}
