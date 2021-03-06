/*
* Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
* http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
*/
package org.wso2.carbon.identity.sso.saml.cloud.response;

import org.wso2.carbon.identity.application.authentication.framework.inbound.FrameworkLogoutResponseFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;
import org.wso2.carbon.identity.application.authentication.framework.inbound.InboundConstants;

import javax.servlet.http.HttpServletResponse;

/**
 * Framework logout response factory implementation for Identity Cloud logout.
 */
public class SAMLCloudFrameworkLogoutResponseFactory extends FrameworkLogoutResponseFactory {

    @Override
    public boolean canHandle(IdentityResponse identityResponse) {
        if(identityResponse instanceof SAMLCloudFrameworkLogoutResponse) {
            return true;
        }
        return false;
    }

    @Override
    public HttpIdentityResponse.HttpIdentityResponseBuilder create(
            HttpIdentityResponse.HttpIdentityResponseBuilder builder, IdentityResponse identityResponse) {

        SAMLCloudFrameworkLogoutResponse response = (SAMLCloudFrameworkLogoutResponse)identityResponse;

        builder.setStatusCode(HttpServletResponse.SC_FOUND);
        builder.addParameter(InboundConstants.RequestProcessor.AUTH_NAME,
                             new String[]{response.getAuthName()});
        builder.addParameter(InboundConstants.RequestProcessor.CONTEXT_KEY,
                             new String[]{response.getContextKey()});
        builder.addParameter(InboundConstants.RequestProcessor.CALL_BACK_PATH,
                             new String[]{response.getCallbackPath()});
        builder.addParameter(InboundConstants.RequestProcessor.RELYING_PARTY,
                             new String[]{response.getRelyingParty()});
        builder.addParameter(InboundConstants.RequestProcessor.AUTH_TYPE,
                             new String[]{response.getAuthType()});
        builder.setRedirectURL(response.getRedirectUrl());

        return builder;
    }

}
