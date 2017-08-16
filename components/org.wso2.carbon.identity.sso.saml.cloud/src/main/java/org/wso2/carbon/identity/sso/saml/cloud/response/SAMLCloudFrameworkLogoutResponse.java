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

import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityMessageContext;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityResponse;

/**
 * Identity Response implementation for Identity Cloud Single Logout.
 */
public class SAMLCloudFrameworkLogoutResponse extends IdentityResponse {

    private String authName;
    private String authType;
    private String contextKey;
    private String relyingParty;
    private String callbackPath;
    private String redirectUrl;

    public String getAuthName() {
        return authName;
    }

    public String getAuthType() {
        return authType;
    }

    public String getContextKey() {
        return contextKey;
    }

    public String getRelyingParty() {
        return relyingParty;
    }

    public String getCallbackPath() {
        return callbackPath;
    }

    public String getRedirectUrl() {
        return redirectUrl;
    }

    protected SAMLCloudFrameworkLogoutResponse(SAMLCloudFrameworkLogoutResponse
                                                       .SAMLCloudFrameworkLogoutResponseBuilder builder) {
        super(builder);
        this.authName = builder.authName;
        this.authType = builder.authType;
        this.contextKey = builder.contextKey;
        this.relyingParty = builder.relyingParty;
        this.callbackPath = builder.callbackPath;
        this.redirectUrl = builder.redirectUrl;
    }

    public static class SAMLCloudFrameworkLogoutResponseBuilder extends IdentityResponseBuilder {
        private String authName;
        private String authType;
        private String contextKey;
        private String relyingParty;
        private String callbackPath;
        private String redirectUrl;

        public SAMLCloudFrameworkLogoutResponseBuilder(IdentityMessageContext context) {
            super(context);
        }

        public SAMLCloudFrameworkLogoutResponseBuilder setAuthName(String authName) {
            this.authName = authName;
            return this;
        }

        public SAMLCloudFrameworkLogoutResponseBuilder setAuthType(String authType) {
            this.authType = authType;
            return this;
        }

        public SAMLCloudFrameworkLogoutResponseBuilder setContextKey(String contextKey) {
            this.contextKey = contextKey;
            return this;
        }

        public SAMLCloudFrameworkLogoutResponseBuilder setRelyingParty(String relyingParty) {
            this.relyingParty = relyingParty;
            return this;
        }

        public SAMLCloudFrameworkLogoutResponseBuilder setCallbackPath(String callbackPath) {
            this.callbackPath = callbackPath;
            return this;
        }

        public SAMLCloudFrameworkLogoutResponseBuilder setRedirectURL(String redirectUrl) {
            this.redirectUrl = redirectUrl;
            return this;
        }

        public SAMLCloudFrameworkLogoutResponse build() {
            return new SAMLCloudFrameworkLogoutResponse(this);
        }
    }
}
