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

package org.wso2.carbon.identity.sso.saml.cloud.request;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.sso.saml.cloud.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.cloud.util.SAMLSSOUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.UnsupportedEncodingException;

public class SAMLSpInitRequest extends SAMLIdentityRequest {

    private static Log log = LogFactory.getLog(SAMLSpInitRequest.class);
    public SAMLSpInitRequest(SAMLSpInitRequestBuilder builder) {
        super(builder);
    }

    public String getSignature() {
        if(this.getParameter(SAMLSSOConstants.SIGNATURE) != null) {
            return this.getParameter(SAMLSSOConstants.SIGNATURE);
        } else {
            try {
                return SAMLSSOUtil.getParameterFromQueryString(this.getQueryString(), SAMLSSOConstants.SIGNATURE);
            } catch(UnsupportedEncodingException e){
                if (log.isDebugEnabled()) {
                    log.debug("Failed to decode the Signature ", e);
                }
            }
        }
        return null;
    }

    public String getSigAlg() {
        if(this.getParameter(SAMLSSOConstants.SIG_ALG) != null) {
            return this.getParameter(SAMLSSOConstants.SIG_ALG);
        } else {
            try {
                return SAMLSSOUtil.getParameterFromQueryString(this.getQueryString(), SAMLSSOConstants.SIG_ALG);
            } catch(UnsupportedEncodingException e){
                if (log.isDebugEnabled()) {
                    log.debug("Failed to decode the Signature Algorithm ", e);
                }
            }
        }
        return null;
    }

    public String getSamlRequest() {
        if(this.getParameter(SAMLSSOConstants.SAML_REQUEST) != null) {
            return this.getParameter(SAMLSSOConstants.SAML_REQUEST);
        } else {
            try {
                return SAMLSSOUtil.getParameterFromQueryString(this.getQueryString(), SAMLSSOConstants.SAML_REQUEST);
            } catch(UnsupportedEncodingException e){
                if (log.isDebugEnabled()) {
                    log.debug("Failed to decode the SAML Request ", e);
                }
            }
        }
        return null;
    }

    public static class SAMLSpInitRequestBuilder extends SAMLIdentityRequestBuilder {
        public SAMLSpInitRequestBuilder(HttpServletRequest request, HttpServletResponse response) {
            super(request, response);
        }

        public SAMLSpInitRequestBuilder() {
        }

        @Override
        public SAMLSpInitRequest build() {
            return new SAMLSpInitRequest(this);
        }
    }
}
