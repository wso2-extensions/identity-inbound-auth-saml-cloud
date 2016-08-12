package org.wso2.carbon.identity.sso.saml.cloud.request;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityRequest;
import org.wso2.carbon.identity.sso.saml.cloud.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.cloud.util.SAMLSSOUtil;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.UnsupportedEncodingException;

public class SAMLIdentityRequest extends IdentityRequest {
    private static Log log = LogFactory.getLog(SAMLIdentityRequest.class);
    public SAMLIdentityRequest(SAMLIdentityRequestBuilder builder) {
        super(builder);
    }

    public String getRelayState() {
        if(this.getParameter(SAMLSSOConstants.RELAY_STATE) != null) {
            return this.getParameter(SAMLSSOConstants.RELAY_STATE);
        } else {
            try {
                return SAMLSSOUtil.getParameterFromQueryString(this.getQueryString(), SAMLSSOConstants.RELAY_STATE);
            } catch(UnsupportedEncodingException e){
                if (log.isDebugEnabled()) {
                    log.debug("Failed to decode the Relay State ", e);
                }
            }
        }
        return null;
    }

    public static class SAMLIdentityRequestBuilder extends IdentityRequestBuilder {
        public SAMLIdentityRequestBuilder(HttpServletRequest request, HttpServletResponse response) {
            super(request, response);
        }

        public SAMLIdentityRequestBuilder() {
        }
    }

    public boolean isRedirect() {
        return this.getMethod() == SAMLSSOConstants.GET_METHOD;
    }
}
