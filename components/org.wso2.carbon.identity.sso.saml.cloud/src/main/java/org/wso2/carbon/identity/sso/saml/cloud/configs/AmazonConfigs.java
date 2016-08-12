/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.sso.saml.cloud.configs;


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.mgt.AbstractInboundAuthenticatorConfig;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.sso.saml.cloud.SAMLSSOConstants;

public class AmazonConfigs extends AbstractInboundAuthenticatorConfig {

    private static Log log = LogFactory.getLog(AmazonConfigs.class);

    @Override
    public String getAuthKey() {
        return null;
    }

    @Override
    public String getConfigName() {
        return "aws";
    }

    //this is the authType
    @Override
    public String getName() {
        return SAMLSSOConstants.SAMLFormFields.SAML_SSO;
    }

    @Override
    public String getFriendlyName() {
        return "Amazon";
    }

    @Override
    public Property[] getConfigurationProperties() {
        Property issuer = new Property();
        issuer.setName(SAMLSSOConstants.SAMLFormFields.ISSUER);
        issuer.setValue("https://signin.aws.amazon.com/saml");
        issuer.setDisplayName("Issuer");

        Property appType = new Property();
        appType.setName(IdentityConstants.ServerConfig.WELLKNOWN_APPLICATION_TYPE);
        appType.setType("hidden");
        appType.setValue(getConfigName());
        appType.setDisplayName("UI Config Type");

        Property acsurls = new Property();
        acsurls.setName(SAMLSSOConstants.SAMLFormFields.ACS_URLS);
        acsurls.setValue("https://signin.aws.amazon.com/saml");
        acsurls.setDisplayName("Assertion Consumer URLs");
        acsurls.setDescription("The url where you should redirected after authenticated.");

        Property defaultacs = new Property();
        defaultacs.setName(SAMLSSOConstants.SAMLFormFields.DEFAULT_ACS);
        defaultacs.setValue("https://signin.aws.amazon.com/saml");
        defaultacs.setDisplayName("Default Assertion Consumer URL");

        Property nameid = new Property();
        nameid.setName(SAMLSSOConstants.SAMLFormFields.NAME_ID_FORMAT);
        nameid.setDisplayName("NameID format ");

        Property signAlgo = new Property();
        signAlgo.setName(SAMLSSOConstants.SAMLFormFields.SIGN_ALGO);
        signAlgo.setDisplayName("Response Signing Algorithm ");
        signAlgo.setValue("http://www.w3.org/2000/09/xmldsig#rsa-sha1");

        Property digestAlgo = new Property();
        digestAlgo.setName(SAMLSSOConstants.SAMLFormFields.DIGEST_ALGO);
        digestAlgo.setDisplayName("Response Digest Algorithm ");
        digestAlgo.setValue("http://www.w3.org/2000/09/xmldsig#sha1");

        Property enableSign = new Property();
        enableSign.setName(SAMLSSOConstants.SAMLFormFields.ENABLE_RESPONSE_SIGNING);
        enableSign.setDisplayName("Enable Response Signing");
        enableSign.setValue("false");

        Property enableEncAssert = new Property();
        enableEncAssert.setName(SAMLSSOConstants.SAMLFormFields.ENABLE_ASSERTION_ENCRYPTION);
        enableEncAssert.setDisplayName("Enable Assertion Encryption ");
        enableEncAssert.setValue("false");

        Property enableAtrProf = new Property();
        enableAtrProf.setName(SAMLSSOConstants.SAMLFormFields.ENABLE_ATTR_PROF);
        enableAtrProf.setDisplayName("Enable Attribute Profile ");
        enableAtrProf.setValue("true");

        Property enableDefaultAtrProf = new Property();
        enableDefaultAtrProf.setName(SAMLSSOConstants.SAMLFormFields.ENABLE_DEFAULT_ATTR_PROF);
        enableDefaultAtrProf.setDisplayName("Include Attributes in the Response Always ");
        enableDefaultAtrProf.setValue("true");

        Property enableIDPSSO = new Property();
        enableIDPSSO.setName(SAMLSSOConstants.SAMLFormFields.ENABLE_IDP_INIT_SSO);
        enableIDPSSO.setValue("true");
        enableIDPSSO.setDisplayName("Enable IdP Initiated SSO ");

        Property enableIDPSLO = new Property();
        enableIDPSLO.setName(SAMLSSOConstants.SAMLFormFields.ENABLE_IDP_INIT_SLO);
        enableIDPSLO.setDisplayName("Enable IdP Initiated SLO ");

        Property idpSLOUrls = new Property();
        idpSLOUrls.setName(SAMLSSOConstants.SAMLFormFields.IDP_SLO_URLS);
        idpSLOUrls.setDisplayName("IDP SLO Urls");

        return new Property[]{issuer, appType, acsurls, defaultacs, nameid, signAlgo, digestAlgo, enableSign,
                enableEncAssert, enableAtrProf, enableDefaultAtrProf, enableIDPSSO, enableIDPSLO, idpSLOUrls};
    }
}
