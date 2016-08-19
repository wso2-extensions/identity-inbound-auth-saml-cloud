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

package org.wso2.carbon.identity.sso.saml.cloud;


import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.core.AbstractAdmin;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.ServiceProviderProperty;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.mgt.ApplicationConstants;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.sso.saml.cloud.util.MetadataParser;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CloudSAMLSSOService extends AbstractAdmin {

    private Log log = LogFactory.getLog(CloudSAMLSSOService.class);


    public boolean addSPConfigByMetadata(String fileContent, String serviceProviderName) {
        try {
            String userName = CarbonContext.getThreadLocalCarbonContext().getUsername();
            String tenantDomain = CarbonContext.getThreadLocalCarbonContext().getTenantDomain();
            ApplicationManagementService appInfo = ApplicationManagementService.getInstance();
            ServiceProvider serviceProvider = appInfo.getServiceProvider(serviceProviderName, tenantDomain);
            List<String> standardInboundAuthTypes = new ArrayList<String>();
            List<InboundAuthenticationRequestConfig> inboundAuthenticators = new ArrayList<>();
            standardInboundAuthTypes.add(FrameworkConstants.OAUTH2);
            standardInboundAuthTypes.add(IdentityApplicationConstants.Authenticator.WSTrust.NAME);
            standardInboundAuthTypes.add(IdentityApplicationConstants.Authenticator.SAML2SSO.NAME);
            standardInboundAuthTypes.add(IdentityApplicationConstants.Authenticator.OpenID.NAME);
            standardInboundAuthTypes.add(IdentityApplicationConstants.Authenticator.PassiveSTS.NAME);
            if (serviceProvider == null) {
                return false;
            }
            String spType = getConfigTypeFromSPProperties(serviceProvider.getSpProperties());
            Map<String, Property> properties = new HashMap<>();
            InboundAuthenticationRequestConfig authnConfig = null;
            for (InboundAuthenticationRequestConfig config : serviceProvider.getInboundAuthenticationConfig()
                    .getInboundAuthenticationRequestConfigs()) {
                if (StringUtils.equals(getAppTypeFromAuthnConfigProps(config), spType) && StringUtils.equals(config
                        .getInboundAuthType(), SAMLSSOConstants.SAMLFormFields.SAML_SSO)) {
                    authnConfig = config;
                    inboundAuthenticators.add(config);
                    for (Property property : config.getProperties()) {
                        properties.put(property.getName(), property);
                    }
                    break;
                } else if (standardInboundAuthTypes.contains(config.getInboundAuthType()) || StringUtils.equals
                        (getAppTypeFromAuthnConfigProps(config), spType)) {
                    inboundAuthenticators.add(config);
                }
            }
            if (authnConfig == null) {
                return false;
            }
            MetadataParser parser = new MetadataParser(fileContent);
            ServiceProvider spWithIssuer = appInfo.getServiceProviderByClientId(parser.getIssuer(),
                    SAMLSSOConstants.SAMLFormFields.SAML_SSO, tenantDomain);
            if (spWithIssuer != null && !StringUtils.equals(spWithIssuer.getApplicationName(),
                    IdentityApplicationConstants.DEFAULT_SP_CONFIG) && spWithIssuer.getApplicationID() !=
                    serviceProvider.getApplicationID()) {
                return false;
            }
            if (properties.get(SAMLSSOConstants.SAMLFormFields.ISSUER) != null) {
                properties.get(SAMLSSOConstants.SAMLFormFields.ISSUER).setValue(parser.getIssuer());
            }
            if (properties.get(SAMLSSOConstants.SAMLFormFields.DEFAULT_ACS) != null) {
                properties.get(SAMLSSOConstants.SAMLFormFields.DEFAULT_ACS).setValue(parser.getDefaultAcs());
            }
            if (properties.get(SAMLSSOConstants.SAMLFormFields.ACS_URLS) != null) {
                properties.get(SAMLSSOConstants.SAMLFormFields.ACS_URLS).setValue(StringUtils.join(parser.getAcsUrls
                        (), ","));
            }
            if (properties.get(SAMLSSOConstants.SAMLFormFields.NAME_ID_FORMAT) != null) {
                properties.get(SAMLSSOConstants.SAMLFormFields.NAME_ID_FORMAT).setValue(parser.getNameIDFormat());
            }
            if (properties.get(SAMLSSOConstants.SAMLFormFields.ENABLE_RESPONSE_SIGNING) != null) {
                properties.get(SAMLSSOConstants.SAMLFormFields.ENABLE_RESPONSE_SIGNING).setValue(Boolean.toString
                        (parser.isWantAssertionsSigned()));
            }
            if (properties.get(SAMLSSOConstants.SAMLFormFields.ALIAS) != null && parser.getX509Certificate() !=
                    null) {
                properties.get(SAMLSSOConstants.SAMLFormFields.ALIAS).setValue(spType);
            }
            serviceProvider.getInboundAuthenticationConfig().setInboundAuthenticationRequestConfigs
                    (inboundAuthenticators.toArray(new InboundAuthenticationRequestConfig[inboundAuthenticators.size
                            ()]));
            appInfo.updateApplication(serviceProvider, tenantDomain, userName);


        } catch (IdentityApplicationManagementException | IdentityException e) {
            if (log.isDebugEnabled()) {
                log.debug("Failed to add the authenticator properties for the serviceprovider " + serviceProviderName);
            }
            return false;
        }
        return true;
    }

    private String getAppTypeFromAuthnConfigProps(InboundAuthenticationRequestConfig config) {
        for (Property property : config.getProperties()) {
            if (StringUtils.equals(property.getName(), IdentityConstants.ServerConfig.WELLKNOWN_APPLICATION_TYPE)) {
                return property.getValue();
            }
        }
        return ApplicationConstants.STANDARD_APPLICATION;
    }

    private String getConfigTypeFromSPProperties(ServiceProviderProperty[] spProperties) {

        for (ServiceProviderProperty spProp : spProperties) {
            if (StringUtils.equals(spProp.getName(), ApplicationConstants.WELLKNOWN_APPLICATION_TYPE)) {
                return spProp.getValue();
            }
        }
        return ApplicationConstants.STANDARD_APPLICATION;
    }

}
