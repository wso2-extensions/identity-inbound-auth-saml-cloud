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

package org.wso2.carbon.identity.saml.listener.listeners;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.ServiceProviderProperty;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.mgt.ApplicationConstants;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.application.mgt.listener.AbstractApplicationMgtListener;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.saml.listener.exception.InvalidMetadataException;
import org.wso2.carbon.identity.saml.listener.util.MetadataParser;
import org.wso2.carbon.identity.sso.saml.cloud.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.cloud.util.SAMLSSOUtil;
import org.wso2.carbon.security.SecurityConfigException;
import org.wso2.carbon.security.keystore.service.KeyStoreAdminInterface;
import org.wso2.carbon.security.keystore.service.KeyStoreAdminServiceImpl;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class SAMLMetadataListener extends AbstractApplicationMgtListener {

    public static final int SUPER_TENANT_ID = -1234;
    private Log log = LogFactory.getLog(SAMLMetadataListener.class);

    @Override
    public int getDefaultOrderId() {
        return 25;
    }

    public boolean doPostUpdateApplication(ServiceProvider serviceProvider, String tenantDomain, String userName)
            throws IdentityApplicationManagementException {
        return true;
    }

    public boolean doPreUpdateApplication(ServiceProvider serviceProvider, String tenantDomain, String userName)
            throws IdentityApplicationManagementException {
        InboundAuthenticationRequestConfig authnConfig = null;
        Map<String, Property> properties = new HashMap<>();
        List<String> standardInboundAuthTypes = new ArrayList<String>();
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        boolean metadataGiven = false;
        String spType = getConfigTypeFromSPProperties(serviceProvider.getSpProperties());
        standardInboundAuthTypes.add(FrameworkConstants.OAUTH2);
        standardInboundAuthTypes.add(IdentityApplicationConstants.Authenticator.WSTrust.NAME);
        standardInboundAuthTypes.add(IdentityApplicationConstants.Authenticator.SAML2SSO.NAME);
        standardInboundAuthTypes.add(IdentityApplicationConstants.Authenticator.OpenID.NAME);
        standardInboundAuthTypes.add(IdentityApplicationConstants.Authenticator.PassiveSTS.NAME);
        for (InboundAuthenticationRequestConfig config : serviceProvider.getInboundAuthenticationConfig()
                .getInboundAuthenticationRequestConfigs()) {
            if (StringUtils.equals(getAppTypeFromAuthnConfigProps(config), spType) && StringUtils.equals(config
                    .getInboundAuthType(), SAMLSSOConstants.SAMLFormFields.SAML_SSO)) {
                authnConfig = config;
                for (Property property : config.getProperties()) {
                    if (StringUtils.equals(property.getName(), SAMLSSOConstants.SAMLFormFields.METADATA) &&
                            StringUtils.isNotBlank(property.getValue())) {
                        //metadata not given
                        metadataGiven = true;
                    }
                    properties.put(property.getName(), property);
                }
            }
        }
        if (metadataGiven) {
            addSPConfigByMetadata(serviceProvider, userName, tenantDomain, authnConfig, properties);
        } else {
            String pemCert = properties.get(SAMLSSOConstants.SAMLFormFields.PUB_CERT).getValue();
            String issuer = properties.get(SAMLSSOConstants.SAMLFormFields.ISSUER).getValue();
            if (pemCert != null && StringUtils.isNotBlank(pemCert)) {
                String alias = getAlias(serviceProvider.getApplicationName(), issuer);
                Property aliasProperty = new Property();
                aliasProperty.setName(SAMLSSOConstants.SAMLFormFields.ALIAS);
                aliasProperty.setValue(alias);
                properties.put(SAMLSSOConstants.SAMLFormFields.ALIAS, aliasProperty);
                addCertToKeyStore(alias, pemCert, tenantId, tenantDomain);
            }
        }
        if (properties.get(SAMLSSOConstants.SAMLFormFields.METADATA) != null) {
            properties.remove(SAMLSSOConstants.SAMLFormFields.METADATA);
        }
        if (properties.get(SAMLSSOConstants.SAMLFormFields.PUB_CERT) != null) {
            properties.remove(SAMLSSOConstants.SAMLFormFields.PUB_CERT);
        }
        authnConfig.setProperties(properties.values().toArray(new Property[properties.keySet().size()]));
        return true;
    }

    private void addCertToKeyStore(String alias, String pemCert, int tenantId, String tenantDomain) {

        KeyStoreAdminInterface keystore = new KeyStoreAdminServiceImpl();
        try {
            if (tenantId != SUPER_TENANT_ID) {// for tenants, load private key from their generated key store
                keystore.importCertToStore(alias, pemCert, SAMLSSOUtil.generateKSNameFromDomainName(tenantDomain));
            } else { // for super tenant, load the default pub. cert using the config. in carbon.xml
                String keyStoreName = ServerConfiguration.getInstance().getFirstProperty("Security.KeyStore.Location");
                String[] keyStorePath = keyStoreName.split("/");
                keyStoreName = keyStorePath[keyStorePath.length - 1];
                keystore.importCertToStore(alias, pemCert, keyStoreName);
            }
        } catch (SecurityConfigException e) {
            if (log.isDebugEnabled()) {
                log.debug("Failed to import the cert in to the keystore.", e);
            }
        }
    }

    /**
     * Adding SAML Confiuration by metadata file
     * Only possible in the initial step.
     * Updates should be done in the User Interface
     *
     * @param serviceProvider
     * @param userName
     * @param tenantDomain
     * @param authnConfig
     * @param properties
     * @return
     */
    public boolean addSPConfigByMetadata(ServiceProvider serviceProvider, String userName, String tenantDomain,
                                         InboundAuthenticationRequestConfig authnConfig, Map<String, Property>
                                                 properties) {
        String serviceProviderName = serviceProvider.getApplicationName();
        try {
            String fileContent = properties.get(SAMLSSOConstants.SAMLFormFields.METADATA).getValue();
            ApplicationManagementService appInfo = ApplicationManagementService.getInstance();
            int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
            if (serviceProvider == null || authnConfig == null) {
                return false;
            }
            MetadataParser parser = new MetadataParser(fileContent);
            //checking whether the service provider has a issuer.
            //If there is no issuer added new issuer will be added

            if (properties.get(SAMLSSOConstants.SAMLFormFields.ISSUER) == null || StringUtils.isBlank(properties.get
                    (SAMLSSOConstants.SAMLFormFields.ISSUER).getValue())) {
                //initiate SAML Configs
                if (properties.get(SAMLSSOConstants.SAMLFormFields.ISSUER) == null) {
                    Property issuerProp = new Property();
                    issuerProp.setName(SAMLSSOConstants.SAMLFormFields.ISSUER);
                    issuerProp.setDisplayName("Issuer");
                    issuerProp.setValue(parser.getServiceProviderDO().getIssuer());
                    properties.put(SAMLSSOConstants.SAMLFormFields.ISSUER, issuerProp);
                } else {
                    properties.get(SAMLSSOConstants.SAMLFormFields.ISSUER).setValue(parser.getServiceProviderDO()
                            .getIssuer());
                }
                setSAMLConfigs(properties, parser, serviceProviderName, tenantDomain, tenantId);
            } else {
                ServiceProvider spWithIssuer = appInfo.getServiceProviderByClientId(parser.getServiceProviderDO()
                        .getIssuer(), SAMLSSOConstants.SAMLFormFields.SAML_SSO, tenantDomain);
                if (spWithIssuer != null && !StringUtils.equals(spWithIssuer.getApplicationName(),
                        IdentityApplicationConstants.DEFAULT_SP_CONFIG) && spWithIssuer.getApplicationID() !=
                        serviceProvider.getApplicationID()) {
                    return false;
                }
                //update SAML Configs
                setSAMLConfigs(properties, parser, serviceProviderName, tenantDomain, tenantId);

            }
        } catch (IdentityApplicationManagementException | IdentityException | InvalidMetadataException e) {
            if (log.isDebugEnabled()) {
                log.debug("Failed to add the authenticator properties for the serviceprovider " + serviceProviderName);
            }
            return false;
        }
        return true;
    }

    private void setSAMLConfigs(Map<String, Property> properties, MetadataParser parser, String spName, String
            tenantDomain, int tenantId) {
        SAMLSSOServiceProviderDO samlConfigs = parser.getServiceProviderDO();

        if (properties.get(SAMLSSOConstants.SAMLFormFields.DEFAULT_ACS) != null) {
            properties.get(SAMLSSOConstants.SAMLFormFields.DEFAULT_ACS).setValue(samlConfigs
                    .getDefaultAssertionConsumerUrl());
        }
        if (properties.get(SAMLSSOConstants.SAMLFormFields.ALIAS) != null) {
            properties.get(SAMLSSOConstants.SAMLFormFields.ALIAS).setValue(spName + "_" + samlConfigs.getCertAlias());
        }
        addCertToKeyStore(samlConfigs.getCertAlias(), parser.getCertificate(), tenantId, tenantDomain);
        if (properties.get(SAMLSSOConstants.SAMLFormFields.ACS_URLS) != null) {
            properties.get(SAMLSSOConstants.SAMLFormFields.ACS_URLS).setValue(StringUtils.join(samlConfigs
                    .getAssertionConsumerUrls(), ","));
        }
        if (properties.get(SAMLSSOConstants.SAMLFormFields.NAME_ID_FORMAT) != null) {
            properties.get(SAMLSSOConstants.SAMLFormFields.NAME_ID_FORMAT).setValue(samlConfigs.getNameIDFormat());
        }
        if (properties.get(SAMLSSOConstants.SAMLFormFields.ENABLE_RESPONSE_SIGNING) != null) {
            properties.get(SAMLSSOConstants.SAMLFormFields.ENABLE_RESPONSE_SIGNING).setValue(Boolean.toString
                    (samlConfigs.isDoSignResponse()));
        }
        if (properties.get(SAMLSSOConstants.SAMLFormFields.SIGN_ALGO) != null) {
            properties.get(SAMLSSOConstants.SAMLFormFields.SIGN_ALGO).setValue(samlConfigs.getSigningAlgorithmUri());
        }
        if (properties.get(SAMLSSOConstants.SAMLFormFields.DIGEST_ALGO) != null) {
            properties.get(SAMLSSOConstants.SAMLFormFields.DIGEST_ALGO).setValue(samlConfigs.getDigestAlgorithmUri());
        }
        if (properties.get(SAMLSSOConstants.SAMLFormFields.ENABLE_SIGNATURE_VALIDATION) != null) {
            properties.get(SAMLSSOConstants.SAMLFormFields.ENABLE_SIGNATURE_VALIDATION).setValue(Boolean.toString
                    (samlConfigs.isDoValidateSignatureInRequests()));
        }
        if (properties.get(SAMLSSOConstants.SAMLFormFields.ENABLE_ASSERTION_SIGNING) != null) {
            properties.get(SAMLSSOConstants.SAMLFormFields.ENABLE_ASSERTION_SIGNING).setValue(Boolean.toString
                    (samlConfigs.isDoSignAssertions()));
        }
        if (properties.get(SAMLSSOConstants.SAMLFormFields.ENABLE_SINGLE_LOGOUT) != null) {
            properties.get(SAMLSSOConstants.SAMLFormFields.ENABLE_SINGLE_LOGOUT).setValue(Boolean.toString
                    (samlConfigs.isDoSingleLogout()));
        }
        if (properties.get(SAMLSSOConstants.SAMLFormFields.SLO_RESPONSE_URL) != null) {
            properties.get(SAMLSSOConstants.SAMLFormFields.SLO_RESPONSE_URL).setValue(samlConfigs.getSloResponseURL());
        }
        if (properties.get(SAMLSSOConstants.SAMLFormFields.SLO_REQUEST_URL) != null) {
            properties.get(SAMLSSOConstants.SAMLFormFields.SLO_REQUEST_URL).setValue(samlConfigs.getSloResponseURL());
        }
    }

    private String getAppTypeFromAuthnConfigProps(InboundAuthenticationRequestConfig config) {
        for (Property property : config.getProperties()) {
            if (StringUtils.equals(property.getName(), ApplicationConstants.WELLKNOWN_APPLICATION_TYPE)) {
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

    private String getAlias(String serviceProviderName, String issuer) {

        return serviceProviderName + "_" + issuer;
    }
}
