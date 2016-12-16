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

package org.wso2.carbon.identity.saml.application.listener.listeners;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.base.ServerConfiguration;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.common.model.ServiceProviderProperty;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.mgt.ApplicationConstants;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.identity.application.mgt.listener.AbstractApplicationMgtListener;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.saml.application.listener.internal.IdentitySAMLListenerComponent;
import org.wso2.carbon.identity.saml.application.listener.util.SAMLMetadataParser;
import org.wso2.carbon.identity.sp.metadata.saml2.Exception.InvalidMetadataException;
import org.wso2.carbon.identity.sso.saml.cloud.SAMLSSOConstants;
import org.wso2.carbon.identity.sso.saml.cloud.util.SAMLSSOUtil;
import org.wso2.carbon.security.SecurityConfigException;
import org.wso2.carbon.security.keystore.service.KeyStoreAdminInterface;
import org.wso2.carbon.security.keystore.service.KeyStoreAdminServiceImpl;
import org.wso2.carbon.user.api.UserStoreException;

import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

public class SAMLMetadataListener extends AbstractApplicationMgtListener {

    private static final ThreadLocal<String> SAMLSPCertificateThreadLocal = new ThreadLocal<>();
    private Log log = LogFactory.getLog(SAMLMetadataListener.class);

    @Override
    public int getDefaultOrderId() {
        return 25;
    }

    public boolean doPreUpdateApplication(ServiceProvider serviceProvider, String tenantDomain, String userName)
            throws IdentityApplicationManagementException {

        InboundAuthenticationRequestConfig authnConfig = null;
        String spType = getConfigTypeFromSPProperties(serviceProvider.getSpProperties());

        for (InboundAuthenticationRequestConfig config : serviceProvider.getInboundAuthenticationConfig()
                .getInboundAuthenticationRequestConfigs()) {
            if (StringUtils.equals(getAppTypeFromAuthnConfigProps(config), spType) && StringUtils.equals(config
                    .getInboundAuthType(), SAMLSSOConstants.SAMLFormFields.SAML_SSO)) {
                authnConfig = config;
            }
        }

        if (authnConfig == null) { // Not SAML, exit from processing inbound authenticator configs
            return true;
        }

        boolean metadataProvided = false;
        Map<String, Property> properties = new HashMap<>();
        for (Property property : authnConfig.getProperties()) {
            if (StringUtils.equals(property.getName(), SAMLSSOConstants.SAMLFormFields.METADATA) && StringUtils
                    .isNotBlank(property.getValue())) {
                //metadata given
                metadataProvided = true;
            }
            properties.put(property.getName(), property);
        }

        if (metadataProvided) {

            if (log.isDebugEnabled()) {
                log.debug("Meta data file uploaded. Updating Service Provider with metadata.");
            }
            updateServiceProviderInboundAuthConfigs(serviceProvider, tenantDomain, authnConfig, properties);
        } else {

            String pemCert = properties.get(SAMLSSOConstants.SAMLFormFields.PUB_CERT).getValue();
            if (pemCert != null && StringUtils.isNotBlank(pemCert) && !"undefined".equalsIgnoreCase(pemCert)) {

                if (log.isDebugEnabled()) {
                    log.debug("Service Provider certificate provided. Adding certificate to the key store.");
                }

                String issuer = properties.get(SAMLSSOConstants.SAMLFormFields.ISSUER).getValue();
                try {
                    // Add certificate to key store
                    addCertToKeyStore(issuer, pemCert, tenantDomain);

                    // If certificate is added successfully set the alias property
                    Property aliasProperty = properties.get(SAMLSSOConstants.SAMLFormFields.ALIAS);
                    if (aliasProperty == null) {
                        aliasProperty = new Property();
                        aliasProperty.setDescription("Certificate Alias");
                        aliasProperty.setName(SAMLSSOConstants.SAMLFormFields.ALIAS);
                        properties.put(SAMLSSOConstants.SAMLFormFields.ALIAS, aliasProperty);
                    }

                    aliasProperty.setValue(issuer);
                } catch (SecurityConfigException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Failed to add provided certificate to the key store", e);
                    }
                }
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

    @Override
    public boolean doPreDeleteApplication(String applicationName, String tenantDomain, String userName) throws
            IdentityApplicationManagementException {

        ApplicationManagementService appInfo = ApplicationManagementService.getInstance();
        ServiceProvider serviceProvider = appInfo.getServiceProvider(applicationName, tenantDomain);

        String spType = getConfigTypeFromSPProperties(serviceProvider.getSpProperties());

        for (InboundAuthenticationRequestConfig config : serviceProvider.getInboundAuthenticationConfig()
                .getInboundAuthenticationRequestConfigs()) {
            if (StringUtils.equals(getAppTypeFromAuthnConfigProps(config), spType) && StringUtils.equals(config
                    .getInboundAuthType(), SAMLSSOConstants.SAMLFormFields.SAML_SSO)) {
                for (Property property : config.getProperties()) {

                    if (StringUtils.equals(property.getName(), SAMLSSOConstants.SAMLFormFields.ALIAS) && StringUtils
                            .isNotBlank(property.getValue())) {
                        SAMLSPCertificateThreadLocal.set(property.getValue());
                    }
                }
            }
        }

        return true;
    }

    @Override
    public boolean doPostDeleteApplication(String applicationName, String tenantDomain, String userName) throws
            IdentityApplicationManagementException {

        String alias = SAMLSPCertificateThreadLocal.get();
        if (StringUtils.isNotBlank(alias)) {
            try {
                removeCertFromKeyStore(alias, tenantDomain);
            } catch (SecurityConfigException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Failed to removed certificate from the key store", e);
                }
            } finally {
                SAMLSPCertificateThreadLocal.remove();
            }
        }

        return true;
    }

    @Override
    public boolean doPostGetApplicationExcludingFileBasedSPs(ServiceProvider serviceProvider, String applicationName,
                                                             String tenantDomain) throws
            IdentityApplicationManagementException {

        InboundAuthenticationRequestConfig authnConfig = null;
        String spType = getConfigTypeFromSPProperties(serviceProvider.getSpProperties());

        for (InboundAuthenticationRequestConfig config : serviceProvider.getInboundAuthenticationConfig()
                .getInboundAuthenticationRequestConfigs()) {
            if (StringUtils.equals(getAppTypeFromAuthnConfigProps(config), spType) && StringUtils.equals(config
                    .getInboundAuthType(), SAMLSSOConstants.SAMLFormFields.SAML_SSO)) {
                authnConfig = config;
            }
        }

        if (authnConfig == null) { // Not SAML, exit from processing inbound authenticator configs
            return true;
        }

        Map<String, Property> properties = new HashMap<>();
        for (Property property : authnConfig.getProperties()) {
            properties.put(property.getName(), property);
        }

        if (properties.get(SAMLSSOConstants.SAMLFormFields.ALIAS) != null) {
            String alias = properties.get(SAMLSSOConstants.SAMLFormFields.ALIAS).getValue();
            if (StringUtils.isNotBlank(alias)) {

                String certificate = getCertFromKeyStore(alias, tenantDomain);
                if (StringUtils.isNotBlank(certificate)) {
                    Property certificateProperty = properties.get(SAMLSSOConstants.SAMLFormFields.PUB_CERT);
                    if (certificateProperty == null) {
                        certificateProperty = new Property();
                        certificateProperty.setDescription("Certificate");
                        certificateProperty.setName(SAMLSSOConstants.SAMLFormFields.PUB_CERT);
                        properties.put(SAMLSSOConstants.SAMLFormFields.PUB_CERT, certificateProperty);
                    }
                    certificateProperty.setValue(certificate);

                    authnConfig.setProperties(properties.values().toArray(new Property[properties.keySet().size()]));
                }
            }
        }

        return true;
    }

    /**
     * Adding SAML Confiuration by metadata file
     * Only possible in the initial step.
     * Updates should be done in the User Interface
     *
     * @param serviceProvider
     * @param tenantDomain
     * @param authnConfig
     * @param properties
     * @return
     */
    private boolean updateServiceProviderInboundAuthConfigs(ServiceProvider serviceProvider, String tenantDomain,
                                                            InboundAuthenticationRequestConfig authnConfig,
                                                            Map<String, Property> properties) {

        String serviceProviderName = serviceProvider.getApplicationName();
        try {
            if (serviceProvider == null || authnConfig == null) {
                return false;
            }

            String fileContent = properties.get(SAMLSSOConstants.SAMLFormFields.METADATA).getValue();
            ApplicationManagementService appInfo = ApplicationManagementService.getInstance();
            SAMLMetadataParser parser = new SAMLMetadataParser();
            SAMLSSOServiceProviderDO samlssoServiceProviderDO = new SAMLSSOServiceProviderDO();
            try {
                samlssoServiceProviderDO = parser.parse(new String(Base64.decodeBase64(fileContent)),
                        samlssoServiceProviderDO);
            } catch (InvalidMetadataException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Failed to parse metadata of the Service Provider " + serviceProviderName);
                }
                return false;
            }

            //checking whether the service provider has a issuer.
            //If there is no issuer added new issuer will be added

            if (properties.get(SAMLSSOConstants.SAMLFormFields.ISSUER) == null || StringUtils.isBlank(properties.get
                    (SAMLSSOConstants.SAMLFormFields.ISSUER).getValue())) {
                //initiate SAML Configs
                Property issuerProperty = properties.get(SAMLSSOConstants.SAMLFormFields.ISSUER);
                if (issuerProperty == null) {
                    issuerProperty = new Property();
                    issuerProperty.setName(SAMLSSOConstants.SAMLFormFields.ISSUER);
                    issuerProperty.setDisplayName("Issuer");
                    properties.put(SAMLSSOConstants.SAMLFormFields.ISSUER, issuerProperty);
                }
                issuerProperty.setValue(samlssoServiceProviderDO.getIssuer());
            } else {
                ServiceProvider spWithIssuer = appInfo.getServiceProviderByClientId(samlssoServiceProviderDO
                        .getIssuer(), SAMLSSOConstants.SAMLFormFields.SAML_SSO, tenantDomain);
                if (spWithIssuer != null && !StringUtils.equals(spWithIssuer.getApplicationName(),
                        IdentityApplicationConstants.DEFAULT_SP_CONFIG) && spWithIssuer.getApplicationID() !=
                        serviceProvider.getApplicationID()) {
                    return false;
                }
            }

            setSAMLConfigs(properties, samlssoServiceProviderDO, parser.getCertificate(), tenantDomain);
        } catch (IdentityApplicationManagementException e) {
            if (log.isDebugEnabled()) {
                log.debug("Failed to add the authenticator properties for the Service Provider " +
                        serviceProviderName, e);
            }
            return false;
        }
        return true;
    }

    private void setSAMLConfigs(Map<String, Property> properties, SAMLSSOServiceProviderDO samlssoServiceProviderDO,
                                String certificate, String tenantDomain) {

        if (properties.get(SAMLSSOConstants.SAMLFormFields.DEFAULT_ACS) != null) {
            properties.get(SAMLSSOConstants.SAMLFormFields.DEFAULT_ACS).setValue(samlssoServiceProviderDO
                    .getDefaultAssertionConsumerUrl());
        }

        if (certificate != null && StringUtils.isNotBlank(certificate)) {
            try {
                addCertToKeyStore(samlssoServiceProviderDO.getCertAlias(), certificate, tenantDomain);
                if (properties.get(SAMLSSOConstants.SAMLFormFields.ALIAS) != null) {
                    properties.get(SAMLSSOConstants.SAMLFormFields.ALIAS).setValue(samlssoServiceProviderDO
                            .getCertAlias());
                }
            } catch (SecurityConfigException e) {
                if (log.isDebugEnabled()) {
                    log.debug("Failed to add provided certificate to the key store", e);
                }
            }
        }

        if (properties.get(SAMLSSOConstants.SAMLFormFields.ACS_URLS) != null) {
            properties.get(SAMLSSOConstants.SAMLFormFields.ACS_URLS).setValue(StringUtils.join
                    (samlssoServiceProviderDO.getAssertionConsumerUrls(), ","));
        }
        if (properties.get(SAMLSSOConstants.SAMLFormFields.NAME_ID_FORMAT) != null) {
            properties.get(SAMLSSOConstants.SAMLFormFields.NAME_ID_FORMAT).setValue(samlssoServiceProviderDO
                    .getNameIDFormat());
        }
        if (properties.get(SAMLSSOConstants.SAMLFormFields.ENABLE_RESPONSE_SIGNING) != null) {
            properties.get(SAMLSSOConstants.SAMLFormFields.ENABLE_RESPONSE_SIGNING).setValue(Boolean.toString
                    (samlssoServiceProviderDO.isDoSignResponse()));
        }
        if (properties.get(SAMLSSOConstants.SAMLFormFields.SIGN_ALGO) != null) {
            properties.get(SAMLSSOConstants.SAMLFormFields.SIGN_ALGO).setValue(samlssoServiceProviderDO
                    .getSigningAlgorithmUri());
        }
        if (properties.get(SAMLSSOConstants.SAMLFormFields.DIGEST_ALGO) != null) {
            properties.get(SAMLSSOConstants.SAMLFormFields.DIGEST_ALGO).setValue(samlssoServiceProviderDO
                    .getDigestAlgorithmUri());
        }
        if (properties.get(SAMLSSOConstants.SAMLFormFields.ENABLE_SIGNATURE_VALIDATION) != null) {
            properties.get(SAMLSSOConstants.SAMLFormFields.ENABLE_SIGNATURE_VALIDATION).setValue(Boolean.toString
                    (samlssoServiceProviderDO.isDoValidateSignatureInRequests()));
        }
        if (properties.get(SAMLSSOConstants.SAMLFormFields.ENABLE_ASSERTION_SIGNING) != null) {
            properties.get(SAMLSSOConstants.SAMLFormFields.ENABLE_ASSERTION_SIGNING).setValue(Boolean.toString
                    (samlssoServiceProviderDO.isDoSignAssertions()));
        }
        if (properties.get(SAMLSSOConstants.SAMLFormFields.ENABLE_SINGLE_LOGOUT) != null) {
            properties.get(SAMLSSOConstants.SAMLFormFields.ENABLE_SINGLE_LOGOUT).setValue(Boolean.toString
                    (samlssoServiceProviderDO.isDoSingleLogout()));
        }
        if (properties.get(SAMLSSOConstants.SAMLFormFields.SLO_RESPONSE_URL) != null) {
            properties.get(SAMLSSOConstants.SAMLFormFields.SLO_RESPONSE_URL).setValue(samlssoServiceProviderDO
                    .getSloResponseURL());
        }
        if (properties.get(SAMLSSOConstants.SAMLFormFields.SLO_REQUEST_URL) != null) {
            properties.get(SAMLSSOConstants.SAMLFormFields.SLO_REQUEST_URL).setValue(samlssoServiceProviderDO
                    .getSloResponseURL());
        }
    }

    private void addCertToKeyStore(String alias, String pemCert, String tenantDomain) throws SecurityConfigException {

        KeyStoreAdminInterface keystore = new KeyStoreAdminServiceImpl();

        if (!MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equalsIgnoreCase(tenantDomain)) {// for tenants, load
            // private key from their generated key store
            keystore.importCertToStore(alias, pemCert, SAMLSSOUtil.generateKSNameFromDomainName(tenantDomain));
        } else { // for super tenant, load the default pub. cert using the config. in carbon.xml
            String keyStoreName = ServerConfiguration.getInstance().getFirstProperty("Security.KeyStore.Location");
            String[] keyStorePath = keyStoreName.split("/");
            keyStoreName = keyStorePath[keyStorePath.length - 1];
            keystore.importCertToStore(alias, pemCert, keyStoreName);
        }
    }

    private String getCertFromKeyStore(String alias, String tenantDomain) {

        int tenantId = 0;
        try {
            tenantId = IdentitySAMLListenerComponent.getRealmService().getTenantManager().getTenantId(tenantDomain);
        } catch (UserStoreException e) {
            if (log.isDebugEnabled()) {
                log.debug("Error getting the tenant ID for the tenant domain " + tenantDomain, e);
            }

            return null;
        }
        // get an instance of the corresponding Key Store Manager instance
        KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(tenantId);

        KeyStore keyStore;

        try {
            if (MultitenantConstants.SUPER_TENANT_ID != tenantId) {// for tenants, load public key from their
                // generated key store
                keyStore = keyStoreManager.getKeyStore(SAMLSSOUtil.generateKSNameFromDomainName(tenantDomain));
            } else { // for super tenant, load the default pub. cert using the config. in carbon.xml
                keyStore = keyStoreManager.getPrimaryKeyStore();
            }
            X509Certificate cert = (X509Certificate) keyStore.getCertificate(alias);
            return new String(Base64.encodeBase64(cert.getEncoded()));
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("Error retrieving the public certificate for alias " + alias, e);
            }
        }

        return null;
    }

    private void removeCertFromKeyStore(String alias, String tenantDomain) throws SecurityConfigException {

        KeyStoreAdminInterface keystore = new KeyStoreAdminServiceImpl();
        if (!MultitenantConstants.SUPER_TENANT_DOMAIN_NAME.equalsIgnoreCase(tenantDomain)) {// for tenants, load
            // private key from their generated key store
            keystore.removeCertFromStore(alias, SAMLSSOUtil.generateKSNameFromDomainName(tenantDomain));
        } else { // for super tenant, load the default pub. cert using the config. in carbon.xml
            String keyStoreName = ServerConfiguration.getInstance().getFirstProperty("Security.KeyStore.Location");
            String[] keyStorePath = keyStoreName.split("/");
            keyStoreName = keyStorePath[keyStorePath.length - 1];
            keystore.removeCertFromStore(alias, keyStoreName);
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
}
