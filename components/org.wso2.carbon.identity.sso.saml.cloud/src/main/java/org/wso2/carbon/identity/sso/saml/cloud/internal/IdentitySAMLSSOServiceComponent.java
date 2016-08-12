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

package org.wso2.carbon.identity.sso.saml.cloud.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.osgi.service.http.HttpService;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityRequestFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.HttpIdentityResponseFactory;
import org.wso2.carbon.identity.application.authentication.framework.inbound.IdentityProcessor;
import org.wso2.carbon.identity.application.mgt.AbstractInboundAuthenticatorConfig;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.handler.AbstractIdentityHandler;
import org.wso2.carbon.identity.core.util.IdentityIOStreamUtils;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.sso.saml.cloud.SSOServiceProviderConfigManager;
import org.wso2.carbon.identity.sso.saml.cloud.configs.SalesForceConfigs;
import org.wso2.carbon.identity.sso.saml.cloud.handler.auth.IDPInitAuthHandler;
import org.wso2.carbon.identity.sso.saml.cloud.handler.auth.SPInitAuthHandler;
import org.wso2.carbon.identity.sso.saml.cloud.handler.validator.IDPInitSAMLValidator;
import org.wso2.carbon.identity.sso.saml.cloud.handler.validator.SAMLValidator;
import org.wso2.carbon.identity.sso.saml.cloud.handler.validator.SPInitSAMLValidator;
import org.wso2.carbon.identity.sso.saml.cloud.processor.IDPInitAuthnRequestProcessor;
import org.wso2.carbon.identity.sso.saml.cloud.processor.SSOLoginProcessor;
import org.wso2.carbon.identity.sso.saml.cloud.request.SAMLIdentityRequestFactory;
import org.wso2.carbon.identity.sso.saml.cloud.response.HttpSAMLResponseFactory;
import org.wso2.carbon.identity.sso.saml.cloud.configs.SAMLAuthenticatorConfigs;
import org.wso2.carbon.identity.sso.saml.cloud.processor.SPInitSSOAuthnRequestProcessor;
import org.wso2.carbon.registry.core.service.RegistryService;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.utils.CarbonUtils;
import org.wso2.carbon.utils.ConfigurationContextService;
import org.wso2.carbon.identity.sso.saml.cloud.util.SAMLSSOUtil;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.nio.charset.StandardCharsets;
import java.util.Hashtable;
import java.util.Scanner;

/**
 * @scr.component name="identity.sso.saml.cloud.component" immediate="true"
 * @scr.reference name="registry.service"
 * interface="org.wso2.carbon.registry.core.service.RegistryService"
 * cardinality="1..1" policy="dynamic" bind="setRegistryService"
 * unbind="unsetRegistryService"
 * @scr.reference name="config.context.service"
 * interface="org.wso2.carbon.utils.ConfigurationContextService" cardinality="1..1"
 * policy="dynamic" bind="setConfigurationContextService"
 * unbind="unsetConfigurationContextService"
 * @scr.reference name="user.realmservice.default" interface="org.wso2.carbon.user.core.service.RealmService"
 * cardinality="1..1" policy="dynamic" bind="setRealmService"
 * unbind="unsetRealmService"
 * @scr.reference name="osgi.httpservice" interface="org.osgi.service.http.HttpService"
 * cardinality="1..1" policy="dynamic" bind="setHttpService"
 * unbind="unsetHttpService"
 * @scr.reference name="saml.processor.request"
 * interface="SPInitSSOAuthnRequestProcessor" cardinality="0..n"
 * policy="dynamic" bind="addAuthnRequestProcessor" unbind="removeAuthnRequestProcessor"
 * @scr.reference name="saml.request.factory"
 * interface="SAMLIdentityRequestFactory" cardinality="0..n"
 * policy="dynamic" bind="addSAMLRequestFactory" unbind="removeSAMLRequestFactory"
 */
public class IdentitySAMLSSOServiceComponent {


    private static Log log = LogFactory.getLog(IdentitySAMLSSOServiceComponent.class);
    private static int defaultSingleLogoutRetryCount = 5;

    private static long defaultSingleLogoutRetryInterval = 60000;

    private SPInitSSOAuthnRequestProcessor authnRequestProcessor;
    private SAMLIdentityRequestFactory samlRequestFactory;
    private static String ssoRedirectPage = null;



    protected void activate(ComponentContext ctxt) {
        SAMLSSOUtil.setBundleContext(ctxt.getBundleContext());
        // Register a SSOServiceProviderConfigManager object as an OSGi Service
        ctxt.getBundleContext().registerService(SSOServiceProviderConfigManager.class.getName(),
                SSOServiceProviderConfigManager.getInstance(), null);
        ctxt.getBundleContext().registerService(HttpIdentityRequestFactory.class.getName(), new
                SAMLIdentityRequestFactory(), null);
        ctxt.getBundleContext().registerService(HttpIdentityResponseFactory.class.getName(), new
                HttpSAMLResponseFactory(), null);
        ctxt.getBundleContext().registerService(IdentityProcessor.class.getName(), new IDPInitAuthnRequestProcessor()
                , null);
        ctxt.getBundleContext().registerService(IdentityProcessor.class.getName(), new SPInitSSOAuthnRequestProcessor
                (), null);
        ctxt.getBundleContext().registerService(IdentityProcessor.class.getName(), new SSOLoginProcessor(), null);
        SPInitSAMLValidator spInitSAMLValidator = new SPInitSAMLValidator();
        IdentitySAMLSSOServiceComponentHolder.getInstance().getSamlValidators().add(spInitSAMLValidator);
        ctxt.getBundleContext().registerService(AbstractIdentityHandler.class.getName(), spInitSAMLValidator, null);

        IDPInitSAMLValidator idpInitSAMLValidator = new IDPInitSAMLValidator();
        IdentitySAMLSSOServiceComponentHolder.getInstance().getSamlValidators().add(idpInitSAMLValidator);
        ctxt.getBundleContext().registerService(AbstractIdentityHandler.class.getName(), idpInitSAMLValidator, null);

        IDPInitAuthHandler idpInitAuthHandler = new IDPInitAuthHandler();
        IdentitySAMLSSOServiceComponentHolder.getInstance().getAuthHandlers().add(idpInitAuthHandler);
        ctxt.getBundleContext().registerService(AbstractIdentityHandler.class.getName(), idpInitAuthHandler, null);

        SPInitAuthHandler spInitAuthHandler = new SPInitAuthHandler();
        IdentitySAMLSSOServiceComponentHolder.getInstance().getAuthHandlers().add(spInitAuthHandler);
        ctxt.getBundleContext().registerService(AbstractIdentityHandler.class.getName(), spInitAuthHandler, null);

        SalesForceConfigs salesforce = new SalesForceConfigs();
        Hashtable<String, String> props = new Hashtable<String, String>();
        ctxt.getBundleContext().registerService(AbstractInboundAuthenticatorConfig.class, salesforce, props);
        SAMLAuthenticatorConfigs samlconfig = new SAMLAuthenticatorConfigs();
        Hashtable<String, String> samlprops = new Hashtable<String, String>();
        ctxt.getBundleContext().registerService(AbstractInboundAuthenticatorConfig.class, samlconfig, samlprops);

        String redirectHtmlPath = null;
        FileInputStream fis = null;
        try {
            IdentityUtil.populateProperties();
            SAMLSSOUtil.setSingleLogoutRetryCount(Integer.parseInt(
                    IdentityUtil.getProperty(IdentityConstants.ServerConfig.SINGLE_LOGOUT_RETRY_COUNT)));
            SAMLSSOUtil.setSingleLogoutRetryInterval(Long.parseLong(IdentityUtil.getProperty(
                    IdentityConstants.ServerConfig.SINGLE_LOGOUT_RETRY_INTERVAL)));

//            SAMLSSOUtil.setResponseBuilder(IdentityUtil.getProperty("SSOService.SAMLSSOResponseBuilder"));
//            SAMLSSOUtil.setIdPInitSSOAuthnRequestValidator(IdentityUtil.getProperty("SSOService.IdPInitSSOAuthnRequestValidator"));
//            SAMLSSOUtil.setSPInitSSOAuthnRequestProcessor(IdentityUtil.getProperty("SSOService.SPInitSSOAuthnRequestProcessor"));
//            SAMLSSOUtil.setSPInitLogoutRequestProcessor(IdentityUtil.getProperty("SSOService.SPInitSSOAuthnRequestProcessor"));
//            SAMLSSOUtil.setIdPInitLogoutRequestProcessor(IdentityUtil.getProperty("SSOService.IdPInitLogoutRequestProcessor"));
//            SAMLSSOUtil.setIdPInitSSOAuthnRequestProcessor(IdentityUtil.getProperty("SSOService.IdPInitSSOAuthnRequestProcessor"));

            if (log.isDebugEnabled()) {
//                log.debug("IdPInitSSOAuthnRequestValidator is set to " +
//                        IdentityUtil.getProperty("SSOService.IdPInitSSOAuthnRequestValidator"));
//                log.debug("SPInitSSOAuthnRequestValidator is set to " +
//                        IdentityUtil.getProperty("SSOService.SPInitSSOAuthnRequestValidator"));
//                log.debug("SPInitSSOAuthnRequestProcessor is set to " +
//                        IdentityUtil.getProperty("SSOService.SPInitSSOAuthnRequestProcessor"));
//                log.debug("SPInitLogoutRequestProcessor is set to " +
//                        IdentityUtil.getProperty("SSOService.SPInitLogoutRequestProcessor"));
//                log.debug("IdPInitLogoutRequestProcessor is set to " +
//                        IdentityUtil.getProperty("SSOService.IdPInitLogoutRequestProcessor"));
//                log.debug("IdPInitSSOAuthnRequestProcessor is set to " +
//                        IdentityUtil.getProperty("SSOService.IdPInitSSOAuthnRequestProcessor"));
                log.debug("Single logout retry count is set to " + SAMLSSOUtil.getSingleLogoutRetryCount());
                log.debug("Single logout retry interval is set to " +
                        SAMLSSOUtil.getSingleLogoutRetryInterval() + " in seconds.");
            }

            redirectHtmlPath = CarbonUtils.getCarbonHome() + File.separator + "repository"
                    + File.separator + "resources" + File.separator + "identity" + File.separator + "pages" + File.separator + "samlsso_response.html";
            fis = new FileInputStream(new File(redirectHtmlPath));
            ssoRedirectPage = new Scanner(fis, StandardCharsets.UTF_8.name()).useDelimiter("\\A").next();
            if (log.isDebugEnabled()) {
                log.debug("samlsso_response.html " + ssoRedirectPage);
            }

//            FileBasedConfigManager.getInstance().addServiceProviders();

            if (log.isDebugEnabled()) {
                log.debug("Identity SAML SSO bundle is activated");
            }
        } catch (FileNotFoundException e) {
            if (log.isDebugEnabled()) {
                log.debug("Failed to find SAML SSO response page in : " + redirectHtmlPath, e);
            }
//        } catch (Throwable e) {
//            SAMLSSOUtil.setSingleLogoutRetryCount(defaultSingleLogoutRetryCount);
//            SAMLSSOUtil.setSingleLogoutRetryInterval(defaultSingleLogoutRetryInterval);
//            if (log.isDebugEnabled()) {
//                log.debug("Failed to load the single logout retry count and interval values." +
//                        " Default values for retry count: " + defaultSingleLogoutRetryCount +
//                        " and interval: " + defaultSingleLogoutRetryInterval + " will be used.", e);
//            }
        } finally {
            IdentityIOStreamUtils.closeInputStream(fis);
        }

    }
    public static String getSsoRedirectHtml() {
        return ssoRedirectPage;
    }

    protected void addSAMLRequestFactory(SAMLIdentityRequestFactory requestFactory){
        if (log.isDebugEnabled()) {
            log.debug("Adding SAMLIdentityRequestFactory " + requestFactory.getName());
        }
        this.samlRequestFactory = requestFactory;

    }
    protected void removeSAMLRequestFactory(SAMLIdentityRequestFactory requestFactory){
        if (log.isDebugEnabled()) {
            log.debug("Removing SAMLIdentityRequestFactory ");
        }
        this.samlRequestFactory = null;

    }

    protected void addAuthnRequestProcessor(SPInitSSOAuthnRequestProcessor processor){
        if (log.isDebugEnabled()) {
            log.debug("Adding SPInitSSOAuthnRequestProcessor " + processor.getName());
        }
        this.authnRequestProcessor = processor;
    }
    protected void removeAuthnRequestProcessor(SPInitSSOAuthnRequestProcessor processor){
        if (log.isDebugEnabled()) {
            log.debug("Removing SPInitSSOAuthnRequestProcessor ");
        }
        this.authnRequestProcessor = null;
    }


    protected void deactivate(ComponentContext ctxt) {
        SAMLSSOUtil.setBundleContext(null);
        if (log.isDebugEnabled()) {
            log.info("Identity SAML SSO bundle is deactivated");
        }
    }

    protected void setRegistryService(RegistryService registryService) {
        if (log.isDebugEnabled()) {
            log.debug("RegistryService set in Identity SAML SSO bundle");
        }
        try {
            SAMLSSOUtil.setRegistryService(registryService);
        } catch (Throwable e) {
            log.error("Failed to get a reference to the Registry in SAML SSO bundle", e);
        }
    }

    protected void unsetRegistryService(RegistryService registryService) {
        if (log.isDebugEnabled()) {
            log.debug("RegistryService unset in SAML SSO bundle");
        }
        SAMLSSOUtil.setRegistryService(null);
    }

    protected void setRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("Realm Service is set in the SAML SSO bundle");
        }
        SAMLSSOUtil.setRealmService(realmService);
    }

    protected void unsetRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("Realm Service is set in the SAML SSO bundle");
        }
        SAMLSSOUtil.setRealmService(null);
    }

    protected void setConfigurationContextService(ConfigurationContextService configCtxService) {
        if (log.isDebugEnabled()) {
            log.debug("Configuration Context Service is set in the SAML SSO bundle");
        }
        SAMLSSOUtil.setConfigCtxService(configCtxService);
    }

    protected void unsetConfigurationContextService(ConfigurationContextService configCtxService) {
        if (log.isDebugEnabled()) {
            log.debug("Configuration Context Service is unset in the SAML SSO bundle");
        }
        SAMLSSOUtil.setConfigCtxService(null);
    }

    protected void setHttpService(HttpService httpService) {
        if (log.isDebugEnabled()) {
            log.debug("HTTP Service is set in the SAML SSO bundle");
        }
        SAMLSSOUtil.setHttpService(httpService);
    }

    protected void unsetHttpService(HttpService httpService) {
        if (log.isDebugEnabled()) {
            log.debug("HTTP Service is unset in the SAML SSO bundle");
        }
        SAMLSSOUtil.setHttpService(null);
    }
}