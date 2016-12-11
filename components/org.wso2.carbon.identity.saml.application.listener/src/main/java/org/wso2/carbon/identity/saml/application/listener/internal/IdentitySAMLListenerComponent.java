package org.wso2.carbon.identity.saml.application.listener.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.application.mgt.listener.ApplicationMgtListener;
import org.wso2.carbon.identity.saml.application.listener.listeners.SAMLMetadataListener;
import org.wso2.carbon.user.core.service.RealmService;

/**
 * @scr.component name="identity.saml.application.listener.component" immediate="true"
 * @scr.reference name="user.realmservice.default" interface="org.wso2.carbon.user.core.service.RealmService"
 * cardinality="1..1" policy="dynamic" bind="setRealmService"
 * unbind="unsetRealmService"
 */
public class IdentitySAMLListenerComponent {

    private static Log log = LogFactory.getLog(IdentitySAMLListenerComponent.class);
    private static BundleContext bundleContext;
    private static RealmService realmService;

    protected void activate(ComponentContext context) {

        try {
            bundleContext = context.getBundleContext();
            bundleContext.registerService(ApplicationMgtListener.class.getName(), new SAMLMetadataListener(), null);
            if (log.isDebugEnabled()) {
                log.info("IdentitySAMLListener bundle is activated");
            }
        } catch (Throwable e) {
            log.error("IdentitySAMLListener bundle activation Failed", e);
        }
    }

    protected void deactivate(ComponentContext context) {

        if (log.isDebugEnabled()) {
            log.info("IdentitySAMLListener bundle is deactivated");
        }
    }

    protected void setRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("Realm Service is set in the IdentitySAMLListener bundle");
        }
        IdentitySAMLListenerComponent.realmService = realmService;
    }

    protected void unsetRealmService(RealmService realmService) {
        if (log.isDebugEnabled()) {
            log.debug("Realm Service is set in the IdentitySAMLListener bundle");
        }
        IdentitySAMLListenerComponent.realmService = null;
    }

    public static RealmService getRealmService() {
        return realmService;
    }
}
