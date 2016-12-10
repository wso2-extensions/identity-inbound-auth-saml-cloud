package org.wso2.carbon.identity.saml.application.listener.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.application.mgt.listener.ApplicationMgtListener;
import org.wso2.carbon.identity.saml.application.listener.listeners.SAMLMetadataListener;

/**
 * @scr.component name="identity.saml.listener.component" immediate="true"
 */
public class IdentitySAMLListenerComponent {

    private static Log log = LogFactory.getLog(IdentitySAMLListenerComponent.class);
    private static BundleContext bundleContext;

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
}
