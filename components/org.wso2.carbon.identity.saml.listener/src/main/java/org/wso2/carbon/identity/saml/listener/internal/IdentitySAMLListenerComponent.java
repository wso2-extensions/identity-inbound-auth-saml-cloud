package org.wso2.carbon.identity.saml.listener.internal;


import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.application.mgt.listener.ApplicationMgtListener;
import org.wso2.carbon.identity.saml.listener.listeners.SAMLMetadataListener;

/**
 * @scr.component name="identity.saml.listener.component" immediate="true"
 */
public class IdentitySAMLListenerComponent {

    private static Log log = LogFactory.getLog(IdentitySAMLListenerComponent.class);
    private static BundleContext bundleContext;

    protected void activate(ComponentContext context) {
        bundleContext = context.getBundleContext();
        bundleContext.registerService(ApplicationMgtListener.class.getName(), new SAMLMetadataListener(), null);
    }
}
