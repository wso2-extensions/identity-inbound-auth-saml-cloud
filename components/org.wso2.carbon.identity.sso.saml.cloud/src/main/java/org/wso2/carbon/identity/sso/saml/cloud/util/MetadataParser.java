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
package org.wso2.carbon.identity.sso.saml.cloud.util;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.RoleDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.security.keyinfo.KeyInfoHelper;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.identity.sso.saml.cloud.exception.IdentitySAML2SSOException;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class MetadataParser {

    private static Log log = LogFactory.getLog(MetadataParser.class);

    private String issuer;
    private String defaultAcs;
    private String defaultBinding;
    private String nameIDFormat;
    private X509Certificate x509Certificate;
    private boolean isAuthnRequestsSigned;
    private boolean isWantAssertionsSigned;
    private List<String> acsUrls = new ArrayList<>();

    public MetadataParser(String encryptedXML) throws IdentityException {
        processXML(encryptedXML);
    }

    private void processXML(String encryptedXML) throws IdentityException {
        XMLObject xmlObject = SAMLSSOUtil.unmarshall(SAMLSSOUtil.decodeForPost(encryptedXML));
        if (!(xmlObject instanceof EntityDescriptor)) {
            throw new IdentitySAML2SSOException("Provided XML doesn't have an EntityDescriptor.");
        }
        this.issuer = ((EntityDescriptor) xmlObject).getEntityID();
        List<RoleDescriptor> roleDescriptors = ((EntityDescriptor) xmlObject).getRoleDescriptors();
        for (RoleDescriptor roledesc : roleDescriptors) {
            if (roledesc instanceof SPSSODescriptor) {
                this.isAuthnRequestsSigned = ((SPSSODescriptor) roledesc).isAuthnRequestsSigned();
                this.isWantAssertionsSigned = ((SPSSODescriptor) roledesc).getWantAssertionsSigned();
                for (AssertionConsumerService acs : ((SPSSODescriptor) roledesc).getAssertionConsumerServices()) {
                    if (acs.isDefault()) {
                        this.defaultAcs = acs.getLocation();
                        this.defaultBinding = acs.getBinding();
                    }
                    this.acsUrls.add(acs.getLocation());
                }
                this.nameIDFormat = ((SPSSODescriptor) roledesc).getNameIDFormats().get(0).getFormat();
                for (KeyDescriptor keyDesc : roledesc.getKeyDescriptors()) {
                    if (StringUtils.equalsIgnoreCase(keyDesc.getUse().name(), "SIGNING")) {
                        try {
                            this.x509Certificate = KeyInfoHelper.getCertificates(keyDesc.getKeyInfo()).get(0);
                        } catch (CertificateException e) {
                            if (log.isDebugEnabled()) {
                                log.debug("Error in generating the X509Certificate from the KeyInfo.", e);
                            }
                        }
                    }
                }
            }

        }
    }

    public String getIssuer() {
        return issuer;
    }

    public String getDefaultAcs() {
        return defaultAcs;
    }

    public String getDefaultBinding() {
        return defaultBinding;
    }

    public String getNameIDFormat() {
        return nameIDFormat;
    }

    public X509Certificate getX509Certificate() {
        return x509Certificate;
    }

    public boolean isAuthnRequestsSigned() {
        return isAuthnRequestsSigned;
    }

    public boolean isWantAssertionsSigned() {
        return isWantAssertionsSigned;
    }

    public List<String> getAcsUrls() {
        return this.acsUrls;
    }
}
