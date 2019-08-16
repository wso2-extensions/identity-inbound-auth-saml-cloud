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
package org.wso2.carbon.identity.saml.application.listener.util;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.wso2.carbon.identity.core.model.SAMLSSOServiceProviderDO;
import org.wso2.carbon.identity.sp.metadata.saml2.util.MetadataParser;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.List;

public class SAMLMetadataParser extends MetadataParser {

    private static final Log log = LogFactory.getLog(SAMLMetadataParser.class);
    private String certificate;

    public String getCertificate() {
        return this.certificate;
    }

    protected void setX509Certificate(EntityDescriptor entityDescriptor, SPSSODescriptor spssoDescriptor,
                                      SAMLSSOServiceProviderDO samlssoServiceProviderDO) {
        List<KeyDescriptor> descriptors = spssoDescriptor.getKeyDescriptors();
        if (descriptors != null && descriptors.size() > 0) {
            KeyDescriptor descriptor = descriptors.get(0);
            if (descriptor != null) {
                if (descriptor.getUse().toString().toUpperCase().equals("SIGNING")) {

                    try {
                        this.certificate = convertToPem(org.opensaml.xml.security.keyinfo.KeyInfoHelper
                                .getCertificates(descriptor.getKeyInfo()).get(0));
                        samlssoServiceProviderDO.setCertAlias(entityDescriptor.getEntityID());
                    } catch (java.security.cert.CertificateException ex) {
                        log.error("Error While setting Certificate and alias", ex);
                    } catch (java.lang.Exception ex) {
                        log.error("Error While setting Certificate and alias", ex);
                    }
                }
            }
        }
    }

    private String convertToPem(X509Certificate cert) throws CertificateEncodingException {
        StringBuilder pemBuilder = new StringBuilder();
        pemBuilder.append(new String(Base64.encodeBase64(cert.getEncoded())));
        return pemBuilder.toString();
    }

}
