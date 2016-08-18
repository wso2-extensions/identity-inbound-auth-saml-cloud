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
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.core.AbstractAdmin;
import org.wso2.carbon.identity.application.common.IdentityApplicationManagementException;
import org.wso2.carbon.identity.application.common.model.InboundAuthenticationRequestConfig;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.model.ServiceProvider;
import org.wso2.carbon.identity.application.mgt.ApplicationManagementService;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CloudSAMLSSOService extends AbstractAdmin{

    public boolean addSPConfigByMetadata(String fileContent, String serviceProviderName, String friendlyName){
        try {
            ApplicationManagementService appInfo = ApplicationManagementService.getInstance();
            ServiceProvider serviceProvider = appInfo.getServiceProvider(serviceProviderName, CarbonContext
                    .getThreadLocalCarbonContext().getTenantDomain());
            Map<String,Property> properties = new HashMap<>();
            for (InboundAuthenticationRequestConfig config : serviceProvider.getInboundAuthenticationConfig()
                    .getInboundAuthenticationRequestConfigs()) {
                if (StringUtils.equals(config.getFriendlyName(), friendlyName) && StringUtils.equals(config
                        .getInboundAuthType(), SAMLSSOConstants.SAMLFormFields.SAML_SSO)) {
                    for(Property property : config.getProperties()) {
                        properties.put(property.getName(),property);
                    }
                }
            }
            String name = "";
        } catch(IdentityApplicationManagementException e){
            return false;
        }
        return true;
    }


}
