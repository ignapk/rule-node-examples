/**
 * Copyright © 2018 The Thingsboard Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.thingsboard.rule.engine.rest;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Data;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.thingsboard.rule.engine.api.NodeConfiguration;

import java.util.Collections;
import java.util.Map;

@JsonIgnoreProperties(ignoreUnknown = true)
@Data
public class TbRestApiCallNodeConfigurationDigest implements NodeConfiguration<TbRestApiCallNodeConfigurationDigest> {

    private String restEndpointUrlPattern;
    private String requestMethod;
    private String proxyHost;
    private int proxyPort;
    private String proxyScheme;
    private String username;
    private String password;

    @Override
    public TbRestApiCallNodeConfigurationDigest defaultConfiguration() {
        TbRestApiCallNodeConfigurationDigest configuration = new TbRestApiCallNodeConfigurationDigest();
        configuration.setRestEndpointUrlPattern("http://localhost/api");
        configuration.setRequestMethod("POST");
        return configuration;
    }
}
