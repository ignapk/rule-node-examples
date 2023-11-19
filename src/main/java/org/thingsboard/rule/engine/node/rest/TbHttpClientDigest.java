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

import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.handler.ssl.SslContextBuilder;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.conn.ssl.DefaultHostnameVerifier;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.nio.client.CloseableHttpAsyncClient;
import org.apache.http.impl.nio.client.HttpAsyncClientBuilder;
import org.apache.http.impl.nio.client.HttpAsyncClients;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.HttpComponentsAsyncClientHttpRequestFactory;
import org.springframework.http.client.Netty4ClientHttpRequestFactory;
import org.springframework.util.concurrent.ListenableFuture;
import org.springframework.util.concurrent.ListenableFutureCallback;
import org.springframework.web.client.AsyncRestTemplate;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestClientResponseException;
import org.springframework.web.util.UriComponentsBuilder;
import org.thingsboard.common.util.JacksonUtil;
import org.thingsboard.rule.engine.api.TbContext;
import org.thingsboard.rule.engine.api.TbNodeException;
import org.thingsboard.rule.engine.api.util.TbNodeUtils;
import org.thingsboard.server.common.data.StringUtils;
import org.thingsboard.server.common.msg.TbMsg;
import org.thingsboard.server.common.msg.TbMsgMetaData;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import java.net.Authenticator;
import java.net.PasswordAuthentication;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.KeyStoreException;
import java.security.KeyManagementException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentLinkedDeque;
import java.util.concurrent.TimeUnit;
import java.util.function.BiConsumer;
import java.util.function.Consumer;

@Data
@Slf4j
@SuppressWarnings("deprecation")
public class TbHttpClientDigest {

    private static final String STATUS = "status";
    private static final String STATUS_CODE = "statusCode";
    private static final String STATUS_REASON = "statusReason";
    private static final String ERROR = "error";
    private static final String ERROR_BODY = "error_body";

    private final TbRestApiCallNodeConfigurationDigest config;

    private EventLoopGroup eventLoopGroup;
    private AsyncRestTemplate httpClient;

    TbHttpClientDigest(TbRestApiCallNodeConfigurationDigest config, EventLoopGroup eventLoopGroupShared) throws TbNodeException {
        try {
            this.config = config;
            
            checkProxyHost(config.getProxyHost());
            checkProxyPort(config.getProxyPort());

            String proxyUser;
            String proxyPassword;

            CloseableHttpAsyncClient asyncClient;
            HttpComponentsAsyncClientHttpRequestFactory requestFactory = new HttpComponentsAsyncClientHttpRequestFactory();

            HttpAsyncClientBuilder httpAsyncClientBuilder = HttpAsyncClientBuilder.create()
                    .setSSLContext(SSLContextBuilder.create().loadTrustMaterial((chain, authType) -> true).build())
                    .setSSLHostnameVerifier(NoopHostnameVerifier.INSTANCE)
                    .setProxy(new HttpHost(config.getProxyHost(), config.getProxyPort(), config.getProxyScheme()));

            asyncClient = httpAsyncClientBuilder.build();
            requestFactory.setAsyncClient(asyncClient);
            httpClient = new AsyncRestTemplate(requestFactory);
        } catch (KeyStoreException | KeyManagementException | NoSuchAlgorithmException e) {
            throw new TbNodeException(e);
        }
    }

    EventLoopGroup getSharedOrCreateEventLoopGroup(EventLoopGroup eventLoopGroupShared) {
        if (eventLoopGroupShared != null) {
            return eventLoopGroupShared;
        }
        return this.eventLoopGroup = new NioEventLoopGroup();
    }

    void destroy() {
        if (this.eventLoopGroup != null) {
            this.eventLoopGroup.shutdownGracefully(0, 5, TimeUnit.SECONDS);
        }
    }

    public void processMessage(TbContext ctx, TbMsg msg,
                               Consumer<TbMsg> onSuccess,
                               BiConsumer<TbMsg, Throwable> onFailure) {
        String endpointUrl = TbNodeUtils.processPattern(config.getRestEndpointUrlPattern(), msg);
        HttpHeaders headers = prepareHeaders(msg);
        HttpMethod method = HttpMethod.valueOf(config.getRequestMethod());
        HttpEntity<String> entity;
        if (HttpMethod.GET.equals(method) || HttpMethod.HEAD.equals(method) ||
                HttpMethod.OPTIONS.equals(method) || HttpMethod.TRACE.equals(method)) {
            entity = new HttpEntity<>(headers);
        } else {
            entity = new HttpEntity<>(getData(msg, false, false), headers);
        }

        URI uri = buildEncodedUri(endpointUrl);
        ListenableFuture<ResponseEntity<String>> future = httpClient.exchange(
                uri, method, entity, String.class);
        future.addCallback(new ListenableFutureCallback<>() {
            @Override
            public void onFailure(Throwable throwable) {
                if (throwable instanceof HttpStatusCodeException &&
                        ((HttpStatusCodeException) throwable).getStatusCode().value() == 401) {
                    handleDigestChallenge(ctx, msg, onSuccess, onFailure, throwable);
                } else {
                    onFailure.accept(processException(msg, throwable), throwable);
                }
            }

            @Override
            public void onSuccess(ResponseEntity<String> responseEntity) {
                if (responseEntity.getStatusCode().is2xxSuccessful()) {
                    onSuccess.accept(processResponse(ctx, msg, responseEntity));
                } else {
                    onFailure.accept(processFailureResponse(msg, responseEntity), null);
                }
            }
        });
    }

    private void handleDigestChallenge(TbContext ctx, TbMsg msg,
                                       Consumer<TbMsg> onSuccess,
                                       BiConsumer<TbMsg, Throwable> onFailure,
                                       Throwable throwable) {

        HttpStatusCodeException ex = (HttpStatusCodeException) throwable;
        String wwwAuthenticateHeader = ex.getResponseHeaders().getFirst("WWW-Authenticate");
        if (wwwAuthenticateHeader != null && wwwAuthenticateHeader.startsWith("Digest")) {
            //DigestCredentials digestCredentials = (DigestCredentials) config.getCredentials();
            String nonce = "", realm = "", opaque = "";
            String[] parts = wwwAuthenticateHeader.substring(7).split(",");
            for (String part : parts) {
                if (part.trim().startsWith("nonce=")) {
                    nonce = part.trim().substring(7).replaceAll("\"", "");
                }
                if (part.trim().startsWith("realm=")) {
                    realm = part.trim().substring(7).replaceAll("\"", "");
                }
                if (part.trim().startsWith("opaque=")) {
                    opaque = part.trim().substring(8).replaceAll("\"", "");
                }
            }
            retryWithDigestAuth(ctx, msg, onSuccess, onFailure, /*digestCredentials, */nonce, realm, opaque);
        } else {
            onFailure.accept(processException(msg, throwable), null);
        }
    }

    private void retryWithDigestAuth(TbContext ctx, TbMsg msg,
                                     Consumer<TbMsg> onSuccess,
                                     BiConsumer<TbMsg, Throwable> onFailure,
                                     //DigestCredentials credentials,
                                     String nonce, String realm, String opaque) {
        String endpointUrl = TbNodeUtils.processPattern(config.getRestEndpointUrlPattern(), msg);
        URI uri = buildEncodedUri(endpointUrl);
        HttpHeaders headers = prepareHeaders(msg);
        headers.add("Authorization", buildDigestAuthHeader(/*credentials, */nonce, realm, opaque, uri.getPath()));
        HttpMethod method = HttpMethod.valueOf(config.getRequestMethod());
        HttpEntity<String> entity;
        if (HttpMethod.GET.equals(method) || HttpMethod.HEAD.equals(method) ||
                HttpMethod.OPTIONS.equals(method) || HttpMethod.TRACE.equals(method)) {
            entity = new HttpEntity<>(headers);
        } else {
            entity = new HttpEntity<>(getData(msg, false, false), headers);
        }

        ListenableFuture<ResponseEntity<String>> retryFuture = httpClient.exchange(
            uri, method, entity, String.class);
        retryFuture.addCallback(new ListenableFutureCallback<>() {
            @Override
            public void onFailure(Throwable throwable) {
                onFailure.accept(processException(msg, throwable), throwable);
            }

            @Override
            public void onSuccess(ResponseEntity<String> responseEntity) {
                if (responseEntity.getStatusCode().is2xxSuccessful()) {
                    onSuccess.accept(processResponse(ctx, msg, responseEntity));
                } else {
                    onFailure.accept(processFailureResponse(msg, responseEntity), null);
                }
            }
        });
    }

    private String buildDigestAuthHeader(/*DigestCredentials credentials, */String nonce,
                                  String realm, String opaque, String uri) {
        String qop = "auth";
        byte[] randomBytes = new byte[16];
        new SecureRandom().nextBytes(randomBytes);
        String cnonce = new String(Base64.encodeBase64(randomBytes));
        //String username = credentials.getUsername();
        //String password = credentials.getPassword();
        String username = config.getUsername();
        String password = config.getPassword();
        String method = config.getRequestMethod();

        String ha1 = calculateMD5(username + ":" + realm + ":" + password);
        String ha2 = calculateMD5(method + ":" + uri);
        String response = calculateMD5(ha1 + ":" + nonce + ":00000001:" + cnonce + ":" + qop + ":" + ha2);

        String authHeader = "Digest " +
                "username=\"" + username + "\", " +
                "realm=\"" + realm + "\", " +
                "nonce=\"" + nonce + "\", " +
                "uri=\"" + uri + "\", " +
                "qop=" + qop + ", " +
                "nc=00000001, " +
                "cnonce=\"" + cnonce + "\", " +
                "response=\"" + response + "\", " +
                "opaque=\"" + opaque + "\"";

        return authHeader;
    }

    private String calculateMD5(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            return Hex.encodeHexString(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Error calculating MD5 hash", e);
        }
    }

    public URI buildEncodedUri(String endpointUrl) {
        if (endpointUrl == null) {
            throw new RuntimeException("Url string cannot be null!");
        }
        if (endpointUrl.isEmpty()) {
            throw new RuntimeException("Url string cannot be empty!");
        }

        URI uri = UriComponentsBuilder.fromUriString(endpointUrl).build().encode().toUri();
        if (uri.getScheme() == null || uri.getScheme().isEmpty()) {
            throw new RuntimeException("Transport scheme(protocol) must be provided!");
        }

        boolean authorityNotValid = uri.getAuthority() == null || uri.getAuthority().isEmpty();
        boolean hostNotValid = uri.getHost() == null || uri.getHost().isEmpty();
        if (authorityNotValid || hostNotValid) {
            throw new RuntimeException("Url string is invalid!");
        }

        return uri;
    }

    private String getData(TbMsg tbMsg, boolean ignoreBody, boolean parseToPlainText) {
        if (!ignoreBody && parseToPlainText) {
            return parseJsonStringToPlainText(tbMsg.getData());
        }
        return tbMsg.getData();
    }

    protected String parseJsonStringToPlainText(String data) {
        if (data.startsWith("\"") && data.endsWith("\"") && data.length() >= 2) {
            final String dataBefore = data;
            try {
                data = JacksonUtil.fromString(data, String.class);
            } catch (Exception ignored) {}
            log.trace("Trimming double quotes. Before trim: [{}], after trim: [{}]", dataBefore, data);
        }

        return data;
    }

    private TbMsg processResponse(TbContext ctx, TbMsg origMsg, ResponseEntity<String> response) {
        TbMsgMetaData metaData = origMsg.getMetaData();
        metaData.putValue(STATUS, response.getStatusCode().name());
        metaData.putValue(STATUS_CODE, response.getStatusCode().value() + "");
        metaData.putValue(STATUS_REASON, response.getStatusCode().getReasonPhrase());
        headersToMetaData(response.getHeaders(), metaData::putValue);
        String body = response.getBody() == null ? TbMsg.EMPTY_JSON_OBJECT : response.getBody();
        return ctx.transformMsg(origMsg, metaData, body);
    }

    void headersToMetaData(Map<String, List<String>> headers, BiConsumer<String, String> consumer) {
        if (headers == null) {
            return;
        }
        headers.forEach((key, values) -> {
            if (values != null && !values.isEmpty()) {
                if (values.size() == 1) {
                    consumer.accept(key, values.get(0));
                } else {
                    consumer.accept(key, JacksonUtil.toString(values));
                }
            }
        });
    }

    private TbMsg processFailureResponse(TbMsg origMsg, ResponseEntity<String> response) {
        TbMsgMetaData metaData = origMsg.getMetaData();
        metaData.putValue(STATUS, response.getStatusCode().name());
        metaData.putValue(STATUS_CODE, response.getStatusCode().value() + "");
        metaData.putValue(STATUS_REASON, response.getStatusCode().getReasonPhrase());
        metaData.putValue(ERROR_BODY, response.getBody());
        headersToMetaData(response.getHeaders(), metaData::putValue);
        return TbMsg.transformMsgMetadata(origMsg, metaData);
    }

    private TbMsg processException(TbMsg origMsg, Throwable e) {
        TbMsgMetaData metaData = origMsg.getMetaData();
        metaData.putValue(ERROR, e.getClass() + ": " + e.getMessage());
        if (e instanceof RestClientResponseException) {
            RestClientResponseException restClientResponseException = (RestClientResponseException) e;
            metaData.putValue(STATUS, restClientResponseException.getStatusText());
            metaData.putValue(STATUS_CODE, restClientResponseException.getRawStatusCode() + "");
            metaData.putValue(ERROR_BODY, restClientResponseException.getResponseBodyAsString());
        }
        return TbMsg.transformMsgMetadata(origMsg, metaData);
    }

    private HttpHeaders prepareHeaders(TbMsg msg) {
        HttpHeaders headers = new HttpHeaders();
        return headers;
    }

    private static void checkProxyHost(String proxyHost) throws TbNodeException {
        if (StringUtils.isEmpty(proxyHost)) {
            throw new TbNodeException("Proxy host can't be empty");
        }
    }

    private static void checkProxyPort(int proxyPort) throws TbNodeException {
        if (proxyPort < 0 || proxyPort > 65535) {
            throw new TbNodeException("Proxy port out of range:" + proxyPort);
        }
    }

}
