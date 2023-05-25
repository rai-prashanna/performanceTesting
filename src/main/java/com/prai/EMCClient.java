package com.prai;

import org.apache.http.HttpHeaders;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Properties;
import com.prai.metrics.MyMetrics;
import com.prai.metrics.SettingEnum;
public class EMCClient {
    private static final Logger logger = LogManager.getLogger(EMCClient.class);

    private static String serverIP = "testserver";
    private static String serverPort = "30161";
    private static String testEndPoint = "";

    public static void init(String nodePortServiceIP){
        testEndPoint = "https://" + serverIP + ":" + nodePortServiceIP + "/redfish/v1/Systems";
    }
    public static void executeRequest(String url, String token,SettingEnum flag) throws NoSuchAlgorithmException, KeyManagementException, IOException {
//        HttpGet request = new HttpGet("https://www.example.com/");
        CloseableHttpClient client = getSSLDisableHTTPClient();
        MyMetrics.startAuthzDecisionTimer(flag);
        HttpGet request = new HttpGet(testEndPoint);
        // add request headers
        request.addHeader("Authorization", "Bearer " + token);
        request.addHeader(HttpHeaders.USER_AGENT, "PRAIBot");
        CloseableHttpResponse response = client.execute(request);
        MyMetrics.stopAuthzDecisionTimer(flag);
        int statusCode = response.getStatusLine().getStatusCode();
        logger.debug("respose code {}", statusCode);
    }

    public static CloseableHttpClient getSSLDisableHTTPClient() throws KeyManagementException, NoSuchAlgorithmException {
        final Properties props = System.getProperties();
        props.setProperty("jdk.internal.httpclient.disableHostnameVerification", Boolean.TRUE.toString());

        SSLContext context = SSLContext.getInstance("TLSv1.2");
        TrustManager[] trustManager = new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }

                    public void checkClientTrusted(X509Certificate[] certificate, String str) {
                    }

                    public void checkServerTrusted(X509Certificate[] certificate, String str) {
                    }
                }
        };
        context.init(null, trustManager, new SecureRandom());

        SSLConnectionSocketFactory socketFactory = new SSLConnectionSocketFactory(context,
                SSLConnectionSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER);

        CloseableHttpClient client = HttpClientBuilder.create().setSSLSocketFactory(socketFactory).build();
        return client;
    }

}
