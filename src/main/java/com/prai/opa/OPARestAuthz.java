package com.prai.opa;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Collections;
import java.util.List;

public class OPARestAuthz implements Authz{
    private HttpClient httpClient;
    private ObjectMapper objectMapper;
    private SingleOPAInput singleInput;
    private BulkOPAInput bulkInput;
    private BulkOPARequest bulkOPARequest;
    private SingleOPARequest singleOPARequest;

    private final String serverIP = "testserver";
    private final String serverPort = "32323";
    private final String coarsegrainedendpoint = "http://" + serverIP + ":" + serverPort + "/v1/data/authz/redfish/v1/policy";
    private final String finegrainedendpoint = "http://" + serverIP + ":" + serverPort + "/v1/data/authz/redfish/v1/fine/policy";
    private static final Logger logger = LogManager.getLogger(OPARestAuthz.class);
    private static OPARestAuthz instance=null;

    private OPARestAuthz(){}
    public static OPARestAuthz getInstance(){
        if (instance == null) {
            instance = new OPARestAuthz();
        }
        return instance;
    }
    public void initOPARESTMode(){
        httpClient = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(Duration.ofSeconds(10))
                .build();
        objectMapper = new ObjectMapper();
        singleInput = new SingleOPAInput();
        bulkInput= new BulkOPAInput();
        bulkOPARequest= new BulkOPARequest();
        singleOPARequest= new SingleOPARequest();
    }
    @Override
    public List<String> isAllowed(List<String> uris, List<String> methods, List<String> roles) {
        List<String> allowedUris = Collections.EMPTY_LIST;
        bulkInput.setMethods(methods);
        bulkInput.setRoles(roles);
        bulkInput.setResources(uris);
        bulkOPARequest.setInput(bulkInput);
        BulkOPAResponse response;
        try {
            String inputJson = objectMapper.writeValueAsString(bulkOPARequest);
            HttpRequest httpRequest = HttpRequest.newBuilder()
                    .POST(HttpRequest.BodyPublishers.ofString(inputJson))
                    .uri(URI.create(finegrainedendpoint))
                    .setHeader("User-Agent", "PRASHANNA")
                    .build();

            HttpResponse<String> httpResponse = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());
            response = objectMapper.readValue(httpResponse.body(), BulkOPAResponse.class);
            allowedUris = response.getResult().getBatchAllow();
        } catch (JsonProcessingException e) {
            logger.error("OPADecisionMaker Exception while processing Json  .....{}", e.toString());
        } catch (IOException e) {
            logger.error("OPADecisionMaker Exception while IO operations  .....{}", e.toString());
        } catch (InterruptedException e) {
            logger.error("OPADecisionMaker InterruptedException operations  .....{}", e.toString());
        } finally {
            return allowedUris;
        }
    }

    @Override
    public boolean isAllowed(String uri, String method, List<String> roles) {
        boolean opaDecision = false;
        singleInput.setResource(uri);
        singleInput.setMethod(method);
        singleInput.setRoles(roles);
        singleOPARequest.setInput(singleInput);
        SingleOPAResponse response;
        try {
            String inputJson = objectMapper.writeValueAsString(singleOPARequest);
            HttpRequest httpRequest = HttpRequest.newBuilder()
                    .POST(HttpRequest.BodyPublishers.ofString(inputJson))
                    .uri(URI.create(coarsegrainedendpoint))
                    .setHeader("User-Agent", "PRASHANNA")
                    .build();
            HttpResponse<String> httpResponse = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());

            response = objectMapper.readValue(httpResponse.body(), SingleOPAResponse.class);
            opaDecision = response.getResult().isAllow();
        } catch (JsonProcessingException e) {
            logger.info("OPADecisionMaker JsonProcessingException ....{}", e.toString());
        } catch (IOException e) {
            logger.info("OPADecisionMaker IOException ....{}", e.toString());
        } catch (InterruptedException e) {
            logger.info("OPADecisionMaker InterruptedException ....{}", e.toString());
        } finally {
            return opaDecision;
        }
    }

    @Override
    public void init() {
        initOPARESTMode();
    }
}
