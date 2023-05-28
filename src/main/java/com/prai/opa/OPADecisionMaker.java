package com.prai.opa;

import by.borge.jarl.Jarl;
import by.borge.jarl.Plan;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.sangkeon.opa.wasm.Bundle;
import io.github.sangkeon.opa.wasm.BundleUtil;
import io.github.sangkeon.opa.wasm.OPAModule;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class OPADecisionMaker {
    private final String serverIP = "localhost";
    private final String serverPort = "8181";
    private final String coarsegrainedendpoint = "http://" + serverIP + ":" + serverPort + "/v1/data/authz/redfish/v1/policy";
    private final String finegrainedendpoint = "http://" + serverIP + ":" + serverPort + "/v1/data/authz/redfish/v1/fine/policy";
    private static final Logger logger = LogManager.getLogger(OPADecisionMaker.class);
    private final String coarsedGrainedentrypoint = "authz/redfish/v1/policy/allow";
    private final String fineGrainedentrypoint = "authz/redfish/v1/fine/policy/batch_allow";
    private Plan coarsedGraindePlan;
    private static Plan fineGraindePlan;
    private Bundle coarsedGrainedWASMBundle;

    private Bundle fineGrainedWASMBundle;

    private OPAModule coarsedGrainedWASMModule;
    private OPAModule fineGrainedWASMModule;
    private HashMap<String,?> data;
    private static OPADecisionMaker instance=null;
    private HttpClient httpClient;

    private ObjectMapper objectMapper;

    private SingleOPAInput singleInput;
    private BulkOPAInput bulkInput;
    private BulkOPARequest bulkOPARequest;
    private SingleOPARequest singleOPARequest;

    public OPADecisionMaker(){

    }
    public static OPADecisionMaker getInstance(){
        if (instance == null) {
            instance = new OPADecisionMaker();
        }
        return instance;
    }
    public static void init() throws IOException {

        OPADecisionMaker.getInstance().initOPARESTMode();
        OPADecisionMaker.getInstance().initWASMMode();
        OPADecisionMaker.getInstance().initJARLMode();
    }
    private void initJARLMode(){
        String coarsedGrainedIRFilePath = "/repo/policy/optimizedPlans/coarse-grained-policies-plan.json";
        String fineGrainedIRFilePath = "/repo/policy/optimizedPlans/fine-grained-policies-plan.json";
        var coarsedGrainedfile = new File(coarsedGrainedIRFilePath);
        try {
            coarsedGraindePlan=  Jarl.builder(coarsedGrainedfile).build().getPlan(coarsedGrainedentrypoint);
        } catch (IOException e) {
            logger.info("OPADecisionMaker Exception while creating coarsedGraindePlan..... {}", e);
        }
        var fineGrainedfile = new File(fineGrainedIRFilePath);
        try {
            fineGraindePlan= Jarl.builder(fineGrainedfile).build().getPlan(fineGrainedentrypoint);
        } catch (IOException e) {
            logger.info("OPADecisionMaker Exception while creating fineGraindePlan..... {}", e);
        }
        ObjectMapper mapper = new ObjectMapper();
        try {
            data =mapper.readValue(new File("/repo/policy/unoptimizedPlans/data.json"),HashMap.class);
        } catch (IOException e) {
            logger.info("OPADecisionMaker Exception while reading data.json ..... {}", e);
        }
    }
    private void initWASMMode(){
      String coarsedGrainedWASMPath = "/repo/policy/unoptimizedWASM/coarsed-bundle.tar.gz";
       String fineGrainedWASMPath = "/repo/policy/unoptimizedWASM/finebundle.tar.gz";
        try {
            coarsedGrainedWASMBundle = BundleUtil.extractBundle(coarsedGrainedWASMPath);
        } catch (IOException e) {
            logger.info("OPADecisionMaker Exception while using Bundle  ..... {}", e);
        }
        try {
            fineGrainedWASMBundle=  BundleUtil.extractBundle(fineGrainedWASMPath);
        } catch (IOException e) {
            logger.info("OPADecisionMaker Exception while using Bundle  ..... {}", e);
        }
        coarsedGrainedWASMModule = new OPAModule(coarsedGrainedWASMBundle);
        fineGrainedWASMModule= new OPAModule(fineGrainedWASMBundle);
    }
    private void initOPARESTMode(){
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
    public List<String> isAllowedOPA(List<String> uris, List<String> methods, List<String> roles) {
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
    public boolean isAllowedOPA(String uri, String method, List<String> roles) {
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



    public boolean isAllowedJarl(String uri, String method, List<String> roles) {
        boolean decision = false;
        Map<String, Object> map = new HashMap<>();
        map.put("roles", roles);
        map.put("method", method);
        map.put("resource", uri);
        try {
            decision = coarsedGraindePlan.eval(map, data).allowed();
        } catch (Exception e) {
            logger.info("OPADecisionMaker Exception while making decision by Jarl library ..... {}", e);
        } finally {
            return decision;
        }
    }


    public List<String> isAllowedJarl(List<String> uris, List<String> methods, List<String> roles) {
        List<String> allowedUrls = Collections.EMPTY_LIST;
        Map<String, Object> map = new HashMap<>();
        map.put("roles", roles);
        map.put("methods", methods);
        map.put("resources", uris);
        try {
            var resultSet = fineGraindePlan.eval(map, data);
            allowedUrls = (List<String>) resultSet.getFirst().getValue(List.class).stream().map(Object::toString).collect(Collectors.toList());
        } catch (Exception e) {
            logger.info("OPADecisionMaker Exception while making decision by Jarl library  .....{}", e);
        } finally {
            return allowedUrls;
        }
    }

    public boolean isAllowedWASM(String uri, String method, List<String> roles) throws IOException {
        Boolean opaDecision = false;
        ObjectMapper objectMapper = new ObjectMapper();
        WASMSingleInput input = new WASMSingleInput(method, uri, roles);
{
            String inputJson = objectMapper.writeValueAsString(input);
            String output =coarsedGrainedWASMModule.evaluate(inputJson, coarsedGrainedentrypoint);

            var rawoutput = objectMapper.readValue(output, WASMOutput[].class);
            opaDecision = rawoutput[0].isResult();
        }
        return opaDecision;
    }

    public List<String> isAllowedWASM(List<String> uris, List<String> methods, List<String> roles) throws IOException {
        List<String> allowedURIS = Collections.EMPTY_LIST;
        ObjectMapper objectMapper = new ObjectMapper();
        WASMBulkInput input = new WASMBulkInput(methods, uris, roles);
{
            String inputJson = objectMapper.writeValueAsString(input);
            String output = fineGrainedWASMModule.evaluate(inputJson, fineGrainedentrypoint);
            var rawoutput = objectMapper.readValue(output, WASMBulkOutput[].class);
            allowedURIS = rawoutput[0].getResult();
        }
        return allowedURIS;
    }
}
