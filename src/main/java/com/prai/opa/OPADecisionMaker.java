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
    private static final String serverIP = "testserver";
    private static final String serverPort = "32323";
    private static final String coarsegrainedendpoint = "http://" + serverIP + ":" + serverPort + "/v1/data/authz/redfish/v1/policy";
    private static final String finegrainedendpoint = "http://" + serverIP + ":" + serverPort + "/v1/data/authz/redfish/v1/fine/policy";
    private static final String entrypoint = "authz/redfish/v1/policy/allow";
    private static final String entrypoint2 = "authz/redfish/v1/fine/policy/batch_allow";
    private static final Logger logger = LogManager.getLogger(OPADecisionMaker.class);
    private static String coarsedGrainedIRFile = "/repo/performanceTesting/performanceTesting/src/main/resources/coarse-grained-policies-plan.json";
    private static String fineGrainedIRFile = "/repo/performanceTesting/performanceTesting/src/main/resources/fine-grained-policies-plan.json";
    private static String coarsedGrainedWASMFile = "/repo/performanceTesting/performanceTesting/src/main/resources/coarsed-bundle.tar.gz";
    private static String fineGrainedWASMFile = "/repo/performanceTesting/performanceTesting/src/main/resources/finebundle.tar.gz";
    private static String coarsedGrainedentrypoint = "authz/redfish/v1/policy/allow";
    private static String fineGrainedentrypoint = "authz/redfish/v1/fine/policy/batch_allow";

    private static Plan coarsedGraindePlan;
    private static Plan fineGraindePlan;
    private static Bundle coarsedGrainedWASMBundle;

    private static Bundle fineGrainedWASMBundle;

    private static  OPAModule coarsedGrainedWASMModule;
    private static  OPAModule fineGrainedWASMModule;
    public static void init() throws IOException {
        var coarsedGrainedfile = new File(coarsedGrainedIRFile);
        coarsedGraindePlan=  Jarl.builder(coarsedGrainedfile).build().getPlan(coarsedGrainedentrypoint);
        var fineGrainedfile = new File(fineGrainedIRFile);
        fineGraindePlan= Jarl.builder(fineGrainedfile).build().getPlan(fineGrainedentrypoint);
        coarsedGrainedWASMBundle = BundleUtil.extractBundle(coarsedGrainedWASMFile);
        fineGrainedWASMBundle=  BundleUtil.extractBundle(fineGrainedWASMFile);
        coarsedGrainedWASMModule = new OPAModule(coarsedGrainedWASMBundle);
        fineGrainedWASMModule= new OPAModule(fineGrainedWASMBundle);
    }
    public static boolean isAllowedJarl(String uri, String method, List<String> roles) {
        boolean decision = false;

        Map<String, ?> data = Map.of();
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


    public static List<String> isAllowedJarl(List<String> uris, List<String> methods, List<String> roles) {
        //  String IRFile2= "/repo/policy/optimizedPlans/fine-grained-policies-plan.json";

        List<String> allowedUrls = Collections.EMPTY_LIST;
        Map<String, ?> data = Map.of();
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

    public static boolean isAllowed(String uri, String method, List<String> roles) {
        boolean opaDecision = false;
        ObjectMapper objectMapper = new ObjectMapper();
        SingleOPAInput input = new SingleOPAInput();
        input.setResource(uri);
        input.setMethod(method);
        input.setRoles(roles);
        SingleOPARequest opaRequest = new SingleOPARequest(input);
        HttpClient httpClient = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(Duration.ofSeconds(10))
                .build();
        SingleOPAResponse response;
        try {
            String inputJson = objectMapper.writeValueAsString(opaRequest);

        //    LOGGER.info("OPADecisionMaker InputJSON created .....{}", inputJson);

            HttpRequest httpRequest = HttpRequest.newBuilder()
                    .POST(HttpRequest.BodyPublishers.ofString(inputJson))
                    .uri(URI.create(coarsegrainedendpoint))
                    .setHeader("User-Agent", "PRASHANNA")
                    .build();

            HttpResponse<String> httpResponse = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());

            response = objectMapper.readValue(httpResponse.body(), SingleOPAResponse.class);

      //      LOGGER.info("OPADecisionMaker httpResponse Body....{}", httpResponse.body());

            opaDecision = response.getResult().isAllow();
     //       LOGGER.info("OPADecisionMaker Value of allow....{}", opaDecision);
            return response.getResult().isAllow();
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

    public static List<String> isAllowed(List<String> uris, List<String> methods, List<String> roles) {
        List<String> allowedUris = Collections.EMPTY_LIST;
        ObjectMapper objectMapper = new ObjectMapper();
        OPAInput1 input = new OPAInput1();
        input.setMethods(methods);
        input.setRoles(roles);
        input.setResources(uris);
        BulkOPARequest1 opaRequest = new BulkOPARequest1(input);

        HttpClient httpClient = HttpClient.newBuilder()
                .version(HttpClient.Version.HTTP_1_1)
                .connectTimeout(Duration.ofSeconds(10))
                .build();
        BulkOPAResponse response;
        try {
            String inputJson = objectMapper.writeValueAsString(opaRequest);

      //      LOGGER.info("OPADecisionMaker BulkInputJSON created .....{}", inputJson);

            HttpRequest httpRequest = HttpRequest.newBuilder()
                    .POST(HttpRequest.BodyPublishers.ofString(inputJson))
                    .uri(URI.create(finegrainedendpoint))
                    .setHeader("User-Agent", "PRASHANNA")
                    .build();

            HttpResponse<String> httpResponse = httpClient.send(httpRequest, HttpResponse.BodyHandlers.ofString());
            response = objectMapper.readValue(httpResponse.body(), BulkOPAResponse.class);
            allowedUris = response.getResult().getBatchAllow();
     //       LOGGER.info("OPADecisionMaker Bulk Value of allow .....{}", allowedUris);
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

    public static boolean isAllowedWASM(String uri, String method, List<String> roles) throws IOException {
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

    public static List<String> isAllowedWASM(List<String> uris, List<String> methods, List<String> roles) throws IOException {
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
