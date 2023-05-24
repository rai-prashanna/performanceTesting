package com.prai;

import by.borge.jarl.Jarl;
import by.borge.jarl.Plan;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.sangkeon.opa.wasm.Bundle;
import io.github.sangkeon.opa.wasm.BundleUtil;
import io.github.sangkeon.opa.wasm.OPAModule;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

public class OPADecisionMaker {
    private static final String serverIP = "testserver";
    private static final String serverPort = "32323";
    private static final String coarsegrainedendpoint = "http://" + serverIP + ":" + serverPort + "/v1/data/authz/redfish/v1/policy";
    private static final String finegrainedendpoint = "http://" + serverIP + ":" + serverPort + "/v1/data/authz/redfish/v1/fine/policy";
    private static final String entrypoint = "authz/redfish/v1/policy/allow";
    private static final String entrypoint2 = "authz/redfish/v1/fine/policy/batch_allow";
    private static final Logger logger = LogManager.getLogger(OPADecisionMaker.class);
    private static String coarsedGrainedIRFile = "/opt/ericsson/hds/resources/coarse-grained-policies-plan.json";
    private static String fineGrainedIRFile = "/opt/ericsson/hds/resources/fine-grained-policies-plan.json";
    private static String coarsedGrainedentrypoint = "authz/redfish/v1/policy/allow";
    private static String fineGrainedentrypoint = "authz/redfish/v1/fine/policy/batch_allow";

    private static Plan coarsedGraindePlan;
    private static Plan fineGraindePlan;
    private static Bundle coarsedGrainedWASMBundle;

    private static Bundle fineGrainedWASMBundle;

    public static void init() throws IOException {
        var file = new File(coarsedGrainedIRFile);
        coarsedGraindePlan = Jarl.builder(file).build().getPlan(coarsedGrainedentrypoint);
        var file1 = new File(fineGrainedIRFile);
        fineGraindePlan = Jarl.builder(file).build().getPlan(fineGrainedentrypoint);
        coarsedGrainedWASMBundle = BundleUtil.extractBundle("/repo/policy/tmp/coarsed-bundle.tar.gz");
        fineGrainedWASMBundle=  BundleUtil.extractBundle("/repo/policy/unoptimizedWASM/finebundle.tar.gz");

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
            logger.info("OPADecisionMaker Jarl The value of Coarse-grained IR file ..... {}", decision);
            return decision;
        }
    }


    public static List<String> isAllowedJarl(List<String> uris, List<String> methods, List<String> roles) {
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
            logger.info("OPADecisionMaker Jarl The value of fine-grained IR file ..... {}", allowedUrls);
            return allowedUrls;
        }
    }

    public static boolean isAllowedWASM(String uri, String method, List<String> roles) throws IOException {
        Boolean opaDecision = false;
        ObjectMapper objectMapper = new ObjectMapper();
        WASMSingleInput input = new WASMSingleInput(method, uri, roles);

        try (
                OPAModule om = new OPAModule(coarsedGrainedWASMBundle);
        ) {
            String inputJson = objectMapper.writeValueAsString(input);
            String output = om.evaluate(inputJson, coarsedGrainedentrypoint);

            var rawoutput = objectMapper.readValue(output, WASMOutput[].class);
            System.out.println(output);
            opaDecision = rawoutput[0].isResult();
        }
        return opaDecision;
    }

    public static List<String> isAllowedWASM(List<String> uris, List<String> methods, List<String> roles) throws IOException {
        List<String> allowedURIS = Collections.EMPTY_LIST;
        ObjectMapper objectMapper = new ObjectMapper();
        WASMBulkInput input = new WASMBulkInput(methods, uris, roles);
        try (
                OPAModule om = new OPAModule(fineGrainedWASMBundle);
        ) {
            String inputJson = objectMapper.writeValueAsString(input);
            String output = om.evaluate(inputJson, fineGrainedentrypoint);
            var rawoutput = objectMapper.readValue(output, WASMBulkOutput[].class);
            System.out.println(rawoutput[0].getResult());
            allowedURIS = rawoutput[0].getResult();
        }
        return allowedURIS;
    }
}
