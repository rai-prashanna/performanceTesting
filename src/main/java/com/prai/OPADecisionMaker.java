package com.prai;

import by.borge.jarl.Jarl;
import java.io.File;
import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

public class OPADecisionMaker {
    private static String serverIP= "testserver";
    private static String serverPort= "32323";
    private static String coarsegrainedendpoint = "http://"+serverIP+":"+serverPort+"/v1/data/authz/redfish/v1/policy";
    private static String finegrainedendpoint = "http://"+serverIP+":"+serverPort+"/v1/data/authz/redfish/v1/fine/policy";

    private static String coarsedGrainedIRFile= "/repo/policy/optimizedPlans/coarse-grained-policies-plan.json";
    private static String coarsedGrainedentrypoint= "authz/redfish/v1/policy/allow";
    private static String fineGrainedIRFile= "/repo/policy/optimizedPlans/fine-grained-policies-plan.json";
    private static String fineGrainedIRFileentrypoint="authz/redfish/v1/fine/policy/batch_allow";
    public static boolean isAllowedJarl(String uri, String method, List<String> roles) {
        var file = new File(coarsedGrainedIRFile);
        boolean decision = false;

        Map<String, ?> data = Map.of();
        Map<String,Object> map = new HashMap<>();
        map.put("roles", roles);
        map.put("method",method);
        map.put("resource",uri);

        try {
            decision= Jarl.builder(file).build().getPlan(coarsedGrainedentrypoint).eval(map, data).allowed();
        } catch (IOException e) {
            System.out.println( "Exception while making decision by Jarl library " +e.getStackTrace() );
        }
        finally{
            return decision;
        }
    }


    public static List<String> isAllowedJarl(List < String > uris, List < String > methods, List < String > roles) {
      //  String IRFile2= "/repo/policy/optimizedPlans/fine-grained-policies-plan.json";
        var file = new File(fineGrainedIRFile);
        List<String> allowedUrls= Collections.EMPTY_LIST;
        Map<String, ?> data = Map.of();
        Map<String,Object> map = new HashMap<>();
        map.put("roles", roles);
        map.put("methods",methods);
        map.put("resources",uris);
        try {
            var resultSet = Jarl.builder(file)
                    .build()
                    .getPlan(fineGrainedIRFileentrypoint)
                    .eval(map, data);
            allowedUrls= (List<String>) resultSet.getFirst().getValue(List.class).stream().map(Object::toString).collect(Collectors.toList());
        } catch (IOException e) {
            System.out.println( "Exception while making decision by Jarl library " +e.getStackTrace() );
        }
        finally{
            return allowedUrls;
        }
    }

    }
