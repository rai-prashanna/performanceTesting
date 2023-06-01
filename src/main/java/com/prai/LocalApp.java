package com.prai;

import com.prai.opa.Authz;
import com.prai.opa.FileBasedAuthz;
import com.prai.opa.JARLAuthz;
import io.prometheus.client.exporter.HTTPServer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.List;

/**
 * Testing with Jarl library!
 */
public class LocalApp {
    private static final Logger logger = LogManager.getLogger(LocalApp.class);
    private static HTTPServer prometheusServer;

    public static void main(String[] args) throws URISyntaxException, IOException {
        // ARGS[0] -> SETTINGS (like OPA,JARL, PermissionHandler)
        // ARGS[1] -> prometheusExporterPort
        // ARGS[1] -> loop
//        int loops=Integer.valueOf(args[2]);
//        int port=Integer.valueOf(args[1]);
//        SettingEnum setting= SettingEnum.valueOf(args[0]);
        String uri = "BlueService";
        String method = "GET";
        List<String> roles = Arrays.asList("SystemModerator");

        String baseDir = "/repo/performanceTesting/performanceTesting/grafana-prometheus/opa/unoptimizedPlans/";
        String corasedGrainedFilePath = baseDir + "coarsed-grained-policy-plan.json";
        String fineGrainedFilePath = baseDir + "fine-grained-policy-plan.json";
        FileBasedAuthz unoptijarlAuthz = JARLAuthz.getInstance();
        String dataPath="/repo/performanceTesting/performanceTesting/grafana-prometheus/opa/raw/data.json";
        unoptijarlAuthz.init(corasedGrainedFilePath, fineGrainedFilePath,dataPath);
        boolean decision = unoptijarlAuthz.isAllowed(uri, method, roles);
        List<String> nextroles = Arrays.asList("SystemModerator", "invalidRole","SchoolAdmin");
        List<String> uris = Arrays.asList("BlueService",
                "files/upload/updateservice/Datapackage",
                "files/upload/updateservice/Datapackage",
                "Ioe/Prai_1/Containerss/prai/Actions/Prai2Containers.DisconnectManualSelectedDoors",
                "Ioe/Prai_1/Containerss/prai/Actions/Prai2Containers.CreateZWithAutomaticConnectivityForSelectedDoors");

        List<String> methods = Arrays.asList("GET", "GET", "POST","POST","POST");
        var decisions = unoptijarlAuthz.isAllowed(uris, methods, nextroles);

        String baseOptiDir="/repo/performanceTesting/performanceTesting/grafana-prometheus/opa/optimizedPlans";
        String corasedGrainedOptiFilePath = baseDir + "coarsed-grained-policy-plan.json";
        String fineGrainedOptiFilePath = baseDir + "fine-grained-policy-plan.json";
        FileBasedAuthz optijarlAuthz = JARLAuthz.getInstance();
        optijarlAuthz.init(corasedGrainedOptiFilePath, fineGrainedOptiFilePath);
        boolean decision1 = optijarlAuthz.isAllowed(uri, method, roles);
        var decisions1 = optijarlAuthz.isAllowed(uris, methods, nextroles);

        System.out.println("******************************************");
/*        prometheusServer = new HTTPServer(port);
        for (int i = 0; i < loops; i++) {
            if(setting==SettingEnum.JARL){
                MyMetrics.startAuthzDecisionTimer(SettingEnum.JARL);
                boolean jarlDecision=jarlAuthz.isAllowed(uri, method, roles);
                jarlAuthz.isAllowed(uris, methods, nextroles);
                MyMetrics.stopAuthzDecisionTimer(SettingEnum.JARL);
            }
            if(setting==SettingEnum.OPA){
                MyMetrics.startAuthzDecisionTimer(SettingEnum.OPA);
                boolean opaDecision=opaRESTAuthz.isAllowed(uri, method, roles);
                opaRESTAuthz.isAllowed(uris, methods, nextroles);
                MyMetrics.stopAuthzDecisionTimer(SettingEnum.OPA);
            }
            if(setting==SettingEnum.WASM){
                MyMetrics.startAuthzDecisionTimer(SettingEnum.WASM);
                boolean wasmdecision=wasmAuthz.isAllowed(uri, method, roles);
                wasmAuthz.isAllowed(uris, methods, nextroles);
                MyMetrics.stopAuthzDecisionTimer(SettingEnum.WASM);
            }
            logger.debug("Iteration : {}", i);
        }
        prometheusServer.close();*/

        System.out.println("******************************************");


    }
}


