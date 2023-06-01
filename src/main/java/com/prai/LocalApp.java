package com.prai;

import com.prai.metrics.AuthzMetrics;
import com.prai.metrics.JarlAuthzMetrics;
import com.prai.metrics.OPAAuthzMetrics;
import com.prai.metrics.SettingEnum;
import com.prai.opa.Authz;
import com.prai.opa.FileBasedAuthz;
import com.prai.opa.JARLAuthz;
import com.prai.opa.OPARestAuthz;
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

        String baseDir = "/repo/performanceTesting/performanceTesting/grafana-prometheus/opa/unoptimizedPlans/";
        String corasedGrainedFilePath = baseDir + "coarsed-grained-policy-plan.json";
        String fineGrainedFilePath = baseDir + "fine-grained-policy-plan.json";
        FileBasedAuthz unoptijarlAuthz = JARLAuthz.getInstance();
        String dataPath="/repo/performanceTesting/performanceTesting/grafana-prometheus/opa/raw/data.json";
        unoptijarlAuthz.init(corasedGrainedFilePath, fineGrainedFilePath,dataPath);

//        String baseOptiDir="/repo/performanceTesting/performanceTesting/grafana-prometheus/opa/optimizedPlans";
//        String corasedGrainedOptiFilePath = baseDir + "coarsed-grained-policy-plan.json";
//        String fineGrainedOptiFilePath = baseDir + "fine-grained-policy-plan.json";
//        FileBasedAuthz optijarlAuthz = JARLAuthz.getInstance();
//        optijarlAuthz.init(corasedGrainedOptiFilePath, fineGrainedOptiFilePath);
//        boolean decision1 = optijarlAuthz.isAllowed(uri, method, roles);
//        var decisions1 = optijarlAuthz.isAllowed(uris, methods, nextroles);
        Authz opaauthz= OPARestAuthz.getInstance();
        opaauthz.init();
        System.out.println("******************************************");
        String uri = "BlueService";
        String method = "GET";
        List<String> roles = Arrays.asList("SystemModerator");
        List<String> nextroles = Arrays.asList("SystemModerator", "invalidRole","SchoolAdmin");
        List<String> uris = Arrays.asList("BlueService",
                "files/upload/updateservice/Datapackage",
                "files/upload/updateservice/Datapackage",
                "Ioe/Prai_1/Containerss/prai/Actions/Prai2Containers.DisconnectManualSelectedDoors",
                "Ioe/Prai_1/Containerss/prai/Actions/Prai2Containers.CreateZWithAutomaticConnectivityForSelectedDoors");

        List<String> methods = Arrays.asList("GET", "GET", "POST","POST","POST");

        SettingEnum setting= SettingEnum.valueOf(args[0]);
        int port=Integer.valueOf(args[1]);
        int loops=Integer.valueOf(args[2]);
AuthzMetrics jarlMetrics= JarlAuthzMetrics.getInstance();
AuthzMetrics opaMetrics= OPAAuthzMetrics.getInstance();
        prometheusServer = new HTTPServer(port);
        for (int i = 0; i < loops; i++) {
            if(setting==SettingEnum.JARL){
                jarlMetrics.startAuthzDecisionTimer();

                boolean decision = unoptijarlAuthz.isAllowed(uri, method, roles);

                var decisions = unoptijarlAuthz.isAllowed(uris, methods, nextroles);
                jarlMetrics.stopAuthzDecisionTimer();
            }
            if(setting==SettingEnum.OPA){
                opaMetrics.startAuthzDecisionTimer();
                var result=opaauthz.isAllowed(uri,method,roles);
                var result1=opaauthz.isAllowed(uris,methods,nextroles);
                opaMetrics.stopAuthzDecisionTimer();
            }
            logger.debug("Iteration : {}", i);
        }
        prometheusServer.close();
        System.out.println("******************************************");
    }
}


