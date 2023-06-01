package com.prai;

import com.prai.opa.Authz;
import com.prai.opa.JARLAuthz;
import io.prometheus.client.exporter.HTTPServer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.List;

/**
 * Testing with Jarl, WASM binary, OPA REST library!
 */
public class LocalApp1 {
    private static final Logger logger = LogManager.getLogger(LocalApp1.class);
    private static HTTPServer prometheusServer;

    public static void main(String[] args) throws URISyntaxException, IOException {
        // ARGS[0] -> SETTINGS (like OPA,JARL, PermissionHandler)
        // ARGS[1] -> prometheusExporterPort
        // ARGS[1] -> loop

//        SettingEnum setting= SettingEnum.valueOf(args[0]);
//        int port=Integer.valueOf(args[1]);
//        int loops=Integer.valueOf(args[2]);

        String uri = "BlueService";
        String method = "GET";
        List<String> roles = Arrays.asList("SystemModerator");

//        Authz wasmAuthz= WASMAuthz.getInstance();
        Authz optijarlAuthz = JARLAuthz.getInstance();

//        Authz opaRESTAuthz= OPARestAuthz.getInstance();
//        opaRESTAuthz.init();
        // boolean test =opaRESTAuthz.isAllowed(uri,method,roles);
//        wasmAuthz.init();
        optijarlAuthz.init();
        //   boolean output= optijarlAuthz.isAllowed(uri, method, roles);

        List<String> nextroles = Arrays.asList("SystemModerator",
                "invalidRole");
        List<String> uris = Arrays.asList("BlueService",
                "files/upload/updateservice/Datapackage");
        List<String> methods = Arrays.asList("GET", "GET");
        var test = optijarlAuthz.isAllowed(uris, methods, nextroles);
        System.out.println("******************************************");
/*AuthzMetrics metric=new OPAAuthzMetrics();
        prometheusServer = new HTTPServer(port);
        for (int i = 0; i < loops; i++) {
            if(setting==SettingEnum.JARL){
                MyMetrics.startAuthzDecisionTimer(SettingEnum.JARL);
                boolean jarlDecision=jarlAuthz.isAllowed(uri, method, roles);
                jarlAuthz.isAllowed(uris, methods, nextroles);
                MyMetrics.stopAuthzDecisionTimer(SettingEnum.JARL);
            }
            if(setting==SettingEnum.OPA){
                metric.startRequestResponseTimer();
                System.out.println("******************************************");
                System.out.println("******************************************");

                metric.startAuthzDecisionTimer();
                boolean opaDecision=opaRESTAuthz.isAllowed(uri, method, roles);
                opaRESTAuthz.isAllowed(uris, methods, nextroles);
                metric.stopAuthzDecisionTimer();
                System.out.println("******************************************");
                System.out.println("******************************************");
                metric.stopRequestResponseTimer();
            }
            if(setting==SettingEnum.WASM){
                MyMetrics.startAuthzDecisionTimer(SettingEnum.WASM);
//                boolean wasmdecision=wasmAuthz.isAllowed(uri, method, roles);
//                wasmAuthz.isAllowed(uris, methods, nextroles);
                MyMetrics.stopAuthzDecisionTimer(SettingEnum.WASM);
            }
            logger.debug("Iteration : {}", i);
        }
        prometheusServer.close();*/

        System.out.println("******************************************");

//        System.out.println( "The value of decision from Jarl " );   ((JSONObject) ((JSONArray) test).get(0)).get("result")

    }
}


