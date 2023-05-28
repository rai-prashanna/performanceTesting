package com.prai;

import com.prai.metrics.MyMetrics;
import com.prai.metrics.SettingEnum;
import com.prai.opa.*;
import io.prometheus.client.exporter.HTTPServer;
import org.apache.http.util.Args;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.List;
import io.prometheus.client.exporter.HTTPServer;
/**
 * Testing with Jarl, WASM binary, OPA REST library!
 */
public class LocalApp {
    private static final Logger logger = LogManager.getLogger(LocalApp.class);
    private static HTTPServer prometheusServer;

    public static void main(String[] args) throws URISyntaxException, IOException {
        // ARGS[0] -> SETTINGS (like OPA,JARL, PermissionHandler)
        // ARGS[1] -> prometheusExporterPort
        // ARGS[1] -> loop

        SettingEnum setting= SettingEnum.valueOf(args[0]);
        int port=Integer.valueOf(args[1]);
        int loops=Integer.valueOf(args[2]);

        String uri = "Chassis";
        String method = "GET";
        List<String> roles = Arrays.asList("OmcSecurityAdministrator", "default-roles-omc", "DeleteJob", "OmcEquipmentAdministrator", "offline_access", "OmcEquipmentObserver", "OmcSystemAdministrator", "uma_authorization", "CreateJob", "OmcSystemObserver");

        Authz wasmAuthz= WASMAuthz.getInstance();
        Authz opaRESTAuthz= OPARestAuthz.getInstance();
        Authz jarlAuthz= JARLAuthz.getInstance();
        wasmAuthz.init();
        opaRESTAuthz.init();
        jarlAuthz.init();

        List<String> nextroles = Arrays.asList("CreateJob",
                "DeleteJob",
                "OmcEquipmentAdministrator");
        List<String> uris = Arrays.asList("/TaskService/Tasks/1/",
                "files/upload/updateservice/package",
                "/TaskService/Tasks/3/",
                "Chassis");
        List<String> methods = Arrays.asList("GET", "GET", "GET", "GET");
        System.out.println("******************************************");
        prometheusServer = new HTTPServer(port);
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
        prometheusServer.close();

        System.out.println("******************************************");

//        System.out.println( "The value of decision from Jarl " );   ((JSONObject) ((JSONArray) test).get(0)).get("result")

    }
}


