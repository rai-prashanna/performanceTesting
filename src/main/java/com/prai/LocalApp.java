package com.prai;

import com.prai.authorization.PermissionHandler;
import com.prai.metrics.MyMetrics;
import com.prai.metrics.SettingEnum;
import com.prai.opa.OPADecisionMaker;
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
 * Testing with Jarl library!
 */
public class LocalApp {
    private static final Logger logger = LogManager.getLogger(LocalApp.class);
    private static HTTPServer prometheusServer;

    public static void main(String[] args) throws URISyntaxException, IOException {
        // ARGS[0] -> SETTINGS (like OPA,JARL, PermissionHandler)
        // ARGS[1] -> prometheusExporterPort
        // ARGS[1] -> loop
        int loops=Integer.valueOf(args[2]);
        int port=Integer.valueOf(args[1]);
        SettingEnum setting= SettingEnum.valueOf(args[0]);
        String uri = "Chassis";
        String method = "GET";
        List<String> roles = Arrays.asList("OmcSecurityAdministrator", "default-roles-omc", "DeleteJob", "OmcEquipmentAdministrator", "offline_access", "OmcEquipmentObserver", "OmcSystemAdministrator", "uma_authorization", "CreateJob", "OmcSystemObserver");
        OPADecisionMaker.init();
        PermissionHandler.getInstance();

        String uri1="/redfish/v1/Chassis";
//        List<String> nextroles = Arrays.asList("CreateJob",
//                "DeleteJob",
//                "OmcEquipmentAdministrator");
//        List<String> uris = Arrays.asList("/TaskService/Tasks/1/",
//                "files/upload/updateservice/package",
//                "/TaskService/Tasks/3/",
//                "Chassis");
//        List<String> methods = Arrays.asList("GET", "GET", "GET", "GET");
//        OPADecisionMaker.getInstance().isAllowedOPA(uri,method,
//                roles);
//        OPADecisionMaker.getInstance().isAllowedJarl(uri,method,
//                roles);
//     OPADecisionMaker.getInstance().isAllowedJarl(uris,methods,
//                nextroles);
        prometheusServer = new HTTPServer(port);
        for (int i = 0; i < loops; i++) {
            if(setting==SettingEnum.JARL){
                MyMetrics.startAuthzDecisionTimer(SettingEnum.JARL);
                boolean wasmdecision=OPADecisionMaker.getInstance().isAllowedJarl(uri, method, roles);
                MyMetrics.stopAuthzDecisionTimer(SettingEnum.JARL);
            }
            if(setting==SettingEnum.OPA){
                MyMetrics.startAuthzDecisionTimer(SettingEnum.OPA);
                boolean opadecision=OPADecisionMaker.getInstance().isAllowedOPA(uri, method, roles);
                MyMetrics.stopAuthzDecisionTimer(SettingEnum.OPA);
            }
            if(setting==SettingEnum.WASM){
                MyMetrics.startAuthzDecisionTimer(SettingEnum.WASM);
                boolean wasmdecision=OPADecisionMaker.getInstance().isAllowedWASM(uri, method, roles);
                MyMetrics.stopAuthzDecisionTimer(SettingEnum.WASM);
            }
            if(setting==SettingEnum.PH){
                MyMetrics.startAuthzDecisionTimer(SettingEnum.PH);
                boolean phdecision=PermissionHandler.getInstance().isAllowed(roles, method, uri1);
                MyMetrics.stopAuthzDecisionTimer(SettingEnum.PH);
            }
            logger.debug("Iteration : {}", i);
        }
        prometheusServer.close();

//        String uri1="Chassis";
//        String method1 = "GET";
//        List<String> roles1=Arrays.asList("OmcEquipmentAdministrator");
//        boolean localDecision= OPADecisionMaker.isAllowedWASM(uri1,method1,roles1);

//        List<String> allowedUris = OPADecisionMaker.isAllowedWASM(uris, methods, nextroles);
//        System.out.println("******************************************");

//        System.out.println( "The value of decision from Jarl " );   ((JSONObject) ((JSONArray) test).get(0)).get("result")

    }
}


