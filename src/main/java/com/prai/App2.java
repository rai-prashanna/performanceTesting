package com.prai;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

public class App2 {
    private static final Logger logger = LogManager.getLogger(App2.class);

    public static void main( String[] args ) throws URISyntaxException, IOException {
//        String uri1="Chassis";
//        String method1 = "GET";
//
//        List<String> roles1= Arrays.asList("OmcSecurityAdministrator", "default-roles-omc", "DeleteJob", "OmcEquipmentAdministrator", "offline_access", "OmcEquipmentObserver", "OmcSystemAdministrator", "uma_authorization", "CreateJob", "OmcSystemObserver");
//        boolean localDecision= OPADecisionMaker.isAllowedJarl("files/upload/updateservice/package","POST",Arrays.asList("OmcEquipmentAdministrator"));
//logger.debug("the local decision ...{}",localDecision);
        Utility app =new Utility();
        String fileName = "coarse-grained-policies-plan.json";
        URI fileURI = app.getPathsFromResourceJAR(fileName);
        System.out.println("The value of uri");
        System.out.println(fileURI);
    }
}
