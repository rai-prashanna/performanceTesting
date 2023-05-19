package com.prai;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

import static com.prai.Utility.printFile;
import static com.prai.Utility.printInputStream;

/**
 * Testing with Jarl library!
 *
 */
public class App1
{
    private static final Logger logger = LogManager.getLogger(App1.class);

    public static void main( String[] args )
    {
        Utility app =new Utility();
        String fileName = "coarse-grained-policies-plan.json";

        System.out.println("getResourceAsStream : " + fileName);
        InputStream is = app.getFileFromResourceAsStream(fileName);
        Utility.printInputStream(is);

        System.out.println("\ngetResource : " + fileName);
        File file = null;
        try {
            file = app.getFileFromResource(fileName);
        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
        printFile(file);
        System.out.println("************* : ");



        System.out.println( "******************************************" );
        String uri1="Chassis";
        String method1 = "GET";

        List<String> roles1=Arrays.asList("OmcSecurityAdministrator", "default-roles-omc", "DeleteJob", "OmcEquipmentAdministrator", "offline_access", "OmcEquipmentObserver", "OmcSystemAdministrator", "uma_authorization", "CreateJob", "OmcSystemObserver");
      //  boolean localDecision1= OPADecisionMaker.isAllowedWASM("Systems",method1,roles1);
        boolean localDecision= OPADecisionMaker.isAllowedJarl("files/upload/updateservice/package","POST",Arrays.asList("OmcEquipmentAdministrator"));
        logger.debug("the decision made by Jarl.......{}",localDecision);

        List<String> roles=Arrays.asList("CreateJob",
                "DeleteJob",
                "OmcEquipmentAdministrator");
        List<String> uris=Arrays.asList("/TaskService/Tasks/1/",
                "files/upload/updateservice/package",
                "/TaskService/Tasks/3/",
                "Chassis");
        List<String> methods=Arrays.asList("GET","GET","GET","GET");
      //  List<String> allowedUris=OPADecisionMaker.isAllowedWASM(uris,methods,roles);
        System.out.println( "******************************************" );
        logger.debug("*****END*****************");

//        System.out.println( "The value of decision from Jarl " );   ((JSONObject) ((JSONArray) test).get(0)).get("result")


    }
}


