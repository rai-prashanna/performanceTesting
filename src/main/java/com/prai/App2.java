package com.prai;

import java.util.Arrays;
import java.util.List;

public class App2 {
    public static void main( String[] args ){
        System.out.println( "******************************************" );
        String uri1="Chassis";
        String method1 = "GET";

        List<String> roles1= Arrays.asList("OmcSecurityAdministrator", "default-roles-omc", "DeleteJob", "OmcEquipmentAdministrator", "offline_access", "OmcEquipmentObserver", "OmcSystemAdministrator", "uma_authorization", "CreateJob", "OmcSystemObserver");
        //  boolean localDecision1= OPADecisionMaker.isAllowedWASM("Systems",method1,roles1);

        boolean localDecision= OPADecisionMaker.isAllowedJarl("files/upload/updateservice/package","POST",Arrays.asList("OmcEquipmentAdministrator"));
        System.out.println("the local decision : " + localDecision);

    }
}
