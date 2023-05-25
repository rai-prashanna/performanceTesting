package com.prai;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;

public class App2 {
    private static final Logger logger = LogManager.getLogger(App2.class);

    public static void main( String[] args ) throws URISyntaxException, IOException {
        Utility app =new Utility();
        String fileName = "coarse-grained-policies-plan.json";
        URI fileURI = app.getPathsFromResourceJAR(fileName);
        System.out.println("The value of uri");
        System.out.println(fileURI);
    }
}
