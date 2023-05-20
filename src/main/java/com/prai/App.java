package com.prai;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.util.Properties;
import io.prometheus.client.exporter.HTTPServer;
import io.prometheus.client.hotspot.DefaultExports;

/**
 * Hello world!
 *
 */
public class App
{

    private static final Logger logger = LogManager.getLogger(App.class);

    public static void main( String[] args )
    {
        EMCClient.init(args[0]);
        logger.debug("Web server for Prometheus client exporter started..");
        try {
  //ARGS[0] -> nodePortServiceIP, ARGS[1] -> TOKEN, ARGS[2] -> SETTINGS
            HTTPServer server = new HTTPServer("localhost",9081);
            for (int i = 0; i < 8000; i++) {
                EMCClient.executeRequest("",args[1],SettingEnum.valueOf(args[2]));
            }
            server.close();
        } catch (NoSuchAlgorithmException e) {
            logger.debug("NoSuchAlgorithmException {}", e.getMessage());
        } catch (KeyManagementException e) {
            logger.debug("KeyManagementException {}", e.getMessage());
            throw new RuntimeException(e);
        } catch (IOException e) {
            logger.debug("IOException {}", e.getMessage());
        }
    }
}
