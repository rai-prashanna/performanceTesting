package com.prai;

import com.prai.metrics.SettingEnum;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;

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
        int loops= Integer.parseInt(args[3]);
        logger.debug("Web server for Prometheus client exporter started..");
        try {
  //ARGS[0] -> nodePortServiceIP,
  // ARGS[1] -> TOKEN,
  // ARGS[2] -> SETTINGS (like OPA,JARL, PermissionHandler)
  // ARGS[3] -> numberOfLoops
  // ARGS[4] -> exporterPort
            //HTTPServer server = new HTTPServer("localhost",Integer.valueOf(args[4]));
            for (int i = 0; i < loops; i++) {
                EMCClient.executeRequest("",args[1], SettingEnum.valueOf(args[2]));
            }
          //  server.close();
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
