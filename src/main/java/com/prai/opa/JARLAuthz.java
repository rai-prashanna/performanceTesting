package com.prai.opa;

import by.borge.jarl.Jarl;
import by.borge.jarl.Plan;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

public class JARLAuthz implements FileBasedAuthz {
    private static final Logger logger = LogManager.getLogger(JARLAuthz.class);
    private Plan coarsedGraindePlan;
    private Plan fineGraindePlan;
    private HashMap<String, ?> data;
    private static JARLAuthz instance = null;
    private String coarsedGrainedIRFilePath;
    private String fineGrainedIRFilePath;

    private JARLAuthz() {
    }

    public static JARLAuthz getInstance() {
        if (instance == null) {
            instance = new JARLAuthz();
        }
        return instance;
    }

    public void initJARLMode() {

        var coarsedGrainedfile = new File(coarsedGrainedIRFilePath);
        try {
            coarsedGraindePlan = Jarl.builder(coarsedGrainedfile).build().getPlan(coarsedGrainedentrypoint);
        } catch (IOException e) {
            logger.info("OPADecisionMaker Exception while creating coarsedGraindePlan..... {}", e);
        }
        var fineGrainedfile = new File(fineGrainedIRFilePath);
        try {
            fineGraindePlan = Jarl.builder(fineGrainedfile).build().getPlan(fineGrainedentrypoint);
        } catch (IOException e) {
            logger.info("OPADecisionMaker Exception while creating fineGraindePlan..... {}", e);
        }

    }

    @Override
    public List<String> isAllowed(List<String> uris, List<String> methods, List<String> roles) {
        List<String> allowedUrls = Collections.EMPTY_LIST;
        Map<String, Object> map = new HashMap<>();
        map.put("roles", roles);
        map.put("methods", methods);
        map.put("resources", uris);
        try {
            var resultSet = fineGraindePlan.eval(map, data);
            allowedUrls = (List<String>) resultSet.getFirst().getValue(List.class).stream().map(Object::toString).collect(Collectors.toList());
        } catch (Exception e) {
            logger.info("OPADecisionMaker Exception while making decision by Jarl library  .....{}", e);
        } finally {
            return allowedUrls;
        }

    }

    @Override
    public boolean isAllowed(String uri, String method, List<String> roles) {
        boolean decision = false;
        Map<String, Object> map = new HashMap<>();
        map.put("roles", roles);
        map.put("method", method);
        map.put("resource", uri);
        try {
            decision = coarsedGraindePlan.eval(map, data).allowed();
        } catch (Exception e) {
            logger.info("OPADecisionMaker Exception while making decision by Jarl library ..... {}", e);
        } finally {
            return decision;
        }
    }

    @Override
    public void init() {
        initJARLMode();
    }

    @Override
    public void init(String file1, String file2) {
        this.coarsedGrainedIRFilePath = file1;
        this.fineGrainedIRFilePath = file2;
        init();
    }

    @Override
    public void init(String file1, String file2, String file3) {
        init(file1,file2);
        ObjectMapper mapper = new ObjectMapper();
        try {
            String path = file3;
            data = mapper.readValue(new File(path), HashMap.class);
        } catch (IOException e) {
            logger.info("OPADecisionMaker Exception while reading data.json ..... {}", e);
        }
    }

}
