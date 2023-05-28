package com.prai.opa;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.sangkeon.opa.wasm.Bundle;
import io.github.sangkeon.opa.wasm.BundleUtil;
import io.github.sangkeon.opa.wasm.OPAModule;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import java.io.IOException;
import java.util.Collections;
import java.util.List;

public class WASMAuthz implements Authz{
    private Bundle coarsedGrainedWASMBundle;

    private Bundle fineGrainedWASMBundle;

    private OPAModule coarsedGrainedWASMModule;
    private OPAModule fineGrainedWASMModule;
    private static final Logger logger = LogManager.getLogger(WASMAuthz.class);
    private static WASMAuthz instance=null;

    private WASMAuthz(){}
    public static WASMAuthz getInstance(){
        if (instance == null) {
            instance = new WASMAuthz();
        }
        return instance;
    }
    public void initWASMMode(){
        String coarsedGrainedWASMPath = "/repo/policy/unoptimizedWASM/coarsed-bundle.tar.gz";
        String fineGrainedWASMPath = "/repo/policy/unoptimizedWASM/finebundle.tar.gz";
        try {
            coarsedGrainedWASMBundle = BundleUtil.extractBundle(coarsedGrainedWASMPath);
        } catch (IOException e) {
            logger.info("OPADecisionMaker Exception while using Bundle  ..... {}", e);
        }
        try {
            fineGrainedWASMBundle=  BundleUtil.extractBundle(fineGrainedWASMPath);
        } catch (IOException e) {
            logger.info("OPADecisionMaker Exception while using Bundle  ..... {}", e);
        }
        coarsedGrainedWASMModule = new OPAModule(coarsedGrainedWASMBundle);
        fineGrainedWASMModule= new OPAModule(fineGrainedWASMBundle);
    }
    @Override
    public List<String> isAllowed(List<String> uris, List<String> methods, List<String> roles) {
        List<String> allowedURIS = Collections.EMPTY_LIST;
        ObjectMapper objectMapper = new ObjectMapper();
        WASMBulkInput input = new WASMBulkInput(methods, uris, roles);
        {
            String inputJson = null;
            try {
                inputJson = objectMapper.writeValueAsString(input);
            } catch (JsonProcessingException e) {
                throw new RuntimeException(e);
            }
            String output = fineGrainedWASMModule.evaluate(inputJson, fineGrainedentrypoint);
            WASMBulkOutput[] rawoutput = new WASMBulkOutput[0];
            try {
                rawoutput = objectMapper.readValue(output, WASMBulkOutput[].class);
            } catch (JsonProcessingException e) {
                logger.info("OPADecisionMaker Exception while processing JSON ..... {}", e);
            }
            allowedURIS = rawoutput[0].getResult();
        }
        return allowedURIS;
    }

    @Override
    public boolean isAllowed(String uri, String method, List<String> roles) {
        Boolean opaDecision = false;
        ObjectMapper objectMapper = new ObjectMapper();
        WASMSingleInput input = new WASMSingleInput(method, uri, roles);
        {
            String inputJson = null;
            try {
                inputJson = objectMapper.writeValueAsString(input);
            } catch (JsonProcessingException e) {
                throw new RuntimeException(e);
            }
            String output =coarsedGrainedWASMModule.evaluate(inputJson, coarsedGrainedentrypoint);

            WASMOutput[] rawoutput = new WASMOutput[0];
            try {
                rawoutput = objectMapper.readValue(output, WASMOutput[].class);
            } catch (JsonProcessingException e) {
                logger.info("OPADecisionMaker Exception while processing JSON ..... {}", e);
            }
            opaDecision = rawoutput[0].isResult();
        }
        return opaDecision;
    }

    @Override
    public void init() {
initWASMMode();
    }
}
