package com.prai.metrics;

import io.prometheus.client.Summary;
import io.prometheus.client.Summary.Timer;

public class OPAAuthzMetrics implements AuthzMetrics {
    private static final Summary opaAuthzDecisionLatency = Summary.build()
            .name("opa_decision_latency_seconds")
            .help("opa HTTP server spend on authorization decision latency in seconds")
            .register();
    private static final Summary opaAuthzRequestResponseLatency = Summary.build()
            .name("opa_requests_response_latency_seconds")
            .help("opa authorization request-response latency in seconds")
            .register();
    private static Timer opaDecisionTimer;
    private static Timer opaRequestResponseTimer;
    private static OPAAuthzMetrics instance = null;

    private OPAAuthzMetrics() {
    }

    public static OPAAuthzMetrics getInstance() {
        if (instance == null) {
            instance = new OPAAuthzMetrics();
        }
        return instance;
    }

    @Override
    public void startAuthzDecisionTimer() {
        opaDecisionTimer = opaAuthzDecisionLatency.startTimer();

    }

    @Override
    public void stopAuthzDecisionTimer() {
        opaDecisionTimer.observeDuration();
    }

    @Override
    public void startRequestResponseTimer() {
        opaRequestResponseTimer = opaAuthzRequestResponseLatency.startTimer();

    }

    @Override
    public void stopRequestResponseTimer() {
        opaRequestResponseTimer.observeDuration();
    }

}
