package com.prai.metrics;

import io.prometheus.client.Summary;

public class PHAuthzMetrics implements AuthzMetrics {
    private static final Summary permissionHandlerAuthzRequestResponseLatency = Summary.build()
            .name("permission_handler_requests_response_latency_seconds")
            .help("permissionHandler authorization request-response latency in seconds")
            .register();
    private static final Summary permissionHandlerAuthzDecisionLatency = Summary.build()
            .name("permission_handler_decision_latency_seconds")
            .help("permission_handler spend on authz decision latency in seconds")
            .register();
    private static Summary.Timer permissionHandlerRequestResponseTimer;

    private static Summary.Timer permissionHandlerDecisionTimer;

    private static PHAuthzMetrics instance = null;

    private PHAuthzMetrics() {
    }

    public static PHAuthzMetrics getInstance() {
        if (instance == null) {
            instance = new PHAuthzMetrics();
        }
        return instance;
    }

    @Override
    public void startAuthzDecisionTimer() {
        permissionHandlerDecisionTimer = permissionHandlerAuthzDecisionLatency.startTimer();
    }

    @Override
    public void stopAuthzDecisionTimer() {
        permissionHandlerDecisionTimer.observeDuration();
    }

    @Override
    public void startRequestResponseTimer() {
        permissionHandlerRequestResponseTimer = permissionHandlerAuthzRequestResponseLatency.startTimer();
    }

    @Override
    public void stopRequestResponseTimer() {
        permissionHandlerRequestResponseTimer.observeDuration();
    }

}
