package com.prai.metrics;

import io.prometheus.client.Summary;

public class JarlAuthzMetrics implements AuthzMetrics {
    private static final Summary jarlAuthzRequestResponseLatency = Summary.build()
            .name("jarl_requests_latency_seconds")
            .help("JARL authorization request-response latency in seconds")
            .register();

    private static final Summary jarlAuthzDecisionLatency = Summary.build()
            .name("jarl_authorization_decision_latency_seconds")
            .help("JARL spend on authorization decision latency in seconds")
            .register();
    private static Summary.Timer jarlRequestResponseTimer;

    private static Summary.Timer jarlDecisionTimer;
    private static JarlAuthzMetrics instance = null;

    private JarlAuthzMetrics() {
    }

    public static JarlAuthzMetrics getInstance() {
        if (instance == null) {
            instance = new JarlAuthzMetrics();
        }
        return instance;
    }

    @Override
    public void startAuthzDecisionTimer() {
        jarlDecisionTimer = jarlAuthzDecisionLatency.startTimer();

    }

    @Override
    public void stopAuthzDecisionTimer() {
        jarlDecisionTimer.observeDuration();
    }

    @Override
    public void startRequestResponseTimer() {
        jarlRequestResponseTimer = jarlAuthzRequestResponseLatency.startTimer();

    }

    @Override
    public void stopRequestResponseTimer() {
        jarlRequestResponseTimer.observeDuration();
    }

}
