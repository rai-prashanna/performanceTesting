package com.prai.metrics;

import io.prometheus.client.Summary;

public class WasmAuthzMetrics implements AuthzMetrics{
    private static final Summary wasmAuthzDecisionLatency= Summary.build()
            .name("wasm_authorization_decision_latency_seconds")
            .help("WASM spend on authorization decision latency in seconds")
            .register();
    private static Summary wasmAuthzRequestResponseLatency= Summary.build()
            .name("wasm_requests_response_latency_seconds")
            .help("WASM spend on request-response decision latency in seconds")
            .register();
    private static Summary.Timer wasmDecisionTimer;

    private static Summary.Timer wasmRequestResponseTimer;
    private static WasmAuthzMetrics instance=null;
    private WasmAuthzMetrics(){}
    public static WasmAuthzMetrics getInstance(){
        if (instance == null) {
            instance = new WasmAuthzMetrics();
        }
        return instance;
    }
    @Override
    public void startAuthzDecisionTimer() {
        wasmDecisionTimer=wasmAuthzDecisionLatency.startTimer();
    }
    @Override
    public void stopAuthzDecisionTimer() {
        wasmDecisionTimer.observeDuration();
    }
    @Override
    public void startRequestResponseTimer() {
        wasmRequestResponseTimer = wasmAuthzRequestResponseLatency.startTimer();
    }
    @Override
    public void stopRequestResponseTimer() {
        wasmRequestResponseTimer.observeDuration();

    }
}
