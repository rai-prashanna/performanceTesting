package com.prai.metrics;

import io.prometheus.client.Counter;
import io.prometheus.client.Summary;
import io.prometheus.client.Summary.Timer;
public class MyMetrics {
    public static final Counter coarse_grained_authorization_requests_total = Counter.build().name("coarse_grained_authorization_requests_total").help("Total coarse grained authorization requests").register();
    public static final Counter fine_grained_authorization_requests_total = Counter.build().name("fine_grained_authorization_requests_total").help("Total fine grained authorization requests").register();
    public static final Summary opaAuthzDecisionLatency = Summary.build()
            .name("opa_decision_latency_seconds")
            .help("opa HTTP server spend on authorization decision latency in seconds")
            .register();
    public static final Summary opaAuthzRequestResponseLatency = Summary.build()
            .name("opa_requests_response_latency_seconds")
            .help("opa authorization request-response latency in seconds")
            .register();
    public static final Summary permissionHandlerAuthzRequestResponseLatency = Summary.build()
            .name("permission_handler_requests_response_latency_seconds")
            .help("permissionHandler authorization request-response latency in seconds")
            .register();
    public static final Summary permissionHandlerAuthzDecisionLatency = Summary.build()
            .name("permission_handler_decision_latency_seconds")
            .help("permission_handler spend on authz decision latency in seconds")
            .register();
    public static final Summary jarlAuthzRequestResponseLatency = Summary.build()
            .name("jarl_requests_latency_seconds")
            .help("JARL authorization request-response latency in seconds")
            .register();

    public static final Summary jarlAuthzDecisionLatency = Summary.build()
            .name("jarl_authorization_decision_latency_seconds")
            .help("JARL spend on authorization decision latency in seconds")
            .register();
    private static final Summary wasmAuthzDecisionLatency= Summary.build()
            .name("wasm_authorization_decision_latency_seconds")
            .help("WASM spend on authorization decision latency in seconds")
            .register();
    private static Summary wasmAuthzRequestResponseLatency= Summary.build()
            .name("wasm_requests_response_latency_seconds")
            .help("WASM spend on request-response decision latency in seconds")
            .register();
    private static Timer opaRequestResponseTimer;
    private static Timer permissionHandlerRequestResponseTimer;

    private static Timer jarlRequestResponseTimer;

    private static Timer jarlDecisionTimer;
    private static Timer opaDecisionTimer;
    private static Timer permissionHandlerDecisionTimer;
    private static Timer wasmDecisionTimer;

    private static Timer wasmRequestResponseTimer;

    public static void startRequestResponseTimer(SettingEnum flag) {
        if (flag == SettingEnum.OPA) {
            startOPARequestResponseTimer();
        }
        if (flag == SettingEnum.PERMISSIONHANDLER) {
            startPermissionHandlerRequestResponseTimer();
        }
        if (flag == SettingEnum.JARL) {
            startJARLRequestResponseTimer();
        }
        if (flag == SettingEnum.WASM) {
            startWASMRequestResponseTimer();
        }
    }


    public static void startAuthzDecisionTimer(SettingEnum flag) {
        if (flag == SettingEnum.OPA) {
            startOPAAuthzTimer();
        }
        if (flag == SettingEnum.PERMISSIONHANDLER) {
            startPermissionHandlerAuthzTimer();
        }
        if (flag == SettingEnum.JARL) {
            startJARLAuthzTimer();
        }
        if (flag == SettingEnum.WASM) {
            startWASMAuthzTimer();
        }
    }

    private static void startWASMAuthzTimer() {
        wasmDecisionTimer=MyMetrics.wasmAuthzDecisionLatency.startTimer();
    }

    private static void startJARLAuthzTimer() {
        jarlDecisionTimer = MyMetrics.jarlAuthzDecisionLatency.startTimer();
    }

    private static void startPermissionHandlerAuthzTimer() {
        permissionHandlerDecisionTimer=MyMetrics.permissionHandlerAuthzDecisionLatency.startTimer();
    }

    private static void startOPAAuthzTimer() {
        opaDecisionTimer=MyMetrics.opaAuthzDecisionLatency.startTimer();
    }

    public static void stopAuthzDecisionTimer(SettingEnum flag) {
        if (flag == SettingEnum.OPA) {
            stopOPAAuthzTimer();
        }
        if (flag == SettingEnum.PERMISSIONHANDLER) {
            stopPermissionHandlerAuthzTimer();
        }
        if (flag == SettingEnum.JARL) {
            stopJARLAuthzTimer();
        }
        if (flag == SettingEnum.WASM) {
            stopWASMAuthzTimer();
        }
    }

    private static void stopWASMAuthzTimer() {wasmDecisionTimer.observeDuration();
    }

    private static void stopJARLAuthzTimer() {
        jarlDecisionTimer.observeDuration();
    }

    private static void stopPermissionHandlerAuthzTimer() {
        permissionHandlerDecisionTimer.observeDuration();
    }

    private static void stopOPAAuthzTimer() {
        opaDecisionTimer.observeDuration();
    }

    public static void stopRequestResponseTimer(SettingEnum flag) {
        if (flag == SettingEnum.OPA) {
            stopOPARequestResponseTimer();
        }
        if (flag == SettingEnum.PERMISSIONHANDLER) {
            stopPermissionHandlerRequestResponseTimer();
        }
        if (flag == SettingEnum.JARL) {
            stopJARLRequestResponseTimer();
        }
        if (flag == SettingEnum.WASM) {
            stopWASMRequestResponseTimer();
        }
    }

    private static void  stopWASMRequestResponseTimer() {
        wasmRequestResponseTimer.observeDuration();
    }

    public static void stopPermissionHandlerRequestResponseTimer() {
        permissionHandlerRequestResponseTimer.observeDuration();
    }

    public static void stopOPARequestResponseTimer() {
        opaRequestResponseTimer.observeDuration();
    }

    public static void stopJARLRequestResponseTimer() {
        jarlRequestResponseTimer.observeDuration();
    }
    public static void startOPARequestResponseTimer() {
        opaRequestResponseTimer = MyMetrics.opaAuthzRequestResponseLatency.startTimer();
    }
    public static void startJARLRequestResponseTimer() {
        jarlRequestResponseTimer = MyMetrics.jarlAuthzRequestResponseLatency.startTimer();
    }
    public static void startPermissionHandlerRequestResponseTimer() {
        permissionHandlerRequestResponseTimer = MyMetrics.permissionHandlerAuthzRequestResponseLatency.startTimer();
    }
    private static void startWASMRequestResponseTimer() {
        wasmRequestResponseTimer = MyMetrics.wasmAuthzRequestResponseLatency.startTimer();

    }
}
