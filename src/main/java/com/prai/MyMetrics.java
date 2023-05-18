package com.prai;

import io.prometheus.client.Counter;
import io.prometheus.client.Summary;

public class MyMetrics {
    public static final Counter coarse_grained_authorization_requests_total = Counter.build().name("coarse_grained_authorization_requests_total").help("Total coarse grained authorization requests").register();
    public static final Counter fine_grained_authorization_requests_total = Counter.build().name("fine_grained_authorization_requests_total").help("Total fine grained authorization requests").register();

    public static final Counter correct_authorization_decision_total = Counter.build().name("correct_authorization_decision_total").help("Total correct authorization decision").register();

    public static final Counter incorrect_authorization_decision_total = Counter.build().name("incorrect_authorization_decision_total").help("Total incorrect authorization decision").register();

    public static final Summary opaAuthorizationRequestLatency = Summary.build()
            .name("opa_authorization_requests_requests_latency_seconds")
            .help("opa authorization request latency in seconds")
            .register();
    public static final Summary permissionHandlerAuthorizationRequestLatency = Summary.build()
            .name("permissionHandler_authorization_requests_requests_latency_seconds")
            .help("permissionHandler authorization request latency in seconds")
            .register();

    private static Summary.Timer opaRequestTimer;
    private static Summary.Timer permissionHandlerRequestTimer;

    public static void startOPATimer() {
        opaRequestTimer = MyMetrics.opaAuthorizationRequestLatency.startTimer();
    }

    public static void startTimer(SettingEnum flag) {
        if (flag == SettingEnum.OPA) {
            startOPATimer();
        }
        if (flag == SettingEnum.PERMISSIONHANDLER) {
            startPermissionHandlerTimer();
        }
    }

    public static void stopTimer(SettingEnum flag) {
        if (flag == SettingEnum.OPA) {
            stopOPATimer();
        }
        if (flag == SettingEnum.PERMISSIONHANDLER) {
            stopPermissionHandlerTimer();
        }
    }

    public static void startPermissionHandlerTimer() {
        permissionHandlerRequestTimer = MyMetrics.permissionHandlerAuthorizationRequestLatency.startTimer();
    }

    public static void stopPermissionHandlerTimer() {
        permissionHandlerRequestTimer.observeDuration();
    }

    public static void stopOPATimer() {
        opaRequestTimer.observeDuration();
    }
}
