package com.prai.metrics;

public interface AuthzMetrics
{
    public void startAuthzDecisionTimer();
    public void stopAuthzDecisionTimer();
    public void startRequestResponseTimer();
    public void stopRequestResponseTimer();

    }
