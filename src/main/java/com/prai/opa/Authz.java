package com.prai.opa;

import java.util.List;

public interface Authz {
    public final String coarsedGrainedentrypoint = "authz/redfish/v1/policy/allow";
    public final String fineGrainedentrypoint = "authz/redfish/v1/fine/policy/batch_allow";
    public List<String> isAllowed(List<String> uris, List<String> methods, List<String> roles);
    public boolean isAllowed(String uri, String method, List<String> roles);
}
