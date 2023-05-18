# performanceTesting
does curl like operations to TLS protected REST API endpoint
## promql
(rate(opa_authorization_requests_requests_latency_seconds_sum[10m])/rate(opa_authorization_requests_requests_latency_seconds_count[10m]))/
(rate(permissionHandler_authorization_requests_requests_latency_seconds_sum[10m])/rate(permissionHandler_authorization_requests_requests_latency_seconds_count[10m]))

## do batch testing 
* for i in {1..500};do getAccessToken AllAdmin;java -jar /repo/performanceTesting/performanceTesting/target/performanceTesting.jar $TOKEN;done

