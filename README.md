# performanceTesting
does curl like operations to TLS protected REST API endpoint
## promql
(rate(opa_authorization_requests_requests_latency_seconds_sum[10m])/rate(opa_authorization_requests_requests_latency_seconds_count[10m]))/
(rate(permissionHandler_authorization_requests_requests_latency_seconds_sum[10m])/rate(permissionHandler_authorization_requests_requests_latency_seconds_count[10m]))

## compile java application
* mvn clean install 
## do batch testing 
* java -jar target/performanceTesting.jar JARL 9081 70000
* java -jar target/performanceTesting.jar WASM 9082 70000
* java -jar target/performanceTesting.jar OPA 9080 70000