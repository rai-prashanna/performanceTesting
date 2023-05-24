# performanceTesting
does curl like operations to TLS protected REST API endpoint
## promql
(rate(opa_authorization_requests_requests_latency_seconds_sum[10m])/rate(opa_authorization_requests_requests_latency_seconds_count[10m]))/
(rate(permissionHandler_authorization_requests_requests_latency_seconds_sum[10m])/rate(permissionHandler_authorization_requests_requests_latency_seconds_count[10m]))

## do batch testing 
* for i in {1..500};do getAccessToken AllAdmin;java -jar /repo/performanceTesting/performanceTesting/target/performanceTesting.jar $TOKEN;done
* getAccessToken AllAdmin;java -jar /repo/performanceTesting/performanceTesting/target/performanceTesting.jar $TOKEN OPA

export -f function curl_cmd() {
kubectl exec -i eric-sec-access-mgmt-0 -c iam -- curl "$@" || kubectl exec -i eric-sec-access-mgmt-1 -c iam -- curl "$@"
}

getAccessToken AllAdmin;java -jar target/performanceTesting.jar 30754 $TOKEN "JARL" 2