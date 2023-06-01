# performanceTesting
## run prometheus service and grafan service using docker-compose 
* go to directory of grafana-prometheus
* docker-compose build --no-cache 
* docker-compose up 

## compile java application
* mvn clean install 

## do batch testing / execute jar application 
* java -jar target/performanceTesting.jar JARL 9081 70000
* java -jar target/performanceTesting.jar OPA 9080 70000

## Grafana Dashboard
* Grafana is available on localhost:3000 
* import grafana dashboard using dashaboard.json
## promql
* rate(opa_decision_latency_seconds_sum[2m])/rate(opa_decision_latency_seconds_count[2m])

* rate(jarl_authorization_decision_latency_seconds_sum[2m])/rate(jarl_authorization_decision_latency_seconds_count[2m])
