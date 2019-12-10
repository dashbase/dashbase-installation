#!/usr/bin/env bash

# check statefulsets
echo "Checking Statefulsets pods..."
for STS_INFO in $(kubectl get statefulsets -o=jsonpath='{range .items[*]}{.metadata.name},{.spec.replicas}{"\n"}{end}' -n dashbase); do
  read -r STS_NAME STS_REPLICAS <<<"$(echo "$STS_INFO" | tr ',' ' ')"
  if [ $STS_REPLICAS -lt 1 ]; then
    :
  elif [ $STS_REPLICAS -eq 1 ]; then
    kubectl wait --for=condition=Ready pods/"${STS_NAME}"-0 -n dashbase
  else
    ((STS_REPLICAS--))
    REPLICAS_SERIES=$(seq -s , 0 "$STS_REPLICAS")
    if [[ "$OSTYPE" == "darwin"* ]]; then
      REPLICAS_SERIES="${REPLICAS_SERIES%?}"
    fi
    REPLICAS_SERIES="{${REPLICAS_SERIES}}"
    kubectl wait --for=condition=Ready pods/"${STS_NAME}"-"${REPLICAS_SERIES}" -n dashbase
  fi
done

# check deployment
echo "Checking Deployments..."
kubectl wait --for=condition=Available deployment --all -n dashbase

# check ingress-nginx-ingress-controller svc must have an external ip
echo "Checking Ingress External IP..."
if kubectl get svc ingress-nginx-ingress-controller -n dashbase &>/dev/null; then
  EXTERNAL_IP=$(kubectl get svc ingress-nginx-ingress-controller -o=jsonpath='{.status.loadBalancer.ingress[0].ip}' -n dashbase)
  if [[ -n "$EXTERNAL_IP" ]]; then
    echo "Ingress: External IP is ready"
  else
    echo "Ingress: External IP is not ready"
  fi
else
  echo "Warning: Ingress is not installed in this namespace."
fi

# check loadbalancers
for SERVICE_INFO in $(kubectl get service -o=jsonpath='{range .items[*]}{.metadata.name},{.spec.type},{.status.loadBalancer.ingress[0].ip}{"\n"}{end}' -n dashbase); do
  read -r SERVICE_NAME SERVICE_TYPE SERVICE_LB_IP <<<"$(echo "$SERVICE_INFO" | tr ',' ' ')"
  if [ "$SERVICE_TYPE" != "LoadBalancer" ]; then
    continue
  fi

  # ingress is one of the loadbalancer, skip here to make the logic clear.
  if [ "$SERVICE_NAME" == "ingress-nginx-ingress-controller" ]; then
    continue
  fi

  if [[ -n "$SERVICE_LB_IP" ]]; then
    echo "LoadBalancer($SERVICE_NAME): IP is ready."
  else
    echo "LoadBalancer($SERVICE_NAME): IP is not ready."
  fi
done
