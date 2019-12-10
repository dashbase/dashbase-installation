#!/usr/bin/env bash
set -e

if [ "$1" == "--http" ]; then
  SCHEMA="http"
  PORT="80"
else
  SCHEMA="https"
  PORT="443"
fi

if ! kubectl get service web -n dashbase &>/dev/null; then
  echo "Kubernetes service \"web\" is not found, Please check your dashbase installation is ok."
  exit 1
fi

# expose web
if kubectl get service web-lb -n dashbase &>/dev/null; then
  echo "LoadBalancer web-lb is already existed, skip creation."
else
  echo "Exposing web..."
  kubectl expose service web --port=${PORT} --target-port=8080 --name=web-lb --type=LoadBalancer -l type=lb -n dashbase
  echo "Waiting kubernetes to ensure LoadBalancer..."
  while true; do
    WEB_LB_IP=$(kubectl get service web-lb -o=jsonpath='{.status.loadBalancer.ingress[0].ip}' -n dashbase)
    if [[ -n "$WEB_LB_IP" ]]; then
      echo "Web exposed to $SCHEMA://$WEB_LB_IP:$PORT successfully."
      break
    fi
    echo "Wait another 15 seconds to do a next check."
    sleep 15
  done
fi

# expose CQ tables only
for TABLE_NAME in $(kubectl get service -l component=table,type!=lb -o=jsonpath='{.items[*].metadata.name}' -n dashbase); do
  if kubectl get service "$TABLE_NAME"-lb -n dashbase &>/dev/null; then
    echo "LoadBalancer $TABLE_NAME-lb is already existed, skip creation."
  else
    echo "Exposing $TABLE_NAME..."
    kubectl expose service "$TABLE_NAME" --port=${PORT} --target-port=7888 --name="$TABLE_NAME"-lb --type=LoadBalancer -l type=lb -n dashbase
    echo "Waiting kubernetes to ensure LoadBalancer..."
    while true; do
      TABLE_LB_IP=$(kubectl get service "$TABLE_NAME"-lb -o=jsonpath='{.status.loadBalancer.ingress[0].ip}' -n dashbase)
      if [[ -n "$TABLE_LB_IP" ]]; then
        echo "$TABLE_NAME exposed to $SCHEMA://$TABLE_LB_IP:$PORT successfully."
        break
      fi
      echo "Wait another 15 seconds to do a next check."
      sleep 15
    done
  fi
done
