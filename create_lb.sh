#!/usr/bin/env bash
set -e

if [ "$1" == "--http" ]; then
  SCHEMA="http"
  PORT="80"
else
  SCHEMA="https"
  PORT="443"
fi

# expose web
if kubectl get service web-lb -n default &>/dev/null; then
  echo "LoadBalancer web-lb is already existed, skip creation."
else
  echo "Exposing web..."
  kubectl expose service web --port=${PORT} --target-port=8080 --name=web-lb --type=LoadBalancer -l type=lb -n default
  echo "Waiting kubernetes to ensure LoadBalancer..."
  while true; do
    sleep 5
    WEB_LB_IP=$(kubectl get service web-lb -o=jsonpath='{.status.loadBalancer.ingress[0].ip}' -n default)
    if [[ -n "$WEB_LB_IP" ]]; then
      echo "Web exposed to $SCHEMA://$WEB_LB_IP:$PORT successfully."
      break
    fi
    echo "Wait another 5 seconds to do a next check."
  done
fi

# expose CQ tables only
for TABLE_NAME in $(kubectl get service -l component=table,type!=lb -o=jsonpath='{.items[*].metadata.name}' -n default); do
  if kubectl get service "$TABLE_NAME"-lb -n default &>/dev/null; then
    echo "LoadBalancer $TABLE_NAME-lb is already existed, skip creation."
  else
    echo "Exposing $TABLE_NAME..."
    kubectl expose service "$TABLE_NAME" --port=${PORT} --target-port=7888 --name="$TABLE_NAME"-lb --type=LoadBalancer -l type=lb -n default
    echo "Waiting kubernetes to ensure LoadBalancer..."
    while true; do
      sleep 5
      TABLE_LB_IP=$(kubectl get service "$TABLE_NAME"-lb -o=jsonpath='{.status.loadBalancer.ingress[0].ip}' -n default)
      if [[ -n "$TABLE_LB_IP" ]]; then
        echo "$TABLE_NAME exposed to $SCHEMA://$TABLE_LB_IP:$PORT successfully."
        break
      fi
      echo "Wait another 5 seconds to do a next check."
    done
  fi
done
