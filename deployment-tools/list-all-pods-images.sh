#!/bin/bash

NAMESPACE="dashbase"

PODS=$(kubectl get po -n $NAMESPACE |sed -e 1d |grep -Eiv 'search-runner|filebeat|nginx-json' |awk '{print $1}' |tr '\n' ' ')
#PODS=$(kubectl get po -n $NAMESPACE |awk '{print $1}' |tr '\n' ' ')

for PD in $PODS ; do
  echo -e "$PD\t \
$(kubectl describe po $PD -n $NAMESPACE |grep Image: |tail -1 |awk '{print $2}')"
done

