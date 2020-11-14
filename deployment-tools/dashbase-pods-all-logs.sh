#!/bin/bash

NAMESPACE="dashbase"
DASHBASEPOD=$(kubectl get po -n dashbase  |grep -E 'api|web|indexer|searcher|auth|table' |grep -iv "0/1" |awk '{print $1}' |tr '\n' ' ')

rm -rf dashbase-app-logs
mkdir -p dashbase-app-logs

for DPOD in $DASHBASEPOD ; do
  echo "$DPOD"
  rm -rf dashbase-app-logs
  kubectl cp $NAMESPACE/"$DPOD":/app/logs  ./dashbase-app-logs/"$DPOD"/logs
done

ls -al dashbase-app-logs
tar -zcvf dashbase-app-logs-$(date +%d%m%Y_%H-%M-%S).tar.gz  dashbase-app-logs
