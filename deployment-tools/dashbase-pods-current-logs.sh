#!/bin/bash

for TD in indexer searcher table web api ; do
  echo $TD
  rm -rf "$TD"-logs
  mkdir -p "$TD"-logs

  POD=$(kubectl get po -n dashbase |grep "$TD" |awk '{print $1}' |tr '\n' ' ' )
  for PD in $POD ; do
     echo "$PD"
     kubectl logs "$PD" -n dashbase > "$TD"-logs/"$PD"-$(date "+%Y-%m-%d_%H%M:%S").log
  done
done

ls -a *-logs

tar -cvf dashbase_pods_logs.tar  *-logs