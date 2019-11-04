#!/bin/bash
# Init environment
BASEDIR="$(cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd)"
RULES=$(ls $BASEDIR/alerts)

if [ ! -d $BASEDIR/prometheus-rules ]; then
  mkdir $BASEDIR/prometheus-rules
fi

case "$1" in
  "generate")
    cp -rf $BASEDIR/alerts $BASEDIR/alerts-template
    for filename in $RULES
    do
       alerts_name=$(echo $filename | cut -d . -f1)
       helm template $BASEDIR/alerts-template --set alert_name=$alerts_name --set alert_path=alerts/$alerts_name.yml > $BASEDIR/prometheus-rules/$alerts_name.yml
    done
    rm -rf $BASEDIR/alerts-template/alerts
    exit 0;
  ;;

  "test")
    if [ `kubectl get PrometheusRule -A  &> /dev/null` $? -ne 0 ]; then
      Applied_PrometheusRule="false"
      echo $Applied_PrometheusRule
      echo "Test should be run with K8S and Prometheus Operator"
      exit 1
    else
      cp -rf $BASEDIR/alerts alerts-template
      for filename in $RULES
      do
         alerts_name=$(echo $filename | cut -d . -f1)
         helm template $BASEDIR/alerts-template --set alert_name=$alerts_name --set alert_path=alerts/$alerts_name.yml | kubectl create --dry-run=true --validate=true -f -
      done
      rm -rf alerts-template/alerts
      exit 0;
    fi
  ;;
  "--help")
    printf -- 'usage: \n';
    printf -- 'generate -- Generate Prometheus Operator rules.\n';
    printf -- 'test -- Run test for Prometheus Operator rules.\n';
    exit 0;
  ;;
  *)
    echo "Option should be provied, Please use --help for help."
    exit 0;
esac