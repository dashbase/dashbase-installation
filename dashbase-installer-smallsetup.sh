#!/bin/bash

PLATFORM="undefined"
INGRESS_FLAG="false"
VALUEFILE="dashbase-values.yaml"
NOSSL_FLAG="false"

# log functions and input flag setup
function log_info() {
  echo -e "INFO *** $*"
}

function log_warning() {
  echo -e "WARN *** $*"
}

function log_fatal() {
  echo -e "FATAL *** $*"
  exit 1
}

function fail_if_empty() {
  [[ -z "$2" ]] && log_fatal "Parameter $1 must have a value."
  return 0
}

echo "$@" >setup_arguments
echo "$#" >no_arguments

while [[ $# -gt 0 ]]; do
  PARAM=${1%%=*}
  [[ "$1" == *"="* ]] && VALUE=${1#*=} || VALUE=""
  log_info "Parsing ($1): $PARAM with ${VALUE:-no value}"
  shift 1

  case $PARAM in
  --subdomain)
    fail_if_empty "$PARAM" "$VALUE"
    SUBDOMAIN=$VALUE
    ;;
  --platform)
    fail_if_empty "$PARAM" "$VALUE"
    PLATFORM=$VALUE
    ;;
  --version)
    fail_if_empty "$PARAM" "$VALUE"
    VERSION=$VALUE
    ;;
  --valuefile)
    fail_if_empty "$PARAM" "$VALUE"
    VALUEFILE=$VALUE
    ;;
  --ingress)
    INGRESS_FLAG="true"
    ;;
  --nopresto)
    NOPRESTO_FLAG="true"
    ;;
  --nossl)
    NOSSL_FLAG="true"
    ;;
  --exposemon)
    EXPOSEMON="--exposemon"
    ;;
  *)
    log_warning "Unknown parameter ($PARAM) with ${VALUE:-no value}"
    ;;
  esac
done

show_spinner() {
  local -r pid="${1}"
  local -r delay='0.75'
  local spinstr='\|/-'
  local temp
  while ps a | awk '{print $1}' | grep -q "${pid}"; do
    temp="${spinstr#?}"
    printf " [%c]  " "${spinstr}"
    spinstr=${temp}${spinstr%"${temp}"}
    sleep "${delay}"
    printf "\b\b\b\b\b\b"
  done
  printf "    \b\b\b\b"
}

check_platform_input() {
  # check entered platform
  if [[ "$PLATFORM" == "undefined" || -z "$PLATFORM" ]]; then
    log_fatal "--platform is required"
  elif [ "$PLATFORM" == "aws" ]; then
    log_info "entered plaform type is $PLATFORM"
  elif [ "$PLATFORM" == "azure" ]; then
    log_info "entered plaform type is $PLATFORM"
  elif [ "$PLATFORM" == "gce" ]; then
    log_info "entered plaform type is $PLATFORM"
  else
    log_fatal "Incorrect platform type, and platform type should be either aws, gce, or azure"
  fi
}

check_ingress_subdomain() {
  if [[ "$INGRESS_FLAG" == "true" && -z "$SUBDOMAIN" ]]; then
    log_fatal "--subomain is required when using --ingress flag"
  elif [[ "$INGRESS_FLAG" == "true" && -n "$SUBDOMAIN" ]]; then
    log_info "entered subdomain is $SUBDOMAIN"
  elif [[ "$INGRESS_FLAG" == "false" && -n "$SUBDOMAIN" ]]; then
    log_warning "Ingress is not used but entered the subdomain name"
  fi
}

check_k8s_permission() {
  # check permission
  ## permissions required by dashbase charts
  echo "Checking your RBAC permission:"
  rm -rf check_k8_permission.txt
  echo -n "Admin permission in namespace dashbase: "
  kubectl auth can-i '*' '*' -n dashbase > >(tee -a check_k8_permission.txt) 2>&1
  echo -n "Admin permission on namespaces: "
  kubectl auth can-i '*' namespaces --all-namespaces > >(tee -a check_k8_permission.txt) 2>&1
  echo -n "Admin permission on nodes: "
  kubectl auth can-i '*' nodes --all-namespaces > >(tee -a check_k8_permission.txt) 2>&1
  echo -n "Admin permission on storageclasses: "
  kubectl auth can-i '*' storageclasses --all-namespaces > >(tee -a check_k8_permission.txt) 2>&1
  echo -n "Admin permission on persistentvolumes: "
  kubectl auth can-i '*' persistentvolumes --all-namespaces > >(tee -a check_k8_permission.txt) 2>&1
  echo -n "Admin permission on clusterroles: "
  kubectl auth can-i '*' clusterroles --all-namespaces > >(tee -a check_k8_permission.txt) 2>&1
  echo -n "Admin permission on clusterrolebindings: "
  kubectl auth can-i '*' clusterrolebindings --all-namespaces > >(tee -a check_k8_permission.txt) 2>&1
  echo -n "Admin permission on priorityclasses: "
  kubectl auth can-i '*' priorityclasses --all-namespaces > >(tee -a check_k8_permission.txt) 2>&1
  ## permission required by helm
  echo -n "Admin permission in namespace kube-system(required by helm): "
  kubectl auth can-i '*' '*' -n kubes-system > >(tee -a check_k8_permission.txt) 2>&1
  ## exit if K8 permission not met requirement
  if [ -z "$(cat check_k8_permission.txt | grep -iv yes)" ]; then
    echo "K8s permission met the requirement"
  else
    echo "The account don't have sufficient permission to access K8 cluster"
    exit 1
  fi
}

check_node_cpu() {
  ## check nodes resources
  if [[ "$2" =~ ^([0-9]+)m$ ]]; then
    if [[ ${BASH_REMATCH[1]} -ge 1800 ]]; then
      return 0
    fi
  elif [[ "$2" =~ ^([0-9]+)$ ]]; then
    if [[ ${BASH_REMATCH[1]} -ge 2 ]]; then
      return 0
    fi
  else
    echo "Can't determine the cpu($2) of node($1)."
  fi
  return 1
}

check_node_memory() {
  if [[ "$2" =~ ^([0-9]+)Ki?$ ]]; then
    if [[ ${BASH_REMATCH[1]} -ge 3000000 ]]; then
      return 0
    fi
  elif [[ "$2" =~ ^([0-9]+)Mi?$ ]]; then
    if [[ ${BASH_REMATCH[1]} -ge 3000 ]]; then
      return 0
    fi
  elif [[ "$2" =~ ^([0-9]+)Gi?$ ]]; then
    if [[ ${BASH_REMATCH[1]} -ge 3 ]]; then
      return 0
    fi
  else
    echo "Can't determine the memory($2) of node($1)."
  fi
  return 1
}

check_node() {
  if ! check_node_cpu "$1" "$2"; then
    echo "Node($1) doesn't have enough cpu resources(8 core at least)."
    return 0
  fi
  if ! check_node_memory "$1" "$3"; then
    echo "Node($1) doesn't have enough memory resources(32Gi at least)."
    return 0
  fi

  ((AVAIILABLE_NODES++))
  return 0
}

check_version() {
  if [ -z "$VERSION" ]; then
    log_info "No input dashbase version, use default nightly"
  else
    log_info "Dashbase version entered is $VERSION"
  fi
}


preflight_check() {
  # preflight checks
  log_info "OS type running this script is $OSTYPE"
  CMDS="kubectl curl"
  for x in $CMDS; do
    command -v "$x" >/dev/null && continue || {
      log_fatal "This script requires $x command and is not found."
    }
  done

  # check kubernetes API server is connectable
  if ! kubectl cluster-info &>/dev/null; then
    log_fatal "Failed to connect your Kubernetes API server, please check your config or network."
  fi

  check_k8s_permission

  echo ""
  echo "Checking kubernetes nodes capacity..."
  AVAIILABLE_NODES=0
  # get comma separated nodes info
  # gke-chao-debug-default-pool-a5df0776-588v,3920m,12699052Ki
  for NODE_INFO in $(kubectl get node -o jsonpath='{range .items[*]}{.metadata.name},{.status.capacity.cpu},{.status.capacity.memory}{"\n"}{end}'); do
    # replace comma with spaces.
    read -r NODE_NAME NODE_CPU NODE_MEMORY <<<"$(echo "$NODE_INFO" | tr ',' ' ')"
    check_node "$NODE_NAME" "$NODE_CPU" "$NODE_MEMORY"
  done
  echo ""
  if [ $AVAIILABLE_NODES -ge 2 ]; then
    log_info "This cluster is ready for dashbase installation on resources"
  else
    log_fatal "This cluster doesn't have enough resources for dashbase installation(2 nodes with each have 8 core and 32 Gi at least)."
  fi
}

adminpod_setup() {
  # create namespace dashbase and admin service account for installation
  if [ "$(kubectl get namespace | grep -c dashbase)" -gt 0 ]; then
    log_warning "Previous dashbase namespace exists"
  else
    kubectl create namespace dashbase
  fi
  if [ "$(kubectl get sa -n dashbase | grep -c dashadmin)" -gt 0 ]; then
    log_warning "Previous service account dashadmin exists in dashbase namespace"
  else
    kubectl create serviceaccount dashadmin -n dashbase
  fi
  if [ "$(kubectl get clusterrolebindings | grep -c admin-user-binding)" -gt 0 ]; then
    log_warning "Previous cluster role binding admin-user-binding exists"
  else
    kubectl create clusterrolebinding admin-user-binding --clusterrole=cluster-admin --serviceaccount=dashbase:dashadmin
  fi
  if [ "$(kubectl get po -n dashbase | grep -c admindash)" -gt 0 ]; then
    log_fatal "Previous admin pod admindash exists"
  else
    # Download and install installer helper statefulset yaml file
    curl -k https://dashbase-public.s3-us-west-1.amazonaws.com/admindash-sts.yaml -o admindash-sts.yaml
    kubectl apply -f admindash-sts.yaml -n dashbase
    kubectl wait --for=condition=Ready pods/admindash-0 --timeout=60s -n dashbase
    # Check to ensure admin pod is available else exit 1
    APODSTATUS=$(kubectl wait --for=condition=Ready pods/admindash-0 -n dashbase | grep -c "condition met")
    if [ "$APODSTATUS" -eq "1" ]; then echo "Admin Pod is available"; else log_fatal "Admin Pod  admindash-0 is not available"; fi
  fi
}

setup_helm_tiller() {
  # create tiller service account in kube-system namespace
  kubectl exec -it admindash-0 -n dashbase -- bash -c "wget https://raw.githubusercontent.com/dashbase/dashbase-installation/master/dashbase/rbac-config.yaml"
  kubectl exec -it admindash-0 -n dashbase -- bash -c "kubectl apply -f rbac-config.yaml"
  # start tiller
  kubectl exec -it admindash-0 -n dashbase -- bash -c "helm init --service-account tiller"
  kubectl wait --for=condition=Available deployment/tiller-deploy -n kube-system
  # check helm
  # kubectl exec -it admindash-0 -n dashbase -- bash -c "helm ls"
  # adding dashbase helm repo
  kubectl exec -it admindash-0 -n dashbase -- bash -c "helm repo add dashbase https://charts.dashbase.io"
  kubectl exec -it admindash-0 -n dashbase -- bash -c "helm repo list"
}

create_storageclass() {
  # create storageclass
  if [ "$PLATFORM" == "aws" ]; then
    log_info "create storageclass for AWS disk"
    kubectl exec -it admindash-0 -n dashbase -- bash -c "kubectl apply -f dashbase-data-aws.yaml -n dashbase"
    kubectl exec -it admindash-0 -n dashbase -- bash -c "kubectl apply -f dashbase-meta-aws.yaml -n dashbase"
  elif [ "$PLATFORM" == "gce" ]; then
    log_info "create storageclass for GCE disk"
    kubectl exec -it admindash-0 -n dashbase -- bash -c "kubectl apply -f dashbase-data-gce.yaml -n dashbase"
    kubectl exec -it admindash-0 -n dashbase -- bash -c "kubectl apply -f dashbase-meta-gce.yaml -n dashbase"
  elif [ "$PLATFORM" == "azure" ]; then
    log_info "create storageclass for Azure disk"
    kubectl exec -it admindash-0 -n dashbase -- bash -c "kubectl apply -f dashbase-data-azure.yaml -n dashbase"
  fi
  kubectl exec -it admindash-0 -n dashbase -- bash -c "kubectl get storageclass |grep dashbase"
  STORECLASSCHK=$(kubectl get storageclass | grep -c dashbase)
  if [ "$STORECLASSCHK" -eq "2" ]; then echo "Dashbase storageclasses are available"; else log_fatal "Dashbase storageclasses not found"; fi
}

download_dashbase() {
  # download and update the dashbase helm value yaml files
  log_info "Downloading dashbase setup tar file from S3 bucket"
  kubectl exec -it admindash-0 -n dashbase -- bash -c "wget https://dashbase-public.s3-us-west-1.amazonaws.com/dashbase_setup_small.tar"
  kubectl exec -it admindash-0 -n dashbase -- bash -c "tar -xvf dashbase_setup_small.tar"
  kubectl exec -it admindash-0 -n dashbase -- bash -c "chmod a+x /dashbase/*.sh"
}

update_dashbase_valuefile() {
  # update dashbase-values.yaml for platform choice and subdomain
  if [ -n "$SUBDOMAIN" ]; then
    log_info "update ingress subdomain in dashbase-values.yaml file"
    kubectl exec -it admindash-0 -n dashbase -- bash -c "sed -i 's|test.dashbase.io|$SUBDOMAIN|' dashbase-values.yaml"
  elif [ -z "$SUBDOMAIN" ]; then
    log_info "no input on --subdomain will use default which is test.dashbase.io"
  fi
  # update platform type in dashbase-values.yaml file
  if [ "$PLATFORM" == "aws" ]; then
    log_info "use default platform type aws in dashbase-values.yaml"
  elif [ "$PLATFORM" == "gce" ]; then
    log_info "update platform type gce in dashbase-values.yaml"
    kubectl exec -it admindash-0 -n dashbase -- sed -i 's/aws/gce/' dashbase-values.yaml
  elif [ "$PLATFORM" == "azure" ]; then
    log_info "update platform type azure in dashbase-values.yaml"
    kubectl exec -it admindash-0 -n dashbase -- sed -i 's/aws/azure/' dashbase-values.yaml
  fi

  # update dashbase version
  if [ -z "$VERSION" ]; then
    log_info "use default nightly in dashbase_version on dashbase-values.yaml"
  else
    log_info "use $VERSION in dashbase_version on dashbase-values.yaml"
    kubectl exec -it admindash-0 -n dashbase -- sed -i "s|dashbase_version: nightly|dashbase_version: $VERSION|" dashbase-values.yaml
  fi

  # check NOSSL flag input by user
  if [ "$NOSSL_FLAG" == "true" ]; then
    log_info "deploy dashbase with non secure connection, and this deployment will skip presto setup"
    kubectl exec -it admindash-0 -n dashbase -- sed -i "s|https: true|https: false|" dashbase-values.yaml
    NOPRESTO_FLAG="true"
    log_info "setup non-secure dashbase"
  else
    log_info "deploy dashbase with secure connection internally"
    log_info "creating dashbase internal SSL cert, key, keystore, keystore password"
    #kubectl exec -it admindash-0 -n dashbase -- bash -c "chmod a+x /dashbase/https_dashbase.sh"
    kubectl exec -it admindash-0 -n dashbase -- bash -c "/dashbase/https_dashbase.sh"
    kubectl exec -it admindash-0 -n dashbase -- bash -c "kubectl apply -f  https-dashbase.yaml -n dashbase"
    kubectl get secrets -n dashbase | grep -E 'dashbase-cert|dashbase-key'
    CHKDSECRETS=$(kubectl get secrets -n dashbase | grep -E -c 'dashbase-cert|dashbase-key')
    if [ "$CHKDSECRETS" -eq "4" ]; then
      log_info "dashbase SSL cert, key, keystore and keystore password are created"
      log_info "setup secure dashbase"
      #kubectl exec -it admindash-0 -n dashbase -- bash -c "helm install dashbase/dashbase -f dashbase-values.yaml --name dashbase --namespace dashbase --devel --debug --no-hooks"
    else
      log_fatal "Error to create presto SSL cert, key, keystore, and keystore password"
    fi
  fi
}

install_dashbase() {
  DASHVALUEFILE=$(echo $VALUEFILE | rev | cut -d"/" -f1 | rev)
  log_info "the filename for dashbase value yaml file is $DASHVALUEFILE"
  kubectl exec -it admindash-0 -n dashbase -- bash -c "helm install dashbase/dashbase -f $DASHVALUEFILE --name dashbase --namespace dashbase --debug --no-hooks > /dev/null"
  echo ""
  echo "please wait a few minutes for all dashbase resources be ready"
  echo ""
  sleep 100 &
  show_spinner "$!"
  # check dashbase deployed resources success or not
  kubectl exec -it admindash-0 -n dashbase -- bash -c "/dashbase/check-dashbase-deploy.sh > >(tee check-dashbase-deploy-output.txt) 2>&1"
  CHKDEPLOYNUM=$(kubectl exec -it admindash-0 -n dashbase -- cat check-dashbase-deploy-output.txt | grep -iv -c Checking)
  CHKSUCCEDNUM=$(kubectl exec -it admindash-0 -n dashbase -- cat check-dashbase-deploy-output.txt | grep -c met)
  if [ "$CHKDEPLOYNUM" -eq "$CHKSUCCEDNUM" ]; then log_info "dashbase installation is completed"; else log_fatal "dashbase installation is failed"; fi
}

install_presto() {
  #CHKPSECRETS=$(kubectl get secrets -n dashbase | grep -E -c 'presto-cert|presto-key')
  if [ "$NOPRESTO_FLAG" == "true" ]; then
    log_info "NOPRESTO_FLAG is set to true, presto is not installed"
  else
    log_info "setup presto internal SSL cert, key, keystore, keystore password"
    kubectl exec -it admindash-0 -n dashbase -- bash -c "chmod a+x /dashbase/https_presto.sh"
    kubectl exec -it admindash-0 -n dashbase -- bash -c "/dashbase/https_presto.sh"
    kubectl exec -it admindash-0 -n dashbase -- bash -c "kubectl apply -f  https-presto.yaml -n dashbase"
    kubectl get secrets -n dashbase | grep -E 'presto-cert|presto-key'
    CHKPSECRETS=$(kubectl get secrets -n dashbase | grep -c 'presto')
    if [ "$CHKPSECRETS" -eq "4" ]; then
      log_info "presto SSL cert, key, keystore and keystore password are created"
      log_info "setup secure presto"
      kubectl exec -it admindash-0 -n dashbase -- bash -c "/dashbase/install_presto.sh >/dev/null"
      log_info "please wait a minute for presto resources be ready "
      sleep 60 &
      show_spinner "$!"
      # check presto deployed resources success or not
      kubectl exec -it admindash-0 -n dashbase -- bash -c "/dashbase/check-presto-deploy.sh > >(tee check-presto-deploy-output.txt) 2>&1"
      CHKPDEPLOYNUM=$(kubectl exec -it admindash-0 -n dashbase -- cat check-presto-deploy-output.txt | grep -iv -c Checking)
      CHKPSUCCEDNUM=$(kubectl exec -it admindash-0 -n dashbase -- cat check-presto-deploy-output.txt | grep -c met)
      if [ "$CHKPDEPLOYNUM" -eq "$CHKPSUCCEDNUM" ]; then log_info "presto installation is completed"; else log_fatal "presto installation is failed"; fi
    else
      log_fatal "Error to create presto SSL cert, key, keystore, and keystore password"
    fi
  fi
}

# Expose endpoints via Ingress or LoadBalancer
expose_endpoints() {
  if [ "$INGRESS_FLAG" == "true" ]; then
    log_info "setup ngnix ingress controller to expose service "
    kubectl exec -it admindash-0 -n dashbase -- bash -c "helm install stable/nginx-ingress --name nginx-ingress --namespace dashbase"
    kubectl exec -it admindash-0 -n dashbase -- bash -c "kubectl get po -n dashbase |grep ingress"
    # get the exposed IP address from nginx ingress controller
    EXTERNAL_IP=$(kubectl exec -it admindash-0 -n dashbase -- kubectl get svc nginx-ingress-controller -n dashbase | tail -n +2 | awk '{ print $4}')
    log_info "the exposed IP address for web and tables endpoint is $EXTERNAL_IP"
  else
    if [ "$NOSSL_FLAG" == "true" ]; then
      log_info "setup LoadBalancer with http endpoints to expose services"
      kubectl exec -it admindash-0 -n dashbase -- bash -c "/dashbase/create-lb.sh --http $EXPOSEMON"
    else
      log_info "setup LoadBalancer with https endpoints to expose services"
      kubectl exec -it admindash-0 -n dashbase -- bash -c "/dashbase/create-lb.sh --https $EXPOSEMON"
    fi
    # list all LoadBalancer external IP addresses in dashbase namespace
    # kubectl exec -it admindash-0 -n dashbase --bash -c "kubectl get svc -n dashbase |grep LoadBalancer"
  fi
}

# main processes executed below this line
# pre-installation checks
check_platform_input
check_ingress_subdomain
check_version
preflight_check

# install admin pod
echo "setup adminpod"
adminpod_setup
download_dashbase

# setup storageclass
if [ "$(kubectl get storageclass -n dashbase | grep -c dashbase)" -gt "0" ]; then
  log_warning "previous dashbase storageclass exists"
  if [ "$(kubectl get pv -n dashbase | grep -c dashbase-)" -gt "0" ]; then
    log_fatal "previous dashbase persistent volumes are detected in this cluster"
  fi
else
  echo "creating dashbase storageclass"
  create_storageclass
fi

# setup helm tiller
if [ "$(kubectl get pod -n kube-system | grep -c tiller)" -gt "0" ]; then
  log_fatal "previous tiller pod exists in this K8s cluster"
else
  echo "creating tiller in K8s"
  setup_helm_tiller
fi

# setup dashbase value yaml file and install dashbase
if [ "$VALUEFILE" == "dashbase-values.yaml" ]; then
  log_info "dashbase value yaml file is using default $VALUEFILE"
  update_dashbase_valuefile
  install_dashbase
else
  log_info "using custom dashbase value file $VALUEFILE"
  kubectl cp "$VALUEFILE" dashbase/admindash-0:/dashbase/
  install_dashbase
fi

# setup presto
install_presto

# expose services
expose_endpoints

# display endpoints
echo "Exposed endpoints are below"

if [[ "$INGRESS_FLAG" == "true" && "$NOSSL_FLAG" == "true" ]]; then
   echo ""
   echo "Update your DNS server with the following ingress controller IP to map with this name *.$SUBDOMAIN"
   kubectl get svc -n dashbase |grep ingress-nginx-ingress-controller |awk '{print $1 "    " $4}'
   echo "Access to dashbase web UI with http://web.$SUBDOMAIN"
   echo "Access to dashbase table endpoint with http://table-logs.$SUBDOMAIN"
   echo ""
elif [[ "$INGRESS_FLAG" == "true" && "$NOSSL_FLAG" == "false" ]]; then
   echo ""
   echo "Update your DNS server with the following ingress controller IP to map with this name *.$SUBDOMAIN"
   kubectl get svc -n dashbase |grep ingress-nginx-ingress-controller |awk '{print $1 "    " $4}'
   echo "Access to dashbase web UI with https://web.$SUBDOMAIN"
   echo "Access to dashbase table endpoint with https://table-logs.$SUBDOMAIN"
   echo ""
else

  for SERVICE_INFO in $(kubectl get service -o=jsonpath='{range .items[*]}{.metadata.name},{.spec.type},{.status.loadBalancer.ingress[0].ip},{.status.loadBalancer.ingress[0].hostname}{"\n"}{end}' -n dashbase); do
  read -r SERVICE_NAME SERVICE_TYPE SERVICE_LB_IP SERVICE_LB_HOSTNAME <<<"$(echo "$SERVICE_INFO" | tr ',' ' ')"
  if [ "$SERVICE_TYPE" != "LoadBalancer" ]; then
    continue
  fi
  # ingress is one of the loadbalancer, skip here to make the logic clear.
  if [ "$SERVICE_NAME" == "ingress-nginx-ingress-controller" ]; then
    continue
  fi

  if [[ -n "$SERVICE_LB_IP" && "$NOSSL_FLAG" == "false" ]]; then
    echo "LoadBalancer($SERVICE_NAME): IP is ready and is https://$SERVICE_LB_IP"
  elif [[ -n "$SERVICE_LB_IP" && "$NOSSL_FLAG" == "true" ]]; then
    echo "LoadBalancer($SERVICE_NAME): IP is ready and is http://$SERVICE_LB_IP"
  elif [[ -n "$SERVICE_LB_HOSTNAME" && "$NOSSL_FLAG" == "false" ]]; then
    echo "LoadBalancer($SERVICE_NAME): IP is ready and is https://$SERVICE_LB_HOSTNAME"
  elif [[ -n "$SERVICE_LB_HOSTNAME" && "$NOSSL_FLAG" == "true" ]]; then
    echo "LoadBalancer($SERVICE_NAME): IP is ready and is http://$SERVICE_LB_HOSTNAME"
  else
    echo "LoadBalancer($SERVICE_NAME): IP is not ready."
  fi
done
fi

