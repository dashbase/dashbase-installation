#!/bin/bash

BASEDIR=$(dirname "$0")
rm -rf "$BASEDIR"/estnodecountfile
rm -rf "$BASEDIR"/no_arguments
rm -rf "$BASEDIR"/setup_arguments
rm -rf "$BASEDIR"/target-eks-cluster.yaml
rm -rf "$BASEDIR"/my_dashbase_specfile
rm -rf "$BASEDIR"/dashbase_rsa.pub
rm -rf "$BASEDIR"/dashbase_rsa
rm -rf "$BASEDIR"/awsfile


# This script requires openssl
command -v openssl >/dev/null
if [[ "${?}" -ne 0 ]]; then
  printf "openssl is not installed, exiting\\n"
  exit 1
fi

RANDOM=$(openssl rand -hex 3 >randomstring)
RSTRING=$(cat randomstring)

AWS_EKS_SCRIPT_VERSION="2.6.1"
AWS_ACCESS_KEY="undefined"
AWS_SECRET_ACCESS_KEY="undefined"
REGION="us-east-1"
HELM_VERSION="v3.1.1"
CLUSTERNAME="mydash$RSTRING"
CMDS="curl tar unzip git openssl bc wget sed"
KUBECTLVERSION="1.16"

cp "$BASEDIR"/dashbase_specfile "$BASEDIR"/my_dashbase_specfile
SPECFILE="$BASEDIR"/my_dashbase_specfile

echo "AWS EKS setup script version is $AWS_EKS_SCRIPT_VERSION"

display_help() {
  echo "Usage: $0 [options...]"
  echo ""
  echo "   all options usage  e.g. --option_key=value  or --option_key"
  echo ""
  echo "     --aws_access_key         AWS ACCESS KEY "
  echo "                              e.g. --aws_access_key=YOURAWSACCESSKEY"
  echo "     --aws_secret_access_key  AWS SECRET ACCESS KEY"
  echo "                              e.g. --aws_secret_access_key=YOURACESSSECRETACCESSKEY"
  echo "     --region                 AWS region e.g. --region=us-west-2"
  echo "     --cluster_name           EKS cluster name, default is mydash appends 6 characters"
  echo "                              e.g. --cluster_name=myclustername"
  echo "     --subdomain              subdomain is required for default setup_type = ingress"
  echo "                              e.g. --subdomain=test.dashbase.io"
  echo "     --install_dashbase       setup dashbase after EKS setup complete, e.g. --install_dashbase"
  echo "     --ssh_key_path           enter the custom ssh pub key for EKS node"
  echo "                              e.g. --ssh_key_path=my_ssh_key.pub"
  echo "     --bucketname             enter existing or custom s3 bucket name"
  echo "                              e.g. --bucketname=mys3-bucket"
  echo "     --dry-run                will run dependency check and create 2 files below"
  echo "                              my_dashbase_specfile  &  target-eks-cluster.yaml"
  echo ""
  echo "   Command example "
  echo "   ./aws_eks_dashbase_install.sh --aws_access_key=YOURAWSACCESSKEY \ "
  echo "                                 --aws_secret_access_key=YOURACESSSECRETACCESSKEY \ "
  echo "                                 --region=us-east-1 --subdomain=test.dashase.io  \ "
  echo "                                 --install_dashbase  "
  echo ""
  exit 0
}

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
  log_info "Parsing ($1)"
  shift 1

  case $PARAM in
  --help)
    display_help
    ;;
  --dry-run)
    DRY_RUN="true"
    log_info "DRY_RUN flag is $DRY_RUN"
    ;;
  --aws_access_key)
    fail_if_empty "$PARAM" "$VALUE"
    AWS_ACCESS_KEY=$VALUE
    ;;
  --aws_secret_access_key)
    fail_if_empty "$PARAM" "$VALUE"
    AWS_SECRET_ACCESS_KEY=$VALUE
    ;;
  --region)
    fail_if_empty "$PARAM" "$VALUE"
    REGION=$VALUE
    ;;
  --cluster_name)
    fail_if_empty "$PARAM" "$VALUE"
    CLUSTERNAME=$VALUE
    ;;
  --subdomain)
    fail_if_empty "$PARAM" "$VALUE"
    SUBDOMAIN=$VALUE
    ;;
  --install_dashbase)
    INSTALL_DASHBASE="true"
    ;;
  --ssh_key_path)
    fail_if_empty "$PARAM" "$VALUE"
    SSH_KEY_PATH=$VALUE
    ;;
  --bucketname)
    fail_if_empty "$PARAM" "$VALUE"
    BUCKETNAME=$VALUE
    ;;
  *)
    log_fatal "Unknown parameter ($PARAM) with ${VALUE:-no value}"
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

run_by_root() {
  if [[ $EUID -ne 0 ]]; then
    log_fatal "This script must be run as root"
  fi
}

check_commands() {
  for x in $CMDS; do
    command -v "$x" >/dev/null && continue || { log_warning "$x command not found." &&  yum install -y $x > /dev/null 2>&1 ; }
  done
}

check_ostype() {
  if [[ $OSTYPE == *"darwin"* ]]; then
    WKOSTYPE="mac"
    log_faltal "Dedected current workstation is a $WKOSTYPE"
  elif [[ $OSTYPE == *"linux"* ]]; then
    WKOSTYPE="linux"
    log_info "Dedected current workstation is a $WKOSTYPE"
  else
    log_fatal "This script is only tested on linux; and fail to detect the current worksattion os type"
  fi
}

check_specfile() {
  if [ ! -f "$SPECFILE" ]; then
    log_fatal "Dashbase spec file $SPECFILE is not found"
  fi
  CLUSTERTYPE=$(cat $SPECFILE | grep CLUSTERTYPE | cut -d"=" -f2 | sed -e 's/\"//g')
  DASHVERSION=$(cat $SPECFILE | grep DASHVERSION | cut -d"=" -f2 | sed -e 's/\"//g')
  SUBDOMAIN_IN_SPECFILE=$(cat $SPECFILE | grep SUBDOMAIN | cut -d"=" -f2 | sed -e 's/\"//g')
  V1_FLAG=$(cat $SPECFILE | grep V1_FLAG | cut -d"=" -f2 | sed -e 's/\"//g')
  BUCKETNAME_IN_SPECFILE=$(cat $SPECFILE | grep BUCKETNAME | cut -d"=" -f2 | sed -e 's/\"//g')
  log_info "From dashbase_sepcfile cluster setup type is $CLUSTERTYPE"
  log_info "From dashbase_specfile target dashbase version is $DASHVERSION"
}

check_version() {
  VERSION=$DASHVERSION
  if [ "$(curl --silent -k https://registry.hub.docker.com/v2/repositories/dashbase/api/tags/$VERSION | tr -s ',' '\n' | grep -c digest)" -eq 1 ]; then
    log_info "Dashbase version $VERSION in dashbase_specfile is valid"
  else
    log_fatal "Dashbase version $VERSION in dashbase_specfile is invalid"
  fi
  # create VNUM
  if [ "$V1_FLAG" == "true" ]; then
    log_info "From dashbase specfile V1 Backend is selected"
    VNUM=1
  else
    if [[ "$VERSION" == *"nightly"* ]]; then
      log_info "nightly version is used, VNUM is set to 2 by default"
      VNUM=2
    else
      VNUM=$(echo $VERSION | cut -d "." -f1)
      log_info "version is $VERSION and VNUM is $VNUM"
    fi
  fi
}

check_bucketname() {
 if [ "$VNUM" -eq 2 ]; then
   if [[ -n "$BUCKETNAME" ]]; then
     log_info "Entered bucketname is $BUCKETNAME"
     sed -i "s|bucketnotfound|$BUCKETNAME|" "$SPECFILE"
   elif [[ -z "$BUCKETNAME" ]] && [[ "$BUCKETNAME_IN_SPECFILE" == "bucketnotfound" ]]; then
     BUCKETNAME="s3-$CLUSTERNAME"
     log_info "No bucketname is entered use default bucketname $BUCKETNAME"
     sed -i "s|bucketnotfound|$BUCKETNAME|" "$SPECFILE"
   elif [[ -z "$BUCKETNAME" ]] && [[ "$BUCKETNAME_IN_SPECFILE" != "bucketnotfound" ]]; then
     BUCKETNAME="$BUCKETNAME_IN_SPECFILE"
     log_info "No bucketname is entered use bucketname from dashbase_specfile $BUCKETNAME"
   fi
 fi
}

check_subdomain() {
  if [ -n "$SUBDOMAIN" ] && [ "$SUBDOMAIN_IN_SPECFILE" == "test.dashbase.io" ]; then
    log_info "Entered subdomain is $SUBDOMAIN"
    sed -i "s|test.dashbase.io|$SUBDOMAIN|g" "$SPECFILE"
  elif [ "$SUBDOMAIN_IN_SPECFILE" != "test.dashbase.io" ]; then
    SUBDOMAIN="$SUBDOMAIN_IN_SPECFILE"
    log_info "Subdomain $SUBDOMAIN from dashbase_specfile is used"
  elif [ -z "$SUBDOMAIN" ] && [ "$SUBDOMAIN_IN_SPECFILE" == "test.dashbase.io" ]; then
    log_fatal "No subdomain is entered in script argument or defined in dashbase_specfile"
  fi
}

check_aws_key() {
  # if either AWS key or AWS secret is not present, script run will be fail and exit 1
  if [ "$AWS_ACCESS_KEY" == "undefined" ] || [ "$AWS_SECRET_ACCESS_KEY" == "undefined" ]; then
    log_fatal "Missing either AWS access key id or secret"
  else
    log_info "Entered aws access key id = $AWS_ACCESS_KEY"
    log_info "Entered aws secret access key = $AWS_SECRET_ACCESS_KEY"
    log_info "Default AWS region = $REGION"
  fi
}

check_instance_type() {
  if [ "$VNUM" -ge 2 ] && ([ "$CLUSTERTYPE" == "prod" ] || [ "$CLUSTERTYPE" == "large" ]); then
    INSTYPE="c5.4xlarge"
  elif [ "$VNUM" -ge 2 ] && [ "$CLUSTERTYPE" == "small" ]; then
    INSTYPE="c5.2xlarge"
  elif [ "$VNUM" -eq 1 ] && ([ "$CLUSTERTYPE" == "prod" ] || [ "$CLUSTERTYPE" == "large" ]); then
    INSTYPE="r5.2xlarge"
  elif [ "$VNUM" -eq 1 ] && [ "$CLUSTERTYPE" == "small" ]; then
    INSTYPE="r5.xlarge"
  fi
  log_info "AWS instance type using is $INSTYPE"
}

estimate_node_count() {
source "$SPECFILE"
if [ "$VNUM" -ge 2 ]; then
  for j in {1..10} ; do
   if [[ -n $(eval "echo \$TABLENAME$j") ]]; then
     eval "echo TABLENAME$j is set and is \${TABLENAME$j}"
     # check V2 table manager replica
     if [[ -n $(eval "echo \$TMR_REPL_CNT$j") ]]; then
        eval "echo TMR_REPL_CNT$j is \${TMR_REPL_CNT$j}"
     else
        export TMR_REPL_CNT$j=1
        eval "echo TMR_REPL_CNT$j is \${TMR_REPL_CNT$j}"
     fi
     # check V2 indexer replica
     if [[ -n $(eval "echo \$INX_REPL_CNT$j") ]]; then
        eval "echo INX_REPL_CNT$j is \${INX_REPL_CNT$j}"
     else
        export INX_REPL_CNT$j=1
        eval "echo INX_REPL_CNT$j is \${INX_REPL_CNT$j}"
     fi
     echo $(printf %.$2f $(echo "scale=2; ($(eval "echo \${TMR_REPL_CNT$j}") / 5) + ($(eval "echo \${INX_REPL_CNT$j}") / 2)" |bc)) |tee -a "$BASEDIR"/estnodecountfile
   else
     eval "echo TABLENAME$j is not set"
   fi
  done
  # check V2 searcher replica
  if [[ -n $SER_REPL_CNT ]]; then
     echo "A custom searcher replica count is used"
  elif  [[ "$CLUSTERTYPE" == "prod" ]]; then
     export SER_REPL_CNT=2
     echo "Default prod searcher replica count is used"
  else
     export SER_REPL_CNT=1
     echo "Default searcher replica count is used"
  fi
  echo "The searcher replica count is $SER_REPL_CNT"
  echo $(printf %.$2f $(echo "scale=2; $SER_REPL_CNT / 2" |bc)) | tee -a "$BASEDIR"/estnodecountfile
else
  for j in {1..10} ; do
   if [[ -n $(eval "echo \$TABLENAME$j") ]]; then
     eval "echo TABLENAME$j is set and is \${TABLENAME$j}"
     # check V1 table replica count
     if [[ -n $(eval "echo \$TB_REPL_CNT$j") ]]; then
        eval "echo TB_REPL_CNT$j is \${TB_REPL_CNT$j}"
     else
        if [[ "$CLUSTERTYPE" == "prod" ]]; then
           export TB_REPL_CNT$j=2
        else
           export TB_REPL_CNT$j=1
        fi
        eval "echo TB_REPL_CNT$j is \${TB_REPL_CNT$j}"
     fi
     echo $(printf %.$2f $(echo "scale=2; ($(eval "echo \${TB_REPL_CNT$j}") / 2) + 0.1" |bc)) | tee -a "$BASEDIR"/estnodecountfile
   else
     eval "echo TABLENAME$j is not set"
   fi
  done
fi

# Evaluate total node numbers
BACKEND_NODES=$(cat "$BASEDIR"/estnodecountfile | awk '{node_num += $0} END{print node_num}')

if [[ "$CLUSTERTYPE" == "prod" ]]; then
   TOTAL_NODES=$BACKEND_NODES
   echo "The total number of backend nodes  with instance type $INSTYPE required in dashbase-backend nodegroup is $TOTAL_NODES"
   echo "The total number of core nodes with instance type c5.xlarge required in dashbase-core nodegroup is 3"
elif [[ "$CLUSTERTYPE" == "large" ]]; then
   TOTAL_NODES=$(expr $BACKEND_NODES + 1)
   echo "The total number of nodes with instance type $INSTYPE required is $TOTAL_NODES"
elif [[ "$CLUSTERTYPE" == "small" ]]; then
   TOTAL_NODES=$(expr $BACKEND_NODES + 2)
   echo "The total number of nodes with instance type $INSTYPE required is $TOTAL_NODES"
fi
}

install_aws_cli() {
  # install aws cli and its dependency
  yum install -y glibc groff less unzip > /dev/null 2>&1
  curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
  unzip -o awscliv2.zip > /dev/null 2>&1
  sudo ./aws/install > /dev/null 2>&1
}

check_and_install_aws_cli() {
  if [ "$(
    command -v aws >/dev/null
    echo $?
  )" -eq "0" ]; then
    AWSVER=$(aws --version -o text &> awsfile ;  cat awsfile |awk '{print $1}' | cut -d"/" -f2 | cut -c-1)
    log_info "aws cli is already installed and is in version $AWSVER"
    if [ "$AWSVER" -lt 2 ]; then
      log_warning "aws version $AWSVER does not meet requirement, reinstalling aws cli to version 2"
      install_aws_cli
    else
      log_info "aws version $AWSVER meet requirement"
    fi
  else
    log_info "aws cli is not installed, installing it now"
    install_aws_cli
  fi
}

install_kubectl() {
  if [ "$(
    command -v kubectl >/dev/null
    echo $?
  )" -eq "0" ]; then
    log_info "kubectl is installed in this host"
    kubectl version --client --short=true
  else
    log_info "kubectl is not installed, installing it now"
    curl -k https://storage.googleapis.com/kubernetes-release/release/v1.17.0/bin/linux/amd64/kubectl -o /usr/local/bin/kubectl
    chmod a+x /usr/local/bin/kubectl
  fi
}

install_eksctl() {
  if [ "$(
    command -v eksctl >/dev/null
    echo $?
  )" -eq "0" ]; then
    log_info "eksctl is installed in this host"
    eksctl version
  else
    log_info "eksctl is not installed, installing it now"
    curl --silent --location "https://github.com/weaveworks/eksctl/releases/download/latest_release/eksctl_$(uname -s)_amd64.tar.gz" | tar xz -C /tmp
    mv /tmp/eksctl /usr/local/bin
    chmod +x /usr/local/bin/eksctl
  fi
}

install_helm3() {
  if [ "$(
    command -v helm >/dev/null
    echo $?
  )" -eq "0" ]; then
    log_info "helm is installed, checking helm version"
    # check helm version 2 or 3
    if [ "$(helm version --client | grep -c "v3.")" -eq "1" ]; then log_info "this is helm3"; else log_fatal "helm2 is detected, please uninstall it before proceeding"; fi
  else
    log_info "helm 3 is not installed, isntalling it now"
    curl -k https://get.helm.sh/helm-${HELM_VERSION}-linux-amd64.tar.gz -o helm-${HELM_VERSION}-linux-amd64.tar.gz
    tar -zxvf helm-${HELM_VERSION}-linux-amd64.tar.gz
    cp linux-amd64/helm /usr/local/bin/
    chmod +x /usr/local/bin/helm
  fi
}

create_ssh_key_pairs() {
  if [ -z "$SSH_KEY_PATH" ]; then
    log_info "No ssh key path is entered, create ssh keypairs dashbase_rsa and dashbase_rsa.pub"
    rm -rf "$BASEDIR"/dashbase_rsa
    ssh-keygen -q -t rsa -N '' -f "$BASEDIR"/dashbase_rsa <<< ""$'\n'"y"
    PUBKEY="$BASEDIR/dashbase_rsa.pub"
  else
    log_info "ssh key path is entered"
    PUBKEY="$SSH_KEY_PATH"
  fi
  log_info "The ssh pub key path is $PUBKEY"
}

setup_centos() {
  # the setup_centos function  will install aws cli, kubectl, eksctl and helm3
  # install aws cli
  check_and_install_aws_cli
  log_info "Configure AWS CLI"
  /usr/local/bin/aws --version
  /usr/local/bin/aws --profile default configure set aws_access_key_id $AWS_ACCESS_KEY
  /usr/local/bin/aws --profile default configure set aws_secret_access_key $AWS_SECRET_ACCESS_KEY
  /usr/local/bin/aws --profile default configure set region $REGION
  sleep 5
  /usr/local/bin/aws configure list

  # install kubectl
  install_kubectl

  # install eksctl
  install_eksctl

  # install helm 3
  install_helm3

  # export all command path
  export PATH=$PATH:/usr/local/bin/kubectl:/usr/local/bin/helm:/usr/local/bin/eksctl
}

set_eks_file(){
  if [ "$CLUSTERTYPE" == "prod" ]; then
    cp "$BASEDIR"/prod-eks-cluster.yaml "$BASEDIR"/target-eks-cluster.yaml
  else
    cp "$BASEDIR"/eks-cluster.yaml "$BASEDIR"/target-eks-cluster.yaml
  fi
  EKSFILE="$BASEDIR"/target-eks-cluster.yaml
}

update_eks_cluster_yaml(){
  set_eks_file
  sed -i "s|CLUSTERNAME|$CLUSTERNAME|" $EKSFILE
  sed -i "s|REGION|$REGION|g" $EKSFILE
  sed -i "s|KUBECTLVERSION|$KUBECTLVERSION|" $EKSFILE
  sed -i "s|MYINSTYPE|$INSTYPE|" $EKSFILE
  sed -i "s|NODECOUNT|$TOTAL_NODES|g" $EKSFILE
  sed -i "s|MYPUBKEY|$PUBKEY|" $EKSFILE
}

check_previous_mydash() {
  echo "Checking exiting EKS clusters in $REGION"
  PREVIOUSEKS=$(aws eks list-clusters --region $REGION | grep mydash | sed -e 's/\"//g' | sed -e 's/^[ \t]*//')
  if [ -z "$PREVIOUSEKS" ]; then
    log_info "No previous mydashXXXXXX EKS cluster detected"
  else
    if [ "$DRY_RUN" == "true" ]; then
      log_warning "Previous mydashXXXXXX EKS clustername $PREVIOUSEKS is detected"
    else
      log_fatal "Previous mydashXXXXXX EKS clustername $PREVIOUSEKS is detected"
    fi
  fi
}

check_max_vpc_limit() {
  echo "Checking the current number of VPC in the region $REGION"
  VPC_LIMIT=$(aws service-quotas get-service-quota --service-code 'vpc' --region $REGION --quota-code 'L-F678F1CE' --output text | awk '{print $NF}' | awk '{$0=int($0)}1')
  log_info "The max vpc limit in the region $REGION is $VPC_LIMIT"
  # verify vpc max limit is int or not
  if [[ $VPC_LIMIT =~ ^-?[0-9]+$ ]]; then
    log_info "Checking VPC max limit value and  is an integer and is equal to $VPC_LIMIT"
  else
    log_warning "The detected VPC max limit is not an integer, something may be wrong, and will use default vpc max limit in the region $REGION and is 5"
    VPC_LIMIT="5"
  fi
}

setup_eks_cluster() {
  # Setup AWS EKS cluster with provided AWS Access key from the centos nodea
  check_previous_mydash
  check_max_vpc_limit
  # compare vpc count with max vpc limit , the vpc count should be less than vpc limit
  if [ "$(/usr/local/bin/aws ec2 describe-vpcs --region $REGION --output text | grep -c VPCS)" -lt $VPC_LIMIT ]; then
    log_info "creating AWS eks cluster, please wait. This process will take 15-20 minutes"
    date +"%T"
    echo "/usr/local/bin/eksctl create cluster -f $EKSFILE"
    /usr/local/bin/eksctl create cluster -f $EKSFILE
    date +"%T"
  else
    log_fatal "Specified EKS cluser region may not have sufficient capacity for additional VPC"
  fi
}

check_eks_cluster() {
  # check AWS EKS cluster status
  while [ -z "$(/usr/local/bin/aws eks list-clusters --region $REGION --output text | awk '{print $2}' | grep $CLUSTERNAME)" ] && [ $SECONDS -lt 30 ]; do echo -n "#"; done
  if [ "$(/usr/local/bin/aws eks describe-cluster --name $CLUSTERNAME --region $REGION | grep status | awk '{print $2}' | sed -e 's/\"//g' | sed -e 's/\,//g' | tr -d '\r')" == "ACTIVE" ]; then
    log_info "The EKS cluster $CLUSTERNAME is ACTIVE and ready"
  else
    log_fatal "The EKS cluster $CLUSTERNAME status is not ACTIVE"
  fi
  aws eks --region "$REGION" update-kubeconfig --name "$CLUSTERNAME"
  log_info "Checking K8s nodes"
  /usr/local/bin/kubectl get nodes
}

create_s3() {
  if [ "$(aws s3 ls / | grep -c $BUCKETNAME)" -eq "1" ]; then
    log_info "S3 bucket already be created previously"
  else
    log_info "s3 bucekt with name %BUCKETNAME is not found, creating"
    aws s3 mb s3://$BUCKETNAME --region $REGION
    if [ "$(
      aws s3 ls s3://$BUCKETNAME >/dev/null
      echo $?
    )" -eq "0" ]; then
      log_info "S3 bucket $BUCKETNAME created successfully"
    else
      log_fatal "S3 bucket $BUCKETNAME failed to create"
    fi
  fi
}

update_s3_policy_json() {
  # remove any previous mydash-s3.json file if exists
  rm -rf mydash-s3.json
  # download the mydash-s3.json from github
  curl -k https://raw.githubusercontent.com/dashbase/dashbase-installation/master/deployment-tools/mydash-s3.json -o mydash-s3.json
  sed -i "s/MYDASHBUCKET/$BUCKETNAME/" mydash-s3.json
}

# create s3 bucket policy
create_s3_bucket_policy() {
  POARN=$(echo "aws iam list-policies --query 'Policies[?PolicyName==\`$BUCKETNAME\`].Arn' --output text |awk '{ print $1}'" | bash)
  if [ -z "$POARN" ]; then
    log_info "s3 bucket policy $BUCKETNAME not exists, and now creating"
    aws iam create-policy --policy-name $BUCKETNAME --policy-document file://mydash-s3.json
    POARN=$(echo "aws iam list-policies --query 'Policies[?PolicyName==\`$BUCKETNAME\`].Arn' --output text |awk '{ print $1}'" | bash)
    log_info "The s3 bucket policy ARN is $POARN"
  else
    log_info "s3 bucket policy $POARN exists"
  fi
}

# attach the s3 bucket policy to the EKS worker nodegroup instance profile
insert_s3_policy_to_nodegroup() {
  command -v jq >/dev/null
  if [[ "${?}" -ne 0 ]]; then
    printf "jq is not installed, install jq now\\n"
    yum install -y https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
    yum install jq -y
  fi

  POARN=$(echo "aws iam list-policies --query 'Policies[?PolicyName==\`$BUCKETNAME\`].Arn' --output text |awk '{ print $1}'" | bash)
  for NODEGROUP in $(aws eks list-nodegroups --region=$REGION --output json --cluster-name $CLUSTERNAME | jq -r '.nodegroups[]'); do
    IAMINSROLE=$(aws eks describe-nodegroup --region=$REGION --output json --cluster-name $CLUSTERNAME --nodegroup-name $NODEGROUP | jq -r '.nodegroup.nodeRole' | cut -d "/" -f2)
    log_info "Found associated worker nodegroup: $IAMINSROLE"
    log_info "attaching the s3 bucket policy $POARN to the role $IAMINSROLE"
    aws iam attach-role-policy --policy-arn "$POARN" --role-name "$IAMINSROLE"
    #check_role_policy
    log_info "checking attached s3 bucket policy on the role $IAMINSROLE"
    COUNTPO=$(aws iam list-attached-role-policies --role-name "$IAMINSROLE" --output text | grep -c "$POARN")
    if [ "$COUNTPO" -eq "1" ]; then
      log_info "The s3 bucket access policy $POARN is attached to role $IAMINSROLE"
    else
      log_fatal "The s3 bucket access policy $POARN is not attached to role $IAMINSROLE"
    fi
  done
}


setup_dashbase() {
  if [ "$INSTALL_DASHBASE" == "true" ]; then
    log_info "Install dashbase option is entered. This will install dashbase on the previously created EKS cluster $CLUSTERNAME"
    if [ "$VNUM" -eq 2 ]; then
      log_info "Setup Dashbase V2 required s3 buckets"
      create_s3
      update_s3_policy_json
      create_s3_bucket_policy
      insert_s3_policy_to_nodegroup
      sleep 10
    fi
    echo "setup and configure dashbase, this process will take 20-30 minutes"
    "$BASEDIR"/dashbase-installer.sh --specfile="$SPECFILE"
  else
    log_info "Install dashbase option is not selected, please run dashbase install script to setup your cluster"
  fi
}

display_bucketname() {
  if [[ $INSTALL_DASHBASE == "true" ]] && [[ ${VNUM} -ge 2 ]]; then
    POARN=$(echo "aws iam list-policies --query 'Policies[?PolicyName==\`$BUCKETNAME\`].Arn' --output text |awk '{ print $1}'" | bash)
    IAMINSROLE=$(aws iam get-instance-profile --instance-profile-name "$INSPROFILENAME" | grep RoleName | sed -e 's/\"//g' | sed -e 's/\,//g' | awk '{ print $2}')
    echo "The S3 bucket name used in dashbase V2 setup is $BUCKETNAME"
    echo "The S3 bucket policy is $POARN"
    echo "The IAM role attached with the s3 bucket policy is $IAMINSROLE"
  fi
}

main_jobs() {
    run_by_root
    check_ostype
    check_commands
    check_specfile
    check_version
    check_bucketname
    check_subdomain
    check_aws_key
    check_instance_type
    estimate_node_count
    setup_centos
    create_ssh_key_pairs
    update_eks_cluster_yaml
    setup_eks_cluster
    check_eks_cluster
    setup_dashbase
    display_bucketname
}

# main process below this line
{
  if [ "$DRY_RUN" == "true" ]; then
    run_by_root
    check_ostype
    check_commands
    check_specfile
    check_version
    check_bucketname
    check_subdomain
    check_instance_type
    estimate_node_count
    PUBKEY="$BASEDIR/dashbase_rsa.pub"
    update_eks_cluster_yaml
    check_previous_mydash
    check_max_vpc_limit
    # compare vpc count with max vpc limit , the vpc count should be less than vpc limit
    if [ "$(/usr/local/bin/aws ec2 describe-vpcs --region $REGION --output text | grep -c VPCS)" -lt $VPC_LIMIT ]; then
      log_info "The region $REGION still has available quota for additional VPC for EKS cluster"
    else
      log_warning "The region $REGION doesn't have enough quota for additional VPC, please contact AWS support to raise the VPC quota"
    fi
    echo "The aws_eks_dashbase_install script is in dry-run mode, no change has made"
    echo "please check the file target-eks-cluster.yaml and my_dashbase_specfile"
    echo ""
  else
    main_jobs
  fi
} 2>&1 | tee -a /tmp/aws_eks_setup_"$(date +%d-%m-%Y_%H-%M-%S)".log
