#!/bin/bash

openssl rand -hex 4 >randomstring2
RSTRING2=$(cat randomstring2)

CLUSTERNAME="dashbase-$RSTRING2"
CMDS="curl tar unzip git aws kubectl"
REGION="us-east-2"
BUCKETNAME="undefined"

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

echo "$@" >/tmp/setup_arguments
echo "$#" >/tmp/no_arguments

while [[ $# -gt 0 ]]; do
  PARAM=${1%%=*}
  [[ "$1" == *"="* ]] && VALUE=${1#*=} || VALUE=""
  log_info "Parsing ($1)"
  shift 1

  case $PARAM in
  --cluster_name)
    fail_if_empty "$PARAM" "$VALUE"
    CLUSTERNAME=$VALUE
    ;;
  --region)
    fail_if_empty "$PARAM" "$VALUE"
    REGION=$VALUE
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

run_by_root() {
  if [[ $EUID -ne 0 ]]; then
    log_fatal "This script must be run as root"
  fi
}

check_commands() {
  for x in $CMDS; do
    command -v "$x" >/dev/null && continue || { log_fatal "$x command not found."; }
  done
}

if [ $BUCKETNAME == "undefined" ]; then
  BUCKETNAME="s3-$CLUSTERNAME"
fi

log_info "the S3 bucket that will be created with name $BUCKETNAME"
# create s3 bucket
create_s3() {
  if [ "$(aws s3 ls / |grep -c $BUCKETNAME)" -eq "1" ]; then
     log_info "S3 bucket already be created previously"
  else
     log_info "s3 bucekt with name %BUCKETNAME is not found, creating"
     aws s3 mb s3://$BUCKETNAME --region $REGION
     if [ "$(aws s3 ls s3://$BUCKETNAME > /dev/null; echo $?)" -eq "0" ]; then log_info "S3 bucket $BUCKETNAME created successfully"; else log_fatal "S3 bucket $BUCKETNAME failed to create"; fi
  fi
}

check_ostype() {
  if [[ $OSTYPE == *"darwin"* ]]; then
    WKOSTYPE="mac"
    log_fatal "Dedected current workstation is a $WKOSTYPE, this script only tested on linux"
  elif [[ $OSTYPE == *"linux"* ]]; then
    WKOSTYPE="linux"
    log_info "Dedected current workstation is a $WKOSTYPE"
  else
    log_fatal "This script is only tested on linux; and fail to detect the current worksattion os type"
  fi
}

# update bucket policy json with BUCKETNAME
update_s3_policy_json() {
   # remove any previous mydash-s3.json file if exists
   rm -rf mydash-s3.json
   # download the mydash-s3.json from github
   curl -k https://raw.githubusercontent.com/dashbase/dashbase-installation/master/deployment-tools/mydash-s3.json -o mydash-s3.json
   if [ "$WKOSTYPE" == "mac" ]; then
      sed -i "" "s/MYDASHBUCKET/$BUCKETNAME/" mydash-s3.json
   elif [ "$WKOSTYPE" == "linux" ]; then
      sed -i "s/MYDASHBUCKET/$BUCKETNAME/" mydash-s3.json
   fi
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

# main process below this line
#run_by_root
check_commands
check_ostype
create_s3
update_s3_policy_json
create_s3_bucket_policy
insert_s3_policy_to_nodegroup