#!/bin/sh

BASEDIR=$(dirname "$0")
rm -rf "$BASEDIR"/nodecountfile
rm -rf "$BASEDIR"/dashbase-values.yaml
rm -rf "$BASEDIR"/newv2table_template.yaml
rm -rf "$BASEDIR"/newv1table_template.yaml
rm -rf "$BASEDIR"/dashbase-license.txt
rm -rf "$BASEDIR"/data

CMDS="curl tar unzip git openssl java wget"

DASHVERSION="2.6.0"
INSTALLER_VERSION="2.6.0"
PLATFORM="undefined"
INGRESS_FLAG="false"
V2_FLAG="false"
V1_FLAG="false"
VALUEFILE="dashbase-values.yaml"
USERNAME="undefined"
LICENSE="undefined"
AUTHBASICUSERNAME="tester"
AUTHBASICPASSWORD="tester123!"
AUTHADMINUSERNAME="dashbaseadm"
AUTHADMINPASSWORD="dashbaseadm123!"
ADMINUSERNAME="dashbaseadm"
ADMINPASSWORD="dashbase123"
BUCKETNAME="undefined"
STORAGE_ACCOUNT="undefined"
STORAGE_KEY="undefined"
STORAGE_ENDPOINT="undefined"
PRESTO_FLAG="false"
PROD_FLAG="false"
TABLENAME1="logs"
CALL_FLOW_CDR_FLAG="false"
CALL_FLOW_SIP_FLAG="false"
DEMO_FLAG="false"
WEBRTC_FLAG="false"
SYSTEM_LOG="false"
SYSLOG_FLAG="false"
CLUSTERTYPE="large"
MIRROR_FLAG="false"
HPA_FLAG="false"
VPA_FLAG="false"
VPA_TBL_MINMEM="1G"
VPA_TBL_MAXMEM="10G"

echo "Installer script version is $INSTALLER_VERSION"

display_help() {
  echo "Usage: $0 [options...]"
  echo ""
  echo "   all options usage e.g. --option_key=value  or --option_key"
  echo "     --platform     aws/azure/gce/aliyun  e.g. --platform=aws"
  echo "     --version      dashbase version e.g. --version=1.3.2"
  echo "     --ingress      exposed dashbase services using ingress controller  e.g. --ingress"
  echo "     --ingresstable enable table endpoints expose in dedicated nginx ingress controller"
  echo "                    ingresstable flag need to be used together with ingress flag"
  echo "                    e.g.  --ingresstable"
  echo "     --subdomain    use together with ingress option e.g.  --subdomain=test.dashbase.io"
  echo "     --username     dashbase license username e.g. --username=myname"
  echo "     --license      dashbase license string  e.g. --license=my_license_string"
  echo "     --exposemon    expose dashbase prometheus and pushgateway endpoints when using LB (not ingress)"
  echo "                    e.g.  --exposemon"
  echo "     --basic_auth   use basic auth to secure dashbase web UX e.g.  --basic_auth"
  echo "                    basic auth requires authusername and authpassword options"
  echo "     --authusername basic auth username with basic role, use together with basic_auth option"
  echo "                    e.g. --authusername=myuser"
  echo "     --authpassword basic auth password for basic role user, use together with authusername option"
  echo "                    e.g. --authpassword=dashbase"
  echo "     --authadmin_username  basic auth username with admin role, use together with basic_auth option"
  echo "                           e.g. --authusername=myadmin"
  echo "     --authadmin_password  basic auth password for admin role user, use together with authusername option"
  echo "                           e.g. --authpassword=dashbase"
  echo "     --adminusername specify admin username to access to admin page web portal"
  echo "                     default admin user is dashbaseadm"
  echo "                     e.g. --adminusername=myechadmin"
  echo "     --adminpassword specify admin password to access to admin page web portal"
  echo "                     default admin passowrd is dashbase123"
  echo "                     e.g. --adminpassword=myadminpass"
  echo "     --syslog       enable dashbase syslog daemon, e.g. --syslog"
  echo "     --valuefile    specify a custom values yaml file"
  echo "                    e.g. --valuefile=/tmp/mydashbase_values.yaml"
  echo "     --tablename        dashbase table name, default table name is logs"
  echo "                        e.g. --tablename=freeswitch"
  echo "     --cluster_type specify the cluster type using the predefined standard"
  echo "                    e.g. --cluster_type=prod          2 * 16core/32Gi required, 2 nodegroups: dashbase-backend & dashbase-core"
  echo "                         --cluster_type=large         2 * 16core/32Gi required"
  echo "                         --cluster_type=small         3 * 8core/32Gi required"
  echo "                         --cluster_type=local         no limits"
  echo "     --mirror       use mirror to download images. (Currently, it's only for ingress controller)"
  echo ""
  echo "     UCASS CALL FLOW features, enable either call flow cdr or sip or netsapiens log"
  echo "     --callflow_cdr enable ucass call flow cdr log feature, e.g. --callflow_cdr"
  echo "     --callflow_sip enable ucass call flow SIP log feature, e.g. --callflow_sip"
  echo ""
  echo "     --help         display command options and usage example"
  echo "     --webrtc       enable remote read on prometheus to api url for webrtc data e.g. --webrtc"
  echo "     --systemlog    enable dashbase system log table, e.g. --systemlog  this will create a table called system."
  echo "                    and contains all dashbase pods logs in this system table"
  echo "     --demo         setup freeswitch,filebeat pods and feed log data into the target table"
  echo "                    e.g. --prod"
  echo "                    dashbase apps will deploy to nodgegroups dashbase-core and dashbase-backend"
  echo ""
  echo "   The following options only be used on V2 dashbase"
  echo "     --v2               setup dashbase V2"
  echo "     --v1               setup dashbase using V1 backend even if dashbase version 2.X is specified"
  echo "     --bucketname       cloud object storage bucketname"
  echo "                        e.g. --bucketname=my-s3-bucket"
  echo "     --storage_account  cloud object storage account value, in AWS is the ACCESS KEY"
  echo "                        e.g. --storage_account=MYSTORAGEACCOUNTSTRING"
  echo "     --storage_key      cloud object storage key, in AWS is the ACCESS SECRET"
  echo "                        e.g. --storage_key=MYSTORAGEACCOUNTACCESSKEY"
  echo "     --storage_endpoint cloud object endpoint url. (currently only available in aliyun platform)"
  echo "                        e.g. --storage_endpoint=https://oss-cn-hangzhou.aliyuncs.com"
  echo "     --hpa              enable horizontal autoscaler for indexer"
  echo "                        e.g. --hpa"
  echo "     --vpa              enable vertical autoscaler for table-manager on memory resource"
  echo "                        e.g. --vpa"
  echo "     --vpa_min          enable table-manager vertical autoscaler, and set min memory value"
  echo "                        e.g. --vpa_min=2G"
  echo "     --vpa_max          enable table-manager vertical autoscaler, and set max memory value"
  echo "                        e.g. --vpa_max=10G"
  echo ""
  echo "   Command example in V1"
  echo "   ./dashbase-create-valuesfile.sh --platform=aws --ingress --subdomain=test.dashbase.io \ "
  echo "                                   --v1 --version=2.4.1 --callflow_cdr "
  echo ""
  echo "   Command example in V2"
  echo "   ./dashbase-create-valuesfile.sh --platform=aws  --ingress \ "
  echo "                                   --subdomain=test.dashase.io \ "
  echo "                                   --bucketname=my-s3-bucket \ "
  echo "                                   --hpa --vpa --vpa_min=2G --vpa_max=9G \ "
  echo "                                   --ingresstable --basic_auth "
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

echo "$@" > /tmp/setup_arguments
echo "$#" > /tmp/no_arguments

while [[ $# -gt 0 ]]; do
  PARAM=${1%%=*}
  [[ "$1" == *"="* ]] && VALUE=${1#*=} || VALUE=""
  log_info "Parsing ($1)"
  shift 1

  case $PARAM in
  --help)
    display_help
    ;;
  --specfile)
    fail_if_empty "$PARAM" "$VALUE"
    SPECFILE=$VALUE
    source "$BASEDIR/$SPECFILE"
    log_info "Spec file $SPECFILE is used"
    break
    ;;
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
  --username)
    fail_if_empty "$PARAM" "$VALUE"
    USERNAME=$VALUE
    ;;
  --license)
    fail_if_empty "$PARAM" "$VALUE"
    LICENSE=$VALUE
    ;;
  --bucketname)
    fail_if_empty "$PARAM" "$VALUE"
    BUCKETNAME=$VALUE
    ;;
  --tablename1)
    fail_if_empty "$PARAM" "$VALUE"
    TABLENAME1=$VALUE
    ;;
  --tablename2)
    fail_if_empty "$PARAM" "$VALUE"
    TABLENAME2=$VALUE
    ;;
  --tablename3)
    fail_if_empty "$PARAM" "$VALUE"
    TABLENAME3=$VALUE
    ;;
  --tablename4)
    fail_if_empty "$PARAM" "$VALUE"
    TABLENAME4=$VALUE
    ;;
  --tablename5)
    fail_if_empty "$PARAM" "$VALUE"
    TABLENAME5=$VALUE
    ;;
  --v2)
    V2_FLAG="true"
    ;;
   --v1)
    V1_FLAG="true"
    ;;
  --callflow_cdr)
    CALL_FLOW_CDR_FLAG="true"
    ;;
  --callflow_sip)
    CALL_FLOW_SIP_FLAG="true"
    ;;
  --authusername)
    fail_if_empty "$PARAM" "$VALUE"
    AUTHBASICUSERNAME=$VALUE
    ;;
  --authpassword)
    fail_if_empty "$PARAM" "$VALUE"
    AUTHBASICPASSWORD=$VALUE
    ;;
  --authadmin_username)
    fail_if_empty "$PARAM" "$VALUE"
    AUTHADMINUSERNAME=$VALUE
    ;;
  --authadmin_password)
    fail_if_empty "$PARAM" "$VALUE"
    AUTHADMINPASSWORD=$VALUE
    ;;
  --adminusername)
    fail_if_empty "$PARAM" "$VALUE"
    ADMINUSERNAME=$VALUE
    ;;
  --adminpassword)
    fail_if_empty "$PARAM" "$VALUE"
    ADMINPASSWORD=$VALUE
    ;;
  --cluster_type)
    fail_if_empty "$PARAM" "$VALUE"
    CLUSTERTYPE=$VALUE
    ;;
  --storage_account)
    fail_if_empty "$PARAM" "$VALUE"
    STORAGE_ACCOUNT=$VALUE
    ;;
  --storage_key)
    fail_if_empty "$PARAM" "$VALUE"
    STORAGE_KEY=$VALUE
    ;;
  --storage_endpoint)
    fail_if_empty "$PARAM" "$VALUE"
    STORAGE_ENDPOINT=$VALUE
    ;;
  --basic_auth)
    BASIC_AUTH="true"
    ;;
  --ingress)
    INGRESS_FLAG="true"
    ;;
  --ingresstable)
    INGRESS_TABLE="true"
    ;;
  --exposemon)
    EXPOSEMON="--exposemon"
    ;;
  --demo)
    DEMO_FLAG="true"
    ;;
  --systemlog)
    SYSTEM_LOG="true"
    ;;
  --webrtc)
    WEBRTC_FLAG="true"
    ;;
  --syslog)
    SYSLOG_FLAG="true"
    ;;
  --mirror)
    MIRROR_FLAG="true"
    ;;
  --hpa)
    HPA_FLAG="true"
    ;;
  --vpa)
    VPA_FLAG="true"
    ;;
  --vpa_min)
    fail_if_empty "$PARAM" "$VALUE"
    VPA_TBL_MINMEM=$VALUE
    ;;
  --vpa_max)
    fail_if_empty "$PARAM" "$VALUE"
    VPA_TBL_MAXMEM=$VALUE
    ;;
  --dry-run)
    DRY_RUN="true"
    ;;
  *)
    log_fatal "Unknown parameter ($PARAM) with ${VALUE:-no value}"
    ;;
  esac
done

check_commands() {
  for x in $CMDS; do
    command -v "$x" > /dev/null && continue || { log_fatal "$x command not found."; }
  done
}

check_ostype() {
  if [[ $OSTYPE == *"darwin"* ]]; then
    WKOSTYPE="mac"
    log_fatal "Detected current workstation is a $WKOSTYPE, and this script is not supported in $WKOSTYPE"
    #COMMAND_SED() {
    #  sed -i '' "$@"
    #}
  elif [[ $OSTYPE == *"linux"* ]]; then
    WKOSTYPE="linux"
    log_info "Detected current workstation is a $WKOSTYPE"
    COMMAND_SED() {
      sed -i "$@"
    }
  else
    log_fatal "This script is only tested on linux or mac; and fail to detect the current workstation os type"
  fi
}


check_cluster_type_input() {
  # check entered cluster type
  if [ "$CLUSTERTYPE" == "prod" ]; then
    echo "using cluster type: $CLUSTERTYPE"
  elif [ "$CLUSTERTYPE" == "large" ]; then
    echo "using cluster type: $CLUSTERTYPE"
  elif [ "$CLUSTERTYPE" == "small" ]; then
    echo "using cluster type: $CLUSTERTYPE"
  elif [ "$CLUSTERTYPE" == "local" ]; then
    echo "using cluster type: $CLUSTERTYPE"
  else
    echo "Incorrect cluster type, and platform type should be either large, small or local"
  fi

  case "$CLUSTERTYPE" in
  prod)
    INDEXERCPU=7
    INDEXERMEMORY=15
    ;;
  large)
    INDEXERCPU=7
    INDEXERMEMORY=15
    ;;
  small)
    INDEXERCPU=3
    INDEXERMEMORY=8
    ;;
  local)
    INDEXERCPU=4
    INDEXERMEMORY=8
    ;;
  esac
}

check_v2() {
  # check v2 input
  if [[ "$V2_FLAG" ==  "true" ]] || [[ ${VNUM} -ge 2 ]]; then
    log_info "V2 is selected checking V2 requirement"
    if [ "$BUCKETNAME" == "undefined" ]; then
       log_fatal "V2 is selected but not provide any cloud object storage bucket name"
    elif [ "$BUCKETNAME" != "undefined" ]; then
       log_info "V2 is selected and bucket name is $BUCKETNAME"
       V2_NODE="true"
    fi
    if [ "$PLATFORM" == "gce" ] || [ "$PLATFORM" == "azure" ] || [ "$PLATFORM" == "aliyun" ]; then
       log_info "V2 is selected and cloud platform is $PLATFORM"
       if [ "$STORAGE_ACCOUNT" == "undefined" ] || [ "$STORAGE_KEY" == "undefined" ]; then
          log_fatal "V2 setup on $PLATFORM requires inputs for --storage_account and --storage_key"
       fi
    fi
  elif [[ "$V2_FLAG" ==  "false" ]] && [[ ${VNUM} -eq 1 ]]; then
      log_info "V2 is not selected in this installation"
      V2_NODE="false"
  fi
}

check_version() {
  if [ -z "$VERSION" ]; then
    VERSION=$DASHVERSION
    log_info "No input dashbase version, use default version $DASHVERSION"
  else
    log_info "Dashbase version entered is $VERSION"
    if [ "$(curl --silent -k https://registry.hub.docker.com/v2/repositories/dashbase/api/tags/$VERSION |tr -s ',' '\n' |grep -c digest)" -eq 1 ]; then
      log_info "Entered dashbase version $VERSION is valid"
    else
      log_fatal "Entered dashbase version $VERSION is invalid"
    fi
  fi
  # set VNUM
  if [ "$V1_FLAG" == "true" ]; then
    log_info "V1 Backend is selected"
    VNUM="1"
  else
    log_info "V1 Backend is not specified, checking input dashbase version $VERSION"
    if [[ "$VERSION" == *"nightly"* ]]; then
       log_info "nightly version is used, VNUM is set to 2 by default"
        VNUM="2"
     else
        VNUM=$(echo $VERSION |cut -d "." -f1)
        log_info "version is $VERSION and VNUM is $VNUM"
    fi
  fi
}

copy_dashbase_files() {
# copy dashbase-values.yaml file to the working directory
if [ "$V2_FLAG" == "true" ] || [ "$VNUM" -ge 2 ]; then
  echo "Copy dashbase-values-v2.yaml file for v2 setup"
  cp "$BASEDIR"/deployment-tools/dashbase-admin/dashbase_setup_tarball/${CLUSTERTYPE}setup/dashbase-values-v2.yaml "$BASEDIR"/dashbase-values.yaml
else
  echo "Copy dashbase-values.yaml file for v1 setup"
  cp "$BASEDIR"/deployment-tools/dashbase-admin/dashbase_setup_tarball/${CLUSTERTYPE}setup/dashbase-values.yaml "$BASEDIR"/dashbase-values.yaml
fi
# copy other required files locally
mkdir -p "$BASEDIR"/data
cp -rf "$BASEDIR"/deployment-tools/dashbase-admin/dashbase_setup_tarball/dashbase_setup_nolicy.tar "$BASEDIR"/data/
tar -xvf "$BASEDIR"/data/dashbase_setup_nolicy.tar -C "$BASEDIR"/data/
}


required_node_count() {
if [ "$V2_FLAG" ==  "true" ] || [ "$VNUM" -ge 2 ]; then
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
     echo $(printf %.$2f $(echo "scale=2; ($(eval "echo \${TMR_REPL_CNT$j}") / 5) + ($(eval "echo \${INX_REPL_CNT$j}") / 2)" |bc)) |tee -a "$BASEDIR"/nodecountfile
     # updates yaml file for V2 tables
     sed -e "s|LOGS|$(eval "echo \$TABLENAME$j")|" "$BASEDIR"/deployment-tools/dashbase-admin/dashbase_setup_tarball/${CLUSTERTYPE}setup/v2table_template.yaml >> $BASEDIR/newv2table_template.yaml
     sed -i "s|TABLEMANREPLICA|$(eval "echo \$TMR_REPL_CNT$j")|" "$BASEDIR"/newv2table_template.yaml
     sed -i "s|INDEXERREPLICA|$(eval "echo \$INX_REPL_CNT$j")|" "$BASEDIR"/newv2table_template.yaml
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
  echo $(printf %.$2f $(echo "scale=2; $SER_REPL_CNT / 2" |bc)) | tee -a "$BASEDIR"/nodecountfile
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
     echo $(printf %.$2f $(echo "scale=2; ($(eval "echo \${TB_REPL_CNT$j}") / 2) + 0.1" |bc)) | tee -a "$BASEDIR"/nodecountfile
     # update yaml file for V1 tables
     sed -e "s|LOGS|$(eval "echo \$TABLENAME$j")|" "$BASEDIR"/deployment-tools/dashbase-admin/dashbase_setup_tarball/${CLUSTERTYPE}setup/v1table_template.yaml >> "$BASEDIR"/newv1table_template.yaml
     sed -i "s|TABLEREPLICA|$(eval "echo \$TB_REPL_CNT$j")|" "$BASEDIR"/newv1table_template.yaml
   else
     eval "echo TABLENAME$j is not set"
   fi
  done
fi

# Evaluate total node numbers
BACKEND_NODES=$(cat "$BASEDIR"/nodecountfile | awk '{node_num += $0} END{print node_num}')

if [[ "$CLUSTERTYPE" == "prod" ]]; then
   TOTAL_NODES=$BACKEND_NODES
   echo "The total number of backend nodes required in dashbase-backend nodegroup is $TOTAL_NODES"
   echo "The total number of core nodes required in dashbase-core nodegroup is 3"
elif [[ "$CLUSTERTYPE" == "large" ]]; then
   TOTAL_NODES=$(expr $BACKEND_NODES + 1)
   echo "The total number of nodes required is $TOTAL_NODES"
elif [[ "$CLUSTERTYPE" == "small" ]]; then
   TOTAL_NODES=$(expr $BACKEND_NODES + 2)
   echo "The total number of nodes required is $TOTAL_NODES"
fi
}

create_internal_token() {
  # create 32 bits internal token
  cat /dev/urandom | tr -dc 'a-z-0-9' | fold -w 32 | head -n 1 > "$BASEDIR"/data/TOKEN-STRING
  TOKEN=$(cat -v "$BASEDIR"/data/TOKEN-STRING | tr -d '\n')
  log_info "created internal token is $TOKEN"

  # update dashbase-values.yaml file
  COMMAND_SED "s|TOKENSTRING|$TOKEN|g" "$BASEDIR"/dashbase-values.yaml
  COMMAND_SED "s|TOKENSTRING|$TOKEN|g" "$BASEDIR"/data/web_env.yaml
  COMMAND_SED "s|TOKENSTRING|$TOKEN|g" "$BASEDIR"/data/api_env.yaml
  COMMAND_SED "s|MYDOMAIN|$SUBDOMAIN|g" "$BASEDIR"/data/web_env.yaml
  COMMAND_SED "s|MYDOMAIN|$SUBDOMAIN|g" "$BASEDIR"/data/api_env.yaml
}

update_dashbase_valuefile() {
  # update dashbase-values.yaml for platform choice and subdomain
  if [ -n "$SUBDOMAIN" ]; then
    log_info "update ingress subdomain in dashbase-values.yaml file"
    COMMAND_SED "s|test.dashbase.io|$SUBDOMAIN|g" "$BASEDIR"/dashbase-values.yaml
  elif [ -z "$SUBDOMAIN" ]; then
    log_info "no input on --subdomain will use default which is test.dashbase.io"
  fi
  # update platform type in dashbase-values.yaml file
  if [ "$PLATFORM" == "aws" ]; then
    log_info "use default platform type aws in dashbase-values.yaml"
  elif [ "$PLATFORM" == "gce" ]; then
    log_info "update platform type gce in dashbase-values.yaml"
    COMMAND_SED 's/aws/gce/' "$BASEDIR"/dashbase-values.yaml
  elif [ "$PLATFORM" == "azure" ]; then
    log_info "update platform type azure in dashbase-values.yaml"
    COMMAND_SED 's/aws/azure/' "$BASEDIR"/dashbase-values.yaml
  elif [ "$PLATFORM" == "aliyun" ]; then
    log_info "update platform type aliyun in dashbase-values.yaml"
    COMMAND_SED 's/aws/aliyun/' "$BASEDIR"/dashbase-values.yaml
  fi
  # update dashbase version
  if [ -z "$VERSION" ]; then
    log_info "use default version $DASHVERSION in dashbase_version on dashbase-values.yaml"
    COMMAND_SED "s|dashbase_version: nightly|dashbase_version: $DASHVERSION|" "$BASEDIR"/dashbase-values.yaml
  else
    log_info "use $VERSION in dashbase_version on dashbase-values.yaml"
    COMMAND_SED "s|dashbase_version: nightly|dashbase_version: $VERSION|" "$BASEDIR"/dashbase-values.yaml
  fi

  # enabling presto
  if [ "$PRESTO_FLAG" == "true" ]; then
     log_info "enabling presto and updating dashbase-values.yaml file"
     COMMAND_SED '/^presto\:/{n;d}' "$BASEDIR"/dashbase-values.yaml
     COMMAND_SED '/^presto\:/a \ \ enabled\:\ true' "$BASEDIR"/dashbase-values.yaml
     # Add presto secrets in web pod
     COMMAND_SED '/\#PRESTO\_SECRETS/ r data/presto_secrets.yaml' "$BASEDIR"/dashbase-values.yaml
  fi

  # update basic auth
  if [ "$BASIC_AUTH" == "true" ]; then
    log_info "update dashbase-values.yaml file for basic auth"
    COMMAND_SED '/web\:/!b;n;c\ \ \ \ expose\: false' "$BASEDIR"/dashbase-values.yaml
    COMMAND_SED '/\#AUTH\_SET/!b;n;c\ \ \ \ enabled\: true' "$BASEDIR"/dashbase-values.yaml
    create_internal_token
    COMMAND_SED '/\#WEB\_ENV/ r data/web_env.yaml' "$BASEDIR"/dashbase-values.yaml
    COMMAND_SED '/\#API\_ENV/ r data/api_env.yaml' "$BASEDIR"/dashbase-values.yaml
  fi
  # update dashbase tables
  if [ "$V2_FLAG" ==  "true" ] || [ "$VNUM" -ge 2 ]; then
    sed -i '/tablesv2/ r newv2table_template.yaml' $BASEDIR/dashbase-values.yaml
    sed -i "s|SEARCHERREPLICA|$SER_REPL_CNT|g" $BASEDIR/dashbase-values.yaml
  else
    sed -i '/V1_tables/ r newv1table_template.yaml' $BASEDIR/dashbase-values.yaml
  fi
  log_info "update dashbase-values.yaml file for LOGS with first table name = $TABLENAME1"
  COMMAND_SED "s|LOGS|$TABLENAME1|" "$BASEDIR"/dashbase-values.yaml
  # exporter is currently not using, exporter related config will be removed in future
  # kubectl exec -it admindash-0 -n dashbase -- sed -i "s|LOGS|$TABLENAME|" /data/exporter_metric.yaml

  # update indexer cpu and memory
  if [ "$V2_FLAG" ==  "true" ] || [ "$VNUM" -ge 2 ]; then
    log_info "update dashbase indexer cpu value to $INDEXERCPU"
    COMMAND_SED "s|INXCPU|$INDEXERCPU|g" "$BASEDIR"/dashbase-values.yaml
    log_info "update dashbase indexer memory value to $INDEXERMEMORY"
    COMMAND_SED "s|INXMEM|$INDEXERMEMORY|g" "$BASEDIR"/dashbase-values.yaml
  fi

  # update fluentd for syslog ingestion
  if [ "$SYSLOG_FLAG" == "true" ]; then
     log_info "update dashbase-values.yaml file to enable fluentd for syslog ingestion"
     COMMAND_SED '/syslog\:/!b;n;c\ \ \ \ enabled\: true' "$BASEDIR"/dashbase-values.yaml
  fi

  # update dashbase system logs
  if [ "$SYSTEM_LOG" == "true" ]; then
    log_info "update dashbase-values.yaml file to enable dashbase system log collection"
    COMMAND_SED '/filebeat\:/!b;n;c\ \ enabled\: true' "$BASEDIR"/dashbase-values.yaml
    if [ "$VNUM" -ge 2 ]; then
       COMMAND_SED '/V1_tables/ r data/dashbase_system_log_table_v2.yaml' "$BASEDIR"/dashbase-values.yaml
    else
       COMMAND_SED '/Dashbase_Logs/ r data/dashbase_system_log_table_v1.yaml' "$BASEDIR"/dashbase-values.yaml
    fi
  fi

  # update ucaas callflow options cdr, sip log type
  if [ "$CALL_FLOW_SIP_FLAG" == "true" ]; then
    log_info "update dashbase-values.yaml file to enable callflow SIP_PAGE feature"
    COMMAND_SED 's/SIP_PAGE\:\ \"false\"/SIP_PAGE\:\ \"true\"/' "$BASEDIR"/dashbase-values.yaml
    COMMAND_SED 's/ENABLE_UCAAS\:\ \"false\"/ENABLE_UCAAS\:\ \"true\"/' "$BASEDIR"/dashbase-values.yaml
    COMMAND_SED 's/ENABLE_CALL\:\ \"false\"/ENABLE_CALL\:\ \"true\"/' "$BASEDIR"/dashbase-values.yaml
  fi
  if [ "$CALL_FLOW_CDR_FLAG" == "true" ]; then
     log_info "update dashbase-values.yaml file to enable callflow CDR_PAGE feature"
     COMMAND_SED 's/CDR_PAGE\:\ \"false\"/CDR_PAGE\:\ \"true\"/' "$BASEDIR"/dashbase-values.yaml
     COMMAND_SED 's/ENABLE_APPS\:\ \"false\"/ENABLE_APPS\:\ \"true\"/' "$BASEDIR"/dashbase-values.yaml
     COMMAND_SED 's/ENABLE_APPS_NETSAPIENS\:\ \"false\"/ENABLE_APPS_NETSAPIENS\:\ \"true\"/' "$BASEDIR"/dashbase-values.yaml
     sleep 3
     COMMAND_SED "/ENABLE\_APPS\_NETSAPIENS\:\ \"true\"/a\ \ \ \ \ \ APPS\_NETSAPIENS\_TABLE\:\ $TABLENAME1" "$BASEDIR"/dashbase-values.yaml
  fi
  # update webrtc remote read url for prometheus
  if [ "$WEBRTC_FLAG" == "true" ]; then
    log_info "update prometheus configuration to enable remote read url point to https://api:9876/prometheus/read"
    COMMAND_SED '/prometheus\_env\_variable/ r data/prometheus_webrtc' "$BASEDIR"/dashbase-values.yaml
  fi
  # update bucket name and storage access
  if [ "$V2_FLAG" ==  "true" ] || [ "$VNUM" -ge 2 ]; then
    log_info "update object storage bucket name"
    COMMAND_SED "s|MYBUCKET|$BUCKETNAME|" "$BASEDIR"/dashbase-values.yaml

    # update storage account and key for aws,gce,azure object storage access
    if [ "$STORAGE_ACCOUNT" != "undefined" ] && [ "$STORAGE_KEY" != "undefined" ]; then
       log_info "update store_access files for cloud object storage access credentials"
       COMMAND_SED "s|STOREACCOUNT|$STORAGE_ACCOUNT|" "$BASEDIR"/data/store_access_1
       COMMAND_SED "s|STOREACCOUNT|$STORAGE_ACCOUNT|" "$BASEDIR"/data/store_access_2
       COMMAND_SED "s|STOREKEY|$STORAGE_KEY|" "$BASEDIR"/data/store_access_1
       COMMAND_SED "s|STOREKEY|$STORAGE_KEY|" "$BASEDIR"/data/store_access_2
       if [ "$PLATFORM" == "azure" ]; then
         log_info "update store_access files with azure blob storage env variables"
         COMMAND_SED "s|AWS_ACCESS_KEY_ID|AZURE_STORAGE_ACCOUNT|" "$BASEDIR"/data/store_access_1
         COMMAND_SED "s|AWS_ACCESS_KEY_ID|AZURE_STORAGE_ACCOUNT|" "$BASEDIR"/data/store_access_2
         COMMAND_SED "s|AWS_SECRET_ACCESS_KEY|AZURE_STORAGE_KEY|" "$BASEDIR"/data/store_access_1
         COMMAND_SED "s|AWS_SECRET_ACCESS_KEY|AZURE_STORAGE_KEY|" "$BASEDIR"/data/store_access_2
       fi
       log_info "update dashbase-values.yaml file with store_access files"
       COMMAND_SED '/searcher\:/ r data/store_access_1' "$BASEDIR"/dashbase-values.yaml
       COMMAND_SED '/table_manager\:/ r data/store_access_2' "$BASEDIR"/dashbase-values.yaml
       COMMAND_SED '/indexer\:/ r data/store_access_2' "$BASEDIR"/dashbase-values.yaml
    fi
    # update V2 bucket mount options for gce
    if [ "$PLATFORM" == "gce" ]; then
      log_info "update dashbase-values.yaml file with google bucket mount options"
      COMMAND_SED '/^\ \ bucket\:/ r data/gce_mount_options' "$BASEDIR"/dashbase-values.yaml
    elif [ "$PLATFORM" == "aliyun" ]; then
      log_info "update dashbase-values.yaml file with aliyun bucket mount options"
      COMMAND_SED '/^\ \ bucket\:/ r data/aliyun_mount_options' "$BASEDIR"/dashbase-values.yaml
      if [ "$STORAGE_ENDPOINT" != "undefined" ]; then
         COMMAND_SED "s|https://oss-accelerate.aliyuncs.com|$STORAGE_ENDPOINT|" "$BASEDIR"/dashbase-values.yaml
      fi
    fi
    # update V2 table-manager VPA
    if [ "$VPA_FLAG" == "true" ]; then
       log_info "enable VPA in this K8s cluster"
       COMMAND_SED '/metrics-server\:/!b;n;c\ \ enabled\:\ true' "$BASEDIR"/dashbase-values.yaml
       COMMAND_SED '/vertical-pod-autoscaler\:/!b;n;c\ \ enabled\:\ true' "$BASEDIR"/dashbase-values.yaml
       COMMAND_SED '/memoryAutoScaler\:/!b;n;c\ \ \ \ \ \ \ \ enabled\: true' "$BASEDIR"/dashbase-values.yaml
    fi
    COMMAND_SED "s|MINMEMTBLMAN|$VPA_TBL_MINMEM|" "$BASEDIR"/dashbase-values.yaml
    COMMAND_SED "s|MAXMEMTBLMAN|$VPA_TBL_MAXMEM|" "$BASEDIR"/dashbase-values.yaml
    # update V2 indexer to use HPA
    if [ "$HPA_FLAG" == "true" ]; then
      log_info "enable HPA for indexers"
      COMMAND_SED '/horizontalpodautoscaler\:/!b;n;c\ \ \ \ \ \ \ \ enabled\: true' "$BASEDIR"/dashbase-values.yaml
    fi
  fi
  # update dashbase and presto keystore passwords in presto configuration
  if [ "$PRESTO_FLAG" == "true" ]; then
    log_warning " presto keystore password need to updated manually in dashbase-values.yaml"
    #"$BASEDIR"/data/configure_presto.sh
  fi

  # update prometheus image version
  if [ "$VERSION" == *"nightly"* ]; then
    log_info "dashbase nightly version is used, update prometheus image to use nightly version"
    COMMAND_SED '/\# image\: \"dashbase\/prometheus\:nightly\"/a\ \ \ \ image\: dashbase\/prometheus\:nightly' "$BASEDIR"/dashbase-values.yaml
  fi

  # update ingress table for dedicated table's nginx ingress controller
  if [ "$INGRESS_TABLE" == "true" ]; then
    COMMAND_SED 's/includetable:\ true/includetable\:\ false/' "$BASEDIR"/dashbase-values.yaml
    COMMAND_SED 's/ingresstable:\ false/ingresstable\:\ true/' "$BASEDIR"/dashbase-values.yaml
  fi

  # update dashbase license information
  if [ "$USERNAME" == "undefined" ] && [ "$LICENSE" == "undefined" ]; then
    USERNAME="dashuser"
    log_warning "No License information is entered, install default 60 days trial license"
    wget -q https://dashbase-public.s3-us-west-1.amazonaws.com/lapp/dash-lapp-1.0.0-rc9.jar -O dash-lapp-1.0.0-rc9.jar
    /usr/bin/java -jar dash-lapp-1.0.0-rc9.jar -u $USERNAME -d 60 > 60dlicensestring
    LICENSE=$(cat 60dlicensestring)
    echo "username: \"$USERNAME\"" > dashbase-license.txt
    echo "license: \"$LICENSE\"" >> dashbase-license.txt
    #kubectl cp dashbase-license.txt dashbase/admindash-0:/data/
    cat -v dashbase-license.txt | sed -e 's/\^M//' >> "$BASEDIR"/dashbase-values.yaml
    rm -rf dash-lapp-1.0.0-rc9.jar
  else
    log_info "update default dashbase-values.yaml file with entered license information"
    echo "username: \"$USERNAME\"" > dashbase-license.txt
    echo "license: \"$LICENSE\"" >> dashbase-license.txt
    #kubectl cp dashbase-license.txt dashbase/admindash-0:/data/
    cat -v dashbase-license.txt | sed -e 's/\^M//' >> "$BASEDIR"/dashbase-values.yaml
  fi

}

# main process 
check_commands
check_ostype
check_v2
check_version
check_cluster_type_input
required_node_count
copy_dashbase_files
update_dashbase_valuefile
