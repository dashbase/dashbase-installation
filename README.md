# Dashbase Installation

### AWS only: Create EKS cluster and install Dashbase:

```
   1. create a t2.micro EC2 instance with CentOS 7.6  (e.g. ami-0b49723d871f1073a on us-eest-1) that will be used as cluster admin jump host.
   2. once the EC2 is up, ssh to the EC2 and become root. Ensure git  command is installed on this centos.
   3. inside the EC2, run the following commands:
      ** Remember to change the AWS access key and secret, region and subdomain below

      git clone https://github.com/dashbase/dashbase-installation.git
      cd dashbase-installation/

      ./aws_eks_dashbase_install.sh  --aws_access_key=YOURAWSACCESSKEY \
                                     --aws_secret_access_key=YOURACESSSECRETACCESSKEY \
                                     --region=YOURREGION --subdomain=YOURSUBDOMAIN --install_dashbase
                                     
     This following script argument must be provided, otherwise script run will be failing.
       --aws_access_key
       --aws_secret_access_key
       --region
       --subdomain

     By default dashbase installation is using K8s ingress to expose the service endpoints, and subdomain is used in the ingress host value.
         An example of subdomain is test.dashbase.io
         And the dashbase web endpoint will be web.test.dashbase.io

     You can specify subdomain in the dashbase-installation/dashbase_specfile, and the script arguments will be like below.

     ./aws_eks_dashbase_install.sh   --aws_access_key=YOURAWSACCESSKEY \
                                     --aws_secret_access_key=YOURACESSSECRETACCESSKEY \
                                     --region=YOURREGION --install_dashbase 

    The dashbase-installation/dashbase_specfile is used to specify configuration spec for dashbase installation. And if you entered flags for bucketname or subdomain, the input flags will override  setting defined in dashbase_specfile.
    dashbase_spec file can also define mutiple tables and specify replicas count for table-manager, indexer and searcher. 
    Please consult Dashbase wiki page or Dashbase support for planning an EKS cluster size.

    In default setup, with default dashbase_spec file setting, it will create 1 table with 1 table-manager,  1 searcher, and 1 indexer, and the table name is named logs.
    The default setup use 2 X C5.4xlarge nodes.
    
    You can use the aws_eks_dashbase_install.sh script to just create the EKS cluster by removing the --install_dashbase flag

     ./aws_eks_dashbase_install.sh   --aws_access_key=YOURAWSACCESSKEY \
                                     --aws_secret_access_key=YOURACESSSECRETACCESSKEY \
                                     --region=YOURREGION
       
   You can also do dry-run mode in which no EKS cluster or dashbase is installed; but will create 2 files below

     ./aws_eks_dashbase_install.sh   --dry-run --region=YOURREGION 

     1. target-eks-cluster.yaml file is created in dry-run and  is used to for EKS cluster setup, and you can inspect the node count.
     2. my_dashbase_specfile <-- an updated dashbase spec file which can be used in dashbase-installer.sh script

```

The aws_eks_dashbase_install.sh script saves the script output on a log file in /tmp/ folder; and the log file is named like below
```
 aws_eks_setup_`date +%d-%m-%Y_%H-%M-%S`.log
```

At the end of installation process, ingress controller public IP will be provided.
Create Record Set mapping from ingress controller public IP to endpoints FQDN (e.g. web.raydash345.dashbase.io) using AWS Route 53.
After that, endpoints to access Dashbase Web UI, Dashbase table for indexing and Dashbase grafana for monitoring can be accessed.
```
Update your DNS server with the following nginx-ingress-controller public IP to map with this name *.raydash345.dashbase.io
nginx-ingress-controller    a5d2a09d5a1db4843909aaa59355bbad-975300330.us-east-1.elb.amazonaws.com

Update your DNS server with the following nginx-ingress-table-controller public IP to map with this mame table-logs.raydash345.dashbase.io
nginx-ingress-table-controller    ae8f36086b0384513863d2c3cd4fbcd7-1658389230.us-east-1.elb.amazonaws.com

Access to dashbase web UI with https://web.raydash345.dashbase.io
Access to dashbase table endpoint with https://table-logs.raydash345.dashbase.io
Access to dashbase grafana endpoint with https://grafana.raydash345.dashbase.io
Access to dashbase admin page endpoint with https://admindash.raydash345.dashbase.io

```

### AWS only: Uninstall Dashbase 

Run `uninstall-dashbase.sh` script
It will remove the dashbase installation on the EKS cluster

```
cd dashbase-installation/
deployment-tools/uninstall-dashbase.sh
```

### AWS, GCE, AZURE: Install Dashbase on already created K8s cluster:

Pre-reqs:
```
 1. You have K8s cluster with minimum 2 nodes of r5.xlarge or equivalent
 2. You have kubectl command installed and able to access K8s cluster
 3. You cloned Dashbase installation repository with:
    git clone https://github.com/dashbase/dashbase-installation.git
```

Update the `dashbase-installation/dashbase_specfile` file 
And run `dashbase-installer.sh` script
```
cd dashbase-installation/
./dashbase-installer.sh --specfile=dashbase_specfile
```
You can do dry-run for `dashbase-installer.sh` which will check your K8s cluster and other dependency only
```
./dashbase-installer.sh --dry-run --specfile=dashbase_specfile
```
For dry-run mode, --dry-run need to be the first argument.

You can also run `dashbase-isntaller.sh` script with other script options, use --help to display the help page
```
./dashbase-installer.sh --help

```
    
###Examples of typical script options, on AWS platform

By default the `dashbase-installer.sh` script will use nginx ingress controller to expose the web & table endpoints. See below script options used.

    ./dashbase-installer.sh --platform=aws --ingress \
                            --bucketname=s3-mybucket \
                            --subdomain=test.dashbase.io \
                            --ingresstable \
                            --basic_auth --version=2.6.1

The standard installation requires minium 2 nodes with 16 CPU, and 32 GB Ram per node (e.g. C5.4xlarge in AWS).
For large deployment setup please contact Dashbase support.

### Create a dashbase-values.yaml file only
From the git repo, `dashbase-installation/dashbase-create-valuesfile.sh` script will only read spec file or script options and create the `dashbase-values.yaml` file.

```
    ./dashbase-create-valuesfile.sh --specfile=dashbase_specfile

```

### Update dashbase license or upgrade dashbase version

Use Dashbase Admin UI to manage or update your dashbase license. 
You can use Admin UI to upgrade dashbase version and inspect dashbase cluster status.







