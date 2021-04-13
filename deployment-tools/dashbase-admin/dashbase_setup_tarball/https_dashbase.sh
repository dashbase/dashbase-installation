# This script will nstall secure dashbase in k8s  and also will setup redash.
# run the script example
# ./https_dashbase.sh <namespace>

#!/bin/bash
# enter namespace value, not entering namespace value will auto exit
if [ -z "$1" ]
then
   echo "no namespace entered"
   echo "will use default namespace = dashbase"
   NAMESPACE="dashbase"
else
   echo "entered namespace value = $1"
   NAMESPACE=$1
fi

# remove previous dashbase cert, key and keystore in the current folder
[ -e dashbase-keystore ] && rm -rf dashbase-keystore
[ -e dashbase-keystore.p12 ] && rm -rf dashbase-keystore.p12
[ -e dashbase-cert.pem ] && rm -rf dashbase-cert.pem
[ -e dashbase-key.pem ] && rm -rf dashbase-key.pem
[ -e dashbase_keystore_password ] && rm -rf dashbase_keystore_password
[ -e https.yaml ] && rm -rf https.yaml

# bash generate random 32 character alphanumeric string (upper and lowercase) and

export LC_CTYPE=C

KEYSTORE_PASS=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
#NAMESPACE=$1
#echo "entered namespace is $NAMESPACE"
echo $KEYSTORE_PASS > dashbase_keystore_password
KEYSTORE_PASSWORD=$(cat dashbase_keystore_password)
echo "Creating dashbase-keystore file"

keytool -genkey -noprompt \
 -alias dashbase \
 -dname "CN=dashbase.io, OU=Engineering, O=Dashbase, L=Santa clara, S=CA, C=US" \
 -keystore dashbase-keystore \
 -storepass $KEYSTORE_PASSWORD \
 -keypass $KEYSTORE_PASSWORD \
 -keyalg RSA  \
 -validity 3650 \
 -keysize 2048

echo "Convert dashbase-keystore into p12 format and output is dashbase-keystore.p12 file"
keytool -importkeystore -srckeystore dashbase-keystore \
  -destkeystore dashbase-keystore.p12 -deststoretype PKCS12 \
  -deststorepass $KEYSTORE_PASSWORD -srcstorepass $KEYSTORE_PASSWORD


echo "using openssl command creating dashbase-cert.pem  and  dashbase-key.pem  file from dashbase-keystore.p12"
openssl pkcs12 -in dashbase-keystore.p12 -nokeys -out dashbase-cert.pem -passin pass:$KEYSTORE_PASSWORD
openssl pkcs12 -in dashbase-keystore.p12 -nodes -nocerts -out dashbase-key.pem -passin pass:$KEYSTORE_PASSWORD


echo "Generate CA Certificate"
KAFKA_CERT_FILE="./kafka-ca-cert"
KAFKA_KEY_FILE="./kafka-ca-key"
openssl req -nodes -new -x509 -keyout "${KAFKA_KEY_FILE}" -out "${KAFKA_CERT_FILE}" -days 3650 -subj "/CN=kafka/O=Dashbase"

echo "Generate Kafka keystore"
keytool -genkey -noprompt \
 -alias kafka \
 -dname "CN=kafka-server, OU=Engineering, O=Dashbase, L=Santa clara, S=CA, C=US" \
 -keystore dashbase-kafka-keystore \
 -storepass $KEYSTORE_PASSWORD \
 -keypass $KEYSTORE_PASSWORD \
 -keyalg RSA  \
 -validity 3650 \
 -keysize 2048

echo "Importing CARoot to Kafka keystore"

keytool -keystore dashbase-kafka-keystore -alias CARoot -importcert -file "${KAFKA_CERT_FILE}" -noprompt -storepass "${KEYSTORE_PASSWORD}"

echo "Sign dashbase certificate and import it"
keytool -keystore dashbase-kafka-keystore -alias kafka -certreq -file cert-file -storepass "$KEYSTORE_PASSWORD"
openssl x509 -req -CA "${KAFKA_CERT_FILE}" -CAkey "${KAFKA_KEY_FILE}" -in cert-file -out cert-signed.pem -days 3650 -CAcreateserial
keytool -keystore dashbase-kafka-keystore -alias kafka -import -file cert-signed.pem -noprompt -storepass "$KEYSTORE_PASSWORD"

echo "Generate kafka client key"
openssl genrsa -out kafka.client.pkcs1.key 4096
openssl pkcs8 -topk8 -in ./kafka.client.pkcs1.key -nocrypt -out kafka.client.key
openssl req -new -sha256 -key kafka.client.key -subj "/CN=kafka-client/O=Dashbase" -out kafka.client.csr
openssl x509 -req -CA "${KAFKA_CERT_FILE}" -CAkey "${KAFKA_KEY_FILE}" -in kafka.client.csr -out kafka.client.pem -days 3650 -CAcreateserial

echo "signed signed-cert generation for dashbase is completed"
echo "you should have the following files:"
echo "1. dashbase-kestore  java keystore for dashbase"
echo "2. dashbase-keystore.p12 P12 format file for dashbase-keystore"
echo "3. dashbase-cert.pem base 64 cert file for dashbase"
echo "4. dashbase-key.pem  base 64 key file for dashbase"
echo "The CN of this self-signed cert is dashbase.io"

# create Base 64 encryption for generated key, cert, keystore, keystore password

if [[ "$OSTYPE" == "darwin"* ]]; then
   echo "create dashbase Base 64 encryption for generated key, cert, keystore, keystore password from mac workstation"
   DASHBASE_KEYSTORE_PASS_B64=`echo -n "$KEYSTORE_PASSWORD" |base64`
   DASHBASE_KEYSTORE_B64=`cat dashbase-keystore |base64`
   DASHBASE_KAFKA_KEYSTORE_B64=`cat dashbase-kafka-keystore |base64`
   DASHBASE_CERT_B64=`cat dashbase-cert.pem |base64`
   DASHBASE_KEY_B64=`cat dashbase-key.pem |base64`
   KAFKA_CA_CERT=$(base64 < "${KAFKA_CERT_FILE}")
   KAFKA_CLIENT_CERT=$(base64 < kafka.client.pem)
   KAFKA_CLIENT_PEM=$(base64 < kafka.client.key)
elif [[ "$OSTYPE" == "linux-gnu" ]] || [[ "$OSTYPE" == "linux-musl" ]]; then
   echo "create dashbase Base 64 encryption for generated key, cert, keystore, keystore password from linux workstation"
   DASHBASE_KEYSTORE_PASS_B64=`echo -n "$KEYSTORE_PASSWORD" |base64 -w 0`
   DASHBASE_KEYSTORE_B64=`cat dashbase-keystore |base64 -w 0`
   DASHBASE_KAFKA_KEYSTORE_B64=`cat dashbase-kafka-keystore |base64 -w 0`
   DASHBASE_CERT_B64=`cat dashbase-cert.pem |base64 -w 0`
   DASHBASE_KEY_B64=`cat dashbase-key.pem |base64 -w 0`
   KAFKA_CA_CERT=$(base64 -w 0 < "${KAFKA_CERT_FILE}")
   KAFKA_CLIENT_CERT=$(base64 -w 0 < kafka.client.pem)
   KAFKA_CLIENT_PEM=$(base64 -w 0 < kafka.client.key)
else
   echo "OSTYPE is not supported"
   exit
fi

#echo "Presto keystore password"
#echo $DASHBASE_KEYSTORE_PASS_B64
#echo "####################################################"
#echo "dashbase keystore"
#echo $DASHBASE_KEYSTORE_B64
#echo "####################################################"
#echo "dashbase cert"
#echo $DASHBASE_CERT_B64
#echo "####################################################"
#echo "dashbase key"
#echo $DASHBASE_KEY_B64
#echo "####################################################"

# feed the base64 outputs of key, cert, keystore, and keystore password into https-dashbase.yaml file

echo "feed the base64 outputs of key, cert, keystore, and keystore password into https-dashbase.yaml file"
cp https-dashbase-template.yaml https-dashbase.yaml


if [[ "$OSTYPE" == "darwin"* ]]; then
   sed -i .bak "s|KAFKA_KEYSTORE|${DASHBASE_KAFKA_KEYSTORE_B64}|" https-dashbase.yaml
   sed -i .bak "s|KEYSTORE|${DASHBASE_KEYSTORE_B64}|" https-dashbase.yaml
   sed -i .bak "s|KEYPASS|${DASHBASE_KEYSTORE_PASS_B64}|" https-dashbase.yaml
   sed -i .bak "s|CERTPEM|${DASHBASE_CERT_B64}|" https-dashbase.yaml
   sed -i .bak "s|KEYPEM|${DASHBASE_KEY_B64}|" https-dashbase.yaml
   sed -i .bak "s|KAFKA_CA_CERT|${KAFKA_CA_CERT}|" https-dashbase.yaml
   sed -i .bak "s|KAFKA_CLIENT_CERT|${KAFKA_CLIENT_CERT}|" https-dashbase.yaml
   sed -i .bak "s|KAFKA_CLIENT_PEM|${KAFKA_CLIENT_PEM}|" https-dashbase.yaml
elif [[ "$OSTYPE" == "linux-gnu" ]] || [[ "$OSTYPE" == "linux-musl" ]]; then
   sed -i "s|KAFKA_KEYSTORE|${DASHBASE_KAFKA_KEYSTORE_B64}|" https-dashbase.yaml
   sed -i "s|KEYSTORE|${DASHBASE_KEYSTORE_B64}|" https-dashbase.yaml
   sed -i "s|KEYPASS|${DASHBASE_KEYSTORE_PASS_B64}|" https-dashbase.yaml
   sed -i "s|CERTPEM|${DASHBASE_CERT_B64}|" https-dashbase.yaml
   sed -i "s|KEYPEM|${DASHBASE_KEY_B64}|" https-dashbase.yaml
   sed -i "s|KAFKA_CA_CERT|${KAFKA_CA_CERT}|" https-dashbase.yaml
   sed -i "s|KAFKA_CLIENT_CERT|${KAFKA_CLIENT_CERT}|" https-dashbase.yaml
   sed -i "s|KAFKA_CLIENT_PEM|${KAFKA_CLIENT_PEM}|" https-dashbase.yaml
else
   echo "OSTYPE is not supported"
   exit
fi

echo "https.yaml file is updated"
echo "kubectl apply -f https.yaml -n $NAMESPACE"
#kubectl apply -f https-dashbase.yaml -n $NAMESPACE
kubectl get secrets -n $NAMESPACE |grep dashbase
echo "install steps for dashbase SSL cert, pem, keystore on K8s cluster is completed"
