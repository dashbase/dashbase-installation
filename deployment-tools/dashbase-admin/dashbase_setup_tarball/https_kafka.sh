#!/bin/bash
# This script will nstall secure dashbase in k8s  and also will setup redash.
# run the script example
# ./https_kafka.sh <namespace>

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

KAFKA_CERT_FILE="./kafka-ca-cert"
KAFKA_KEY_FILE="./kafka-ca-key"
# remove previous dashbase cert, key and keystore in the current folder
[ -e kafka-keystore ] && rm -rf kafka-keystore
[ -e kafka-client-key.pem ] && rm -rf kafka-client-key.pem
[ -e kafka.csr ] && rm -rf kafka.csr
[ -e kafka-client-cert.pem ] && rm -rf kafka-client-cert.pem
[ -e kafka_keystore_password ] && rm -rf kafka_keystore_password
[ -e kafka_https.yaml ] && rm -rf kafka_https.yaml
[ -e "${KAFKA_CERT_FILE}" ] && rm -rf "${KAFKA_CERT_FILE}"
[ -e "${KAFKA_KEY_FILE}" ] && rm -rf "${KAFKA_KEY_FILE}"
[ -e kafka.client.pkcs1.key ] && rm -rf kafka.client.pkcs1.key
[ -e kafka.client.key ] && rm -rf kafka.client.key
[ -e kafka.client.csr ] && rm -rf kafka.client.csr
[ -e kafka.client.pem ] && rm -rf kafka.client.pem
[ -e kafka-cert-signed.pem ] && rm -rf kafka-cert-signed.pem
[ -e https-kafka.yaml ] && rm -rf https-kafka.yaml


# bash generate random 32 character alphanumeric string (upper and lowercase) and

export LC_CTYPE=C

KEYSTORE_PASS=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
NAMESPACE=$1
echo "entered namespace is $NAMESPACE"
echo "$KEYSTORE_PASS" > kafka_keystore_password
KEYSTORE_PASSWORD=$(cat kafka_keystore_password)

echo "Generate CA Certificate"
openssl req -nodes -new -x509 -keyout "${KAFKA_KEY_FILE}" -out "${KAFKA_CERT_FILE}" -days 3650 -subj "/CN=kafka/O=Dashbase"

echo "Generate Kafka keystore"
keytool -genkey -noprompt \
 -alias kafka \
 -dname "CN=kafka-server, OU=Engineering, O=Dashbase, L=Santa clara, S=CA, C=US" \
 -keystore kafka-keystore \
 -storepass "$KEYSTORE_PASSWORD" \
 -keypass "$KEYSTORE_PASSWORD" \
 -keyalg RSA  \
 -validity 3650 \
 -keysize 2048

echo "Importing CARoot to Kafka keystore"
keytool -keystore kafka-keystore -alias CARoot -importcert -file "${KAFKA_CERT_FILE}" -noprompt -storepass "${KEYSTORE_PASSWORD}"

echo "Sign kafka certificate and import it"
keytool -keystore kafka-keystore -alias kafka -certreq -file kafka.csr -storepass "$KEYSTORE_PASSWORD"
openssl x509 -req -CA "${KAFKA_CERT_FILE}" -CAkey "${KAFKA_KEY_FILE}" -in kafka.csr -out kafka-cert-signed.pem -days 3650 -CAcreateserial
keytool -keystore kafka-keystore -alias kafka -import -file kafka-cert-signed.pem -noprompt -storepass "$KEYSTORE_PASSWORD"

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
   DASHBASE_KAFKA_KEYSTORE_B64=`cat kafka-keystore |base64`
   DASHBASE_KEYSTORE_PASS_B64=`echo -n "$KEYSTORE_PASSWORD" |base64`
   KAFKA_CA_CERT=$(base64 < "${KAFKA_CERT_FILE}")
   KAFKA_CLIENT_CERT=$(base64 < kafka.client.pem)
   KAFKA_CLIENT_PEM=$(base64 < kafka.client.key)
elif [[ "$OSTYPE" == "linux-gnu" ]] || [[ "$OSTYPE" == "linux-musl" ]]; then
   echo "create dashbase Base 64 encryption for generated key, cert, keystore, keystore password from linux workstation"
   DASHBASE_KAFKA_KEYSTORE_B64=`cat kafka-keystore |base64 -w 0`
   DASHBASE_KEYSTORE_PASS_B64=`echo -n "$KEYSTORE_PASSWORD" |base64 -w 0`
   KAFKA_CA_CERT=$(base64 -w 0 < "${KAFKA_CERT_FILE}")
   KAFKA_CLIENT_CERT=$(base64 -w 0 < kafka.client.pem)
   KAFKA_CLIENT_PEM=$(base64 -w 0 < kafka.client.key)
else
   echo "OSTYPE is not supported"
   exit
fi

echo "feed the base64 outputs of key, cert, keystore, and keystore password into https-kafka.yaml file"
cp https-kafka-template.yaml https-kafka.yaml


if [[ "$OSTYPE" == "darwin"* ]]; then
   sed -i .bak "s|KAFKA_KEYSTORE|${DASHBASE_KAFKA_KEYSTORE_B64}|" https-kafka.yaml
   sed -i .bak "s|KAFKA_CA_CERT|${KAFKA_CA_CERT}|" https-kafka.yaml
   sed -i .bak "s|KAFKA_CLIENT_CERT|${KAFKA_CLIENT_CERT}|" https-kafka.yaml
   sed -i .bak "s|KAFKA_CLIENT_PEM|${KAFKA_CLIENT_PEM}|" https-kafka.yaml
   sed -i .bak "s|KEYPASS|${DASHBASE_KEYSTORE_PASS_B64}|" https-kafka.yaml
elif [[ "$OSTYPE" == "linux-gnu" ]] || [[ "$OSTYPE" == "linux-musl" ]]; then
   sed -i "s|KEYPASS|${DASHBASE_KEYSTORE_PASS_B64}|" https-kafka.yaml
   sed -i "s|KAFKA_KEYSTORE|${DASHBASE_KAFKA_KEYSTORE_B64}|" https-kafka.yaml
   sed -i "s|KAFKA_CA_CERT|${KAFKA_CA_CERT}|" https-kafka.yaml
   sed -i "s|KAFKA_CLIENT_CERT|${KAFKA_CLIENT_CERT}|" https-kafka.yaml
   sed -i "s|KAFKA_CLIENT_PEM|${KAFKA_CLIENT_PEM}|" https-kafka.yaml
else
   echo "OSTYPE is not supported"
   exit
fi

echo "https.yaml file is updated"
echo "kubectl apply -f kafka_https.yaml -n $NAMESPACE"
# #kubectl apply -f https-kafka.yaml -n $NAMESPACE
kubectl get secrets -n $NAMESPACE |grep dashbase
echo "install steps for kafka SSL cert, pem, keystore on K8s cluster is completed"
