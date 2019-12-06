#!/bin/bash
set -e

# check kubernetes API server is connectable
if ! kubectl cluster-info &>/dev/null; then
  echo "Failed to connect your Kubernetes API server, please check your config or network."
  exit 1
fi

# check permission
## permissions required by dashbase charts
echo "Checking permission:"

echo -n "Admin permission in namespace dashbase: "
kubectl auth can-i '*' '*' -n dashbase;

echo -n "Admin permission on namespaces: "
kubectl auth can-i '*' namespaces --all-namespaces

echo -n "Admin permission on nodes: "
kubectl auth can-i '*' nodes --all-namespaces

echo -n "Admin permission on storageclasses: "
kubectl auth can-i '*' storageclasses --all-namespaces

echo -n "Admin permission on persistentvolumes: "
kubectl auth can-i '*' persistentvolumes --all-namespaces

echo -n "Admin permission on clusterroles: "
kubectl auth can-i '*' clusterroles --all-namespaces

echo -n "Admin permission on clusterrolebindings: "
kubectl auth can-i '*' clusterrolebindings --all-namespaces

echo -n "Admin permission on priorityclasses: "
kubectl auth can-i '*' priorityclasses --all-namespaces

## permission required by detecting nodes resource
kubectl auth can-i '*' serviceaccounts -n kubes-system

if kubectl auth can-i list pods --all-namespaces; then
  echo "You don't have permission to get nodes resources usage, so you need to check the remaining resource manually".
fi

kubectl get --raw "/api/v1/nodes"
# check cpu/memory resources remained.
# Disgarded the label.
