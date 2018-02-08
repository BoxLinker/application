#!/bin/bash

kubectl delete secret registry-server-config --namespace=boxlinker
kubectl create secret generic registry-server-config --from-file=`pwd`/auth_config.yml --namespace=boxlinker
