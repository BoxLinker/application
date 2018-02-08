#!/bin/bash

kubectl delete secret application-server-config --namespace=boxlinker
kubectl create secret generic application-server-config --from-file=`pwd`/env.yml --namespace=boxlinker

