#!/bin/bash

kubectl delete secret prometheus-config --namespace=boxlinker || true
kubectl create secret generic prometheus-config --from-file=`pwd`/prometheus.yml --namespace=boxlinker

