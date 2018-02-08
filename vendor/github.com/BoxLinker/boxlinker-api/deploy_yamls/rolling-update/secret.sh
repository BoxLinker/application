#!/bin/bash

kubectl delete secret env-rolling-update --namespace=boxlinker
kubectl create secret generic env-rolling-update --from-file=`pwd`/env.yml --namespace=boxlinker

