#!/bin/bash
DIR=`dirname "$BASH_SOURCE"`

kubectl create configmap "mysql-conf-d" --from-file="$DIR/conf-d/" --namespace=boxlinker
