#!/bin/bash
host=$1
type=${2:-"master"}

echo "deploy ${type} to host $1"

function kssh() {
	ssh root@$host $@
}

function deploy_master() {
	ssh root@$host systemctl stop kube-apiserver kube-controller-manager kube-scheduler
	ssh root@$host cp -r /opt/kubernetes /opt/kubernetes_v1.5.7
	scp -r /opt/kubernetes/bin/ root@${host}:/opt/kubernetes/
	ssh root@$host systemctl restart kube-apiserver kube-controller-manager kube-scheduler
	sleep 1
	ssh root@$host systemctl status kube-apiserver kube-controller-manager kube-scheduler
}

function deploy_node() {
	kssh systemctl stop kubelet kube-proxy
	kssh cp -r /opt/kubernetes /opt/kubernetes_v1.5.7
	scp -r /opt/kubernetes/bin/ root@${host}:/opt/kubernetes/
	kssh systemctl restart kubelet kube-proxy
	sleep 1
	kssh systemctl status kubelet kube-proxy
}

case "$type" in
	"master" ) deploy_master ;;
	"node" ) deploy_node ;;
esac

