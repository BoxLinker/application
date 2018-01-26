all: push

PREFIX=index.boxlinker.com/boxlinker

IMAGE_APP=application-server
IMAGE_APP_TAG=${shell git describe --tags --long}

build:
	CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-w' -o application
	docker build -t ${PREFIX}/${IMAGE_APP}:${IMAGE_APP_TAG} .

push: build
	docker push ${PREFIX}/${IMAGE_APP}:${IMAGE_APP_TAG}

minikube:
	minikube start --kubernetes-version=v1.6.0 --extra-config=kubelet.PodInfraContainerImage="registry.cn-beijing.aliyuncs.com/cabernety/pause-amd64:3.0" --registry-mirror="2h3po24q.mirror.aliyuncs.com"