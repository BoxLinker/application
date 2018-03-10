package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/Sirupsen/logrus"
	"github.com/cabernety/gopkg/httplib"
	"github.com/gorilla/mux"
	appsv1beta1 "k8s.io/api/apps/v1beta1"
	apiv1 "k8s.io/api/core/v1"
	extv1beta1 "k8s.io/api/extensions/v1beta1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

type ServicePortForm struct {
	Name      string `json:"name"`
	Protocol  string `json:"protocol"`
	Port      int    `json:"port"`
	Path      string `json:"path"`
	IsPrivate bool   `json:"is_private"`
}
type ServiceHostVolumeForm struct {
	Name     string `json:"name"`
	Path     string `json:"path"`
	HostPath string `json:"host_path"`
	ReadOnly bool   `json:"readonly"`
}

type ServiceForm struct {
	Name        string                   `json:"name"`
	Image       string                   `json:"image"`
	Memory      string                   `json:"memory"`
	CPU         string                   `json:"cpu"`
	Ports       []*ServicePortForm       `json:"ports"`
	HostVolumes []*ServiceHostVolumeForm `json:"host_volumes"`
	Host        string                   `json:"host"`
}

func getDeployByName(name string, list *appsv1beta1.DeploymentList) *appsv1beta1.Deployment {
	for _, item := range list.Items {
		if item.Name == name {
			return &item
		}
	}
	return nil
}

func getIngByName(name string, list *extv1beta1.IngressList) *extv1beta1.Ingress {
	for _, item := range list.Items {
		if item.Name == name {
			return &item
		}
	}
	return nil
}

func getSvcByName(name string, list *apiv1.ServiceList) *apiv1.Service {
	for _, item := range list.Items {
		if item.Name == name {
			return &item
		}
	}
	return nil
}

func (a *Api) IsServiceExist(w http.ResponseWriter, r *http.Request) {
	svcName := mux.Vars(r)["name"]
	user := a.getUserInfo(r)
	namespace := user.Name
	found, err, _, _, _ := a.manager.GetServiceByName(namespace, svcName)
	if err != nil {
		httplib.Resp(w, httplib.STATUS_NOT_FOUND, nil, err.Error())
		return
	}
	if !found {
		httplib.Resp(w, httplib.STATUS_NOT_FOUND, nil)
		return
	}
	httplib.Resp(w, httplib.STATUS_OK, nil)
}

func (a *Api) DeleteService(w http.ResponseWriter, r *http.Request) {
	svcName := mux.Vars(r)["name"]
	user := a.getUserInfo(r)
	namespace := user.Name
	deployOperator := a.clientSet.AppsV1beta1().Deployments(namespace)
	deploy, err := deployOperator.Get(svcName, metav1.GetOptions{})
	if err != nil {
		httplib.Resp(w, httplib.STATUS_NOT_FOUND, nil, err.Error())
		return
	}
	svcOperator := a.clientSet.CoreV1().Services(namespace)
	svc, err := svcOperator.Get(svcName, metav1.GetOptions{})
	if err != nil {
		httplib.Resp(w, httplib.STATUS_NOT_FOUND, nil, fmt.Sprintf("service not found (%s/%s)", namespace, svcName))
		return
	}
	ingOperator := a.clientSet.ExtensionsV1beta1().Ingresses(namespace)
	ing, err := ingOperator.Get(svcName, metav1.GetOptions{})
	if err != nil {
		httplib.Resp(w, httplib.STATUS_NOT_FOUND, nil, fmt.Sprintf("ingress not found (%s/%s)", namespace, svcName))
		return
	}

	deletePolicy := metav1.DeletePropagationForeground
	if err := deployOperator.Delete(deploy.Name, &metav1.DeleteOptions{
		PropagationPolicy: &deletePolicy,
	}); err != nil {
		httplib.Resp(w, httplib.STATUS_FAILED, nil, err.Error())
		return
	}
	if err := svcOperator.Delete(svc.Name, &metav1.DeleteOptions{}); err != nil {
		httplib.Resp(w, httplib.STATUS_FAILED, nil, err.Error())
		return
	}
	if err := ingOperator.Delete(ing.Name, &metav1.DeleteOptions{}); err != nil {
		httplib.Resp(w, httplib.STATUS_FAILED, nil, err.Error())
		return
	}

	httplib.Resp(w, httplib.STATUS_OK, nil)
}

func (a *Api) UpdateService(w http.ResponseWriter, r *http.Request) {
	svcName := mux.Vars(r)["name"]
	user := a.getUserInfo(r)
	namespace := user.Name
	form := &ServiceForm{}
	if err := httplib.ReadRequestBody(r, form); err != nil {
		httplib.Resp(w, httplib.STATUS_FORM_VALIDATE_ERR, nil, err.Error())
		return
	}
	deployOperator := a.clientSet.AppsV1beta1().Deployments(namespace)
	deploy, err := deployOperator.Get(svcName, metav1.GetOptions{})
	if err != nil {
		httplib.Resp(w, httplib.STATUS_NOT_FOUND, nil, err.Error())
		return
	}
	svcOperator := a.clientSet.CoreV1().Services(namespace)
	svc, err := svcOperator.Get(svcName, metav1.GetOptions{})
	if err != nil {
		httplib.Resp(w, httplib.STATUS_NOT_FOUND, nil, fmt.Sprintf("service not found (%s/%s)", namespace, svcName))
		return
	}
	ingOperator := a.clientSet.ExtensionsV1beta1().Ingresses(namespace)
	ing, err := ingOperator.Get(svcName, metav1.GetOptions{})
	if err != nil {
		httplib.Resp(w, httplib.STATUS_NOT_FOUND, nil, fmt.Sprintf("ingress not found (%s/%s)", namespace, svcName))
		return
	}

	var container *apiv1.Container
	containers := deploy.Spec.Template.Spec.Containers
	if len(containers) == 1 {
		container = &containers[0]

	}

	// update image
	if form.Image != "" {
		if form.Image != container.Image {
			logrus.Debugf("Update deploy %s/%s with new image (%s)", user.Name, svcName, form.Image)
			container.Image = form.Image
		}
	}

	// update memory
	if form.Memory != "" {
		memory, err := resource.ParseQuantity(form.Memory)
		if err != nil {
			httplib.Resp(w, httplib.STATUS_FORM_VALIDATE_ERR, nil, fmt.Sprintf("memory param (%s) is invalid", form.Memory))
			return
		}
		logrus.Debugf("Update deploy %s/%s with new memory (%s)", user.Name, svcName, form.Memory)
		container.Resources.Limits[apiv1.ResourceMemory] = memory
		container.Resources.Requests[apiv1.ResourceMemory] = memory
	}

	// update cpu
	if form.CPU != "" {
		cpu, err := resource.ParseQuantity(form.CPU)
		if err != nil {
			httplib.Resp(w, httplib.STATUS_FORM_VALIDATE_ERR, nil, fmt.Sprintf("cpu param (%s) is invalid", form.CPU))
			return
		}
		logrus.Debugf("Update deploy %s/%s with new cpu (%s)", user.Name, svcName, form.CPU)
		container.Resources.Limits[apiv1.ResourceCPU] = cpu
		container.Resources.Requests[apiv1.ResourceCPU] = cpu
	}

	// update ports/path
	ports := make([]apiv1.ContainerPort, 0)
	svcPorts := make([]apiv1.ServicePort, 0)
	paths := make([]extv1beta1.HTTPIngressPath, 0)
	if len(form.Ports) > 0 {
		for _, port := range form.Ports {
			ports = append(ports, FormatContainerPort(port.Name, port.Protocol, port.Port))
			svcPorts = append(svcPorts, FormatServicePort(port.Name, port.Protocol, port.Port))
			paths = append(paths, FormatIngressPath(port.Path, svcName, port.Port))
		}
		container.Ports = ports
		logrus.Debugf("updated deployment (%s/%s) ports: ->\n\t%+v", namespace, svcName, svcPorts)

		svc.Spec.Ports = svcPorts
		logrus.Debugf("updated service (%s/%s) ports: ->\n\t%+v", namespace, svcName, svcPorts)

		rules := ing.Spec.Rules
		if len(rules) > 0 {
			rule := rules[0]
			rule.HTTP.Paths = paths
			logrus.Debugf("updated ingress (%s/%s) paths: ->\n\t%+v", namespace, svcName, paths)
		}
	}

	// 处理 ingress
	if _, err := ingOperator.Update(ing); err != nil {
		httplib.Resp(w, httplib.STATUS_INTERNAL_SERVER_ERR, nil, fmt.Sprintf("update ingress (%s/%s) error: %v", namespace, svcName, err))
		return
	}

	// 处理 service
	if _, err := svcOperator.Update(svc); err != nil {
		httplib.Resp(w, httplib.STATUS_INTERNAL_SERVER_ERR, nil, fmt.Sprintf("update service (%s/%s) error: %v", namespace, svcName, err))
		return
	}

	// 处理 deployment
	if _, err := deployOperator.Update(deploy); err != nil {
		httplib.Resp(w, httplib.STATUS_INTERNAL_SERVER_ERR, nil, err.Error())
		return
	}

	httplib.Resp(w, httplib.STATUS_OK, deploy)
}

// GetService 根据名称获取服务
/**
 * @api {get} /services/:name 根据名称查询服务详情
 * @apiName GetService
 * @apiGroup Service
 *
 * @apiParam {string} name 服务名称
 *
 * @apiSuccess {String} name 服务名称
 * @apiSuccess {String} image  服务的镜像
 * @apiSuccess {String} memory  服务的内存配额
 * @apiSuccess {String} host  服务访问全路径
 * @apiSuccess {Object[]} ports  服务的内存配额
 * @apiSuccess {Object[]} ports.protocol  端口协议
 * @apiSuccess {Object[]} ports.port  端口
 * @apiSuccess {Object[]} ports.path  端口对应的服务访问路径
 */
func (a *Api) GetService(w http.ResponseWriter, r *http.Request) {
	user := a.getUserInfo(r)
	svcName := mux.Vars(r)["name"]
	// deployment 里的对应的 container
	containerName := GetContainerNameFromDeployName(svcName)

	deploy, err := a.clientSet.AppsV1beta1().Deployments(user.Name).Get(svcName, metav1.GetOptions{})
	if err != nil {
		httplib.Resp(w, httplib.STATUS_INTERNAL_SERVER_ERR, nil, fmt.Sprintf("获取 deploy 失败：%v", err))
		return
	}
	pods, err := a.clientSet.CoreV1().Pods(user.Name).List(metav1.ListOptions{
		LabelSelector: fmt.Sprintf("app=%s", svcName),
	})
	podsResult := make([]*PodResult, 0)
	for _, pod := range pods.Items {
		containerStatuses := pod.Status.ContainerStatuses
		// TODO 需要支持多 container 的情况
		if len(containerStatuses) != 1 {
			logrus.Errorf("multiple containers found in pod(%s), the container len must be 1.", pod.Name)
			continue
		}
		podResult := &PodResult{
			ID:   string(pod.UID),
			Name: pod.Name,
		}
		// 循环 containerStatuses 获取到 svcName 的 containerStatus
		for _, containerStatus := range containerStatuses {
			if containerName == containerStatus.Name {
				state := containerStatus.State
				if state.Waiting != nil {
					podResult.Status = &PodStatus{
						State:   "waiting",
						Message: state.Waiting.Message,
						Reason:  state.Waiting.Reason,
					}
				}
				if state.Running != nil {
					podResult.Status = &PodStatus{
						State:     "running",
						StartedAt: state.Running.StartedAt.Time,
					}
				}
				if state.Terminated != nil {
					podResult.Status = &PodStatus{
						State:      "terminated",
						ExitCode:   state.Terminated.ExitCode,
						Signal:     state.Terminated.Signal,
						Message:    state.Terminated.Message,
						Reason:     state.Terminated.Reason,
						StartedAt:  state.Terminated.StartedAt.Time,
						FinishedAt: state.Terminated.FinishedAt.Time,
					}
					// 只有在 terminated 下才有 container_id
					podResult.ContainerID = state.Terminated.ContainerID
				}
			}
		}
		podsResult = append(podsResult, podResult)
	}
	if err != nil {
		httplib.Resp(w, httplib.STATUS_INTERNAL_SERVER_ERR, nil, fmt.Sprintf("获取 pod 失败：%v", err))
		return
	}

	deployStatus := &deploy.Status
	containers := deploy.Spec.Template.Spec.Containers
	if len(containers) != 1 {
		httplib.Resp(w, httplib.STATUS_FAILED, nil, fmt.Sprintf("deploy %s 的 container 数量不等于 1: %d", svcName, len(containers)))
		return
	}
	container := containers[0]
	result := &ServiceResult{
		Name:   deploy.Name,
		Image:  container.Image,
		Memory: container.Resources.Limits.Memory().String(),
		Pods:   podsResult,
		Status: &ServiceStatus{
			Replicas:            deployStatus.Replicas,
			AvailableReplicas:   deployStatus.AvailableReplicas,
			ReadyReplicas:       deployStatus.ReadyReplicas,
			UnavailableReplicas: deployStatus.UnavailableReplicas,
		},
	}
	portsResult := make([]*PortResult, 0)
	svc, _ := a.clientSet.CoreV1().Services(user.Name).Get(svcName, metav1.GetOptions{})
	if svc != nil {
		ing, err := a.getIngressByName(user.Name, svcName)
		if err != nil {
			logrus.Errorf("svc 已获取成功，获取 ingress 失败: %v", err)
		}
		ports := svc.Spec.Ports
		for _, port := range ports {
			pPortsResult := &PortResult{
				Port:     int(port.Port),
				Protocol: string(port.Protocol),
			}
			if ing != nil {
				pPortsResult.Path = a.findPathByPortAndSvcName(svc.Name, port, ing)
			}
			portsResult = append(portsResult, pPortsResult)
		}
		result.Host = svc.Annotations["host"]
	}
	result.Ports = portsResult
	httplib.Resp(w, httplib.STATUS_OK, result)
}

// QueryService 查询服务列表
func (a *Api) QueryService(w http.ResponseWriter, r *http.Request) {
	user := a.getUserInfo(r)
	pc := httplib.ParsePageConfig(r)
	deploys, err := a.clientSet.AppsV1beta1().Deployments(user.Name).List(metav1.ListOptions{})
	if err != nil {
		httplib.Resp(w, httplib.STATUS_INTERNAL_SERVER_ERR, nil, err.Error())
		return
	}
	ings, err := a.clientSet.ExtensionsV1beta1().Ingresses(user.Name).List(metav1.ListOptions{})
	if err != nil {
		httplib.Resp(w, httplib.STATUS_INTERNAL_SERVER_ERR, nil, err.Error())
		return
	}
	svcs, err := a.clientSet.CoreV1().Services(user.Name).List(metav1.ListOptions{})
	if err != nil {
		httplib.Resp(w, httplib.STATUS_INTERNAL_SERVER_ERR, nil, err.Error())
		return
	}
	output := make([]*ServiceForm, 0)
	var start, end int
	l := len(svcs.Items)
	// todo 这里得判断 ings deploys 和 svcs 长度是否一��
	pc.TotalCount = l
	if pc.Offset() >= l {
		start = 0
		end = l
	} else {
		start = pc.Offset()
		if pc.Offset()+pc.Limit() >= l {
			end = l
		} else {
			end = pc.Offset() + pc.Limit()
		}
	}
	listOut := deploys.Items[start:end]
	b, _ := json.MarshalIndent(listOut, "", "\t")
	logrus.Debugln(string(b))
	for _, item := range listOut {
		ing := getIngByName(item.Name, ings)
		svc := getSvcByName(item.Name, svcs)
		line := &ServiceForm{
			Name: item.Name,
		}
		containers := item.Spec.Template.Spec.Containers
		if len(containers) == 0 {
			logrus.Warnf("QueryService: deploy %s/%s container len 0", item.ObjectMeta.Namespace, item.ObjectMeta.Name)
			continue
		}
		if len(containers) != 1 {
			logrus.Warnf("Found Service contains more than one container: (%s)", item.Name)
		}
		container := containers[0]
		line.Image = container.Image
		line.Memory = container.Resources.Limits.Memory().String()
		line.CPU = container.Resources.Limits.Cpu().String()
		if svc != nil {
			line.Host = svc.Annotations["host"]
		}
		ports := container.Ports
		portsF := make([]*ServicePortForm, 0)
		for _, port := range ports {
			svcPortForm := &ServicePortForm{
				Name: port.Name,
				// todo 转化 ServicePort Protocol 为 字符串
				Protocol: "tcp",
				Port:     int(port.ContainerPort),
			}
			if ing != nil {
				rules := ing.Spec.Rules
				if len(rules) > 0 {
					paths := rules[0].HTTP.Paths
					for _, path := range paths {
						if path.Backend.ServiceName == item.Name && path.Backend.ServicePort.IntVal == port.ContainerPort {
							svcPortForm.Path = path.Path
						}
					}
				}
			}
			portsF = append(portsF, svcPortForm)
		}
		line.Ports = portsF
		output = append(output, line)
	}
	httplib.Resp(w, httplib.STATUS_OK, map[string]interface{}{
		"pagination": pc.PaginationJSON(),
		"data":       output,
	})
}

// CreateService 创建服务
func (a *Api) CreateService(w http.ResponseWriter, r *http.Request) {
	var (
		deploymentCreated bool
		serviceCreated    bool
		ingressCreated    bool
		errHappend        bool
	)
	user := a.getUserInfo(r)
	form := &ServiceForm{}
	if err := httplib.ReadRequestBody(r, form); err != nil {
		httplib.Resp(w, httplib.STATUS_FORM_VALIDATE_ERR, nil, err.Error())
		return
	}

	logrus.Debugf("Create Service form: (%+v)", form)
	// todo 检查 memory 参数，格式应为 64Mi
	memoryQuantity, err := resource.ParseQuantity(form.Memory)
	if err != nil {
		httplib.Resp(w, httplib.STATUS_FAILED, nil, fmt.Sprintf("memory param (%s) is invalid", form.Memory))
		return
	}
	cpuQuantity, err := resource.ParseQuantity(form.CPU)
	if err != nil {
		httplib.Resp(w, httplib.STATUS_FAILED, nil, fmt.Sprintf("cpu param (%s) is invalid", form.CPU))
		return
	}
	// registry key
	registryKey := make([]apiv1.LocalObjectReference, 0)
	registryKey = append(registryKey, apiv1.LocalObjectReference{Name: "registry-key"})

	// ports
	ports := make([]apiv1.ContainerPort, 0)
	portsF := form.Ports
	if len(portsF) > 0 {
		for _, port := range portsF {
			ports = append(ports, FormatContainerPort(port.Name, port.Protocol, port.Port))
		}
	}

	// volumes
	volumeMounts := make([]apiv1.VolumeMount, 0)
	volumes := make([]apiv1.Volume, 0)
	if len(form.HostVolumes) > 0 {
		for k, v := range form.HostVolumes {
			if v.Name == "" {
				v.Name = fmt.Sprintf("%s-host_volume-%d", form.Name, k)
			}
			if v.Path == "/" || v.HostPath == "/" {
				httplib.Resp(w, httplib.STATUS_PARAM_ERR, nil, "待挂载的宿主机路径不能为根目录 /")
				return
			}
			volumeMounts = append(volumeMounts, apiv1.VolumeMount{
				Name:      v.Name,
				MountPath: v.Path,
				ReadOnly:  v.ReadOnly,
			})
			volumes = append(volumes, apiv1.Volume{
				Name: v.Name,
				VolumeSource: apiv1.VolumeSource{
					HostPath: &apiv1.HostPathVolumeSource{
						Path: v.HostPath,
					},
				},
			})
		}
	}

	deploymentsClient := a.clientSet.AppsV1beta1().Deployments(user.Name)
	svcClient := a.clientSet.CoreV1().Services(user.Name)
	ingClient := a.clientSet.ExtensionsV1beta1().Ingresses(user.Name)

	defer func() {
		if !errHappend {
			return
		}
		name := fmt.Sprintf("%s/%s", user.Name, form.Name)
		logrus.Debugf("err when create service, rollback ...")
		if deploymentCreated {
			if err := deploymentsClient.Delete(form.Name, &metav1.DeleteOptions{}); err != nil {
				logrus.Errorf("rollback to del deploy (%s) failed.", name)
			}
		}
		if serviceCreated {
			if err := svcClient.Delete(form.Name, &metav1.DeleteOptions{}); err != nil {
				logrus.Errorf("rollback to del svc (%s) failed.", name)
			}
		}
		if ingressCreated {
			if err := ingClient.Delete(form.Name, &metav1.DeleteOptions{}); err != nil {
				logrus.Errorf("rollback to del ing (%s) failed.", name)
			}
		}
	}()

	// create deployment
	deployment := &appsv1beta1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name: form.Name,
		},
		Spec: appsv1beta1.DeploymentSpec{
			Replicas: int32Ptr(1),
			Template: apiv1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": form.Name,
					},
				},
				Spec: apiv1.PodSpec{
					ImagePullSecrets: registryKey,
					Containers: []apiv1.Container{
						{
							Name:  GetContainerNameFromDeployName(form.Name),
							Image: form.Image,
							Ports: ports,
							Resources: apiv1.ResourceRequirements{
								Limits: apiv1.ResourceList{
									apiv1.ResourceMemory: memoryQuantity,
									apiv1.ResourceCPU:    cpuQuantity,
								},
								Requests: apiv1.ResourceList{
									apiv1.ResourceMemory: memoryQuantity,
									apiv1.ResourceCPU:    cpuQuantity,
								},
							},
							VolumeMounts: volumeMounts,
						},
					},
					Volumes: volumes,
				},
			},
		},
	}
	logrus.Debugf("Create Deployment %s/%s (%+v)", user.Name, form.Name, deployment)
	result, err := deploymentsClient.Create(deployment)
	if err != nil {
		errHappend = true
		httplib.Resp(w, httplib.STATUS_INTERNAL_SERVER_ERR, nil, err.Error())
		return
	}
	deploymentCreated = true
	logrus.Debugf("Created deployment %q.\n", result.GetObjectMeta().GetName())

	/**
	 *	如果没有暴露 port ，那么就没必要生成 svc 和 ingress 了， 直接返回
	 */
	if len(portsF) <= 0 {
		httplib.Resp(w, httplib.STATUS_OK, nil)
		return
	}

	host := fmt.Sprintf("%s-%s.%s.boxlinker.com", user.Name, form.Name, "lb1")

	// todo 需要权限验证
	if form.Host != "" {
		host = form.Host
	}

	// create service
	svcPorts := make([]apiv1.ServicePort, 0)
	// ports
	for _, port := range portsF {
		svcPorts = append(svcPorts, FormatServicePort(port.Name, port.Protocol, port.Port))
	}

	service := &apiv1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name: form.Name,
			Annotations: map[string]string{
				"host": host,
			},
		},
		Spec: apiv1.ServiceSpec{
			Ports: svcPorts,
			Selector: map[string]string{
				"app": form.Name,
			},
		},
	}
	logrus.Debugf("Create Svc %s/%s (%+v)", user.Name, form.Name, service)
	svc, err := svcClient.Create(service)
	if err != nil {
		errHappend = true
		httplib.Resp(w, httplib.STATUS_FAILED, "", err.Error())
		return
	}
	serviceCreated = true
	logrus.Debugf("Created Svc %q.\n", svc.GetObjectMeta().GetName())

	// create ingress
	paths := make([]extv1beta1.HTTPIngressPath, 0)
	for _, port := range portsF {
		if port.IsPrivate {
			continue
		}
		paths = append(paths, FormatIngressPath(port.Path, form.Name, port.Port))
	}
	// 如果 paths 为空，那么就不用生成 ingress 了
	if len(paths) == 0 {
		httplib.Resp(w, httplib.STATUS_OK, nil)
		return
	}
	rules := make([]extv1beta1.IngressRule, 0)
	rules = append(rules, extv1beta1.IngressRule{
		Host: host,
		IngressRuleValue: extv1beta1.IngressRuleValue{
			HTTP: &extv1beta1.HTTPIngressRuleValue{
				Paths: paths,
			},
		},
	})
	tls := make([]extv1beta1.IngressTLS, 0)
	if user.Name == "boxlinker" { // todo 目前只有系统用户，先简单粗暴一下
		tls = append(tls, extv1beta1.IngressTLS{
			Hosts:      []string{host},
			SecretName: "lb-cert",
		})
	}
	ingress := &extv1beta1.Ingress{
		ObjectMeta: metav1.ObjectMeta{
			Name: form.Name,
		},
		Spec: extv1beta1.IngressSpec{
			Rules: rules,
			// todo 根据用户的证书设置，在这里需要设置 tls 属性
			TLS: tls,
		},
	}
	logrus.Debugf("Create Ingress %s/%s (%+v)", user.Name, form.Name, ingress)
	ing, err := ingClient.Create(ingress)
	if err != nil {
		errHappend = true
		httplib.Resp(w, httplib.STATUS_FAILED, "", err.Error())
		return
	}
	ingressCreated = true

	logrus.Debugf("Created ingress %q.\n", ing.GetObjectMeta().GetName())

	httplib.Resp(w, httplib.STATUS_OK, nil)
}
