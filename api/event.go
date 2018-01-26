package api

import (
	"fmt"
	"net/http"

	"github.com/cabernety/gopkg/httplib"

	"github.com/Sirupsen/logrus"

	"github.com/gorilla/mux"
	apiv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// 这个接口一般是由管理员调用的，验证统一使用 user token，但是指定 username = boxlinker
// 创建 namespace 的同时，还必须创建 registry-key
func (a *Api) Event(w http.ResponseWriter, r *http.Request) {
	u := a.getUserInfo(r)
	if u.Name != "boxlinker" {
		httplib.Resp(w, httplib.STATUS_UNAUTHORIZED, nil, "only admin can operate")
		return
	}
	tType := mux.Vars(r)["type"]
	if tType == "reg_message" {
		var regMsg struct {
			Username    string `json:"username"`
			RegistryKey string `json:"registry_key"`
		}
		if err := httplib.ReadRequestBody(r, &regMsg); err != nil {
			httplib.Resp(w, httplib.STATUS_PARAM_ERR, nil, fmt.Sprintf("获取 ns 参数错误: %v", err))
			return
		}
		ns := regMsg.Username
		if len(ns) == 0 {
			httplib.Resp(w, httplib.STATUS_PARAM_ERR, nil, "需要 ns 参数")
			return
		}
		nsClient := a.clientSet.CoreV1().Namespaces()
		if _, err := nsClient.Get(ns, metav1.GetOptions{}); err == nil { // err == nil 说明找到了
			httplib.Resp(w, httplib.STATUS_FAILED, nil, fmt.Sprintf("%s 已经存在", ns))
			return
		}

		if _, err := nsClient.Create(&apiv1.Namespace{
			ObjectMeta: metav1.ObjectMeta{
				Name: ns,
			},
		}); err != nil {
			httplib.Resp(w, httplib.STATUS_INTERNAL_SERVER_ERR, nil, fmt.Sprintf("create namespace %s err: %v", ns, err))
			return
		}
		// TODO 这里需要拿到用户的明文用户名和密码，得有个安全的解决方式
		// 但毕竟 registry-key 的 secret 文件因为是 base64 编码 也不够安全

		// 创建 registry-key
		dockerconfigJSON := fmt.Sprintf(
			`{
	"auths": {
		"index.boxlinker.com": {
			"auth": "%s"
		}
	}
}`,
			regMsg.RegistryKey)
		logrus.Debugf("create registry-key for namespace(%s): %s", ns, dockerconfigJSON)
		if _, err := a.clientSet.CoreV1().Secrets(ns).Create(&apiv1.Secret{
			Type: apiv1.SecretTypeDockerConfigJson,
			ObjectMeta: metav1.ObjectMeta{
				Name:      "registry-key",
				Namespace: ns,
			},
			Data: map[string][]byte{
				apiv1.DockerConfigJsonKey: []byte(dockerconfigJSON),
			},
		}); err != nil {
			// 如果创建 secret registry-key 失败，那么回滚删除 namespace
			logrus.Errorf("create registry-key secret failed for %s: %v", ns, err)
			logrus.Debugf("start to rollback to delete namespace %s", ns)
			if err := nsClient.Delete(ns, &metav1.DeleteOptions{}); err != nil {
				logrus.Errorf("delete namespace %s err: %v", ns, err)
				// todo 如果这步操作也失败了，应该有一个运行时错误记录服务来记录下这种业务函数的异常处理，然后手工解决
			}
			httplib.Resp(w, httplib.STATUS_FAILED, nil, fmt.Sprintf("create registry key for namespace(%s) err: %v", ns, err))
			return
		}
		logrus.Debugf("event ok %s", ns)
		httplib.Resp(w, httplib.STATUS_OK, map[string]string{
			"namespace": ns,
		})
		return
	}
	logrus.Debugf("unknow type %s", tType)
	httplib.Resp(w, httplib.STATUS_FAILED, nil, fmt.Sprintf("unknow type %s", tType))
}
