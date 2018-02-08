package user

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/BoxLinker/boxlinker-api"
	"github.com/BoxLinker/boxlinker-api/auth"
	userModels "github.com/BoxLinker/boxlinker-api/controller/models/user"
	"github.com/BoxLinker/boxlinker-api/modules/httplib"
	"github.com/Sirupsen/logrus"
)

func (a *Api) ConfirmEmail(w http.ResponseWriter, r *http.Request) {
	confirmToken := r.URL.Query().Get("confirm_token")
	if len(confirmToken) == 0 {
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	ok, result, err := auth.AuthToken(confirmToken)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !ok || result == nil {
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	uid := result["uid"].(string)
	username := result["username"].(string)

	u, err := a.manager.GetUserToBeConfirmed(uid, username)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if u == nil {
		http.Error(w, "", http.StatusBadRequest)
		return
	}

	// 向 application 服务发送注册成功消息，新建 namespace
	// TODO API 用的 token 的 token_key 应该和 user 分开
	apiToken, _ := a.manager.GenerateToken("0", "boxlinker", time.Now().Add(time.Minute*3).Unix())
	regMsg := map[string]string{
		"username":     username,
		"registry_key": u.RegistryKey,
	}
	bA, _ := json.Marshal(regMsg)
	res, err := httplib.Post(a.config.SendRegMessageAPI).Header("X-Access-Token", apiToken).Body(bA).Response()
	if err != nil {
		boxlinker.Resp(w, boxlinker.STATUS_INTERNAL_SERVER_ERR, fmt.Errorf("创建 namespace 错误: %v", err))
		return
	}

	status, msg, results, _ := boxlinker.ParseResp(res.Body)
	logrus.Debugf("request create namespace res: %d, %s, %v", status, msg, results)
	if status != boxlinker.STATUS_OK {
		boxlinker.Resp(w, boxlinker.STATUS_INTERNAL_SERVER_ERR, results, fmt.Sprintf("创建 namespace 失败: %s", msg))
		return
	}

	u1 := &userModels.User{
		Name:        u.Name,
		Email:       u.Email,
		Password:    u.Password,
		RegistryKey: u.RegistryKey,
	}

	if err := a.manager.SaveUser(u1); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if err := a.manager.DeleteUsersToBeConfirmedByName(u.Name); err != nil {
		// to be continue
		logrus.Warnf("DeleteUsersToBeConfirmedByName err: %v, after save user", err)
	}

	http.Redirect(w, r, fmt.Sprintf("https://console.boxlinker.com/login?reg_confirmed_username=%s", u.Name), http.StatusPermanentRedirect)
	//w.Write([]byte("confirm user success: "+u1.Id+" "+ u1.Name))

}
