package user

import (
	"net/http"
	"github.com/BoxLinker/boxlinker-api"
)

func (a *Api) GetUsers(w http.ResponseWriter, r *http.Request) {
	users, err := a.manager.GetUsers(boxlinker.ParseHTTPQuery(r))
	if err != nil {
		boxlinker.Resp(w, boxlinker.STATUS_INTERNAL_SERVER_ERR, nil, err.Error())
		return
	}
	var results []map[string]interface{}
	for _, user := range users {
		results = append(results, user.APIJson())
	}
	boxlinker.Resp(w, boxlinker.STATUS_OK, results)
}

func (a *Api) GetUser(w http.ResponseWriter, r *http.Request){
	us := r.Context().Value("user")
	if us == nil {
		boxlinker.Resp(w, boxlinker.STATUS_NOT_FOUND, nil)
		return
	}
	ctx := us.(map[string]interface{})
	if ctx == nil || ctx["uid"] == nil {
		boxlinker.Resp(w, boxlinker.STATUS_NOT_FOUND, nil)
		return
	}
	id := ctx["uid"].(string)
	u := a.manager.GetUserById(id)
	if u == nil {
		boxlinker.Resp(w, boxlinker.STATUS_NOT_FOUND, nil, "not found")
		return
	}
	boxlinker.Resp(w, boxlinker.STATUS_OK, u.APIJson())
}
