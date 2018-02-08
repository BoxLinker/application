package user

import (
	"net/http"

	"github.com/BoxLinker/boxlinker-api/controller/manager"
	mAuth "github.com/BoxLinker/boxlinker-api/controller/middleware/auth"
	userModels "github.com/BoxLinker/boxlinker-api/controller/models/user"
	log "github.com/Sirupsen/logrus"
	"github.com/codegangsta/negroni"
	"github.com/gorilla/context"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
)

type ApiOptions struct {
	Listen  string
	Manager manager.UserManager
	Config  *ApiConfig
}

type ApiConfig struct {
	ResetPassCallbackURI string
	SendEmailUri         string
	SendRegMessageAPI    string
}

type Api struct {
	listen  string
	manager manager.UserManager
	config  *ApiConfig
}

func NewApi(config ApiOptions) *Api {
	return &Api{
		listen:  config.Listen,
		manager: config.Manager,
		config:  config.Config,
	}
}

// get 	/v1/user/auth/token
// post /v1/user/auth/login
// post	/v1/user/auth/reg
// get	/v1/user/auth/confirm_email?confirm_token=
// put	/v1/user/account/list
// put	/v1/user/account/:id/changepassword
// get	/v1/user/account/:id
func (a *Api) Run() error {
	cs := cors.New(cors.Options{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{"GET", "POST", "DELETE", "PUT", "OPTIONS"},
		AllowedHeaders: []string{"Origin", "Content-Type", "Accept", "token", "X-Requested-With", "X-Access-Token"},
	})
	// middleware
	apiAuthRequired := mAuth.NewAuthRequired(a.manager)

	globalMux := http.NewServeMux()

	loginRegRouter := mux.NewRouter()
	loginRegRouter.HandleFunc("/v1/user/auth/basicAuth", a.BasicAuth).Methods("GET")
	loginRegRouter.HandleFunc("/v1/user/auth/login", a.Login).Methods("POST")
	loginRegRouter.HandleFunc("/v1/user/auth/reg", a.Reg).Methods("POST")
	loginRegRouter.HandleFunc("/v1/user/auth/confirm_email", a.ConfirmEmail).Methods("GET")
	globalMux.Handle("/v1/user/auth/", loginRegRouter)

	accountRouter := mux.NewRouter()
	accountRouter.HandleFunc("/v1/user/account/authToken", a.AuthToken).Methods("GET")
	accountRouter.HandleFunc("/v1/user/account/list", a.GetUsers).Methods("GET")
	// 登录后的修改密码
	accountRouter.HandleFunc("/v1/user/account/changepassword", a.ChangePassword).Methods("PUT")
	accountRouter.HandleFunc("/v1/user/account/userinfo", a.GetUser).Methods("GET")
	// 忘记密码的修改密码
	accountRouter.HandleFunc("/v1/user/account/pass_reset", a.ResetPassword).Methods("POST")
	accountAuthRouter := negroni.New()
	accountAuthRouter.Use(negroni.HandlerFunc(apiAuthRequired.HandlerFuncWithNext))
	accountAuthRouter.UseHandler(accountRouter)
	globalMux.Handle("/v1/user/account/", accountAuthRouter)

	passRouter := mux.NewRouter()
	// 忘记密码的发送邮件
	passRouter.HandleFunc("/v1/user/pub/pass/send_email", a.SendForgotEmail).Methods("POST")
	pubRouter := negroni.New()
	pubRouter.UseHandler(passRouter)
	globalMux.Handle("/v1/user/pub/", pubRouter)

	s := &http.Server{
		Addr:    a.listen,
		Handler: context.ClearHandler(cs.Handler(globalMux)),
	}

	log.Infof("Server listen on: %s", a.listen)

	return s.ListenAndServe()
}

func (a *Api) getUserInfo(r *http.Request) *userModels.User {
	us := r.Context().Value("user")
	if us == nil {
		return nil
	}
	ctx := us.(map[string]interface{})
	if ctx == nil || ctx["uid"] == nil {
		return nil
	}
	return &userModels.User{
		Id:   ctx["uid"].(string),
		Name: ctx["username"].(string),
	}
}
