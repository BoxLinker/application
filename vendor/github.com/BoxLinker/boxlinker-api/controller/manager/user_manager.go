package manager

import (
	"fmt"

	"github.com/BoxLinker/boxlinker-api"
	"github.com/BoxLinker/boxlinker-api/auth"
	mAuth "github.com/BoxLinker/boxlinker-api/auth"
	userModels "github.com/BoxLinker/boxlinker-api/controller/models/user"
	"github.com/BoxLinker/boxlinker-api/pkg/amqp"
	settings "github.com/BoxLinker/boxlinker-api/settings/user"
	log "github.com/Sirupsen/logrus"
	"github.com/go-xorm/xorm"
)

type UserManager interface {
	Manager
	VerifyUsernamePassword(username, password, hash string) (bool, error)
	GenerateToken(uid string, username string, exp ...int64) (string, error)

	// user
	CheckAdminUser() error
	GetUserByName(username string) (*userModels.User, error)
	GetUserById(id string) *userModels.User
	GetUsers(pageConfig boxlinker.PageConfig) ([]*userModels.User, error)
	GetUserByEmail(email string) (*userModels.User, error)
	SaveUser(user *userModels.User) error

	SaveUserToBeConfirmed(user *userModels.UserToBeConfirmed) error
	DeleteUserToBeConfirmed(uid string) error
	DeleteUsersToBeConfirmedByName(username string) error
	GetUserToBeConfirmed(id string, username string) (*userModels.UserToBeConfirmed, error)

	IsUserExists(username string) (bool, error)
	IsEmailExists(email string) (bool, error)
	UpdatePassword(id string, password string) (bool, error)
}

type DefaultUserManager struct {
	DefaultManager
	authenticator mAuth.Authenticator
	engine        *xorm.Engine
	producer      *amqp.Producer
}

type ManagerOptions struct {
	Authenticator mAuth.Authenticator
	DBUser        string
	DBPassword    string
	DBName        string
	DBHost        string
	DBPort        int
}

//func NewUserManager(config ManagerOptions) (Manager, error) {
func NewUserManager(engine *xorm.Engine, authenticator auth.Authenticator, amqpProducer *amqp.Producer) (UserManager, error) {
	return &DefaultUserManager{
		authenticator: authenticator,
		engine:        engine,
		producer:      amqpProducer,
	}, nil
}

func (m DefaultUserManager) VerifyUsernamePassword(username, password, hash string) (bool, error) {
	return m.authenticator.Authenticate(username, password, hash)
}

func (m DefaultUserManager) GenerateToken(uid string, username string, exp ...int64) (string, error) {
	return m.authenticator.GenerateToken(uid, username, exp...)
}

func (m DefaultUserManager) GetUserToBeConfirmed(id string, username string) (*userModels.UserToBeConfirmed, error) {
	sess := m.engine.NewSession()
	defer sess.Close()

	u := &userModels.UserToBeConfirmed{
		Id:   id,
		Name: username,
	}

	has, err := sess.Get(u)
	if err != nil {
		return nil, err
	}
	if !has {
		return nil, nil
	} else {
		return u, nil
	}
}

func (m DefaultUserManager) DeleteUsersToBeConfirmedByName(username string) error {
	sess := m.engine.NewSession()
	defer sess.Close()

	_, err := sess.And("name = ?", username).Delete(new(userModels.UserToBeConfirmed))
	return err
}

func (m DefaultUserManager) DeleteUserToBeConfirmed(uid string) error {
	sess := m.engine.NewSession()
	defer sess.Close()

	if err := sess.Begin(); err != nil {
		return err
	}
	_, err := sess.ID(uid).Delete(new(userModels.UserToBeConfirmed))
	if err != nil {
		return err
	}
	return sess.Commit()
}
func (m DefaultUserManager) SaveUserToBeConfirmed(user *userModels.UserToBeConfirmed) error {
	sess := m.engine.NewSession()
	defer sess.Close()

	if err := sess.Begin(); err != nil {
		return err
	}
	if _, err := sess.Insert(user); err != nil {
		sess.Rollback()
		return err
	}
	return sess.Commit()
}
func (m DefaultUserManager) SaveUser(user *userModels.User) error {
	sess := m.engine.NewSession()
	defer sess.Close()

	if err := sess.Begin(); err != nil {
		return err
	}
	if _, err := sess.Insert(user); err != nil {
		sess.Rollback()
		return err
	}
	return sess.Commit()
}

func (m DefaultUserManager) CheckAdminUser() error {
	log.Debugf("CheckAdminUser ...")
	sess := m.engine.NewSession()
	defer sess.Close()
	adminUser := &userModels.User{
		Name: settings.ADMIN_NAME,
	}
	if has, _ := sess.Get(adminUser); !has {
		pass, err := mAuth.Hash(settings.ADMIN_PASSWORD)
		if err != nil {
			return err
		}
		u := &userModels.User{
			Name:     settings.ADMIN_NAME,
			Password: pass,
			Email:    settings.ADMIN_EMAIL,
		}
		if _, err := sess.Insert(u); err != nil {
			sess.Rollback()
			return err
		} else {
			log.Infof("Add admin user: %s", u.Id)
		}
	} else {
		log.Infof("Admin user exists: %s", adminUser.Id)
	}
	return sess.Commit()
}

func (m DefaultUserManager) GetUsers(pageConfig boxlinker.PageConfig) (users []*userModels.User, err error) {
	fmt.Printf("pageConfig:> %+v", pageConfig)
	err = m.engine.Desc("created_unix").Limit(pageConfig.Limit(), pageConfig.Offset()).Find(&users)
	return
}

func (m DefaultUserManager) GetUserByName(username string) (*userModels.User, error) {
	u := &userModels.User{
		Name: username,
	}
	if _, err := m.engine.Get(u); err != nil {
		log.Debugf("GetUserByName err: %s", err.Error())
		return nil, err
	}
	return u, nil
}

func (m DefaultUserManager) GetUserByEmail(email string) (*userModels.User, error) {
	u := &userModels.User{
		Email: email,
	}
	if has, err := m.engine.Get(u); err != nil {
		log.Debugf("GetUserByEmail err: %s", err.Error())
		return nil, err
	} else if !has {
		return nil, nil
	}
	return u, nil
}

func (m DefaultUserManager) GetUserById(id string) *userModels.User {
	u := &userModels.User{}
	if found, _ := m.engine.Id(id).Get(u); found {
		return u
	}
	return nil
}

func (m DefaultUserManager) IsUserExists(username string) (bool, error) {
	u := &userModels.User{
		Name: username,
	}
	if found, err := m.engine.Cols("name").Get(u); err != nil {
		return false, err
	} else if found {
		return true, nil
	} else {
		return false, nil
	}
}

func (m DefaultUserManager) IsEmailExists(email string) (bool, error) {
	u := &userModels.User{
		Email: email,
	}
	if found, err := m.engine.Cols("email").Get(u); err != nil {
		return false, err
	} else if found {
		return true, nil
	} else {
		return false, nil
	}
}

func (m DefaultUserManager) UpdatePassword(id string, password string) (bool, error) {
	sess := m.engine.NewSession()
	defer sess.Close()
	u := &userModels.User{
		Password: password,
	}
	_, err := m.engine.Id(id).Update(u)
	if err != nil {
		sess.Rollback()
		return false, err
	}
	return true, sess.Commit()
}
