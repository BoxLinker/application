package models

import (
	"fmt"
	"net/url"
	"strings"

	log "github.com/Sirupsen/logrus"
	_ "github.com/go-sql-driver/mysql"
	"github.com/go-xorm/core"
	"github.com/go-xorm/xorm"
	"github.com/robfig/cron"
	"github.com/urfave/cli"
)

func Tables() []interface{} {
	var tables []interface{}
	tables = append(tables, new(PodConfigure))
	return tables
}

type DBOptions struct {
	User     string
	Password string
	Host     string
	Port     int
	Name     string
}

func GetDBOptions(c *cli.Context) DBOptions {
	return DBOptions{
		User:     c.String("db-user"),
		Password: c.String("db-password"),
		Host:     c.String("db-host"),
		Port:     c.Int("db-port"),
		Name:     c.String("db-name"),
	}
}

func NewEngine(config DBOptions, t []interface{}) (*xorm.Engine, error) {
	var Param string = "?"
	//var _tables []interface{}
	if strings.Contains(config.Name, Param) {
		Param = "&"
	}
	var connStr = fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?charset=utf8&loc=%s",
		url.QueryEscape(config.User),
		url.QueryEscape(config.Password),
		config.Host,
		config.Port,
		config.Name, "Asia%2FShanghai")

	log.Infof("Connect to db: %s", connStr)
	x, err := xorm.NewEngine("mysql", connStr)
	if err != nil {
		return nil, err
	}
	log.Info("Connect to db ok.")
	x.SetMapper(core.GonicMapper{})
	log.Infof("start to sync tables ...")
	//if len(t) > 0 {
	//	_tables = t[0]
	//} else {
	//	_tables = tables
	//}
	if err = x.StoreEngine("InnoDB").Sync2(t...); err != nil {
		return nil, fmt.Errorf("sync tables err: %v", err)
	}
	x.ShowSQL(true)
	go ping(x)
	return x, nil
}

func ping(engine *xorm.Engine) {
	log.Debugf("start to pint db engine.")
	forever := make(chan bool)
	c := cron.New()
	c.AddFunc("@every 1m", func() {
		if err := engine.Ping(); err != nil {
			log.Errorf("ping err: %s", err.Error())
		}
	})
	c.Start()
	<-forever
}
