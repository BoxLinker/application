package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	api "github.com/BoxLinker/boxlinker-api/api/v1/application"
	manager "github.com/BoxLinker/boxlinker-api/controller/manager"
	"github.com/BoxLinker/boxlinker-api/controller/models"
	applicationModels "github.com/BoxLinker/boxlinker-api/controller/models/application"
	"github.com/BoxLinker/boxlinker-api/modules/monitor"
	"github.com/Sirupsen/logrus"
	"github.com/urfave/cli"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var flags = []cli.Flag{
	cli.StringFlag{
		Name:   "config-file",
		Value:  "./config.yml",
		EnvVar: "CONFIG_FILE",
	},
}

func main() {
	app := cli.NewApp()
	app.Name = "Boxlinker Email server"
	app.Before = func(c *cli.Context) error {
		if c.Bool("debug") {
			logrus.SetLevel(logrus.DebugLevel)
		}
		return nil
	}
	app.Action = action
	app.Flags = flags

	if err := app.Run(os.Args); err != nil {
		logrus.Fatal(err)
	}
}

func action(c *cli.Context) error {
	configFilePath := c.String("config-file")
	if len(configFilePath) == 0 {
		return errors.New("no config file provided")
	}

	config, err := api.LoadConfig(configFilePath)
	if err != nil {
		return err
	}

	if config.Server.Debug {
		logrus.SetLevel(logrus.DebugLevel)
	}

	var (
		clientSet *kubernetes.Clientset
	)

	if config.InCluster {
		config, err := rest.InClusterConfig()
		if err != nil {
			return err
		}
		clientSet, err = kubernetes.NewForConfig(config)
		if err != nil {
			return fmt.Errorf("connect to incluster k8s error: %v", err)
		}
	} else {
		var kubeconfig *string
		if home := homeDir(); home != "" {
			kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
		} else {
			kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
		}
		flag.Parse()

		// use the current context in kubeconfig
		k8sConfig, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
		if err != nil {
			panic(err.Error())
		}
		logrus.Infof("kubeconfig (%+v)", k8sConfig)
		// create the clientset
		clientSet, err = kubernetes.NewForConfig(k8sConfig)
		if err != nil {
			return fmt.Errorf("connect to k8s error: %v", err)
		}
	}

	info, err := clientSet.ServerVersion()
	if err != nil {
		return err
	}
	logrus.Infof("connect to api-server (%+v)", info)
	// KUBE_CGROUP_DRIVER="--cgroup-driver=systemd"
	// KUBE_STORAGE_DRIVER="--storage-driver=etcd2"
	engine, err := models.NewEngine(models.DBOptions{
		User:     config.DB.User,
		Password: config.DB.Password,
		Name:     config.DB.Name,
		Host:     config.DB.Host,
		Port:     config.DB.Port,
	}, applicationModels.Tables())
	if err != nil {
		return fmt.Errorf("new db engine err: %v", err)
	}

	// monitor
	pm := &monitor.PrometheusMonitor{
		Host: config.Monitor.URL,
	}

	controllerManager, err := manager.NewApplicationManager(engine, clientSet, pm)
	if err != nil {
		return fmt.Errorf("new controller manager err: %v", err)
	}

	appApi, err := api.NewApi(api.ApiConfig{
		Config:            config,
		ControllerManager: controllerManager,
		ClientSet:         clientSet,
		PrometheusMonitor: pm,
	})

	if err != nil {
		return err
	}
	if err := appApi.Run(); err != nil {
		return err
	}
	return nil
}

func homeDir() string {
	if h := os.Getenv("HOME"); h != "" {
		return h
	}
	return os.Getenv("USERPROFILE") // windows
}
