package monitor

import (
	"fmt"
	"github.com/cabernety/gopkg/httplib"
	"io/ioutil"
	"encoding/json"
	"github.com/Sirupsen/logrus"
)

type PrometheusMonitor struct {
	Host string
}

type Options struct {
	Start string
	End string
	Step string
}

type PrometheusResult struct {
	Status string `json:"status"`
	Data struct{
		ResultType string `json:"resultType"`
		Result []*PrometheusResultValues `json:"result"`
	} `json:"data"`
}

func (pr *PrometheusResult) GetValues() [][]interface{} {
	if len(pr.Data.Result) == 1{
		return pr.Data.Result[0].Values
	} else {
		logrus.Warnf("PrometheusResult wrong num values: \n %+v", pr)
	}
	return nil
}

type PrometheusResultValues struct{
	Metric map[string]interface{} `json:"metric"`
	Values [][]interface{} `json:"values"`
}

func (pm *PrometheusMonitor) Query(query string, options *Options) (*PrometheusResult, error) {
	return pm.fetch(query, options)
}

func (pm *PrometheusMonitor) fetch(query string, options *Options) (*PrometheusResult, error) {
	res, err := httplib.Get(fmt.Sprintf("%s/api/v1/query_range", pm.Host)).
		Param("query", query).
		Param("start", options.Start).
		Param("end", options.End).
		Param("step", options.Step).Response()
	if err != nil {
		return nil, err
	}
	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	var result PrometheusResult
	if err := json.Unmarshal(b, &result); err != nil {
		return nil, err
	}
	logrus.Debugf("monitor fetch result:\n %+v", result)
	return &result, nil
}

func (pm *PrometheusMonitor) GetMemoryMetricByContainerName(containerName, namespace string, options *Options) (*PrometheusResult, error) {
	return pm.fetch(fmt.Sprintf(
		"container_memory_usage_bytes{container_name=\"%s\",namespace=\"%s\"}",
		containerName, namespace), options)
}

func (pm *PrometheusMonitor) GetCPUMetricByContainerName(containerName, namespace string, options *Options) (*PrometheusResult, error) {
	return pm.fetch(fmt.Sprintf(
		"container_cpu_usage_seconds_total{container_name=\"%s\",namespace=\"%s\"}",
		containerName, namespace), options)
}

func (pm *PrometheusMonitor) GetNetworkReceiveMetricByContainerName(containerName, namespace string, options *Options) (*PrometheusResult, error) {
	return pm.fetch(fmt.Sprintf(
		"container_network_receive_bytes_total{container_name=\"%s\",namespace=\"%s\"}",
		containerName, namespace), options)
}

func (pm *PrometheusMonitor) GetNetworkTransmitMetricByContainerName(containerName, namespace string, options *Options) (*PrometheusResult, error) {
	return pm.fetch(fmt.Sprintf(
		"container_network_transmit_bytes_total{container_name=\"%s\",namespace=\"%s\"}",
		containerName, namespace), options)
}

