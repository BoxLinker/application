package application

import (
	"net/http"
	"github.com/gorilla/mux"
	"fmt"
	"github.com/BoxLinker/boxlinker-api"
	"time"
	"github.com/BoxLinker/boxlinker-api/modules/monitor"
)

type rResult struct{
	Result [][]interface{}	`json:"result"`
	Err string `json:"err"`
}

func (a *Api) Monitor(w http.ResponseWriter, r *http.Request) {
	user := a.getUserInfo(r)
	serviceName := mux.Vars(r)["serviceName"]
	start := boxlinker.GetQueryParam(r, "start")
	end := boxlinker.GetQueryParam(r, "end")
	step := boxlinker.GetQueryParam(r, "step")

	if _, err := time.Parse("2006-01-02T15:04:05.000Z", start); err != nil {
		boxlinker.Resp(w, boxlinker.STATUS_PARAM_ERR, nil, "start param err")
		return
	}
	if _, err := time.Parse("2006-01-02T15:04:05.000Z", end); err != nil {
		boxlinker.Resp(w, boxlinker.STATUS_PARAM_ERR, nil, "end param err")
		return
	}
	monitorOps := &monitor.Options{
		Start: start,
		End: end,
		Step: step,
	}
	output := make(map[string]*rResult)


	if re, err := a.prometheusMonitor.Query(fmt.Sprintf("sum(container_memory_usage_bytes{container_name=\"%s\",namespace=\"%s\"}) by (container_name)", serviceName, user.Name), monitorOps); err != nil {
		output["memory"] = &rResult{
			Err: err.Error(),
		}
	} else {
		output["memory"] = &rResult{
			Result: re.GetValues(),
		}
	}
	if re, err := a.prometheusMonitor.Query(fmt.Sprintf(
		"sum(rate(container_network_receive_bytes_total{pod_name=~\"%s-.*\",namespace=\"%s\",interface=\"eth0\"}[1h])) by (container_name)",
			serviceName, user.Name), monitorOps); err != nil {
		output["networkReceive"] = &rResult{
			Err: err.Error(),
		}
	} else {
		output["networkReceive"] = &rResult{
			Result: re.GetValues(),
		}
	}
	if re, err := a.prometheusMonitor.Query(fmt.Sprintf(
		"sum(rate(container_network_transmit_bytes_total{pod_name=~\"%s-.*\",namespace=\"%s\",interface=\"eth0\"}[1h])) by (container_name)",
			serviceName, user.Name), monitorOps); err != nil {
		output["networkTransmit"] = &rResult{
			Err: err.Error(),
		}
	} else {
		output["networkTransmit"] = &rResult{
			Result: re.GetValues(),
		}
	}

	boxlinker.Resp(w, boxlinker.STATUS_OK, output)

}
