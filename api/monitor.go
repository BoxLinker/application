package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/BoxLinker/application/modules/monitor"
	"github.com/cabernety/gopkg/httplib"
	"github.com/gorilla/mux"
)

type rResult struct {
	Result [][]interface{} `json:"result"`
	Err    string          `json:"err"`
}

func (a *Api) Monitor(w http.ResponseWriter, r *http.Request) {
	user := a.getUserInfo(r)
	serviceName := mux.Vars(r)["serviceName"]
	start := httplib.GetQueryParam(r, "start")
	end := httplib.GetQueryParam(r, "end")
	step := httplib.GetQueryParam(r, "step")

	if _, err := time.Parse("2006-01-02T15:04:05.000Z", start); err != nil {
		httplib.Resp(w, httplib.STATUS_PARAM_ERR, nil, "start param err")
		return
	}
	if _, err := time.Parse("2006-01-02T15:04:05.000Z", end); err != nil {
		httplib.Resp(w, httplib.STATUS_PARAM_ERR, nil, "end param err")
		return
	}
	monitorOps := &monitor.Options{
		Start: start,
		End:   end,
		Step:  step,
	}
	output := make(map[string]*rResult)

	if re, err := a.prometheusMonitor.Query(fmt.Sprintf("sum(container_memory_usage_bytes{container_name=~\"%s-.*\",namespace=\"%s\"}) by (container_name)", serviceName, user.Name), monitorOps); err != nil {
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

	httplib.Resp(w, httplib.STATUS_OK, output)

}
