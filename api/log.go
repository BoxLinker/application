package api

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/Sirupsen/logrus"
	"github.com/cabernety/gopkg/httplib"
	"github.com/cabernety/gopkg/stream"
	streamhttp "github.com/cabernety/gopkg/stream/http"
	"github.com/gorilla/mux"
	apiv1 "k8s.io/api/core/v1"
)

type Result struct {
	Hits struct {
		Hits []Hit `json:"hits"`
	} `json:"hits"`
}

type Hit struct {
	ID     string `json:"_id"`
	Source struct {
		Log       string `json:"log"`
		Timestamp string `json:"@timestamp"`
	} `json:"_source"`
}

type esReader struct {
	containerID string
	startTime   string
	notify      chan []byte
	errCh       chan error
	end         bool
}

func newESReader(containerID, startTime string, notify chan []byte) (*esReader, chan error) {
	errCh := make(chan error)
	return &esReader{
		containerID: containerID,
		startTime:   startTime,
		end:         false,
		notify:      notify,
		errCh:       errCh,
	}, errCh
}

func (r *esReader) stop() {
	r.end = true
}

func (r *esReader) start() {
	for {
		if r.end {
			break
		}
		b, err := r.read()
		if err != nil {
			r.errCh <- err
			break
		}

		// 解析结果，并获取最后一条的时间戳
		var result Result
		if err := json.Unmarshal(b, &result); err != nil {
			r.errCh <- err
			break
		}
		hits := result.Hits.Hits
		if len(hits) <= 0 {
			time.Sleep(time.Second)
			continue
		}
		r.startTime = hits[len(hits)-1].Source.Timestamp
		logrus.Debugf("log fetch got hits len: %d", len(hits))
		logrus.Println("========")
		for _, hit := range hits {
			r.notify <- []byte(hit.Source.Log)
		}
		time.Sleep(time.Second / 10)
	}
}

func (r *esReader) read() ([]byte, error) {
	containerID := r.containerID
	startTime := r.startTime
	uri := fmt.Sprintf(
		"https://es.boxlinker.com/%s/fluentd/_search?filter_path=took,hits.hits._id,hits.hits._source.log,hits.hits._source.@timestamp",
		fmt.Sprintf("logstash-%s", time.Now().Format("2006.01.02")))
	body := fmt.Sprintf(
		`
{
  "query": {
	"bool": {
	  "filter": [{
		"term": {
		  "docker.container_id": "%s"
		}
	  },{
		"range": {
		  "@timestamp": {
			"gt": "%s",
			"lte": "now"
		  }
		}
	  }]
	}
  }
}
			`,
		containerID,
		startTime,
	)
	logrus.Debugf("log fetch uri: %s", uri)
	logrus.Debugf("log fetch body: %s", body)
	res, err := httplib.Get(uri).Body(body).SetTimeout(time.Second*10, time.Second*10).Response()
	logrus.Debugf("log fetch (%s -> now)", startTime)
	if err != nil {
		return nil, err
	}
	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	return b, nil
}

func (a *Api) LogCurrent(w http.ResponseWriter, r *http.Request) {
	user := a.getUserInfo(r)
	svcName := mux.Vars(r)["svcName"]
	podName := mux.Vars(r)["podName"]
	req := a.clientSet.CoreV1().Pods(user.Name).GetLogs(podName, &apiv1.PodLogOptions{
		Container: fmt.Sprintf("%s-container", svcName),
		Follow:    true,
	})
	logIO, err := req.Stream()
	if err != nil {
		httplib.Resp(w, httplib.STATUS_INTERNAL_SERVER_ERR, nil, fmt.Sprintf("fetch log err: %v", err))
		return
	}

	if _, err := io.Copy(w, logIO); err != nil {
		httplib.Resp(w, httplib.STATUS_INTERNAL_SERVER_ERR, nil, fmt.Sprintf("copy log err: %v", err))
	}
}

/**
 *	@param {string} startTime 日志的起始时间，格式为 `2017-11-11T05:22:37.000882442Z` 或者不传
 */
func (a *Api) Log(w http.ResponseWriter, r *http.Request) {

	containerID := mux.Vars(r)["containerID"]

	startTime := httplib.GetQueryParam(r, "start_time")

	if startTime == "" {
		startTime = "now-5m" // 默认获取 5 分钟以内的
	}

	w.Header().Set("Content-Type", "text/plain")
	// Chrome won't show data if we don't set this. See
	// http://stackoverflow.com/questions/26164705/chrome-not-handling-chunked-responses-like-firefox-safari.
	w.Header().Set("X-Content-Type-Options", "nosniff")

	rw := streamhttp.StreamingResponseWriter(w)
	defer close(stream.Heartbeat(w, time.Second*25)) // Send a null character every 25 seconds.

	disconnectNotify := w.(http.CloseNotifier).CloseNotify()
	bufCh := make(chan []byte)
	//errCh := make(chan error)
	//exitCh := make(chan error)

	esr, errCh := newESReader(containerID, startTime, bufCh)
	go esr.start()

	done := false

	for {
		if done {
			break
		}
		select {
		case buf := <-bufCh:
			logrus.Debug(string(buf))
			rw.Write(buf)
			//io.WriteString(w, string(buf))
		case <-disconnectNotify:
			logrus.Debug("disconnectNotify")
			esr.stop()
			done = true
			break
		case err := <-errCh:
			logrus.Debug("esReader err")
			esr.stop()
			done = true
			http.Error(w, err.Error(), http.StatusInternalServerError)
			break
		}
	}

}
