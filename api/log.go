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
	done        <-chan struct{}
}

func newESReader(done <-chan struct{}, containerID, startTime string, notify chan []byte) (*esReader, chan error) {
	errCh := make(chan error)
	return &esReader{
		containerID: containerID,
		startTime:   startTime,
		end:         false,
		notify:      notify,
		errCh:       errCh,
		done:        done,
	}, errCh
}

func (r *esReader) start() {
Loop:
	for {
		select {
		case <-r.done:
			logrus.Debugln("esReader done ....")
			break Loop
		case <-time.After(time.Second):
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
			if len(hits) > 0 {
				r.startTime = hits[len(hits)-1].Source.Timestamp
				logrus.Debugf("log fetch got hits len: %d", len(hits))
			}
			r.notify <- b
		}
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
	// logrus.Debugf("log fetch uri: %s", uri)
	// logrus.Debugf("log fetch body: %s", body)
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

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	cw, ok := w.(http.CloseNotifier)
	if !ok {
		httplib.Resp(w, httplib.STATUS_INTERNAL_SERVER_ERR, nil, "Streaming not supported CloseNotifier")
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		httplib.Resp(w, httplib.STATUS_INTERNAL_SERVER_ERR, nil, "Streaming not supported Flusher")
		return
	}

	pingStr := fmt.Sprintf("%x\r\nping", len("ping"))
	io.WriteString(w, pingStr)
	flusher.Flush()

	bufCh := make(chan []byte)
	done := make(chan struct{})
	esr, errCh := newESReader(done, containerID, startTime, bufCh)

	defer close(done)
	go esr.start()
	tick := time.After(time.Second * 30)
Loop:
	for {
		select {
		case <-tick:
			logrus.Debugln("break ....")
			io.WriteString(w, fmt.Sprintf("%x\r\neof", len("eof")))
			flusher.Flush()
			break Loop
		case buf := <-bufCh:
			io.WriteString(w, fmt.Sprintf("%x\r\n%s", len(buf), buf))
			flusher.Flush()
			break
		case err := <-errCh:
			logrus.Errorf("es reader err: %v", err)
			errS := err.Error()
			io.WriteString(w, fmt.Sprintf("%x\r\n%s", len(errS), fmt.Sprintf("error:%s", errS)))
			flusher.Flush()
			break Loop
		case <-cw.CloseNotify():
			logrus.Debugln("client disconnect.")
			break Loop
		}
	}
	logrus.Debugln("log end ======")
}
