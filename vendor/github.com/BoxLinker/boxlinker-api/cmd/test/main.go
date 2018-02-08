package main

import (
	"github.com/Sirupsen/logrus"
	"github.com/olivere/elastic"
	streamhttp "github.com/cabernety/gopkg/stream/http"
	"encoding/json"
	"context"
	"fmt"
	"net/http"
	"time"
	"io"
	"github.com/cabernety/gopkg/stream"
	"github.com/BoxLinker/boxlinker-api/modules/logs/es"
	"github.com/BoxLinker/boxlinker-api/modules/logs"
	"github.com/cabernety/gopkg/httplib"
	"io/ioutil"
)

type logResult struct {
	log string
	timestamp string
	id string
}

func getLogs(ctx context.Context) []*logResult {

	client, err := elastic.NewClient(elastic.SetURL("https://es.boxlinker.com"))
	if err != nil {
		panic(err)
	}
	// Search with a term query
	termQuery := elastic.NewTermQuery("docker.container_id", "d73e02f27f3fa070c53a3408c8f6f25d30cc6138636b937d22bf21c8474b1754")
	elastic.NewMultiTermvectorItem()
	searchResult, err := client.Search().
		Index("logstash-2017.11.07").   // search in index "twitter"
		Query(termQuery).   // specify the query
		Sort("@timestamp", false). // sort by "user" field, ascending
		From(0).Size(9).   // take documents 0-9
		Pretty(true).       // pretty print request and response JSON
		Do(ctx)             // execute

	if err != nil {
		panic(err)
	}
	output := make([]*logResult, 0)

	for _, hit := range searchResult.Hits.Hits {
		var item map[string]interface{}
		b, err := hit.Source.MarshalJSON()
		if err != nil {
			continue
		}
		if err := json.Unmarshal(b, &item); err != nil {
			continue
		}
		output = append(output, &logResult{
			id: hit.Id,
			log: fmt.Sprint(item["log"]),
			timestamp: fmt.Sprint(item["@timestamp"]),
		})
	}
	return output
}

func writeCh(ch chan []byte) {
	i := 0
	for {
		time.Sleep(time.Second*3)
		ch <- []byte(fmt.Sprintf("i :> %d", i))
		i ++
		if i > 20 {
			break
		}
	}
}

type Entity struct {
	Log 		string 			`json:"log"`
	Kubernetes 	map[string]interface{} 	`json:"kubernetes"`
	Timestamp 	string 			`json:"@timestamp"`
}

func getLogger(ctx context.Context) logs.Logger {

	return es.NewLogger(&es.LoggerOptions{
		SearchFunc: func() (string, error) {
			res, err := httplib.Get(fmt.Sprintf(
				"https://es.boxlinker.com/%s/fluentd/_search?filter_path=took,hits.hits._id,hits.hits._score,hits.hits._source.log,hits.hits._source.@timestamp",
					"logstash-2017.11.11",
					)).Body(fmt.Sprintf(
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
										"gte": "%s",
										"lte": "now"
									  }
									}
								  }]
								}
							  }
							}
						`,
						"d73e02f27f3fa070c53a3408c8f6f25d30cc6138636b937d22bf21c8474b1754",
						"2017-11-11T05:22:37.000882442Z",
					)).SetTimeout(time.Second*10, time.Second*10).Response()
			if err != nil {
				return "", err
			}
			b, err := ioutil.ReadAll(res.Body)
			if err != nil {
				return "", err
			}
			return string(b), nil
		},

		//SearchFunc: func() (string, error) {
		//	now := time.Now()
		//	termQuery := elastic.NewTermQuery("docker.container_id", "d73e02f27f3fa070c53a3408c8f6f25d30cc6138636b937d22bf21c8474b1754")
		//	//dateRangeQuery := elastic.NewRangeQuery("@timestamp").Gte(startTime).Lte(now)
		//	dateAggs := elastic.NewDateRangeAggregation().Field("@timestamp")
		//	dateAggs.Gt(startTime)
		//	dateAggs.Lt(now)
		//
		//	results, err := client.Search().
		//		Index("logstash-2017.11.11").
		//		Query(termQuery).
		//		Sort("@timestamp", false).
		//		//Aggregation("date_range", dateAggs).
		//		Pretty(true).
		//		Do(ctx)
		//	if err != nil {
		//		return "", err
		//	}
		//	output := []string{}
		//	for _, hit := range results.Hits.Hits {
		//		var item Entity
		//		b, err := hit.Source.MarshalJSON()
		//		if err != nil {
		//			return "", err
		//		}
		//		if err := json.Unmarshal(b, &item); err != nil {
		//			return "", err
		//		}
		//		output = append(output, fmt.Sprintf("[%s] %s", item.Timestamp, item.Log))
		//	}
		//	startTime = time.Now()
		//	return strings.Join(output, "\n"), nil
		//},
	})
}

func main(){
	logrus.SetLevel(logrus.DebugLevel)
	addr := ":8001"

	server := &http.Server{
		Addr: addr, Handler: nil,
	}

	http.HandleFunc("/", func(rw http.ResponseWriter, r *http.Request){
		//ch := make(chan []byte)
		ctx := context.Background()
		logger := getLogger(ctx)
		reader, err := logger.Open("")
		if err != nil {
			//xuyuntech.Resp(rw, xuyuntech.STATUS_INTERNAL_SERVER_ERR, nil, err.Error())
			return
		}
		//go getLogs(ctx)
		rw.Header().Set("Content-Type", "text/plain")

		// Chrome won't show data if we don't set this. See
		// http://stackoverflow.com/questions/26164705/chrome-not-handling-chunked-responses-like-firefox-safari.
		rw.Header().Set("X-Content-Type-Options", "nosniff")
		w := streamhttp.StreamingResponseWriter(rw)
		defer close(stream.Heartbeat(w, time.Second*25)) // Send a null character every 25 seconds.

		if _, err := io.Copy(w, reader); err != nil {
			logrus.Errorf("copy err: %v", err)
		}

	})
	logrus.Infof("Server listen on %s", addr)
	logrus.Fatal(server.ListenAndServe())
}


type reader struct {
	io.ReadCloser
}

