package es

import (
	"io"
	"time"
	"sync"
	"bytes"
	"fmt"
	"errors"
	"github.com/BoxLinker/boxlinker-api/modules/logs"
)

const (
	readThrottle = time.Second * 3
	writeThrottle = time.Second * 5
)

type Entity struct {
	Log 		string 			`json:"log"`
	Kubernetes 	map[string]interface{} 	`json:"kubernetes"`
	Timestamp 	string 			`json:"@timestamp"`
}

type logger struct {
	searchFunc func() (string, error)
}

type LoggerOptions struct {
	SearchFunc func() (string, error)
}

func NewLogger(option *LoggerOptions) logs.Logger {
	return &logger{
		searchFunc: option.SearchFunc,
	}
}

func (l *logger) Create(name string) (io.Writer, error) {
	return nil, errors.New("es logger not implement writer")
}

func (l *logger) Open(name string) (io.Reader, error) {
	r := &Reader{
		l: l,
		throttle: time.Tick(readThrottle),
		closed: false,
	}
	go r.start()
	return r, nil
}

type writer struct {
	io.WriteCloser
}

func (w *writer) Close() error {
	return w.WriteCloser.Close()
}

type Reader struct {
	l *logger
	io.ReadCloser
	err error
	throttle <-chan time.Time
	b lockingBuffer
	pos int64
	closed bool
}

func (r *Reader) Close() error {
	r.closed = true
	return nil
}

func (r *Reader) start() {
	for {
		<-r.throttle

		if r.closed {
			break
		}

		if r.err = r.read(); r.err != nil {
			fmt.Errorf("es reader err: %v", r.err)
			return
		}

	}
}

func (r *Reader) read() error {
	s, err := r.l.searchFunc()
	if err != nil {
		return err
	}
	r.b.WriteString(s)
	r.pos += int64(len(s))
	return nil
}

func (r *Reader) Read(b []byte) (int, error) {
	if r.err != nil {
		return 0, r.err
	}
	if r.b.Len() == 0 {
		return 0, nil
	}
	return r.b.Read(b)
}


type lockingBuffer struct {
	sync.Mutex
	bytes.Buffer
}

func (r *lockingBuffer) Read(b []byte) (int, error) {
	r.Lock()
	defer r.Unlock()

	return r.Buffer.Read(b)
}

func (r *lockingBuffer) Write(b []byte) (int, error) {
	r.Lock()
	defer r.Unlock()

	return r.Buffer.Write(b)
}