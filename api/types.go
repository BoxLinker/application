package api

import (
	"time"
)

const ()

type PortResult struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Path     string `json:"path"`
}

type PodResult struct {
	Name        string     `json:"name"`
	ID          string     `json:"id"`
	ContainerID string     `json:"container_id"`
	Status      *PodStatus `json:"status"`
}

type PodStatus struct {
	State      string    `json:"state"`
	Message    string    `json:"message"`
	Reason     string    `json:"reason"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at"`
	ExitCode   int32     `json:"exit_code"`
	Signal     int32     `json:"signal"`
}

type ServiceResult struct {
	Name   string         `json:"name"`
	Image  string         `json:"image"`
	Memory string         `json:"memory"`
	Host   string         `json:"host"`
	Ports  []*PortResult  `json:"ports"`
	Pods   []*PodResult   `json:"pods"`
	Status *ServiceStatus `json:"status"`
}

type ServiceStatus struct {
	Replicas            int32 `json:"replicas"`
	AvailableReplicas   int32 `json:"available_replicas"`
	ReadyReplicas       int32 `json:"ready_replicas"`
	UnavailableReplicas int32 `json:"unavailable_replicas"`
}
