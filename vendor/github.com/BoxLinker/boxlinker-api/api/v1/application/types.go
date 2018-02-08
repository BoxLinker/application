package application

type PortResult struct {
	Port int `json:"port"`
	Protocol string `json:"protocol"`
	Path string `json:"path"`
}

type PodResult struct {
	Name string `json:"name"`
	ID string `json:"id"`
	ContainerID string `json:"container_id"`
}

type ServiceResult struct {
	Name string `json:"name"`
	Image string `json:"image"`
	Memory string `json:"memory"`
	Host string `json:"host"`
	Ports []*PortResult `json:"ports"`
	Pods []*PodResult `json:"pods"`
}

