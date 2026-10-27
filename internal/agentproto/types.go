package agentproto

// Parameter and result types of the allow-listed operations. Parameters are
// decoded strictly by the agent (unknown fields rejected).

// Empty is the parameter type of operations without parameters.
type Empty struct{}

// ContainerRef identifies one container by ID or name.
type ContainerRef struct {
	ID string `json:"id"`
}

// ContainerStop stops or restarts a container.
type ContainerStop struct {
	ID             string `json:"id"`
	TimeoutSeconds int    `json:"timeout_seconds"`
}

// ContainersList lists containers.
type ContainersList struct {
	All bool `json:"all"`
}

// AgentInfo describes the agent process.
type AgentInfo struct {
	Version       string `json:"version"`
	Commit        string `json:"commit"`
	UptimeSeconds int64  `json:"uptime_seconds"`
}

// DockerInfo summarizes the Docker Engine.
type DockerInfo struct {
	ServerVersion     string `json:"server_version"`
	APIVersion        string `json:"api_version"`
	NegotiatedVersion string `json:"negotiated_api_version"`
	OS                string `json:"os"`
	Arch              string `json:"arch"`
	KernelVersion     string `json:"kernel_version"`
	Rootless          bool   `json:"rootless"`
	StorageDriver     string `json:"storage_driver"`
	Containers        int    `json:"containers"`
	Running           int    `json:"running"`
	Paused            int    `json:"paused"`
	Stopped           int    `json:"stopped"`
	Images            int    `json:"images"`
}

// Port is a published or exposed container port.
type Port struct {
	IP          string `json:"ip,omitempty"`
	PrivatePort int    `json:"private_port"`
	PublicPort  int    `json:"public_port,omitempty"`
	Type        string `json:"type"`
}

// ContainerSummary is one entry of containers.list.
type ContainerSummary struct {
	ID      string            `json:"id"`
	Names   []string          `json:"names"`
	Image   string            `json:"image"`
	State   string            `json:"state"`
	Status  string            `json:"status"`
	Created int64             `json:"created"`
	Ports   []Port            `json:"ports"`
	Labels  map[string]string `json:"labels"`
}

// Mount is a container mount.
type Mount struct {
	Type        string `json:"type"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	RW          bool   `json:"rw"`
}

// ContainerDetail is the result of containers.inspect: a security-relevant
// summary, not the full Docker document.
type ContainerDetail struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Image         string   `json:"image"`
	Status        string   `json:"status"`
	Running       bool     `json:"running"`
	ExitCode      int      `json:"exit_code"`
	StartedAt     string   `json:"started_at"`
	FinishedAt    string   `json:"finished_at"`
	Health        string   `json:"health,omitempty"`
	RestartPolicy string   `json:"restart_policy"`
	Privileged    bool     `json:"privileged"`
	NetworkMode   string   `json:"network_mode"`
	CapAdd        []string `json:"cap_add"`
	Mounts        []Mount  `json:"mounts"`
}

// ActionResult reports a state change.
type ActionResult struct {
	ID      string `json:"id"`
	Changed bool   `json:"changed"` // false if the container already was in the target state
}
