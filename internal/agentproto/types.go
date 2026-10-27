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
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	Image         string            `json:"image"`
	Status        string            `json:"status"`
	Running       bool              `json:"running"`
	ExitCode      int               `json:"exit_code"`
	StartedAt     string            `json:"started_at"`
	FinishedAt    string            `json:"finished_at"`
	Health        string            `json:"health,omitempty"`
	RestartPolicy string            `json:"restart_policy"`
	Privileged    bool              `json:"privileged"`
	NetworkMode   string            `json:"network_mode"`
	CapAdd        []string          `json:"cap_add"`
	Mounts        []Mount           `json:"mounts"`
	User          string            `json:"user"`
	Labels        map[string]string `json:"labels"`
}

// ActionResult reports a state change.
type ActionResult struct {
	ID      string `json:"id"`
	Changed bool   `json:"changed"` // false if the container already was in the target state
}

// ---- M6: container management ----

// EnvVar is one environment variable.
type EnvVar struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// PortBinding publishes a container port on the host.
type PortBinding struct {
	HostIP        string `json:"host_ip,omitempty"` // empty = all interfaces
	HostPort      int    `json:"host_port"`
	ContainerPort int    `json:"container_port"`
	Protocol      string `json:"protocol,omitempty"` // tcp (default) | udp
}

// MountSpec is a volume, bind or tmpfs mount.
type MountSpec struct {
	Type     string `json:"type"`             // volume | bind | tmpfs
	Source   string `json:"source,omitempty"` // volume name or host path
	Target   string `json:"target"`
	ReadOnly bool   `json:"read_only,omitempty"`
}

// ContainerSpec is the typed subset of Docker's create options Kernhaven
// supports. Anything not representable here cannot be requested (M6).
type ContainerSpec struct {
	Name           string            `json:"name"`
	Image          string            `json:"image"`
	Cmd            []string          `json:"cmd,omitempty"`
	Entrypoint     []string          `json:"entrypoint,omitempty"`
	Env            []EnvVar          `json:"env,omitempty"`
	User           string            `json:"user,omitempty"`
	WorkingDir     string            `json:"working_dir,omitempty"`
	Ports          []PortBinding     `json:"ports,omitempty"`
	Mounts         []MountSpec       `json:"mounts,omitempty"`
	NetworkMode    string            `json:"network_mode,omitempty"` // "" (bridge), "none", "host" or a network name
	RestartPolicy  string            `json:"restart_policy,omitempty"`
	Labels         map[string]string `json:"labels,omitempty"`
	Privileged     bool              `json:"privileged,omitempty"`
	CapAdd         []string          `json:"cap_add,omitempty"`
	CapDrop        []string          `json:"cap_drop,omitempty"`
	PidMode        string            `json:"pid_mode,omitempty"`
	IpcMode        string            `json:"ipc_mode,omitempty"`
	UTSMode        string            `json:"uts_mode,omitempty"`
	Devices        []string          `json:"devices,omitempty"`
	SecurityOpt    []string          `json:"security_opt,omitempty"`
	ReadOnlyRootfs bool              `json:"read_only_rootfs,omitempty"`
	MemoryBytes    int64             `json:"memory_bytes,omitempty"`
	NanoCPUs       int64             `json:"nano_cpus,omitempty"`
}

// CreateContainer creates (and optionally starts) a container. Exceptions
// lists policy rules an owner approved for this container.
type CreateContainer struct {
	Spec       ContainerSpec `json:"spec"`
	Exceptions []string      `json:"exceptions,omitempty"`
	Start      bool          `json:"start,omitempty"`
}

// CreateResult reports a created container.
type CreateResult struct {
	ID       string   `json:"id"`
	Warnings []string `json:"warnings"`
}

// RemoveContainer removes a container.
type RemoveContainer struct {
	ID            string `json:"id"`
	Force         bool   `json:"force,omitempty"`
	RemoveVolumes bool   `json:"remove_volumes,omitempty"`
}

// LogsRequest selects container log lines.
type LogsRequest struct {
	ID         string `json:"id"`
	Tail       int    `json:"tail"`            // 1..10000
	Since      int64  `json:"since,omitempty"` // Unix seconds
	Until      int64  `json:"until,omitempty"` // Unix seconds
	Timestamps bool   `json:"timestamps,omitempty"`
}

// LogLine is one demultiplexed log line.
type LogLine struct {
	Stream string `json:"stream"` // stdout | stderr
	Text   string `json:"text"`
}

// Logs is the result of containers.logs.
type Logs struct {
	Lines     []LogLine `json:"lines"`
	Truncated bool      `json:"truncated"`
}

// ImageRef names an image to pull or remove.
type ImageRef struct {
	Reference string `json:"reference"`
	Force     bool   `json:"force,omitempty"`
}

// ImageSummary is one entry of images.list.
type ImageSummary struct {
	ID          string   `json:"id"`
	RepoTags    []string `json:"repo_tags"`
	RepoDigests []string `json:"repo_digests"`
	Size        int64    `json:"size"`
	Created     int64    `json:"created"`
	Containers  int      `json:"containers"`
}

// PullResult reports a pulled image.
type PullResult struct {
	Reference string `json:"reference"`
	ID        string `json:"id"`
	Digest    string `json:"digest"` // repo digest, e.g. alpine@sha256:...
}

// PruneResult reports reclaimed space.
type PruneResult struct {
	Deleted        int   `json:"deleted"`
	SpaceReclaimed int64 `json:"space_reclaimed"`
}

// NamedObject names a volume or network.
type NamedObject struct {
	Name string `json:"name"`
}

// VolumeCreate creates a named volume.
type VolumeCreate struct {
	Name   string            `json:"name"`
	Labels map[string]string `json:"labels,omitempty"`
}

// VolumeSummary is one entry of volumes.list.
type VolumeSummary struct {
	Name       string            `json:"name"`
	Driver     string            `json:"driver"`
	Mountpoint string            `json:"mountpoint"`
	CreatedAt  string            `json:"created_at"`
	Labels     map[string]string `json:"labels"`
}

// NetworkCreate creates a bridge network.
type NetworkCreate struct {
	Name     string            `json:"name"`
	Internal bool              `json:"internal,omitempty"`
	Labels   map[string]string `json:"labels,omitempty"`
}

// NetworkSummary is one entry of networks.list.
type NetworkSummary struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Driver     string            `json:"driver"`
	Scope      string            `json:"scope"`
	Internal   bool              `json:"internal"`
	Containers int               `json:"containers"`
	Labels     map[string]string `json:"labels"`
	BuiltIn    bool              `json:"built_in"`
}
