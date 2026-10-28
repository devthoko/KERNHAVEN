package agentproto

import "time"

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
	Healthcheck    *Healthcheck      `json:"healthcheck,omitempty"`
}

// Healthcheck configures a container health check (M7).
type Healthcheck struct {
	Test          []string `json:"test"` // ["CMD", ...], ["CMD-SHELL", "..."] or ["NONE"]
	IntervalMS    int64    `json:"interval_ms,omitempty"`
	TimeoutMS     int64    `json:"timeout_ms,omitempty"`
	StartPeriodMS int64    `json:"start_period_ms,omitempty"`
	Retries       int      `json:"retries,omitempty"`
}

// StackRef marks an object as part of a stack; the agent turns it into
// reserved labels.
type StackRef struct {
	Name     string `json:"name"`
	Service  string `json:"service,omitempty"`
	Revision int    `json:"revision,omitempty"`
}

// CreateContainer creates (and optionally starts) a container. Exceptions
// lists policy rules an owner approved for this container.
type CreateContainer struct {
	Spec       ContainerSpec `json:"spec"`
	Exceptions []string      `json:"exceptions,omitempty"`
	Start      bool          `json:"start,omitempty"`
	Stack      *StackRef     `json:"stack,omitempty"`
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
	Stack  *StackRef         `json:"stack,omitempty"`
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
	Stack    *StackRef         `json:"stack,omitempty"`
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

// VolumeCopy replaces the content of Target with a copy of Source (M8). Both
// volumes must belong to Stack; Target is created if it does not exist.
type VolumeCopy struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Stack  string `json:"stack"`
}

// VolumeCopyResult names the helper container doing the copy. The caller
// waits until it has exited and removes it.
type VolumeCopyResult struct {
	Helper string `json:"helper"`
}

// ---- M9: storage ----

// SMART is the health summary of a disk.
type SMART struct {
	Available    bool   `json:"available"`
	Passed       *bool  `json:"passed,omitempty"`
	TemperatureC int    `json:"temperature_c,omitempty"`
	PowerOnHours int    `json:"power_on_hours,omitempty"`
	Message      string `json:"message,omitempty"`
}

// FileSystem is a partition, logical volume or file system on a disk.
type FileSystem struct {
	Path        string   `json:"path"`
	Name        string   `json:"name"`
	Type        string   `json:"type"` // lsblk type: part, disk, lvm, crypt, raid1, …
	FSType      string   `json:"fstype"`
	Label       string   `json:"label"`
	UUID        string   `json:"uuid"`
	SizeBytes   int64    `json:"size_bytes"`
	FSSizeBytes int64    `json:"fs_size_bytes"`
	FSUsedBytes int64    `json:"fs_used_bytes"`
	FSAvailable int64    `json:"fs_available_bytes"`
	Mountpoints []string `json:"mountpoints"`
	MountName   string   `json:"mount_name,omitempty"` // set when mounted by Kernhaven
	Mountable   bool     `json:"mountable"`
}

// Disk classes (M9 classification).
const (
	DiskSystem  = "system"
	DiskInUse   = "in_use"
	DiskManaged = "managed"
	DiskFree    = "free"
)

// Disk is a physical or virtual disk with its classification.
type Disk struct {
	Path        string       `json:"path"`
	Name        string       `json:"name"`
	Model       string       `json:"model"`
	Serial      string       `json:"serial"`
	WWN         string       `json:"wwn"`
	Transport   string       `json:"transport"`
	SizeBytes   int64        `json:"size_bytes"`
	Rotational  bool         `json:"rotational"`
	Removable   bool         `json:"removable"`
	ReadOnly    bool         `json:"read_only"`
	Class       string       `json:"class"`
	Reason      string       `json:"reason,omitempty"`
	Formattable bool         `json:"formattable"`
	FileSystems []FileSystem `json:"file_systems"`
	SMART       SMART        `json:"smart"`
}

// ManagedMount is a mount unit written by Kernhaven.
type ManagedMount struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	Unit   string `json:"unit"`
	What   string `json:"what"`
	FSType string `json:"fstype"`
	Active bool   `json:"active"`
}

// StorageInventory is the result of storage.inventory.
type StorageInventory struct {
	Disks       []Disk         `json:"disks"`
	Mounts      []ManagedMount `json:"mounts"`
	MountRoot   string         `json:"mount_root"`
	FileSystems []string       `json:"formattable_fstypes"` // mkfs tools installed
	SMART       bool           `json:"smart_tool"`
	Privileged  bool           `json:"privileged"`
}

// StorageFormat formats a free disk with one GPT partition. Serial, WWN and
// SizeBytes are the identity the user confirmed; the agent refuses if the
// device at Path no longer matches.
type StorageFormat struct {
	Path      string `json:"path"`
	Serial    string `json:"serial"`
	WWN       string `json:"wwn"`
	SizeBytes int64  `json:"size_bytes"`
	FSType    string `json:"fstype"`
	Label     string `json:"label"`
}

// StorageFormatResult names the new file system.
type StorageFormatResult struct {
	Partition string `json:"partition"`
	UUID      string `json:"uuid"`
	FSType    string `json:"fstype"`
}

// StorageMount mounts the file system Path (identified by UUID) at
// <mount root>/<Name> through a systemd mount unit.
type StorageMount struct {
	Path string `json:"path"`
	UUID string `json:"uuid"`
	Name string `json:"name"`
}

// StorageUnmount removes the mount unit of Name.
type StorageUnmount struct {
	Name string `json:"name"`
}

// ---- M10: files ----

// FileRoot is a configured file root of the storage service.
type FileRoot struct {
	Name       string `json:"name"`
	Path       string `json:"path"`
	Available  bool   `json:"available"`
	FreeBytes  int64  `json:"free_bytes"`
	TotalBytes int64  `json:"total_bytes"`
}

// FileEntry is one directory entry.
type FileEntry struct {
	Name    string    `json:"name"`
	Type    string    `json:"type"` // file, dir, symlink, other
	Size    int64     `json:"size"`
	ModTime time.Time `json:"mod_time"`
	Mode    string    `json:"mode"`
	UID     uint32    `json:"uid"`
	GID     uint32    `json:"gid"`
}

// FilesPath names a path relative to a root ("" is the root itself).
type FilesPath struct {
	Root string `json:"root"`
	Path string `json:"path"`
}

// FilesListing is the result of files.list.
type FilesListing struct {
	Path      string      `json:"path"`
	Entries   []FileEntry `json:"entries"`
	Truncated bool        `json:"truncated"`
}

// FilesRename moves From to To within one root; it never overwrites.
type FilesRename struct {
	Root string `json:"root"`
	From string `json:"from"`
	To   string `json:"to"`
}

// FilesCopy copies From (file or folder) to ToRoot/To; it never overwrites.
type FilesCopy struct {
	Root   string `json:"root"`
	From   string `json:"from"`
	ToRoot string `json:"to_root"`
	To     string `json:"to"`
}

// FilesCopyResult summarises a copy.
type FilesCopyResult struct {
	Files           int   `json:"files"`
	Bytes           int64 `json:"bytes"`
	SkippedSymlinks int   `json:"skipped_symlinks"`
}

// TrashItem is something deleted to the trash of a root.
type TrashItem struct {
	ID        string    `json:"id"`
	Path      string    `json:"path"`
	IsDir     bool      `json:"is_dir"`
	Size      int64     `json:"size"`
	DeletedAt time.Time `json:"deleted_at"`
	DeletedBy string    `json:"deleted_by"`
}

// FilesTrashID addresses one trash item; an empty ID in files.trash.purge
// empties the whole trash of the root.
type FilesTrashID struct {
	Root string `json:"root"`
	ID   string `json:"id"`
}

// FilesRead streams a regular file, optionally a byte range (Limit 0 = all).
type FilesRead struct {
	Root   string `json:"root"`
	Path   string `json:"path"`
	Offset int64  `json:"offset"`
	Limit  int64  `json:"limit"`
}

// FileMeta describes a streamed file (header X-Kernhaven-Meta).
type FileMeta struct {
	Name    string    `json:"name"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"mod_time"`
}

// UploadAppend appends the request body to the staged upload ID at Offset,
// which must equal the bytes staged so far.
type UploadAppend struct {
	Root   string `json:"root"`
	ID     string `json:"id"`
	Path   string `json:"path"`   // target; the staging area is on its file system
	Offset int64  `json:"offset"` // -1 reports the staged size
}

// UploadState is the staged size of an upload.
type UploadState struct {
	Size int64 `json:"size"`
}

// UploadFinish moves a complete staged upload to Path (never overwriting).
type UploadFinish struct {
	Root string `json:"root"`
	ID   string `json:"id"`
	Path string `json:"path"`
	Size int64  `json:"size"`
}

// ---- M12: reverse proxy and network ----

// ProxyRoute is one published route. The upstream is always 127.0.0.1.
type ProxyRoute struct {
	ID           int64    `json:"id"`
	Host         string   `json:"host"`
	PathPrefix   string   `json:"path_prefix,omitempty"`
	StripPrefix  bool     `json:"strip_prefix,omitempty"`
	UpstreamPort int      `json:"upstream_port"`
	SSO          bool     `json:"sso,omitempty"`
	LANOnly      bool     `json:"lan_only,omitempty"`
	AllowCIDRs   []string `json:"allow_cidrs,omitempty"`
}

// ProxyApply replaces the complete set of routes and their TLS settings.
// KernhavenHost is the host of the Core's public origin; it is always
// proxied to the Core. Hosts without a TLSHost entry use the internal CA.
type ProxyApply struct {
	KernhavenHost string           `json:"kernhaven_host"`
	Routes        []ProxyRoute     `json:"routes"`
	TLSHosts      []TLSHost        `json:"tls_hosts,omitempty"`
	Certificates  []TLSCertificate `json:"certificates,omitempty"`
	ACME          *ACMESettings    `json:"acme,omitempty"`
}

// TLS modes of a host in the proxy configuration (M13).
const (
	TLSInternal = "internal"    // Caddy's local CA
	TLSACME     = "acme"        // Caddy's ACME issuer (HTTP-01, TLS-ALPN-01)
	TLSLoaded   = "certificate" // a certificate from Certificates (uploaded or DNS-01)
)

// TLSHost selects how a host gets its certificate.
type TLSHost struct {
	Host          string `json:"host"`
	Mode          string `json:"mode"`
	CertificateID int64  `json:"certificate_id,omitempty"`
}

// TLSCertificate is a certificate chain with its unencrypted key (PEM).
type TLSCertificate struct {
	ID             int64  `json:"id"`
	CertificatePEM string `json:"certificate_pem"`
	KeyPEM         string `json:"key_pem"`
}

// ACME CAs the Core may choose; the proxy service maps them to directories.
const (
	ACMEProduction = "production"
	ACMEStaging    = "staging"
)

// ACMESettings configure Caddy's ACME issuer.
type ACMESettings struct {
	Email string `json:"email"`
	CA    string `json:"ca"`
}

// ProxyCA is the root certificate of Caddy's local CA.
type ProxyCA struct {
	RootPEM string `json:"root_pem"`
	SHA256  string `json:"sha256"`
}

// ProxyApplied reports a successful load.
type ProxyApplied struct {
	Hash      string `json:"hash"`
	Routes    int    `json:"routes"`
	HTTPSPort int    `json:"https_port"`
}

// ProxyStatus describes the running Caddy configuration. Hash is empty when
// Caddy runs without a configuration from Kernhaven.
type ProxyStatus struct {
	Reachable bool   `json:"reachable"`
	Hash      string `json:"hash"`
	HTTPSPort int    `json:"https_port"`
}

// NetworkInterface is a host network interface.
type NetworkInterface struct {
	Name      string   `json:"name"`
	MTU       int      `json:"mtu"`
	MAC       string   `json:"mac,omitempty"`
	Up        bool     `json:"up"`
	Loopback  bool     `json:"loopback"`
	Addresses []string `json:"addresses"`
}

// ListeningSocket is a listening TCP or bound UDP socket.
type ListeningSocket struct {
	Protocol string `json:"protocol"` // tcp, tcp6, udp, udp6
	Address  string `json:"address"`
	Port     int    `json:"port"`
}

// NetworkOverview is the read-only view of the host network (AT-F11-04).
type NetworkOverview struct {
	Interfaces []NetworkInterface `json:"interfaces"`
	Listening  []ListeningSocket  `json:"listening"`
}
