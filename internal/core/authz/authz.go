// Package authz defines roles and permissions. Authorization is decided on the
// server only; the UI merely mirrors it (CLAUDE.md).
package authz

// Role is one of the fixed 1.0 roles.
type Role string

const (
	Owner    Role = "owner"
	Admin    Role = "admin"
	Operator Role = "operator"
	Viewer   Role = "viewer"
)

// Permission names a capability required by a route.
type Permission string

const (
	SelfManage     Permission = "self.manage"
	SystemRead     Permission = "system.read"
	UsersRead      Permission = "users.read"
	UsersManage    Permission = "users.manage"
	SessionsManage Permission = "sessions.manage"
	AuditRead      Permission = "audit.read"
	JobsRead       Permission = "jobs.read"
	JobsManage     Permission = "jobs.manage"

	ContainersRead    Permission = "containers.read"
	ContainersOperate Permission = "containers.operate"
	ContainersManage  Permission = "containers.manage"
	StorageRead       Permission = "storage.read"
	StorageManage     Permission = "storage.manage"
	FilesRead         Permission = "files.read"
	FilesWrite        Permission = "files.write"
	SecurityManage    Permission = "security.manage"
	NetworkRead       Permission = "network.read"
	NetworkManage     Permission = "network.manage"
	PolicyExceptions  Permission = "policy.exceptions"

	AppsRead      Permission = "apps.read"
	AppsManage    Permission = "apps.manage"
	CatalogManage Permission = "catalog.manage"
)

var rolePermissions = map[Role][]Permission{
	Owner: {SelfManage, SystemRead, UsersRead, UsersManage, SessionsManage, AuditRead, JobsRead, JobsManage,
		ContainersRead, ContainersOperate, ContainersManage, PolicyExceptions, AppsRead, AppsManage, CatalogManage, StorageRead, StorageManage, FilesRead, FilesWrite, SecurityManage, NetworkRead, NetworkManage},
	Admin: {SelfManage, SystemRead, UsersRead, UsersManage, AuditRead, JobsRead, JobsManage,
		ContainersRead, ContainersOperate, ContainersManage, AppsRead, AppsManage, StorageRead, StorageManage, FilesRead, FilesWrite, NetworkRead, NetworkManage},
	Operator: {SelfManage, SystemRead, JobsRead, JobsManage, ContainersRead, ContainersOperate, AppsRead, StorageRead, FilesRead, NetworkRead},
	Viewer:   {SelfManage, SystemRead, JobsRead, ContainersRead, AppsRead},
}

// Roles lists all roles from most to least privileged.
func Roles() []Role { return []Role{Owner, Admin, Operator, Viewer} }

// AtLeast reports whether r is min or a more privileged role. Unknown roles
// are never at least anything, and nothing is at least an unknown role.
func (r Role) AtLeast(min Role) bool {
	if !r.Valid() || !min.Valid() {
		return false
	}
	for _, x := range Roles() {
		if x == r {
			return true
		}
		if x == min {
			return false
		}
	}
	return false
}

// Valid reports whether r is a known role.
func (r Role) Valid() bool {
	_, ok := rolePermissions[r]
	return ok
}

// Has reports whether r grants p. Unknown roles grant nothing.
func (r Role) Has(p Permission) bool {
	for _, q := range rolePermissions[r] {
		if q == p {
			return true
		}
	}
	return false
}

// Permissions returns the permissions granted by r.
func (r Role) Permissions() []Permission {
	return append([]Permission(nil), rolePermissions[r]...)
}

// Known reports whether p is granted by at least one role.
func Known(p Permission) bool {
	for _, r := range Roles() {
		if r.Has(p) {
			return true
		}
	}
	return false
}

// CanManage reports whether a user with role actor may create, modify, delete
// or reset a user that has (or would get) role target. Owners manage everyone;
// admins manage only operators and viewers.
func CanManage(actor, target Role) bool {
	switch actor {
	case Owner:
		return target.Valid()
	case Admin:
		return target == Operator || target == Viewer
	default:
		return false
	}
}
