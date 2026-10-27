// Package storage implements the agent's disk operations (M9): inventory
// from lsblk and smartctl, classification of disks, formatting, and systemd
// mount units. It runs a fixed set of host tools (ADR-0022).
package storage

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/devthoko/KERNHAVEN/internal/agentproto"
)

// Errors. Messages are shown to users.
var (
	ErrNotFound = errors.New("device not found")
	ErrBusy     = errors.New("the file system is busy")
)

// InvalidError is a request the agent refuses.
type InvalidError struct{ Msg string }

func (e *InvalidError) Error() string { return e.Msg }

func invalid(format string, a ...any) error { return &InvalidError{fmt.Sprintf(format, a...)} }

// lsblkColumns are requested explicitly so the output does not depend on
// lsblk's defaults.
const lsblkColumns = "NAME,PATH,TYPE,SIZE,RO,RM,ROTA,MODEL,SERIAL,WWN,TRAN,FSTYPE,LABEL,UUID,FSSIZE,FSUSED,FSAVAIL,MOUNTPOINTS"

// flexInt accepts JSON numbers, numeric strings and null (util-linux
// versions differ).
type flexInt int64

func (f *flexInt) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(bytes.TrimSpace(b)), `"`)
	if s == "" || s == "null" {
		*f = 0
		return nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return fmt.Errorf("lsblk number %q: %w", s, err)
	}
	*f = flexInt(n)
	return nil
}

// flexBool accepts true/false, "1"/"0" and null.
type flexBool bool

func (f *flexBool) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(bytes.TrimSpace(b)), `"`)
	*f = flexBool(s == "true" || s == "1")
	return nil
}

type blockDevice struct {
	Name        string        `json:"name"`
	Path        string        `json:"path"`
	Type        string        `json:"type"`
	Size        flexInt       `json:"size"`
	RO          flexBool      `json:"ro"`
	RM          flexBool      `json:"rm"`
	Rota        flexBool      `json:"rota"`
	Model       *string       `json:"model"`
	Serial      *string       `json:"serial"`
	WWN         *string       `json:"wwn"`
	Tran        *string       `json:"tran"`
	FSType      *string       `json:"fstype"`
	Label       *string       `json:"label"`
	UUID        *string       `json:"uuid"`
	FSSize      flexInt       `json:"fssize"`
	FSUsed      flexInt       `json:"fsused"`
	FSAvail     flexInt       `json:"fsavail"`
	Mountpoints []*string     `json:"mountpoints"`
	Mountpoint  *string       `json:"mountpoint"` // util-linux < 2.37
	Children    []blockDevice `json:"children"`
}

func str(p *string) string {
	if p == nil {
		return ""
	}
	return strings.TrimSpace(*p)
}

func (d blockDevice) mounts() []string {
	out := []string{}
	for _, m := range d.Mountpoints {
		if m != nil && *m != "" {
			out = append(out, *m)
		}
	}
	if len(out) == 0 && d.Mountpoint != nil && *d.Mountpoint != "" {
		out = append(out, *d.Mountpoint)
	}
	return out
}

func parseLsblk(out []byte) ([]blockDevice, error) {
	var doc struct {
		BlockDevices []blockDevice `json:"blockdevices"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		return nil, fmt.Errorf("parse lsblk output: %w", err)
	}
	return doc.BlockDevices, nil
}

// systemMounts make a disk the system disk.
var systemMounts = map[string]bool{"/": true, "/boot": true, "/boot/efi": true, "/usr": true, "/var": true, "/home": true,
	"/opt": true, "/srv": true, "/etc": true, "/root": true, "/tmp": true, "[SWAP]": true}

// holderTypes and holderFS mark members of LVM, RAID, encryption and pools.
var holderFS = map[string]bool{"LVM2_member": true, "linux_raid_member": true, "crypto_LUKS": true, "zfs_member": true, "bcache": true, "ddf_raid_member": true, "isw_raid_member": true}

func holderType(t string) bool {
	return t == "lvm" || t == "crypt" || t == "mpath" || t == "dm" || strings.HasPrefix(t, "raid") || t == "md"
}

// Mountable file systems.
var mountableFS = map[string]bool{"ext4": true, "xfs": true, "btrfs": true, "vfat": true, "exfat": true}

// classify turns lsblk output into disks. managed maps mount paths of
// Kernhaven mount units to their names.
func classify(devs []blockDevice, managed map[string]string, includeLoop bool, mkfs []string) []agentproto.Disk {
	disks := []agentproto.Disk{}
	for _, d := range devs {
		switch {
		case d.Type == "disk" && strings.HasPrefix(d.Name, "zram"):
			continue
		case d.Type == "disk":
		case d.Type == "loop" && includeLoop:
		default:
			continue // rom, loop, ram, …
		}
		disk := agentproto.Disk{Path: d.Path, Name: d.Name, Model: str(d.Model), Serial: str(d.Serial), WWN: str(d.WWN), Transport: str(d.Tran),
			SizeBytes: int64(d.Size), Rotational: bool(d.Rota), Removable: bool(d.RM), ReadOnly: bool(d.RO), FileSystems: []agentproto.FileSystem{}}
		var system, inUse, hasManaged bool
		var reasons []string
		var walk func(b blockDevice, depth int)
		walk = func(b blockDevice, depth int) {
			mps := b.mounts()
			fs := agentproto.FileSystem{Path: b.Path, Name: b.Name, Type: b.Type, FSType: str(b.FSType), Label: str(b.Label), UUID: str(b.UUID),
				SizeBytes: int64(b.Size), FSSizeBytes: int64(b.FSSize), FSUsedBytes: int64(b.FSUsed), FSAvailable: int64(b.FSAvail), Mountpoints: mps}
			for _, mp := range mps {
				switch {
				case systemMounts[mp] || strings.HasPrefix(mp, "/boot/"):
					system = true
				case managed[mp] != "":
					hasManaged = true
					fs.MountName = managed[mp]
				default:
					inUse = true
					reasons = append(reasons, fmt.Sprintf("%s is mounted at %s", b.Name, mp))
				}
			}
			if holderFS[fs.FSType] || (depth > 0 && holderType(b.Type)) {
				inUse = true
				reasons = append(reasons, fmt.Sprintf("%s is part of %s", b.Name, holderName(fs.FSType, b.Type)))
			}
			if depth > 0 || fs.FSType != "" {
				disk.FileSystems = append(disk.FileSystems, fs)
			}
			for _, c := range b.Children {
				walk(c, depth+1)
			}
		}
		walk(d, 0)
		switch {
		case system:
			disk.Class, disk.Reason = agentproto.DiskSystem, "holds the operating system"
		case inUse:
			disk.Class, disk.Reason = agentproto.DiskInUse, strings.Join(dedupe(reasons), "; ")
		case disk.ReadOnly:
			disk.Class, disk.Reason = agentproto.DiskInUse, "the disk is read-only"
		case hasManaged:
			disk.Class = agentproto.DiskManaged
		default:
			disk.Class = agentproto.DiskFree
		}
		disk.Formattable = disk.Class == agentproto.DiskFree && len(mkfs) > 0
		for i := range disk.FileSystems {
			fs := &disk.FileSystems[i]
			fs.Mountable = (disk.Class == agentproto.DiskFree || disk.Class == agentproto.DiskManaged) &&
				mountableFS[fs.FSType] && fs.UUID != "" && len(fs.Mountpoints) == 0
		}
		disks = append(disks, disk)
	}
	sort.Slice(disks, func(i, j int) bool { return disks[i].Name < disks[j].Name })
	return disks
}

func holderName(fstype, typ string) string {
	switch {
	case fstype == "LVM2_member" || typ == "lvm":
		return "an LVM volume group"
	case fstype == "crypto_LUKS" || typ == "crypt":
		return "an encrypted volume"
	case fstype == "zfs_member":
		return "a ZFS pool"
	default:
		return "a RAID or multipath device"
	}
}

func dedupe(s []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, x := range s {
		if !seen[x] {
			seen[x] = true
			out = append(out, x)
		}
	}
	return out
}

// underRoot reports whether p is a direct child of root.
func underRoot(root, p string) bool {
	return path.Dir(path.Clean(p)) == path.Clean(root)
}
