//go:build monitor_service

package monitor

// Talks to the real kernhaven-monitor service started by systemd with
// deploy/systemd/kernhaven-monitor.service on a disposable CI runner.
//
//	KH_MONITOR_KEYDIR  directory with the Core grant key (agent-grant.pub is read by the service)
//	KH_MONITOR_SOCKET  the monitor service's socket

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/agentproto"
	"github.com/devthoko/KERNHAVEN/internal/core/agentclient"
)

func TestM14MonitorService(t *testing.T) {
	dir, sock := os.Getenv("KH_MONITOR_KEYDIR"), os.Getenv("KH_MONITOR_SOCKET")
	if dir == "" || sock == "" {
		t.Skip("KH_MONITOR_KEYDIR and KH_MONITOR_SOCKET not set")
	}
	key, err := agentclient.LoadOrCreateKey(dir)
	if err != nil {
		t.Fatal(err)
	}
	cl := agentclient.New(sock, key)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	var m agentproto.HostMetrics
	if err := cl.Do(ctx, agentclient.Call{Op: agentproto.OpHostMetrics, Actor: "it", RequestID: "it"}, &m); err != nil {
		t.Fatal(err)
	}
	// Inside the unit's sandbox the host's counters are visible.
	if m.CPUTotal == 0 || m.CPUs == 0 || m.Memory.Total == 0 || len(m.Interfaces) == 0 || len(m.Disks) == 0 {
		t.Fatalf("metrics %+v", m)
	}
	for _, src := range []string{"cpu", "memory", "load", "disks", "interfaces"} {
		if m.Errors[src] != "" {
			t.Errorf("%s: %s", src, m.Errors[src])
		}
	}
	t.Logf("cpus %d, %d disks, %d interfaces, %d sensors", m.CPUs, len(m.Disks), len(m.Interfaces), len(m.Temperatures))
	// Nothing else is offered.
	if err := cl.Do(ctx, agentclient.Call{Op: agentproto.OpContainersList, Params: agentproto.ContainersList{}, Actor: "it", RequestID: "it"}, nil); err == nil {
		t.Fatal("containers.list in the monitor role")
	}
}
