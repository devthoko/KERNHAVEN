package agent

import (
	"context"

	"github.com/devthoko/KERNHAVEN/internal/agent/storage"
	"github.com/devthoko/KERNHAVEN/internal/agentproto"
)

// errNoStorage is returned when the agent was built without storage support.
var errNoStorage = &errInvalidParams{"storage management is not configured on this agent"}

// storageOperations are the M9 operations. All classification and safety
// checks happen in package storage, on every request.
func storageOperations(h *storage.Host) map[string]handler {
	return map[string]handler{
		agentproto.OpStorageInventory: typed(func(ctx context.Context, _ agentproto.Empty) (any, error) {
			if h == nil {
				return nil, errNoStorage
			}
			return h.Inventory(ctx)
		}),
		agentproto.OpStorageFormat: typed(func(ctx context.Context, p agentproto.StorageFormat) (any, error) {
			if h == nil {
				return nil, errNoStorage
			}
			return h.Format(ctx, p)
		}),
		agentproto.OpStorageMount: typed(func(ctx context.Context, p agentproto.StorageMount) (any, error) {
			if h == nil {
				return nil, errNoStorage
			}
			return h.Mount(ctx, p)
		}),
		agentproto.OpStorageUnmount: typed(func(ctx context.Context, p agentproto.StorageUnmount) (any, error) {
			if h == nil {
				return nil, errNoStorage
			}
			return agentproto.ActionResult{ID: p.Name, Changed: true}, h.Unmount(ctx, p)
		}),
	}
}
