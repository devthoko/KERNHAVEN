package app

import (
	"context"
	"encoding/json"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/core/jobs"
)

// Maintenance job kinds (M3).
const (
	KindPurgeSessions = "maintenance.purge_sessions"
	KindPurgeJobs     = "maintenance.purge_jobs"

	jobRetention = 30 * 24 * time.Hour
)

func (a *App) registerMaintenance() {
	a.Jobs.Register(jobs.Kind{
		Name: KindPurgeSessions,
		Plan: func(json.RawMessage) ([]jobs.Step, error) {
			return []jobs.Step{{Name: "delete expired sessions", Run: func(ctx context.Context, sc *jobs.StepContext) error {
				n, err := a.Identity.PurgeExpiredSessions(ctx)
				if err == nil {
					sc.Logf("deleted %d expired sessions", n)
				}
				return err
			}}}, nil
		},
	})
	a.Jobs.Register(jobs.Kind{
		Name: KindPurgeJobs,
		Plan: func(json.RawMessage) ([]jobs.Step, error) {
			return []jobs.Step{{Name: "delete finished jobs older than 30 days", Run: func(ctx context.Context, sc *jobs.StepContext) error {
				n, err := a.Jobs.PurgeFinished(ctx, a.now().Add(-jobRetention))
				if err == nil {
					sc.Logf("deleted %d finished jobs", n)
				}
				return err
			}}}, nil
		},
	})
}

// EnqueueMaintenance queues the periodic maintenance jobs; duplicates of a
// job that is still pending are skipped.
func (a *App) EnqueueMaintenance(ctx context.Context) error {
	for _, kind := range []string{KindPurgeSessions, KindPurgeJobs} {
		_, err := a.Jobs.Enqueue(ctx, jobs.Request{Kind: kind, Payload: struct{}{}, DedupeKey: kind})
		if err != nil && err != jobs.ErrDuplicate {
			return err
		}
	}
	return nil
}
