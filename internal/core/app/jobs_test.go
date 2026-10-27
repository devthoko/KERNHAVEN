package app

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/devthoko/KERNHAVEN/internal/core/authz"
	"github.com/devthoko/KERNHAVEN/internal/core/jobs"
)

// AT-F18-01: maintenance jobs run through the real runner and are visible
// through the API with their journal.
func TestMaintenanceJobsRunAndAreVisible(t *testing.T) {
	h := newHarness(t)
	owner := h.setupOwner()
	h.createUser(owner, "victor", authz.Viewer)
	if err := h.app.EnqueueMaintenance(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := h.app.EnqueueMaintenance(context.Background()); err != nil { // deduplicated
		t.Fatal(err)
	}
	h.startJobs()

	viewer := h.loginAs("victor")
	var list struct{ Jobs []jobs.Job }
	viewer.do("GET", "/api/v1/jobs", nil).expect(200).json(&list)
	if len(list.Jobs) != 2 {
		t.Fatalf("jobs %+v", list.Jobs)
	}
	for _, j := range list.Jobs {
		done := h.waitJob(j.ID, jobs.Succeeded)
		var detail jobs.Job
		viewer.do("GET", "/api/v1/jobs/"+itoa(j.ID), nil).expect(200).json(&detail)
		if len(detail.Steps) != 1 || detail.Steps[0].State != "done" || len(detail.Logs) == 0 || done.Kind != detail.Kind {
			t.Fatalf("detail %+v", detail)
		}
	}
	viewer.do("GET", "/api/v1/jobs?state=succeeded&limit=10", nil).expect(200)
	if r := viewer.do("GET", "/api/v1/jobs?state=bogus", nil); r.Code != 400 {
		t.Fatalf("bad state filter: %d", r.Code)
	}
	if r := viewer.do("GET", "/api/v1/jobs/abc", nil); r.Code != 404 {
		t.Fatalf("bad id: %d", r.Code)
	}
}

// AT-F18-01: cancel through the API, with authorization and audit.
func TestCancelJobThroughAPI(t *testing.T) {
	h := newHarness(t)
	owner := h.setupOwner()
	h.createUser(owner, "olga", authz.Operator)
	h.createUser(owner, "victor", authz.Viewer)
	started := make(chan struct{}, 1)
	h.app.Jobs.Register(jobs.Kind{Name: "test.block", Plan: func(json.RawMessage) ([]jobs.Step, error) {
		return []jobs.Step{{Name: "wait", Run: func(ctx context.Context, _ *jobs.StepContext) error {
			started <- struct{}{}
			<-ctx.Done()
			return ctx.Err()
		}}}, nil
	}})
	id, err := h.app.Jobs.Enqueue(context.Background(), jobs.Request{Kind: "test.block", Payload: struct{}{}})
	if err != nil {
		t.Fatal(err)
	}
	h.startJobs()
	<-started

	if r := h.loginAs("victor").do("POST", "/api/v1/jobs/"+itoa(id)+"/cancel", nil); r.Code != http.StatusForbidden {
		t.Fatalf("viewer cancel: %d", r.Code)
	}
	operator := h.loginAs("olga")
	operator.do("POST", "/api/v1/jobs/"+itoa(id)+"/cancel", nil).expect(http.StatusAccepted)
	h.waitJob(id, jobs.Cancelled)
	if r := operator.do("POST", "/api/v1/jobs/"+itoa(id)+"/cancel", nil); r.Code != http.StatusConflict {
		t.Fatalf("cancel finished job: %d", r.Code)
	}
	if r := operator.do("POST", "/api/v1/jobs/424242/cancel", nil); r.Code != http.StatusNotFound {
		t.Fatalf("cancel missing job: %d", r.Code)
	}
	var n int
	if err := h.db.QueryRow(`SELECT count(*) FROM audit_events WHERE action = 'job.cancel' AND actor = 'olga' AND result = 'success'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("job.cancel audit records: %d (%v)", n, err)
	}
}
