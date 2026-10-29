package app

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/core/alerts"
	"github.com/devthoko/KERNHAVEN/internal/core/authz"
	"github.com/devthoko/KERNHAVEN/internal/core/jobs"
	"github.com/devthoko/KERNHAVEN/internal/platform/config"
)

// AT-F16-01..03 through the API: channels, rules, a failed job delivered
// to a webhook.
func TestAlertsAPI(t *testing.T) {
	var mu sync.Mutex
	var got []alerts.Message
	rcv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m alerts.Message
		_ = json.Unmarshal(b, &m)
		mu.Lock()
		got = append(got, m)
		mu.Unlock()
	}))
	defer rcv.Close()
	h := newHarnessWith(t, func(c *config.Config) {
		c.Alerts.AllowLoopbackForTests = true
		c.Agent.StorageSocket, c.Agent.FilesSocket = "", "" // not part of this test
	})
	owner := h.setupOwner()
	h.createUser(owner, "operator1", authz.Operator)
	h.createUser(owner, "viewer1", authz.Viewer)
	op, viewer := h.loginAs("operator1"), h.loginAs("viewer1")

	viewer.do("GET", "/api/v1/alerts", nil).expect(403)
	op.do("GET", "/api/v1/alerts/rules", nil).expect(200)
	op.do("POST", "/api/v1/notify/channels", map[string]any{"name": "x", "kind": "webhook", "config": map[string]any{"url": rcv.URL}}).expect(403)

	var ch alerts.Channel
	r := owner.do("POST", "/api/v1/notify/channels", map[string]any{"name": "ops hook", "kind": "webhook", "config": map[string]any{"url": rcv.URL}, "secret": "very-secret"}).expect(201)
	r.json(&ch)
	if !ch.HasSecret || strings.Contains(r.Body.String(), "very-secret") {
		t.Fatalf("channel %s", r.Body)
	}
	var sealed []byte
	if err := h.db.QueryRow(`SELECT secret FROM notify_channels WHERE id = ?`, ch.ID).Scan(&sealed); err != nil || strings.Contains(string(sealed), "very-secret") {
		t.Fatalf("secret stored in clear: %v", err)
	}
	owner.do("POST", "/api/v1/notify/channels", map[string]any{"name": "ops hook", "kind": "webhook", "config": map[string]any{"url": rcv.URL}}).expect(409)
	owner.do("POST", "/api/v1/notify/channels", map[string]any{"name": "bad", "kind": "webhook", "config": map[string]any{"url": "ftp://x"}}).expect(422)
	owner.do("POST", "/api/v1/notify/channels", map[string]any{"name": "gotify", "kind": "gotify", "config": map[string]any{"url": rcv.URL}}).expect(422) // token missing
	owner.do("POST", "/api/v1/notify/channels", map[string]any{"name": "meta", "kind": "webhook", "config": map[string]any{"url": "http://169.254.169.254/latest"}}).expect(422)
	owner.do("POST", "/api/v1/notify/channels", map[string]any{"name": "meta6", "kind": "ntfy", "config": map[string]any{"url": "http://[fe80::1]/", "topic": "x"}}).expect(422)

	var d alerts.Delivery
	owner.do("POST", "/api/v1/notify/channels/"+itoa(ch.ID)+"/test", nil).expect(200).json(&d)
	if d.Status != "sent" || len(got) != 1 || got[0].State != "test" {
		t.Fatalf("test delivery %+v %+v", d, got)
	}
	owner.do("PUT", "/api/v1/alerts/rules/job_failed", map[string]any{"enabled": true, "channels": []int64{ch.ID}}).expect(200)
	owner.do("PUT", "/api/v1/alerts/rules/cpu_high", map[string]any{"enabled": true, "params": map[string]float64{"percent": 500}}).expect(422)
	op.do("PUT", "/api/v1/alerts/rules/job_failed", map[string]any{"enabled": false}).expect(403)

	// A job that fails for real reaches the webhook.
	ctx := context.Background()
	h.app.Alerts.Evaluate(ctx) // starts the cursors
	h.app.Jobs.Register(jobs.Kind{Name: "test.fail", MaxAttempts: 1, Plan: func(json.RawMessage) ([]jobs.Step, error) {
		return []jobs.Step{{Name: "fail", Run: func(context.Context, *jobs.StepContext) error { return errors.New("disk on fire") }}}, nil
	}})
	h.startJobs()
	h.clock.Advance(time.Second)
	id, err := h.app.Jobs.Enqueue(ctx, jobs.Request{Kind: "test.fail", Payload: struct{}{}})
	if err != nil {
		t.Fatal(err)
	}
	h.waitJob(id, jobs.Failed)
	h.app.Alerts.Evaluate(ctx)
	h.app.Alerts.Deliver(ctx)
	mu.Lock()
	if len(got) != 2 || !strings.Contains(got[1].Title, "(test.fail) failed") || !strings.Contains(got[1].Body, "disk on fire") {
		t.Fatalf("webhook got %+v", got)
	}
	mu.Unlock()
	var list struct{ Alerts []alerts.Alert }
	op.do("GET", "/api/v1/alerts", nil).expect(200).json(&list)
	if len(list.Alerts) != 1 || list.Alerts[0].State != "event" {
		t.Fatalf("alerts %+v", list)
	}
	var log struct{ Deliveries []alerts.Delivery }
	op.do("GET", "/api/v1/alerts/deliveries", nil).expect(200).json(&log)
	if len(log.Deliveries) != 2 || log.Deliveries[0].Status != "sent" || log.Deliveries[0].Channel != "ops hook" {
		t.Fatalf("deliveries %+v", log)
	}

	// Changing where the Core sends data needs step-up (AT-F09-04) and is audited.
	h.clock.Advance(11 * time.Minute)
	owner = h.loginAs("owner")
	h.clock.Advance(11 * time.Minute)
	for _, c := range []struct{ method, path string }{{"POST", "/api/v1/notify/channels"}, {"PUT", "/api/v1/notify/channels/" + itoa(ch.ID)}, {"DELETE", "/api/v1/notify/channels/" + itoa(ch.ID)}} {
		if r := owner.do(c.method, c.path, map[string]any{"name": "y", "kind": "webhook", "config": map[string]any{"url": rcv.URL}}); c.method != "DELETE" && r.errorCode() != "step_up_required" || c.method == "DELETE" && r.Code != 403 {
			t.Errorf("%s %s: %d %s", c.method, c.path, r.Code, r.Body)
		}
	}
	if auditCount(t, h, "notify.channel_save", "success") != 1 || auditCount(t, h, "alerts.rule_update", "success") != 1 || auditCount(t, h, "notify.channel_test", "success") != 1 {
		t.Fatal("not audited")
	}
}
