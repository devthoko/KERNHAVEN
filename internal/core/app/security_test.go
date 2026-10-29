package app

import (
	"strings"
	"testing"
	"time"

	"github.com/devthoko/KERNHAVEN/internal/core/audit"
	"github.com/devthoko/KERNHAVEN/internal/core/authz"
	"github.com/devthoko/KERNHAVEN/internal/core/jobs"
	"github.com/devthoko/KERNHAVEN/internal/core/security"
)

func hasFinding(o security.Overview, sev, text string) bool {
	for _, f := range o.Findings {
		if f.Severity == sev && strings.Contains(f.Title, text) {
			return true
		}
	}
	return false
}

// AT-F10-04: the security dashboard shows what needs attention.
func TestSecurityOverview(t *testing.T) {
	h, _ := withAgent(t)
	owner := h.setupOwner()
	h.createUser(owner, "adele", authz.Admin)
	h.createUser(owner, "operator1", authz.Operator)
	admin, op := h.loginAs("adele"), h.loginAs("operator1")
	op.do("GET", "/api/v1/security/overview", nil).expect(403)

	// A stack with an approved exception, deployed.
	priv := "services:\n  vpn:\n    image: wireguard:1\n    cap_add: [NET_ADMIN]\n"
	owner.do("POST", "/api/v1/stacks", map[string]any{"name": "vpn", "compose": priv, "exceptions": []map[string]string{{"service": "vpn", "rule": "capability", "reason": "WireGuard needs NET_ADMIN"}}}).expect(201)
	h.startJobs()
	var job jobRef
	owner.do("POST", "/api/v1/stacks/vpn/deploy", nil).expect(202).json(&job)
	h.waitJob(job.JobID, jobs.Succeeded)
	// Routes as the proxy module stores them: one open, one behind sign-in.
	now := h.clock.Now().UnixMilli()
	for _, r := range []struct {
		host string
		sso  bool
	}{{"open.example.com", false}, {"wiki.example.com", true}} {
		if _, err := h.db.Exec(`INSERT INTO proxy_routes (host, upstream_port, sso, created_by, created_ms, updated_ms) VALUES (?, 8080, ?, 'owner', ?, ?)`, r.host, r.sso, now, now); err != nil {
			t.Fatal(err)
		}
	}
	// A burst of failed sign-ins.
	for range security.FailedLoginWarn {
		h.newClient().login("mallory", "guessing-passwords").expect(401)
	}

	var o security.Overview
	admin.do("GET", "/api/v1/security/overview", nil).expect(200).json(&o)
	if o.MFA.Users != 3 || o.MFA.Covered != 0 || len(o.Routes) != 2 || len(o.Exceptions) != 1 || o.Logins.Failed24h != security.FailedLoginWarn || !o.Audit.OK || !o.ImagesChecked {
		t.Fatalf("overview %+v", o)
	}
	for _, want := range []struct{ sev, text string }{
		{"critical", "owner (owner) signs in with a password only"},
		{"critical", "adele (admin) signs in with a password only"},
		{"warning", "A second factor is not required for the admin role"},
		{"warning", "open.example.com is reachable from anywhere without Kernhaven sign-in"},
		{"info", `vpn/vpn runs with an exception to "capability"`},
		{"warning", "10 failed sign-ins in the last 24 hours"},
		{"warning", "No backup plan is enabled"},
	} {
		if !hasFinding(o, want.sev, want.text) {
			t.Errorf("missing %s finding %q in %+v", want.sev, want.text, o.Findings)
		}
	}
	if hasFinding(o, "warning", "wiki.example.com") || hasFinding(o, "critical", "operator1") {
		t.Error("protected route or operator without required MFA reported")
	}
	if o.Findings[0].Severity != "critical" || o.Logins.BySource["192.0.2.1"] == 0 && len(o.Logins.BySource) == 0 {
		t.Errorf("order or sources: %+v %+v", o.Findings[0], o.Logins.BySource)
	}
	// An expired certificate in use would be critical; the audit chain is checked.
	if _, err := h.db.Exec(`DROP TRIGGER audit_events_no_update`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(`UPDATE audit_events SET actor = 'someone else' WHERE seq = 2`); err != nil {
		t.Fatal(err)
	}
	admin.do("GET", "/api/v1/security/overview", nil).expect(200).json(&o)
	if o.Audit.OK || !hasFinding(o, "critical", "audit log fails verification at record 2") {
		t.Fatalf("tampering not shown: %+v", o.Audit)
	}
}

// AT-F10-03 through the API: search, result filter, time range, export.
func TestAuditSearchAndExport(t *testing.T) {
	h := newHarness(t)
	owner := h.setupOwner()
	for range 3 {
		h.newClient().login("mallory", "guessing-passwords").expect(401)
	}
	var list struct{ Events []audit.Record }
	owner.do("GET", "/api/v1/audit?q=mallory&result=failure", nil).expect(200).json(&list)
	if len(list.Events) != 3 {
		t.Fatalf("search: %d events", len(list.Events))
	}
	since := h.clock.Now().Add(time.Hour).Format(time.RFC3339)
	owner.do("GET", "/api/v1/audit?since="+since, nil).expect(200).json(&list)
	if len(list.Events) != 0 {
		t.Fatalf("since: %d", len(list.Events))
	}
	owner.do("GET", "/api/v1/audit?result=maybe", nil).expect(400)
	owner.do("GET", "/api/v1/audit?since=yesterday", nil).expect(400)
	owner.do("GET", "/api/v1/audit/export?q="+strings.Repeat("x", 201), nil).expect(400)

	r := owner.do("GET", "/api/v1/audit/export", nil).expect(200)
	if r.Header().Get("Content-Type") != "application/x-ndjson" || !strings.Contains(r.Header().Get("Content-Disposition"), ".jsonl") {
		t.Fatalf("headers %v", r.Header())
	}
	s, err := audit.CheckExport(strings.NewReader(r.Body.String()))
	if err != nil || !s.Linked || !s.Genesis {
		t.Fatalf("export check %+v %v", s, err)
	}
	// The export is itself recorded (after the records it contains).
	owner.do("GET", "/api/v1/audit?action=audit.export", nil).expect(200).json(&list)
	if len(list.Events) != 1 || list.Events[0].Actor != "owner" {
		t.Fatalf("export not audited: %+v", list.Events)
	}
	viewer := h.newClient()
	viewer.do("GET", "/api/v1/audit/export", nil).expect(401)
}
