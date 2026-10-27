package app

import (
	"bufio"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/devthoko/KERNHAVEN/internal/core/authz"
)

// publicRoutes is the reviewed allow-list of unauthenticated routes. Adding a
// public route requires changing this list in review.
var publicRoutes = map[string]bool{
	"GET /api/v1/health/live":  true,
	"GET /api/v1/health/ready": true,
	"GET /api/v1/setup":        true,
	"POST /api/v1/setup":       true,
	"POST /api/v1/auth/login":  true,
}

// AT-F09-01: every route declares known access; public routes are reviewed.
func TestRouteAccessContract(t *testing.T) {
	h := newHarness(t)
	routes := h.app.Router.Routes()
	if len(routes) == 0 {
		t.Fatal("no routes")
	}
	for _, r := range routes {
		if r.Access.IsPublic() {
			if !publicRoutes[r.Pattern] {
				t.Errorf("%s is public but not on the reviewed allow-list", r.Pattern)
			}
			continue
		}
		if !authz.Known(authz.Permission(r.Access.Permission())) {
			t.Errorf("%s requires unknown permission %q", r.Pattern, r.Access.Permission())
		}
	}
	for p := range publicRoutes {
		found := false
		for _, r := range routes {
			found = found || (r.Pattern == p && r.Access.IsPublic())
		}
		if !found {
			t.Errorf("allow-listed public route %s is not registered as public", p)
		}
	}
}

var (
	specPath   = regexp.MustCompile(`^  (/[^:]*):\s*$`)
	specMethod = regexp.MustCompile(`^    (get|post|put|patch|delete):\s*$`)
)

// specOperations returns "METHOD /api/v1/path" for every operation in the
// OpenAPI document (paths are relative to the /api/v1 server URL).
func specOperations(t *testing.T) []string {
	t.Helper()
	f, err := os.Open("../../../api/openapi/v1.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var ops []string
	var current string
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if m := specPath.FindStringSubmatch(line); m != nil {
			current = m[1]
			continue
		}
		if strings.HasPrefix(line, "components:") {
			current = ""
		}
		if m := specMethod.FindStringSubmatch(line); m != nil && current != "" {
			ops = append(ops, strings.ToUpper(m[1])+" /api/v1"+current)
		}
	}
	sort.Strings(ops)
	return ops
}

// ADR-0012: routes and the OpenAPI contract stay synchronized.
func TestRoutesMatchOpenAPISpec(t *testing.T) {
	h := newHarness(t)
	spec := map[string]bool{}
	for _, op := range specOperations(t) {
		spec[op] = true
	}
	registered := map[string]bool{}
	for _, r := range h.app.Router.Routes() {
		registered[r.Pattern] = true
		if !spec[r.Pattern] {
			t.Errorf("route %s missing from api/openapi/v1.yaml", r.Pattern)
		}
	}
	for op := range spec {
		if !registered[op] {
			t.Errorf("spec operation %s has no route", op)
		}
	}
}

// AT-F09-01: call every route as every role and check the authorization
// outcome against the role's permissions.
func TestRBACMatrix(t *testing.T) {
	h := newHarness(t)
	owner := h.setupOwner()
	h.createUser(owner, "admin1", authz.Admin)
	h.createUser(owner, "operator1", authz.Operator)
	h.createUser(owner, "viewer1", authz.Viewer)
	users := map[authz.Role]string{authz.Owner: "owner", authz.Admin: "admin1", authz.Operator: "operator1", authz.Viewer: "viewer1"}

	authzCodes := map[string]bool{"unauthenticated": true, "forbidden": true, "csrf_failed": true, "origin_rejected": true}
	for _, route := range h.app.Router.Routes() {
		method, path, _ := strings.Cut(route.Pattern, " ")
		path = strings.ReplaceAll(path, "{id}", "999999")
		var body any
		if method != http.MethodGet {
			body = map[string]any{}
		}

		// Anonymous.
		r := h.newClient().do(method, path, body)
		if route.Access.IsPublic() {
			if authzCodes[r.errorCode()] {
				t.Errorf("anonymous %s: public route answered %d %s", route.Pattern, r.Code, r.errorCode())
			}
		} else if r.Code != http.StatusUnauthorized || r.errorCode() != "unauthenticated" {
			t.Errorf("anonymous %s: got %d %s, want 401", route.Pattern, r.Code, r.errorCode())
		}

		for _, role := range authz.Roles() {
			c := h.loginAs(users[role])
			r := c.do(method, path, body)
			allowed := route.Access.IsPublic() || role.Has(authz.Permission(route.Access.Permission()))
			if allowed && authzCodes[r.errorCode()] {
				t.Errorf("%s %s: allowed role was refused: %d %s", role, route.Pattern, r.Code, r.errorCode())
			}
			if !allowed && (r.Code != http.StatusForbidden || r.errorCode() != "forbidden") {
				t.Errorf("%s %s: got %d %s, want 403 forbidden", role, route.Pattern, r.Code, r.errorCode())
			}
		}
	}
}
