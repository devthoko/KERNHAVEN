package essentials

import (
	"strings"
	"testing"
	"testing/fstest"

	"github.com/devthoko/KERNHAVEN/internal/catalog"
	"github.com/devthoko/KERNHAVEN/internal/compose"
	"github.com/devthoko/KERNHAVEN/internal/policy"
)

// The shipped catalog passes every check a signed catalog must pass, and
// holds itself to stricter rules: pinned images, no policy exceptions, memory
// limits, and default ports that do not collide.
func TestShippedCatalog(t *testing.T) {
	payload, err := Payload()
	if err != nil {
		t.Fatal(err)
	}
	v, err := catalog.OpenBuiltin(payload)
	if err != nil {
		t.Fatal(err)
	}
	if v.Catalog.Name != Name || len(v.Catalog.Apps) < 10 {
		t.Fatalf("catalog %q with %d apps", v.Catalog.Name, len(v.Catalog.Apps))
	}
	again, _ := Payload()
	if string(again) != string(payload) {
		t.Fatal("payload is not deterministic")
	}
	ports := map[string]string{}
	for _, app := range v.Catalog.Apps {
		if len(app.Exceptions) > 0 {
			t.Errorf("%s: essentials must not need policy exceptions", app.ID)
		}
		if app.Web == nil || app.Homepage == "" || app.Description == "" || len(app.Categories) == 0 {
			t.Errorf("%s: web UI, homepage, description and a category are required", app.ID)
		}
		values := map[string]string{}
		for _, f := range app.Fields {
			values[f.Name] = f.Default
			if f.Type == catalog.TypeNumber && strings.HasSuffix(f.Name, "PORT") {
				if f.Min == nil || *f.Min < 1024 {
					t.Errorf("%s: %s must stay above the privileged ports", app.ID, f.Name)
				}
				if other, dup := ports[f.Default]; dup {
					t.Errorf("%s: default port %s is also used by %s", app.ID, f.Default, other)
				}
				ports[f.Default] = app.ID + "/" + f.Name
			}
		}
		proj, errs := compose.Parse([]byte(app.Compose), app.ID, values)
		if errs != nil {
			t.Fatalf("%s: %v", app.ID, errs)
		}
		for _, svc := range proj.Services {
			if !strings.Contains(svc.Spec.Image, "@sha256:") {
				t.Errorf("%s/%s: image %s is not pinned by digest", app.ID, svc.Name, svc.Spec.Image)
			}
			if svc.Spec.MemoryBytes == 0 {
				t.Errorf("%s/%s: no memory limit", app.ID, svc.Name)
			}
			if err := policy.Validate(svc.Spec); err != nil {
				t.Errorf("%s/%s: %v", app.ID, svc.Name, err)
			}
		}
	}
}

func TestPayloadRejectsBadLayout(t *testing.T) {
	for name, fsys := range map[string]fstest.MapFS{
		"id differs from directory": {"apps/x/app.json": {Data: []byte(`{"id":"y"}`)}, "apps/x/compose.yaml": {Data: []byte("services: {}")}},
		"compose inline":            {"apps/x/app.json": {Data: []byte(`{"id":"x","compose":"services: {}"}`)}, "apps/x/compose.yaml": {Data: []byte("")}},
		"unknown field":             {"apps/x/app.json": {Data: []byte(`{"id":"x","icon":"x.png"}`)}, "apps/x/compose.yaml": {Data: []byte("")}},
		"missing compose":           {"apps/x/app.json": {Data: []byte(`{"id":"x"}`)}},
	} {
		if _, err := payload(fsys); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
