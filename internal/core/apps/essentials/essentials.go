// Package essentials holds the app catalog that ships with Kernhaven
// (ADR-0034): one directory per app with its catalog entry (app.json) and
// Compose file (compose.yaml). Images are pinned by digest.
package essentials

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"path"
	"sort"

	"github.com/devthoko/KERNHAVEN/internal/catalog"
)

// Name is the name of the built-in source and catalog.
const Name = "Kernhaven Essentials"

// Serial counts releases of the catalog; raise it with every change.
const Serial = 1

//go:embed apps
var files embed.FS

// Payload assembles the catalog JSON from the embedded files. The result is
// deterministic, so its SHA-256 identifies the catalog version.
func Payload() ([]byte, error) {
	return payload(files)
}

func payload(fsys fs.FS) ([]byte, error) {
	dirs, err := fs.ReadDir(fsys, "apps")
	if err != nil {
		return nil, err
	}
	sort.Slice(dirs, func(i, j int) bool { return dirs[i].Name() < dirs[j].Name() })
	c := catalog.Catalog{Name: Name, Serial: Serial, Apps: []catalog.App{}}
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		dir := path.Join("apps", d.Name())
		raw, err := fs.ReadFile(fsys, path.Join(dir, "app.json"))
		if err != nil {
			return nil, err
		}
		var app catalog.App
		dec := json.NewDecoder(bytes.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&app); err != nil {
			return nil, fmt.Errorf("%s/app.json: %w", dir, err)
		}
		if app.ID != d.Name() || app.Compose != "" {
			return nil, fmt.Errorf("%s/app.json: id must equal the directory name and compose must live in compose.yaml", dir)
		}
		compose, err := fs.ReadFile(fsys, path.Join(dir, "compose.yaml"))
		if err != nil {
			return nil, err
		}
		app.Compose = string(compose)
		c.Apps = append(c.Apps, app)
	}
	return json.Marshal(c)
}
