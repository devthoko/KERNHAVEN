package compose

import (
	"strings"
	"testing"

	"github.com/devthoko/KERNHAVEN/internal/agentproto"
)

const full = `
name: demo
x-common: &common
  restart: unless-stopped
  user: "1000"
services:
  web:
    <<: *common
    image: nginx:${NGINX_TAG:-1.27}
    command: ["nginx", "-g", "daemon off;"]
    environment:
      DB_PASSWORD: ${DB_PASSWORD}
      MODE: production
    ports:
      - "127.0.0.1:8080:80"
      - "8443:443/tcp"
      - target: 53
        published: 5353
        protocol: udp
    volumes:
      - data:/usr/share/nginx/html:ro
      - type: tmpfs
        target: /tmp
    networks: [front]
    depends_on:
      db:
        condition: service_healthy
    healthcheck:
      test: curl -f http://localhost/ || exit 1
      interval: 30s
      timeout: 5s
      retries: 3
    deploy:
      resources:
        limits:
          memory: 256m
          cpus: "0.5"
  db:
    image: postgres:16
    command: postgres -c 'max_connections=50'
    environment:
      - POSTGRES_PASSWORD=$DB_PASSWORD
    volumes:
      - pg:/var/lib/postgresql/data
    mem_limit: 1g
volumes:
  data:
  pg:
    labels:
      backup: daily
networks:
  front:
    internal: true
`

func vars() map[string]string { return map[string]string{"DB_PASSWORD": "s3cret$"} }

// AT-F03-02: a realistic file maps onto container specs.
func TestParseFullProject(t *testing.T) {
	p, errs := Parse([]byte(full), "demo", vars())
	if errs != nil {
		t.Fatalf("errors: %v", errs)
	}
	if len(p.Services) != 2 || len(p.Volumes) != 2 || len(p.Networks) != 2 {
		t.Fatalf("project %+v", p)
	}
	web := p.Services[0].Spec
	want := map[string]any{
		"name": "demo-web", "image": "nginx:1.27", "user": "1000", "restart": "unless-stopped",
		"network": "demo_front", "memory": int64(256 << 20), "cpus": int64(5e8),
	}
	got := map[string]any{
		"name": web.Name, "image": web.Image, "user": web.User, "restart": web.RestartPolicy,
		"network": web.NetworkMode, "memory": web.MemoryBytes, "cpus": web.NanoCPUs,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
	if strings.Join(web.Cmd, "|") != "nginx|-g|daemon off;" {
		t.Errorf("cmd %q", web.Cmd)
	}
	if len(web.Env) != 2 || web.Env[0] != (agentproto.EnvVar{Name: "DB_PASSWORD", Value: "s3cret$"}) {
		t.Errorf("env %+v", web.Env)
	}
	if len(web.Ports) != 3 || web.Ports[0] != (agentproto.PortBinding{HostIP: "127.0.0.1", HostPort: 8080, ContainerPort: 80}) ||
		web.Ports[2] != (agentproto.PortBinding{HostPort: 5353, ContainerPort: 53, Protocol: "udp"}) {
		t.Errorf("ports %+v", web.Ports)
	}
	if len(web.Mounts) != 2 || web.Mounts[0] != (agentproto.MountSpec{Type: "volume", Source: "demo_data", Target: "/usr/share/nginx/html", ReadOnly: true}) || web.Mounts[1].Type != "tmpfs" {
		t.Errorf("mounts %+v", web.Mounts)
	}
	if web.Healthcheck == nil || web.Healthcheck.Test[0] != "CMD-SHELL" || web.Healthcheck.IntervalMS != 30000 || web.Healthcheck.Retries != 3 {
		t.Errorf("healthcheck %+v", web.Healthcheck)
	}
	db := p.Services[1].Spec
	if strings.Join(db.Cmd, "|") != "postgres|-c|max_connections=50" || db.NetworkMode != "demo_default" || db.MemoryBytes != 1<<30 {
		t.Errorf("db %+v", db)
	}
	if p.Volumes[1].Labels["backup"] != "daily" || !p.Networks[1].Internal {
		t.Errorf("volumes %+v networks %+v", p.Volumes, p.Networks)
	}
	order, err := Order(p)
	if err != nil || order[0].Name != "db" || order[1].Name != "web" {
		t.Fatalf("order %v %v", order, err)
	}
}

func errorAt(t *testing.T, src, wantMsg string, wantLine int) {
	t.Helper()
	_, errs := Parse([]byte(src), "demo", vars())
	if errs == nil {
		t.Fatalf("no error for %q", src)
	}
	for _, e := range errs {
		if strings.Contains(e.Message, wantMsg) && (wantLine == 0 || e.Line == wantLine) {
			return
		}
	}
	t.Fatalf("want %q at line %d, got %v", wantMsg, wantLine, errs)
}

// AT-F03-02: line-accurate errors; unsupported features are errors.
func TestErrorsWithLines(t *testing.T) {
	cases := []struct {
		src, msg string
		line     int
	}{
		{"services:\n  web:\n    image: x\n    build: .\n", "building images is not supported", 4},
		{"services:\n  web:\n    image: x\n    hostname: h\n", `service option "hostname" is not supported`, 4},
		{"services:\n  web:\n    command: x\n", "an image is required", 2},
		{"services:\n  web:\n    image: x\n    ports: [\"8000-8010:8000-8010\"]\n", "port ranges are not supported", 4},
		{"services:\n  web:\n    image: x\n    volumes: [\"./data:/d\"]\n", "relative host paths", 4},
		{"services:\n  web:\n    image: x\n    volumes: [\"data:/d\"]\n", `volume "data" is not declared`, 4},
		{"services:\n  web:\n    image: x\n    volumes: [\"/d\"]\n", "anonymous volumes", 4},
		{"services:\n  web:\n    image: x\n    environment: [\"HOME\"]\n", "values from the host environment", 4},
		{"services:\n  web:\n    image: x\n    env_file: .env\n", "env_file is not supported", 4},
		{"services:\n  web:\n    image: x\n    privileged: maybe\n", "must be true or false", 4},
		{"services:\n  web:\n    image: x\n    networks: [a, b]\nnetworks:\n  a:\n  b:\n", "exactly one network", 4},
		{"services:\n  web:\n    image: x\n    network_mode: service:db\n", "not supported", 4},
		{"services:\n  web:\n    image: ${MISSING}\n", "variable MISSING is not set", 3},
		{"services:\n  web:\n    image: ${TAG:?set the tag}\n", "set the tag", 3},
		{"services:\n  web:\n    image: x\n    container_name: other\n", "managed by Kernhaven", 4},
		{"services:\n  web:\n    image: x\n    depends_on: [nope]\n", `unknown service "nope"`, 0},
		{"services:\n  a:\n    image: x\n    depends_on: [b]\n  b:\n    image: x\n    depends_on: [a]\n", "dependency cycle", 0},
		{"secrets:\n  s:\n    file: x\nservices:\n  web:\n    image: x\n", `top-level key "secrets" is not supported`, 1},
		{"services:\n  web:\n    image: x\n    image: y\n", `duplicate key "image"`, 4},
		{"services:\n  web: [1\n", "", 0},
		{"services:\n  web:\n    image: x\n    deploy:\n      replicas: 3\n", `deploy option "replicas"`, 5},
		{"services:\n  web:\n    image: x\n    mem_limit: lots\n", "invalid size", 4},
		{"networks:\n  default:\nservices:\n  web:\n    image: x\n", "default network is managed", 2},
		{"volumes:\n  v:\n    name: hostdata\nservices:\n  web:\n    image: x\n", "only allowed for external", 2},
	}
	for _, tc := range cases {
		errorAt(t, tc.src, tc.msg, tc.line)
	}
}

func TestStackNameAndSize(t *testing.T) {
	if _, errs := Parse([]byte("services: {}"), "Bad_Name", nil); errs == nil {
		t.Fatal("invalid stack name accepted")
	}
	if _, errs := Parse([]byte(strings.Repeat("#", MaxSize+1)), "demo", nil); errs == nil {
		t.Fatal("oversized document accepted")
	}
	if _, errs := Parse([]byte("services: {}"), "demo", nil); errs == nil {
		t.Fatal("empty services accepted")
	}
}

// YAML expansion bombs are stopped.
func TestAliasBomb(t *testing.T) {
	src := `x-a: &a {k: v}
x-b: &b {<<: [*a, *a, *a, *a, *a, *a, *a, *a, *a, *a]}
x-c: &c {<<: [*b, *b, *b, *b, *b, *b, *b, *b, *b, *b]}
x-d: &d {<<: [*c, *c, *c, *c, *c, *c, *c, *c, *c, *c]}
x-e: &e {<<: [*d, *d, *d, *d, *d, *d, *d, *d, *d, *d]}
x-f: &f {<<: [*e, *e, *e, *e, *e, *e, *e, *e, *e, *e]}
services:
  web:
    <<: *f
    image: x
`
	_, errs := Parse([]byte(src), "demo", nil)
	if errs == nil || !strings.Contains(errs.Error(), "too many nodes") {
		t.Fatalf("alias bomb not stopped: %v", errs)
	}
}

func TestInterpolation(t *testing.T) {
	v := map[string]string{"A": "1", "EMPTY": ""}
	cases := map[string]string{
		"$A":          "1",
		"${A}":        "1",
		"x${A}y":      "x1y",
		"${B:-def}":   "def",
		"${EMPTY:-d}": "d",
		"${EMPTY-d}":  "",
		"${B-d}":      "d",
		"$$A":         "$A",
		"cost: $$5":   "cost: $5",
		"plain":       "plain",
	}
	for in, want := range cases {
		got, err := interpolate(in, v)
		if err != nil || got != want {
			t.Errorf("%q → %q (%v), want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"${B}", "$B", "${A", "${A:+x}", "$ x"} {
		if _, err := interpolate(bad, v); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestSplitWordsAndPorts(t *testing.T) {
	w, err := splitWords(`sh -c "echo 'a b'; exit 0" x\ y`)
	if err != nil || strings.Join(w, "|") != `sh|-c|echo 'a b'; exit 0|x y` {
		t.Fatalf("words %q %v", w, err)
	}
	if _, err := splitWords(`echo "open`); err == nil {
		t.Fatal("unterminated quote accepted")
	}
	pb, err := parsePort("[::1]:8080:80/udp")
	if err != nil || pb.HostIP != "::1" || pb.HostPort != 8080 || pb.ContainerPort != 80 || pb.Protocol != "udp" {
		t.Fatalf("ipv6 port %+v %v", pb, err)
	}
	if pb, err := parsePort("80"); err != nil || pb.HostPort != 0 || pb.ContainerPort != 80 {
		t.Fatalf("container-only port %+v %v", pb, err)
	}
}

func TestExternalResources(t *testing.T) {
	src := "services:\n  web:\n    image: x\n    volumes: [shared:/s]\n    networks: [proxy]\nvolumes:\n  shared:\n    external: true\n    name: media\nnetworks:\n  proxy:\n    external: true\n    name: caddy\n"
	p, errs := Parse([]byte(src), "demo", nil)
	if errs != nil {
		t.Fatal(errs)
	}
	s := p.Services[0].Spec
	if s.Mounts[0].Source != "media" || s.NetworkMode != "caddy" || !p.Volumes[0].External || !p.Networks[1].External {
		t.Fatalf("external resources %+v %+v", s, p)
	}
}
