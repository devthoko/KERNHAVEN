package stacks

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/devthoko/KERNHAVEN/internal/agentproto"
	"github.com/devthoko/KERNHAVEN/internal/compose"
	"github.com/devthoko/KERNHAVEN/internal/core/agentclient"
	"github.com/devthoko/KERNHAVEN/internal/core/audit"
	"github.com/devthoko/KERNHAVEN/internal/core/jobs"
	"github.com/devthoko/KERNHAVEN/internal/platform/secretbox"
	"github.com/devthoko/KERNHAVEN/internal/policy"
)

// Job kinds.
const (
	KindDeploy = "stacks.deploy"
	KindDown   = "stacks.down"
)

// Service implements stack management.
type Service struct {
	st        *store
	agent     *agentclient.Client
	audit     *audit.Log
	jobs      *jobs.Service
	wake      func()
	bindRoots []string
	fetcher   *Fetcher
	// VerifyTimeout bounds the post-deploy health verification.
	VerifyTimeout time.Duration
	pollInterval  time.Duration
}

// Options configure the service.
type Options struct {
	BindRoots []string
	Fetcher   *Fetcher // nil = public HTTPS only
	Now       func() time.Time
}

// New returns the service and registers its job kinds.
func New(db *sql.DB, box *secretbox.Box, agent *agentclient.Client, auditLog *audit.Log, js *jobs.Service, wake func(), o Options) *Service {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Fetcher == nil {
		o.Fetcher = NewFetcher(nil, nil)
	}
	s := &Service{st: &store{db: db, box: box, now: o.Now}, agent: agent, audit: auditLog, jobs: js, wake: wake,
		bindRoots: o.BindRoots, fetcher: o.Fetcher, VerifyTimeout: 60 * time.Second, pollInterval: time.Second}
	js.Register(jobs.Kind{Name: KindDeploy, MaxAttempts: 3, Plan: s.planDeploy})
	js.Register(jobs.Kind{Name: KindDown, MaxAttempts: 3, Plan: s.planDown})
	return s
}

// ServiceEvaluation is the policy result for one service.
type ServiceEvaluation struct {
	Service    string           `json:"service"`
	Container  string           `json:"container"`
	Image      string           `json:"image"`
	Violations []policy.Finding `json:"violations"`
	Warnings   []policy.Finding `json:"warnings"`
}

// Evaluation is the result of validating a Compose document.
type Evaluation struct {
	Valid    bool                `json:"valid"`
	Errors   []compose.Error     `json:"errors"`
	Services []ServiceEvaluation `json:"services"`
	// Deployable is true when every violation is covered by an exception.
	Deployable bool `json:"deployable"`
}

func varMap(vars []Variable) map[string]string {
	m := map[string]string{}
	for _, v := range vars {
		m[v.Name] = v.Value
	}
	return m
}

// evaluate parses src and applies the policy with exceptions.
func (s *Service) evaluate(name, src string, vars map[string]string, exceptions []Exception) (Evaluation, *compose.Project) {
	ev := Evaluation{Errors: []compose.Error{}, Services: []ServiceEvaluation{}}
	proj, errs := compose.Parse([]byte(src), name, vars)
	if errs != nil {
		ev.Errors = errs
		return ev, nil
	}
	ev.Valid = true
	ev.Deployable = true
	for _, svc := range proj.Services {
		if err := policy.Validate(svc.Spec); err != nil {
			for _, line := range strings.Split(err.Error(), "\n") {
				ev.Errors = append(ev.Errors, compose.Error{Line: svc.Line, Path: "services." + svc.Name, Message: line})
			}
			ev.Valid, ev.Deployable = false, false
			continue
		}
		res := policy.Evaluate(svc.Spec, policy.Options{AllowedBindRoots: s.bindRoots})
		ev.Services = append(ev.Services, ServiceEvaluation{Service: svc.Name, Container: svc.Spec.Name, Image: svc.Spec.Image,
			Violations: res.Violations, Warnings: res.Warnings})
		if _, err := policy.Check(svc.Spec, rulesFor(exceptions, svc.Name), policy.Options{AllowedBindRoots: s.bindRoots}); err != nil {
			ev.Deployable = false
		}
	}
	return ev, proj
}

func rulesFor(exc []Exception, service string) []string {
	var out []string
	for _, e := range exc {
		if e.Service == service {
			out = append(out, e.Rule)
		}
	}
	return out
}

// mergedVars combines stored variables with request variables (request wins;
// secrets without a value keep the stored value).
func (s *Service) mergedVars(ctx context.Context, stackID int64, in []VariableInput) (map[string]string, error) {
	m := map[string]string{}
	if stackID > 0 {
		stored, err := s.st.variables(ctx, s.st.db, stackID)
		if err != nil {
			return nil, err
		}
		m = varMap(stored)
		if in != nil {
			keep := map[string]string{}
			for _, v := range in {
				if v.Value != nil {
					keep[v.Name] = *v.Value
				} else if old, ok := m[v.Name]; ok {
					keep[v.Name] = old
				}
			}
			m = keep
		}
		return m, nil
	}
	for _, v := range in {
		if v.Value != nil {
			m[v.Name] = *v.Value
		}
	}
	return m, nil
}

// Actor identifies who performs an action.
type Actor struct {
	ID         int64
	Name       string
	RequestID  string
	IP         string
	CanApprove bool // holds policy.exceptions
}

func (a Actor) event(action, target string, result audit.Result, kv ...string) audit.Event {
	ev := audit.Event{ActorID: a.ID, Actor: a.Name, Action: action, Target: target, Result: result, RequestID: a.RequestID, IP: a.IP, Details: map[string]string{}}
	for i := 0; i+1 < len(kv); i += 2 {
		ev.Details[kv[i]] = kv[i+1]
	}
	return ev
}

// RevisionInput creates a stack or a new revision.
type RevisionInput struct {
	Name       string          `json:"name,omitempty"`
	Compose    string          `json:"compose"`
	Comment    string          `json:"comment"`
	Variables  []VariableInput `json:"variables"`
	Exceptions []Exception     `json:"exceptions"`
}

// PolicyError reports uncovered violations or invalid input as an evaluation.
type PolicyError struct{ Evaluation Evaluation }

func (e *PolicyError) Error() string {
	if !e.Evaluation.Valid {
		parts := []string{}
		for _, x := range e.Evaluation.Errors {
			parts = append(parts, x.String())
		}
		return "the Compose file is invalid: " + strings.Join(parts, "; ")
	}
	return "some services violate the container policy and have no approved exception"
}

// ErrForbiddenException means a non-owner tried to approve an exception.
var ErrForbiddenException = errors.New("only owners may approve policy exceptions")

func (s *Service) checkExceptions(a Actor, exc []Exception, previous []Exception) error {
	prev := map[string]bool{}
	for _, e := range previous {
		prev[e.Service+"/"+e.Rule] = true
	}
	for _, e := range exc {
		if utf8.RuneCountInString(strings.TrimSpace(e.Reason)) < 10 || len(e.Reason) > 500 {
			return &ValidationError{"each exception needs a reason of 10 to 500 characters"}
		}
		// Carrying an existing exception into a new revision is allowed for
		// managers; new approvals need an owner.
		if !prev[e.Service+"/"+e.Rule] && !a.CanApprove {
			return ErrForbiddenException
		}
	}
	return nil
}

// Create creates a stack with revision 1.
func (s *Service) Create(ctx context.Context, a Actor, in RevisionInput) (Stack, Evaluation, error) {
	if !compose.ValidStackName(in.Name) {
		return Stack{}, Evaluation{}, &ValidationError{"name must be 1-31 characters: lowercase letters, digits and -"}
	}
	if err := validateVariables(in.Variables); err != nil {
		return Stack{}, Evaluation{}, err
	}
	for _, v := range in.Variables {
		if v.Value == nil {
			return Stack{}, Evaluation{}, &ValidationError{fmt.Sprintf("variable %s has no value", v.Name)}
		}
	}
	vars, _ := s.mergedVars(ctx, 0, in.Variables)
	ev, _ := s.evaluate(in.Name, in.Compose, vars, in.Exceptions)
	if !ev.Valid || !ev.Deployable {
		return Stack{}, ev, &PolicyError{ev}
	}
	if err := s.checkExceptions(a, in.Exceptions, nil); err != nil {
		return Stack{}, ev, err
	}
	var st Stack
	err := s.withTx(ctx, func(tx *sql.Tx) error {
		if _, err := s.st.byName(ctx, tx, in.Name); err == nil {
			return ErrExists
		}
		now := s.st.nowMS()
		res, err := tx.ExecContext(ctx, `INSERT INTO stacks (name, created_by, created_ms, updated_ms) VALUES (?, ?, ?, ?)`, in.Name, a.ID, now, now)
		if err != nil {
			return err
		}
		id, _ := res.LastInsertId()
		if err := s.st.replaceVariables(ctx, tx, id, in.Variables); err != nil {
			return err
		}
		if err := s.insertRevision(ctx, tx, id, a, in); err != nil {
			return err
		}
		if _, err := audit.Append(ctx, tx, s.st.now(), a.event("stack.create", "stack:"+in.Name, audit.Success, "revision", "1")); err != nil {
			return err
		}
		st, err = s.st.byID(ctx, tx, id)
		return err
	})
	return st, ev, err
}

func (s *Service) insertRevision(ctx context.Context, tx *sql.Tx, stackID int64, a Actor, in RevisionInput) error {
	var latest int
	if err := tx.QueryRowContext(ctx, `SELECT latest_revision FROM stacks WHERE id = ?`, stackID).Scan(&latest); err != nil {
		return err
	}
	exc := in.Exceptions
	if exc == nil {
		exc = []Exception{}
	}
	for i := range exc {
		if exc[i].ApprovedBy == "" {
			exc[i].ApprovedBy = a.Name
		}
	}
	excJSON, _ := json.Marshal(exc)
	n := latest + 1
	if _, err := tx.ExecContext(ctx, `INSERT INTO stack_revisions (stack_id, number, compose, comment, exceptions, created_by, created_by_name, created_ms)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, stackID, n, in.Compose, truncate(in.Comment, 500), string(excJSON), a.ID, a.Name, s.st.nowMS()); err != nil {
		return err
	}
	for _, e := range exc {
		if _, err := audit.Append(ctx, tx, s.st.now(), a.event("policy.exception", fmt.Sprintf("stack:%d/%s", stackID, e.Service), audit.Success,
			"rule", e.Rule, "reason", e.Reason, "revision", fmt.Sprint(n))); err != nil {
			return err
		}
	}
	_, err := tx.ExecContext(ctx, `UPDATE stacks SET latest_revision = ?, updated_ms = ? WHERE id = ?`, n, s.st.nowMS(), stackID)
	return err
}

func truncate(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	return string([]rune(s)[:n])
}

// AddRevision stores a new revision (and optionally replaces variables).
func (s *Service) AddRevision(ctx context.Context, a Actor, name string, in RevisionInput) (Revision, Evaluation, error) {
	st, err := s.st.byName(ctx, s.st.db, name)
	if err != nil {
		return Revision{}, Evaluation{}, err
	}
	if in.Variables != nil {
		if err := validateVariables(in.Variables); err != nil {
			return Revision{}, Evaluation{}, err
		}
	}
	vars, err := s.mergedVars(ctx, st.ID, in.Variables)
	if err != nil {
		return Revision{}, Evaluation{}, err
	}
	ev, _ := s.evaluate(name, in.Compose, vars, in.Exceptions)
	if !ev.Valid || !ev.Deployable {
		return Revision{}, ev, &PolicyError{ev}
	}
	var prevExc []Exception
	if st.LatestRevision > 0 {
		if prev, err := s.st.revision(ctx, s.st.db, st.ID, st.LatestRevision); err == nil {
			prevExc = prev.Exceptions
		}
	}
	if err := s.checkExceptions(a, in.Exceptions, prevExc); err != nil {
		return Revision{}, ev, err
	}
	var rev Revision
	err = s.withTx(ctx, func(tx *sql.Tx) error {
		if in.Variables != nil {
			if err := s.st.replaceVariables(ctx, tx, st.ID, in.Variables); err != nil {
				return err
			}
		}
		if err := s.insertRevision(ctx, tx, st.ID, a, in); err != nil {
			return err
		}
		cur, err := s.st.byID(ctx, tx, st.ID)
		if err != nil {
			return err
		}
		if _, err := audit.Append(ctx, tx, s.st.now(), a.event("stack.revision", "stack:"+name, audit.Success, "revision", fmt.Sprint(cur.LatestRevision))); err != nil {
			return err
		}
		rev, err = s.st.revision(ctx, tx, st.ID, cur.LatestRevision)
		return err
	})
	return rev, ev, err
}

// SetVariables replaces the stack's variables.
func (s *Service) SetVariables(ctx context.Context, a Actor, name string, vars []VariableInput) error {
	if err := validateVariables(vars); err != nil {
		return err
	}
	st, err := s.st.byName(ctx, s.st.db, name)
	if err != nil {
		return err
	}
	return s.withTx(ctx, func(tx *sql.Tx) error {
		if err := s.st.replaceVariables(ctx, tx, st.ID, vars); err != nil {
			return err
		}
		names := make([]string, len(vars))
		for i, v := range vars {
			names[i] = v.Name
		}
		_, err := audit.Append(ctx, tx, s.st.now(), a.event("stack.variables", "stack:"+name, audit.Success, "names", strings.Join(names, ",")))
		return err
	})
}

// PublicVariables returns variables with secret values removed.
func (s *Service) PublicVariables(ctx context.Context, stackID int64) ([]Variable, error) {
	vars, err := s.st.variables(ctx, s.st.db, stackID)
	if err != nil {
		return nil, err
	}
	for i := range vars {
		if vars[i].Secret {
			vars[i].Value = ""
		}
	}
	return vars, nil
}

func (s *Service) withTx(ctx context.Context, f func(*sql.Tx) error) error {
	tx, err := s.st.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op after commit
	if err := f(tx); err != nil {
		return err
	}
	return tx.Commit()
}

// Deploy queues a deployment of revision n (0 = latest).
func (s *Service) Deploy(ctx context.Context, a Actor, name string, n int) (int64, error) {
	st, err := s.st.byName(ctx, s.st.db, name)
	if err != nil {
		return 0, err
	}
	if n == 0 {
		n = st.LatestRevision
	}
	if _, err := s.st.revision(ctx, s.st.db, st.ID, n); err != nil {
		return 0, err
	}
	var id int64
	err = s.withTx(ctx, func(tx *sql.Tx) error {
		var err error
		id, err = s.jobs.EnqueueTx(ctx, tx, jobs.Request{Kind: KindDeploy, Payload: deployPayload{StackID: st.ID, Revision: n, Actor: a.Name},
			CreatedBy: a.ID, DedupeKey: "stack:" + name})
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE stacks SET status = 'deploying', status_message = ?, updated_ms = ? WHERE id = ?`,
			fmt.Sprintf("deploying revision %d", n), s.st.nowMS(), st.ID); err != nil {
			return err
		}
		_, err = audit.Append(ctx, tx, s.st.now(), a.event("stack.deploy", "stack:"+name, audit.Success, "revision", fmt.Sprint(n), "job", fmt.Sprint(id)))
		return err
	})
	if err == nil && s.wake != nil {
		s.wake()
	}
	return id, err
}

// Down queues stopping and removing the stack.
func (s *Service) Down(ctx context.Context, a Actor, name string, removeVolumes bool) (int64, error) {
	st, err := s.st.byName(ctx, s.st.db, name)
	if err != nil {
		return 0, err
	}
	var id int64
	err = s.withTx(ctx, func(tx *sql.Tx) error {
		var err error
		id, err = s.jobs.EnqueueTx(ctx, tx, jobs.Request{Kind: KindDown, Payload: downPayload{StackID: st.ID, RemoveVolumes: removeVolumes, Actor: a.Name},
			CreatedBy: a.ID, DedupeKey: "stack:" + name})
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE stacks SET status = 'stopping', status_message = '', updated_ms = ? WHERE id = ?`, s.st.nowMS(), st.ID); err != nil {
			return err
		}
		_, err = audit.Append(ctx, tx, s.st.now(), a.event("stack.down", "stack:"+name, audit.Success, "remove_volumes", fmt.Sprint(removeVolumes), "job", fmt.Sprint(id)))
		return err
	})
	if err == nil && s.wake != nil {
		s.wake()
	}
	return id, err
}

// Delete removes a stack that is not deployed.
func (s *Service) Delete(ctx context.Context, a Actor, name string) error {
	return s.withTx(ctx, func(tx *sql.Tx) error {
		st, err := s.st.byName(ctx, tx, name)
		if err != nil {
			return err
		}
		if st.DeployedRevision > 0 || st.Status == "deploying" || st.Status == "stopping" {
			return ErrDeployed
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM stacks WHERE id = ?`, st.ID); err != nil {
			return err
		}
		_, err = audit.Append(ctx, tx, s.st.now(), a.event("stack.delete", "stack:"+name, audit.Success))
		return err
	})
}

// ServiceState is the runtime state of a service's container.
type ServiceState struct {
	Service   string `json:"service"`
	Container string `json:"container"`
	State     string `json:"state"`
	Status    string `json:"status"`
	Revision  string `json:"revision"`
}

// Runtime lists the stack's containers through the agent.
func (s *Service) Runtime(ctx context.Context, name, actor, requestID string) ([]ServiceState, error) {
	if s.agent == nil {
		return nil, agentclient.ErrUnavailable
	}
	var list []agentproto.ContainerSummary
	if err := s.agent.Do(ctx, agentclient.Call{Op: agentproto.OpContainersList, Params: agentproto.ContainersList{All: true}, Actor: actor, RequestID: requestID}, &list); err != nil {
		return nil, err
	}
	out := []ServiceState{}
	for _, c := range list {
		if c.Labels[labelStack] != name {
			continue
		}
		cn := ""
		if len(c.Names) > 0 {
			cn = c.Names[0]
		}
		out = append(out, ServiceState{Service: c.Labels[labelService], Container: cn, State: c.State, Status: c.Status, Revision: c.Labels[labelRevision]})
	}
	return out, nil
}

// Reserved labels set by the agent (see internal/agent).
const (
	labelStack    = "io.kernhaven.stack"
	labelService  = "io.kernhaven.stack.service"
	labelRevision = "io.kernhaven.stack.revision"
)
