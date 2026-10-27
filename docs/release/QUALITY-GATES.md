# Kernhaven Release Quality Gates

Gates are cumulative: G2 includes G1, G3 includes G2, G4 includes G3.
A gate passes only on evidence (CI run links, test logs, reports) recorded in
the milestone or release document. A gate never passes on assertion alone.

## G1 — Change gate

CI runs at two depths (`.github/workflows/ci.yml`). **Quick** on every push to a
feature branch: formatting, vet, staticcheck, govulncheck, secret scan, Go tests
with the race detector on amd64, web typecheck/tests/build/audit, systemd units.
**Full** on pull requests, pushes to `main`, nightly and on manual runs: in
addition arm64, Debian 13, real-Docker integration, browser end-to-end tests
and fuzzing. A change may only be merged to `main` with a green full run.
A commit message containing `[full-ci]` requests the full suite on a feature
branch (used to record milestone evidence).


- [ ] `gofmt` clean, `go vet` clean, `staticcheck` clean
- [ ] `go test -race ./...` passes on amd64 and arm64
- [ ] Tests run on `debian:13` userland
- [ ] `govulncheck` reports no vulnerabilities in reachable code
- [ ] Build succeeds for `linux/amd64` and `linux/arm64` with `CGO_ENABLED=0`
- [ ] No secrets in the diff (credential patterns, private keys)
- [ ] API contract test passes (from M2)
- [ ] New or changed behaviour has tests, including failure paths

## G2 — Milestone gate

- [ ] Milestone design document committed before implementation
- [ ] All acceptance tests of the milestone automated and passing in their
      required environments
- [ ] Threat model updated; new threats mitigated or explicitly accepted
- [ ] ADRs written for new decisions and dependencies
- [ ] Feature matrix status updated truthfully
- [ ] Known limitations documented
- [ ] Reproducible verification procedure documented and executed
- [ ] Compatibility with existing modules verified (full test suite green)

## G3 — Release candidate gate

- [ ] All milestone gates for included features passed
- [ ] Integration suite green on `int-debian-amd64` and `int-debian-arm64`
- [ ] E2E (Playwright) suite green
- [ ] Nightly fuzzing without new findings for 7 days
- [ ] OWASP ZAP baseline: no high/medium findings without accepted rationale
- [ ] Upgrade from previous release and rollback tested
- [ ] Release artifacts reproducible and signed
- [ ] Release notes and upgrade notes written

## G4 — Version 1.0 gate

All of G3, plus:

- [ ] Every row of the feature matrix is **Done**
- [ ] Supported-platform integration tests pass (Debian 13, amd64 + arm64)
- [ ] Backup and restore tests pass, including restore onto a fresh host
- [ ] Upgrade and rollback tests pass
- [ ] Recovery from interrupted operations is tested (kill -9, power loss)
- [ ] OWASP ASVS 5.0 Level 2 checklist complete with evidence; no open
      critical or high findings
- [ ] No known release-blocking defects
- [ ] User, operator and security documentation complete
- [ ] Threat model reviewed; all threats Mitigated or Accepted with rationale

Version 1.0 must not be tagged while any box above is unchecked.
