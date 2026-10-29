# ADR-0031: A line console and live updates over server-sent events

- Status: Accepted
- Date: 2026-10-29

## Context
AT-F02-07 asks for an interactive shell into containers for admins, audited
without recording content; AT-F01-05 asks for status updates without page
reloads; logs should follow live. The Core never touches Docker (ADR-0005)
and must not run commands from API input; a shell in a privileged container
or one holding the Docker socket is root on the host.

## Decision
- **Transport:** server-sent events from the Core to the browser and plain
  POST requests for input, with the usual session, CSRF and permission
  checks; no WebSocket. Between Core and agent, one full-duplex HTTP stream
  operation per console (`containers.exec`): the request body is the
  input, the response is NDJSON output. The agent answers at once and sends
  refusals as the first line, so the Core never waits on a refusal while
  its input stream is open.
- **What runs:** only `/bin/sh -i` or `/bin/bash -i`, named by `sh` or
  `bash`; never a command from the API. No TTY: the console is line based
  (no editors or `top`); escape sequences are removed in the browser.
- **Where:** only running containers Kernhaven manages; refused for
  privileged containers, containers sharing the host's PID namespace and
  containers with a Docker socket mounted. The shell runs as the
  container's configured user.
- **Who and how long:** `containers.exec` (owner, admin) and a recent
  step-up; the console belongs to the browser session that opened it; at
  most 2 per user and 8 in all; 15 minutes without input or 1 hour end it.
- **Audit:** `container.console_open` and `container.console_close` with
  shell, duration, bytes in and out, exit code and reason — never content.
- **Live updates:** one poller runs while browsers listen and compares
  fingerprints of containers (through the agent), jobs and alerts every
  2 s; browsers are told only *that* a kind changed and reload it through
  the normal, permission-checked API. Streams end after 5 minutes and the
  browser reconnects, so a signed-out session stops receiving events.
- **Log follow:** the agent's `containers.logs.follow` (Docker follow) for
  at most 30 minutes, relayed as events.

## Consequences
- No terminal emulator dependency and no WebSocket implementation; the
  price is a line-based console.
- An admin can still read and change everything inside a container's file
  system as its user — that is the feature; the audit trail shows who and
  when.
- The poller costs one container listing every 2 s while anyone watches.
