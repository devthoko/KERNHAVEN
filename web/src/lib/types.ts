// Types mirror api/openapi/v1.yaml.

export type Role = "owner" | "admin" | "operator" | "viewer";

export const ROLES: readonly Role[] = ["owner", "admin", "operator", "viewer"];

export type Permission =
  | "self.manage"
  | "system.read"
  | "users.read"
  | "users.manage"
  | "sessions.manage"
  | "audit.read"
  | "jobs.read"
  | "jobs.manage"
  | "containers.read"
  | "containers.operate"
  | "containers.manage"
  | "policy.exceptions";

export interface User {
  id: number;
  username: string;
  display_name: string;
  role: Role;
  disabled: boolean;
  locked: boolean;
  created_at: string;
  updated_at: string;
}

export interface SessionInfo {
  user: User;
  permissions: Permission[];
  csrf_token: string;
  expires_at: string;
}

export interface Session {
  id: string;
  created_at: string;
  last_seen_at: string;
  idle_expires_at: string;
  absolute_expires_at: string;
  ip: string;
  user_agent: string;
  current: boolean;
}

export type Theme = "system" | "light" | "dark";

export interface Preferences {
  theme: Theme;
}

export type JobState = "queued" | "running" | "compensating" | "succeeded" | "failed" | "cancelled";

export const ACTIVE_JOB_STATES: readonly JobState[] = ["queued", "running", "compensating"];

export interface JobStep {
  index: number;
  name: string;
  state: "pending" | "done" | "compensated";
  completed_at?: string;
}

export interface JobLog {
  time: string;
  level: "info" | "warn" | "error";
  message: string;
}

export interface Job {
  id: number;
  kind: string;
  state: JobState;
  attempts: number;
  max_attempts: number;
  created_by: number;
  cancel_requested: boolean;
  needs_attention: boolean;
  error?: string;
  steps_done: number;
  steps_total: number;
  created_at: string;
  updated_at: string;
  started_at?: string;
  finished_at?: string;
  steps?: JobStep[];
  logs?: JobLog[];
}

export interface AuditEvent {
  seq: number;
  time: string;
  actor_id: number;
  actor: string;
  action: string;
  target: string;
  result: "success" | "failure" | "denied";
  request_id: string;
  ip: string;
  details: Record<string, string>;
  prev_hash: string;
  hash: string;
}

export interface VerifyResult {
  ok: boolean;
  records: number;
  broken_at?: number;
  reason?: string;
}

export interface Version {
  version: string;
  commit: string;
  build_date: string;
  go_version: string;
}

export interface ComponentStatus<T> {
  available: boolean;
  error?: string;
  info?: T;
}

export interface AgentStatus {
  agent: ComponentStatus<{ version: string; commit: string; uptime_seconds: number }>;
  docker: ComponentStatus<{
    server_version: string;
    api_version: string;
    rootless: boolean;
    containers: number;
    running: number;
    images: number;
  }>;
}

// ---- M6: containers ----

export interface PortInfo {
  ip?: string;
  private_port: number;
  public_port?: number;
  type: string;
}

export interface ContainerSummary {
  id: string;
  names: string[];
  image: string;
  state: string;
  status: string;
  created: number;
  ports: PortInfo[];
  labels: Record<string, string>;
}

export interface ContainerDetail {
  id: string;
  name: string;
  image: string;
  status: string;
  running: boolean;
  exit_code: number;
  started_at: string;
  finished_at: string;
  health?: string;
  restart_policy: string;
  privileged: boolean;
  network_mode: string;
  cap_add: string[];
  mounts: { type: string; source: string; destination: string; rw: boolean }[];
  user: string;
  labels: Record<string, string>;
}

export interface LogLine {
  stream: "stdout" | "stderr";
  text: string;
}

export interface ContainerSpec {
  name: string;
  image: string;
  cmd?: string[];
  env?: { name: string; value: string }[];
  user?: string;
  ports?: { host_ip?: string; host_port: number; container_port: number; protocol?: string }[];
  mounts?: { type: string; source?: string; target: string; read_only?: boolean }[];
  network_mode?: string;
  restart_policy?: string;
  privileged?: boolean;
  cap_add?: string[];
  devices?: string[];
  security_opt?: string[];
  pid_mode?: string;
  memory_bytes?: number;
}

export interface Finding {
  rule: string;
  field: string;
  message: string;
  exemptible: boolean;
}

export interface PolicyEvaluation {
  valid: boolean;
  errors: string[];
  violations: Finding[];
  warnings: Finding[];
}

export interface ImageSummary {
  id: string;
  repo_tags: string[];
  repo_digests: string[];
  size: number;
  created: number;
  containers: number;
}

export interface VolumeSummary {
  name: string;
  driver: string;
  mountpoint: string;
  created_at: string;
  labels: Record<string, string>;
}

export interface NetworkSummary {
  id: string;
  name: string;
  driver: string;
  scope: string;
  internal: boolean;
  containers: number;
  labels: Record<string, string>;
  built_in: boolean;
}
