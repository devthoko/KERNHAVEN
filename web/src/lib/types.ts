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
  | "jobs.manage";

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
