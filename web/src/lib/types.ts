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
  | "policy.exceptions"
  | "apps.read"
  | "apps.manage"
  | "catalog.manage"
  | "storage.read"
  | "storage.manage";

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

// ---- M7: stacks ----

export interface Stack {
  id: number;
  name: string;
  latest_revision: number;
  deployed_revision: number;
  status: "new" | "deploying" | "deployed" | "failed" | "stopping" | "stopped";
  status_message?: string;
  managed_by: "" | "app";
  created_at: string;
  updated_at: string;
}

export interface StackException {
  service: string;
  rule: string;
  reason: string;
  approved_by?: string;
}

export interface StackRevision {
  number: number;
  compose?: string;
  comment: string;
  exceptions: StackException[];
  created_by: string;
  created_at: string;
}

export interface StackVariable {
  name: string;
  value?: string;
  secret: boolean;
}

export interface StackServiceState {
  service: string;
  container: string;
  state: string;
  status: string;
  revision: string;
}

export interface StackEvaluation {
  valid: boolean;
  deployable: boolean;
  errors: { line: number; column: number; path: string; message: string }[];
  services: { service: string; container: string; image: string; violations: Finding[]; warnings: Finding[] }[];
}

export interface StackDetail {
  stack: Stack;
  latest: StackRevision;
  variables: StackVariable[];
  services?: StackServiceState[];
  services_error?: string;
}

// ---- M8: app store ----

export interface CatalogSource {
  id: number;
  name: string;
  url: string;
  public_key: string;
  key_id: string;
  serial: number;
  catalog_name: string;
  expires_at: string | null;
  synced_at: string | null;
  last_error: string;
  app_count: number;
}

export interface CatalogListing {
  source_id: number;
  source_name: string;
  app_id: string;
  name: string;
  version: string;
  summary: string;
  categories: string[];
  installed: string[];
}

export interface AppField {
  name: string;
  label: string;
  description?: string;
  type: "text" | "password" | "number" | "boolean" | "select";
  default?: string;
  required?: boolean;
  options?: string[];
  min?: number;
  max?: number;
  generate?: "password" | "hex32";
}

export interface CatalogException {
  service: string;
  rule: string;
  reason: string;
}

export interface CatalogApp {
  id: string;
  name: string;
  version: string;
  summary: string;
  description?: string;
  categories: string[];
  homepage?: string;
  fields: AppField[];
  web?: { service: string; port: number };
  exceptions: CatalogException[];
}

export interface ServiceDisclosure {
  service: string;
  image: string;
  image_pinned: boolean;
  user: string;
  ports: string[];
  bind_mounts: string[];
  volumes: string[];
  capabilities: string[];
  devices: string[];
  privileged: boolean;
  host_network: boolean;
  violations: Finding[];
  warnings: Finding[];
  exceptions: CatalogException[];
}

export interface Disclosure {
  services: ServiceDisclosure[];
  installable: boolean;
  needs_approval: boolean;
  problems: string[];
}

export interface CatalogAppDetail {
  source: CatalogSource;
  app: CatalogApp;
  disclosure: Disclosure;
  installed: string[];
  expired: boolean;
}

export interface InstalledApp {
  name: string;
  app_id: string;
  app_name: string;
  source_id: number | null;
  source_name: string;
  version: string;
  latest_version: string;
  update_available: boolean;
  status: Stack["status"];
  status_message: string;
  deployed_revision: number;
  web_port: number;
  created_at: string;
}

export interface AppVersion {
  revision: number;
  version: string;
  comment: string;
  deployed: boolean;
  created_by: string;
  created_at: string;
}

export interface UpdatePreview {
  from: string;
  to: string;
  images: { service: string; from: string; to: string }[];
  new_fields: AppField[];
  new_exceptions: CatalogException[];
  disclosure: Disclosure;
}

export interface InstalledAppDetail extends InstalledApp {
  versions: AppVersion[];
  fields: AppField[];
  config: StackVariable[];
  update: UpdatePreview | null;
  homepage: string;
  summary: string;
  web: { service: string; port: number } | null;
}

// ---- M9: storage ----

export interface SmartInfo {
  available: boolean;
  passed?: boolean;
  temperature_c?: number;
  power_on_hours?: number;
  message?: string;
}

export interface FileSystemInfo {
  path: string;
  name: string;
  type: string;
  fstype: string;
  label: string;
  uuid: string;
  size_bytes: number;
  fs_size_bytes: number;
  fs_used_bytes: number;
  fs_available_bytes: number;
  mountpoints: string[];
  mount_name?: string;
  mountable: boolean;
}

export interface DiskInfo {
  path: string;
  name: string;
  model: string;
  serial: string;
  wwn: string;
  transport: string;
  size_bytes: number;
  rotational: boolean;
  removable: boolean;
  read_only: boolean;
  class: "system" | "in_use" | "managed" | "free";
  reason?: string;
  formattable: boolean;
  file_systems: FileSystemInfo[];
  smart: SmartInfo;
}

export interface ManagedMount {
  name: string;
  path: string;
  unit: string;
  what: string;
  fstype: string;
  active: boolean;
}

export interface StorageInventory {
  disks: DiskInfo[];
  mounts: ManagedMount[];
  mount_root: string;
  formattable_fstypes: string[];
  smart_tool: boolean;
  privileged: boolean;
}
