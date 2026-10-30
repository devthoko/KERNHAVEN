import { useEffect, type ReactNode } from "react";
import { Layout } from "./components/Layout";
import { Spinner } from "./components/ui";
import { RouterProvider, matchPath, useRouter } from "./lib/router";
import { SessionProvider, useSession } from "./lib/session";
import type { Permission } from "./lib/types";
import { AccountPage } from "./pages/AccountPage";
import { AppDetailPage } from "./pages/AppDetailPage";
import { AppStorePage, AppsPage, SourcesPage, StoreAppPage } from "./pages/AppsPage";
import { AuditPage } from "./pages/AuditPage";
import { ContainerDetailPage } from "./pages/ContainerDetailPage";
import { ContainersPage } from "./pages/ContainersPage";
import { CreateContainerPage } from "./pages/CreateContainerPage";
import { ImagesPage } from "./pages/ImagesPage";
import { NetworksPage, VolumesPage } from "./pages/VolumesNetworksPage";
import { StackDetailPage } from "./pages/StackDetailPage";
import { NewStackPage, StacksPage } from "./pages/StacksPage";
import { HomePage } from "./pages/HomePage";
import { JobDetailPage } from "./pages/JobDetailPage";
import { JobsPage } from "./pages/JobsPage";
import { LoginPage } from "./pages/LoginPage";
import { NotFoundPage } from "./pages/NotFoundPage";
import { SetupPage } from "./pages/SetupPage";
import { StoragePage } from "./pages/StoragePage";
import { CertificatesPage } from "./pages/CertificatesPage";
import { AlertsPage } from "./pages/AlertsPage";
import { BackupsPage } from "./pages/BackupsPage";
import { SecurityPage } from "./pages/SecurityPage";
import { FilesPage } from "./pages/FilesPage";
import { MonitoringPage } from "./pages/MonitoringPage";
import { GatePage } from "./pages/GatePage";
import { ProxyPage } from "./pages/ProxyPage";
import { UsersPage } from "./pages/UsersPage";

interface RouteDef {
  pattern: string;
  title: string;
  permission?: Permission;
  render: (params: Record<string, string>) => ReactNode;
}

const routes: RouteDef[] = [
  { pattern: "/", title: "Home", render: () => <HomePage /> },
  { pattern: "/monitoring", title: "Monitoring", permission: "system.read", render: () => <MonitoringPage /> },
  { pattern: "/alerts", title: "Alerts", permission: "alerts.read", render: () => <AlertsPage /> },
  { pattern: "/backups", title: "Backups", permission: "backup.read", render: () => <BackupsPage /> },
  { pattern: "/security", title: "Security", permission: "security.read", render: () => <SecurityPage /> },
  { pattern: "/apps", title: "Apps", permission: "apps.read", render: () => <AppsPage /> },
  { pattern: "/apps/store", title: "App store", permission: "apps.read", render: () => <AppStorePage /> },
  { pattern: "/apps/sources", title: "Catalog sources", permission: "apps.read", render: () => <SourcesPage /> },
  { pattern: "/apps/store/:source/:app", title: "App", permission: "apps.read", render: (p) => <StoreAppPage source={p.source ?? ""} app={p.app ?? ""} /> },
  { pattern: "/apps/:name", title: "App", permission: "apps.read", render: (p) => <AppDetailPage name={p.name ?? ""} /> },
  { pattern: "/containers", title: "Containers", permission: "containers.read", render: () => <ContainersPage /> },
  { pattern: "/containers/new", title: "New container", permission: "containers.manage", render: () => <CreateContainerPage /> },
  { pattern: "/containers/:id", title: "Container", permission: "containers.read", render: (p) => <ContainerDetailPage id={p.id ?? ""} /> },
  { pattern: "/stacks", title: "Stacks", permission: "containers.read", render: () => <StacksPage /> },
  { pattern: "/stacks/new", title: "New stack", permission: "containers.manage", render: () => <NewStackPage /> },
  { pattern: "/stacks/:name", title: "Stack", permission: "containers.read", render: (p) => <StackDetailPage name={p.name ?? ""} /> },
  { pattern: "/images", title: "Images", permission: "containers.read", render: () => <ImagesPage /> },
  { pattern: "/volumes", title: "Volumes", permission: "containers.read", render: () => <VolumesPage /> },
  { pattern: "/networks", title: "Networks", permission: "containers.read", render: () => <NetworksPage /> },
  { pattern: "/storage", title: "Storage", permission: "storage.read", render: () => <StoragePage /> },
  { pattern: "/files", title: "Files", permission: "files.read", render: () => <FilesPage /> },
  { pattern: "/proxy", title: "Reverse proxy", permission: "network.read", render: () => <ProxyPage /> },
  { pattern: "/certificates", title: "Certificates", permission: "network.read", render: () => <CertificatesPage /> },
  { pattern: "/gate", title: "Opening app", render: () => <GatePage /> },
  { pattern: "/jobs", title: "Jobs", permission: "jobs.read", render: () => <JobsPage /> },
  { pattern: "/jobs/:id", title: "Job", permission: "jobs.read", render: (p) => <JobDetailPage id={p.id ?? ""} /> },
  { pattern: "/users", title: "Users", permission: "users.read", render: () => <UsersPage /> },
  { pattern: "/audit", title: "Audit log", permission: "audit.read", render: () => <AuditPage /> },
  { pattern: "/account", title: "Account", render: () => <AccountPage /> },
];

function Routes() {
  const { state, can } = useSession();
  const { path, search, navigate } = useRouter();

  // Keep the URL in line with the session state.
  useEffect(() => {
    if (state.status === "setup" && path !== "/setup") navigate("/setup", { replace: true });
    if (state.status === "anonymous" && path !== "/login") {
      // Keep the query: the sign-in gate (M12) carries its route in it.
      const query = search.toString();
      const next = path === "/setup" ? "/" : query ? `${path}?${query}` : path;
      navigate(`/login${next !== "/" ? `?next=${encodeURIComponent(next)}` : ""}`, { replace: true });
    }
    if (state.status === "authenticated" && (path === "/login" || path === "/setup")) navigate("/", { replace: true });
  }, [state.status, path, search, navigate]);

  if (state.status === "loading") {
    return (
      <main className="mx-auto max-w-md p-8">
        <Spinner label="Starting Kernhaven" />
      </main>
    );
  }
  if (state.status === "setup") return <SetupPage />;
  if (state.status === "anonymous") return <LoginPage expired={state.reason === "expired"} />;

  // MFA required by policy but not set up: only the own account (M11).
  if (state.session.mfa_enrollment_required) {
    document.title = "Set up a second factor · Kernhaven";
    return (
      <Layout>
        <AccountPage />
      </Layout>
    );
  }

  for (const r of routes) {
    const params = matchPath(r.pattern, path);
    if (!params) continue;
    const allowed = !r.permission || can(r.permission);
    document.title = `${allowed ? r.title : "Not found"} · Kernhaven`;
    return <Layout>{allowed ? r.render(params) : <NotFoundPage />}</Layout>;
  }
  document.title = "Not found · Kernhaven";
  return (
    <Layout>
      <NotFoundPage />
    </Layout>
  );
}

export function App() {
  return (
    <RouterProvider>
      <SessionProvider>
        <Routes />
      </SessionProvider>
    </RouterProvider>
  );
}
