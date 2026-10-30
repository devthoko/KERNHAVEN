import { useEffect, useState } from "react";
import { Alert, Card, PageHeader, Spinner, link } from "../components/ui";
import { api, ApiError, errorMessage } from "../lib/api";
import { Link, useRouter } from "../lib/router";

/**
 * GatePage is where Caddy sends users of routes that require Kernhaven
 * sign-in (AT-F11-02). The Core checks the role and the return address and
 * hands back the app's one-time sign-in link.
 */
export function GatePage() {
  const { search } = useRouter();
  const route = Number(search.get("route"));
  const rd = search.get("rd") ?? "";
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    api.post<{ redirect: string }>("/proxy/gate", { route_id: route, rd }).then(
      (res) => {
        if (!cancelled) window.location.assign(res.redirect);
      },
      (err) => {
        if (cancelled) return;
        if (err instanceof ApiError && err.status === 403) setError("Your role cannot open this app. Ask an administrator for access.");
        else if (err instanceof ApiError && (err.status === 404 || err.status === 422)) setError("This link does not lead to an app that Kernhaven protects.");
        else setError(errorMessage(err));
      },
    );
    return () => {
      cancelled = true;
    };
  }, [route, rd]);

  // The address is not shown: it is unchecked until the Core accepted it.
  return (
    <>
      <PageHeader title="Opening app" description="Checking your access" />
      <Card>
        {error ? (
          <div className="space-y-3">
            <Alert>{error}</Alert>
            <p className="text-sm">
              <Link to="/" className={link}>
                Back to the dashboard
              </Link>
            </p>
          </div>
        ) : (
          <Spinner label="Opening the app" />
        )}
      </Card>
    </>
  );
}
