import { Link } from "../lib/router";

export function NotFoundPage() {
  return (
    <div className="py-16 text-center">
      <h1 className="text-2xl font-semibold">Page not found</h1>
      <p className="mt-2 text-sm text-slate-600 dark:text-slate-400">The page does not exist or you do not have access to it.</p>
      <Link to="/" className="mt-4 inline-block text-sm font-medium text-brand-700 underline dark:text-brand-500">
        Back to the dashboard
      </Link>
    </div>
  );
}
