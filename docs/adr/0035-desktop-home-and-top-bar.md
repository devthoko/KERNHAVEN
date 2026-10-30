# ADR-0035: Desktop home, top bar and command palette

- Status: Proposed (pending owner review)
- Date: 2026-10-30
- Refines: ADR-0033

## Context
After the first redesign (ADR-0033) the owner asked for a complete redesign
in a "hybrid" direction: the start page should feel like a homeserver
desktop (as in CasaOS — patterns only, no assets or branding), while the
management pages stay a calm SaaS view. Finding things should not depend on
knowing the navigation.

## Decision
- **Top bar on every page:** search ("Search or jump to…", Ctrl+K/⌘K),
  notification bell, account menu (account settings, theme, sign out). On
  phones the account actions sit in the menu drawer.
- **Home is a desktop:** a CSS-only colour background (no image files),
  frosted "glass" widgets on the left (clock, system, storage, network),
  greeting and overall status, installed apps as large launcher icons that
  open the app (a separate *Manage* button per app), *Needs attention*,
  recent activity, and a dock of all management areas, which is the main
  navigation on the home page. There is no sidebar on the home page.
- **Management view:** sidebar of areas (ADR-0033), area tabs, content.
- **One status source:** a `StatusProvider` in the shell reads alerts,
  service health, jobs, installed apps and security findings once for the
  home page and the bell. It uses the normal permission-checked API; what a
  role may not read counts as empty, and a source that fails is reported as
  "Some checks could not run" instead of "all normal".
- **Command palette:** pages the role may open, installed apps (open or
  manage) and actions (install an app, new container or stack, account,
  theme, sign out), filtered by every typed word. Accessible as an ARIA
  combobox with a grouped listbox; it only navigates or calls the same
  actions as the UI, so it adds no new authority.
- **App icons:** gradient tiles with initials, stable per name, until
  catalogs carry icons.

## Consequences
- Two navigation surfaces (dock on home, sidebar elsewhere) with the same
  model from `lib/navigation.ts`; both are named "Main" and never shown at
  the same time.
- E2E signs out through the account menu and checks the palette and the
  bell, including axe.
- Glass surfaces rely on `backdrop-filter`; without it they fall back to
  semi-opaque panels with the same contrast.
