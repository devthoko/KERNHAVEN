# ADR-0033: Web UI information architecture and visual design

- Status: Proposed (pending owner review)
- Date: 2026-10-30

## Context
The first web UI grew one sidebar entry per milestone: 20 flat links, a
dashboard of technical cards (commit hash, build date, audit events, the
session) and tables for everything. The owner's review called it hard to
use and asked for a modern SaaS feel, oriented on the experience of CasaOS:
apps first, the system at a glance, everything else one step away.
Kernhaven shares the problem space with CasaOS, not its code, design assets
or branding (SPECIFICATION); we take the interaction patterns only.

## Decision
- **Areas instead of pages.** The sidebar lists areas grouped by what people
  come to do: *Home, Apps, Files, Storage, Backups*; **System**:
  *Monitoring, Docker, Network, Jobs*; **Administration**: *Users,
  Security*. Related pages of an area are tabs at the top of its content
  (Apps: Installed, App store, Catalog sources; Monitoring: Overview,
  Alerts; Docker: Containers, Stacks, Images, Volumes, Networks; Network:
  Reverse proxy, Certificates; Security: Overview, Audit log). The model is
  one table in `web/src/lib/navigation.ts`; every page belongs to exactly
  one area (unit-tested).
- **Permissions decide visibility only.** An area shows when the role may
  open at least one of its pages, and links to the first such page. The
  server still checks every request (security invariant: never trust
  frontend authorization decisions).
- **Home is apps first.** A greeting with an overall status pill; system
  widgets (processor, memory, storage, network); the installed apps as
  tiles that open the app's web UI with a separate *Manage* action and an
  *Add an app* tile; one *Needs attention* list that merges firing alerts,
  services that are down, jobs after a failed rollback, failed apps and
  available updates, most severe first; recent activity without the
  platform's own housekeeping jobs. Version, commit and agent details moved
  to Monitoring.
- **Account in the user panel.** Name, role, account settings and sign-out
  sit at the bottom of the sidebar (in the mobile drawer on phones).
- **Visual language.** Neutral slate surfaces, the existing teal brand,
  rounded cards with soft borders and shadows, an own 24-px stroke icon set
  (`Icon.tsx`, no icon dependency), coloured initials as app and user
  pictures until catalogs carry icons, ring badges, segmented controls, empty
  states that name the next step, back links on detail pages. Row actions in
  dense lists (files) are icon buttons whose accessible name and tooltip say
  what they do ("Rename note.txt"); first-run pages show the steps to the
  goal (backups). Light and dark
  themes stay; colours keep WCAG AA contrast (axe runs on every page in E2E).
- **No new runtime dependencies** and no inline styles beyond width
  percentages set through the DOM (CSP `style-src 'self'`).

## Consequences
- Fewer top-level choices (11 at most instead of 20); deep links keep
  working because routes did not change.
- E2E selectors changed where the UI did: the home heading is a greeting,
  catalog sources are a tab, the viewer check looks for the *Network* area.
- App tiles use initials until the catalog format gets icons (a later,
  signed catalog field; out of scope here).
- The UI stays English; translation is a separate decision.
