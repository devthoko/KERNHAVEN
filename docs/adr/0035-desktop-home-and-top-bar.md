# ADR-0035: One shell, top bar, command palette and design rules

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
A first version gave the home page its own desktop layout (background,
glass widgets, dock instead of sidebar). The owner found the UI
inconsistent; this decision replaces it with one shell and written rules.

- **One shell for every page:** sidebar of areas (ADR-0033), a top bar with
  search (Ctrl+K/⌘K), notification bell and account menu (account, theme,
  sign-out; in the drawer on phones), area tabs, content. Home has no
  layout of its own.
- **Home** keeps the homeserver feel through its content, not its frame:
  greeting and status pill in the normal page header, four stat cards
  (processor, memory, storage, network), the installed apps as large
  launcher icons in a card (open; separate *Manage*), *Needs attention* and
  recent activity.
- **One status source:** a `StatusProvider` in the shell reads alerts,
  service health, jobs, installed apps and security findings once for the
  home page and the bell; what a role may not read counts as empty, and a
  failed source is reported as "Some checks could not run".
- **Command palette:** pages the role may open, installed apps (open or
  manage) and actions, filtered by every typed word; an ARIA combobox with
  a grouped listbox that only navigates or calls existing actions.

### Design rules (enforced by the shared components in `ui.tsx`)
| Element | Rule |
|---|---|
| Page | `PageHeader` (title, one-line description, actions right) on every page |
| Surfaces | `Card` only; no page-specific panels or backgrounds |
| Links | `link` style (brand colour, soft underline) for every link in content and card headers |
| Link that acts like a button | `buttonClass(variant)` — same look as `Button` |
| States | `StatusBadge` (containers, stacks, apps: Running, Starting, Stopping, Stopped, Failed, Not deployed), `JobStateBadge` (jobs), `DotBadge` for any other state; all with a dot |
| Labels | `Badge` text starts with a capital letter |
| Choices of 2–4 | `Segmented` (time range, theme) |
| Row actions | ghost text buttons, destructive ones `ghost-danger`; the hidden part of the name says the object ("Delete note.txt") |
| Empty lists | `EmptyState` with the next step |
| Pictures | apps: `AppIcon` (gradient tile); people: `Avatar` (circle) |
| Accessible names | from visible text plus hidden words, not `aria-label` over different visible text (WCAG 2.5.3) |

## Consequences
- Every page looks and behaves the same around its content; new pages get
  consistency by using the shared components, and review checks the rules
  above.
- Docker states are worded like apps and stacks ("exited" shows as
  Stopped); E2E follows the new words.
- E2E signs out through the account menu and checks the palette and the
  bell, including axe.
