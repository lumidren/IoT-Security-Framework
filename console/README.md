# IronMesh Console

Operator console for the IronMesh IoT security framework: device lifecycle, certificates, OTA
campaigns, MQTT authorization policy, anomaly alerts, quarantine, audit and tenant access. It
consumes the HTTP and WebSocket interfaces fixed in [`docs/API_CONTRACT.md`](../docs/API_CONTRACT.md)
and follows the lifecycle, assurance and topic rules of [`docs/DESIGN_CONTRACT.md`](../docs/DESIGN_CONTRACT.md).

## Stack

Next.js 15 (App Router, React 19, `output: 'standalone'`), TypeScript strict +
`noUncheckedIndexedAccess`, Tailwind CSS 4, vendored shadcn/ui primitives (`src/components/ui`,
built on the `radix-ui` package), Auth.js v5 (generic OIDC provider), TanStack Query and Table,
Zod schemas for every contract model (`src/lib/api/schemas.ts`), Recharts, MapLibre GL,
CodeMirror 6 (`@uiw/react-codemirror`), lucide-react, next-themes, Vitest + Testing Library,
Playwright + `@axe-core/playwright`, Mock Service Worker, ESLint flat config, Prettier.

## Quick start

```bash
cd console
npm ci
cp .env.example .env.local        # fill in AUTH_SECRET and the OIDC / service URLs
npm run dev                       # http://localhost:3000
```

### Demo mode (no backend)

```bash
npm run build:mock                # builds into .next-mock with NEXT_PUBLIC_MOCK_API=true
AUTH_SECRET=dev-secret npm run start:mock    # http://localhost:3100
```

Or `NEXT_PUBLIC_MOCK_API=true npm run dev`. In demo mode a Mock Service Worker
(`src/mocks/browser.ts`, worker script `public/mockServiceWorker.js`) serves deterministic
fixtures from `src/mocks/fixtures/`: 50 devices across all lifecycle states (including software-key
devices, expiring and revoked certificates), 5 groups, 3 campaigns (running / completed / draft),
12 alerts, the tenant Rego policy with history, users, API keys and ~80 audit events. Mutations
(quarantine, twin patch, campaign creation, policy save, API key creation ...) update the in-memory
database so flows can be exercised end to end, including `409` twin conflicts and `422` Rego
compiler diagnostics. A mocked WebSocket feed emits connect/disconnect churn, per-device telemetry,
campaign progress and new alerts. The sign-in page gains a **Demo sign-in** that creates a session
for any role so RBAC can be explored. Never enable demo mode in production.

## Scripts

| Script                 | Purpose                                                                             |
| ---------------------- | ----------------------------------------------------------------------------------- |
| `npm run dev`          | Next.js dev server                                                                  |
| `npm run build`        | Production build (`.next`, standalone output)                                       |
| `npm run build:mock`   | Production build in demo mode (`.next-mock`)                                        |
| `npm run start`        | Serve the production build                                                          |
| `npm run start:mock`   | Serve the demo build on port 3100                                                   |
| `npm run lint`         | ESLint (flat config: next/core-web-vitals, next/typescript, prettier)               |
| `npm run typecheck`    | `tsc --noEmit`                                                                      |
| `npm test`             | Vitest unit + component tests (jsdom, MSW in Node)                                  |
| `npm run test:e2e`     | Playwright + axe suite against the demo build (builds and starts the server itself) |
| `npm run lhci`         | Lighthouse CI on the overview page of the demo build (needs a Chrome binary)        |
| `npm run format:check` | Prettier check (`npm run format` writes)                                            |

## Configuration

Copy `.env.example`. Two naming schemes are accepted: the Helm chart in `deploy/helm/ironmesh`
injects `CONSOLE_*` / `NEXT_PUBLIC_APP_URL` / `NEXT_PUBLIC_ENVIRONMENT`; the shorter names are
fallbacks for compose and local development.

| Variable                                                                               | Fallback                                           | Purpose                                                                                    |
| -------------------------------------------------------------------------------------- | -------------------------------------------------- | ------------------------------------------------------------------------------------------ |
| `AUTH_SECRET`                                                                          | –                                                  | Auth.js session encryption key (32 random bytes)                                           |
| `AUTH_TRUST_HOST`                                                                      | –                                                  | `true` behind a TLS-terminating reverse proxy                                              |
| `NEXT_PUBLIC_APP_URL`                                                                  | `AUTH_URL`                                         | Public console URL (OIDC redirect URI base, default WebSocket host)                        |
| `CONSOLE_OIDC_ISSUER`, `CONSOLE_OIDC_CLIENT_ID`, `CONSOLE_OIDC_CLIENT_SECRET`          | `AUTH_OIDC_*`, then `NEXT_PUBLIC_OIDC_*`           | Generic OIDC provider (discovery via `/.well-known/openid-configuration`, PKCE + state)    |
| `AUTH_ROLE_CLAIM`, `AUTH_TENANT_CLAIM`, `AUTH_TENANT_NAME_CLAIM`                       | `role`, `tenant_id`, `tenant_name`                 | Claims that carry the tenant role / tenant id (Keycloak `realm_access.roles` is also read) |
| `CONSOLE_REGISTRY_URL`, `CONSOLE_OTA_URL`, `CONSOLE_ANOMALY_URL`, `CONSOLE_POLICY_URL` | `REGISTRY_URL` ..., then `http://localhost:<port>` | Upstream services (server-side only)                                                       |
| `NEXT_PUBLIC_WS_URL`                                                                   | `wss://<app host>/v1/ws`, then current origin      | Browser-reachable registry WebSocket                                                       |
| `NEXT_PUBLIC_MAP_STYLE_URL`                                                            | bundled OSM raster style                           | MapLibre style                                                                             |
| `MAP_TILE_ORIGINS`                                                                     | `https://tile.openstreetmap.org`                   | Tile origins allowed by the CSP                                                            |
| `NEXT_PUBLIC_ENVIRONMENT`                                                              | –                                                  | Label shown next to the tenant badge (hidden for prod/production)                          |
| `NEXT_PUBLIC_MOCK_API`                                                                 | `false`                                            | Demo mode (see above)                                                                      |
| `NEXT_DIST_DIR`                                                                        | `.next`                                            | Build directory override used by the mock build                                            |

`NEXT_PUBLIC_*` values are inlined at build time: pass them as Docker build args.

## Architecture

- **Browser talks only to the console origin.** `src/app/api/proxy/[service]/[...path]/route.ts`
  forwards `/api/proxy/{registry|ota|anomaly|policy}/...` to the configured upstream, adds the
  session's OIDC access token as `Authorization: Bearer`, streams request/response bodies, forwards
  `Idempotency-Key`, `X-IronMesh-Tenant`, `If-Match`, `traceparent` and returns upstream RFC 9457
  problems untouched (plus `Idempotency-Replayed`, `Location`, `Content-Disposition`). It refuses
  `/internal/*` paths and every mutating method for the `viewer` role (403 problem); expired
  access tokens yield a 401 problem so the UI can prompt a new sign-in.
- **Auth.** `src/auth.ts` configures Auth.js with a generic `type: 'oidc'` provider (issuer
  discovery). The access token stays in the encrypted JWT cookie and is read server-side only
  (`src/lib/server/token.ts`); the session exposed to the browser carries `role`, `tenantId`,
  `tenantName`. `src/middleware.ts` redirects anonymous users to `/signin?callbackUrl=...` and
  returns 401 problems for API routes.
- **RBAC.** `src/lib/rbac.ts` maps permissions to minimum roles
  (`owner > admin > operator > viewer`; `factory` can only manufacture devices). Client components
  use `usePermission()` to hide or disable mutations; the proxy enforces the viewer guard
  server-side.
- **Data layer.** `src/lib/api/client.ts` (typed fetch, Zod parsing, `ApiError` with problem
  details, cursor pagination helpers, idempotency keys), `src/lib/api/hooks.ts` (TanStack Query
  hooks per endpoint, query keys in `src/lib/api/keys.ts`).
- **Live updates.** `src/app/api/ws/ticket/route.ts` mints a ticket (`POST /v1/ws/ticket`);
  `src/lib/ws.ts` is a reconnecting client (exponential backoff with full jitter, 30 s ping,
  ref-counted topic subscriptions). `src/providers/ws-provider.tsx` invalidates queries per frame
  (`src/lib/ws-invalidation.ts`) and appends sampled telemetry straight into cached series.
- **Shell.** Authenticated layout with collapsible sidebar (state in a cookie), command palette
  (Ctrl/Cmd+K: pages, actions, device search), tenant badge, WebSocket status, theme toggle, user
  menu. Heavy modules (MapLibre, Recharts, CodeMirror) are loaded with `next/dynamic` and reserve
  their height to avoid layout shift.

### Pages

| Route                                             | Highlights                                                                                                                                                                                                         |
| ------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `/`                                               | KPI tiles, clustered MapLibre fleet map with device drawer, firmware distribution chart, live event feed                                                                                                           |
| `/devices`                                        | Server-driven TanStack table, URL-persisted filters, cursor pagination, bulk add-to-group / send command, software-key warning badges, cards on mobile                                                             |
| `/devices/[id]`                                   | Quarantine / release / decommission with reason dialogs; Overview, Telemetry (live), Twin (version-conflict aware editor), Commands (idempotent, status timeline), Config (admin), Certificates, Timeline          |
| `/provisioning`                                   | Manufactured / enrolled / failed queues with approve and reject                                                                                                                                                    |
| `/campaigns`, `/campaigns/new`, `/campaigns/[id]` | Multi-step builder (firmware picker + upload dialog, target preview, stage editor with validation, review), stage progress, device table, halt / pause / resume / cancel / rollback with four-eyes note, audit tab |
| `/policy`                                         | CodeMirror Rego editor with version and hash, dry-run panel (allow/deny, matched rules, trace), history, owner-only save with 422 diagnostics                                                                      |
| `/alerts`, `/alerts/[id]`                         | Filters, ack / resolve (false-positive flag), explanation, features vs baseline, score sparkline, device timeline, quarantine shortcut                                                                             |
| `/quarantine`                                     | Reason / actor / since, release (admin)                                                                                                                                                                            |
| `/audit`                                          | Filters, details expander, NDJSON export (admin)                                                                                                                                                                   |
| `/settings/access`                                | Users and roles (owner can change), API keys (secret shown once), tenant security settings                                                                                                                         |
| `/signin`, `/forbidden`                           | OIDC button, demo sign-in in mock mode                                                                                                                                                                             |

## Deployment notes

### Reverse proxy and WebSocket

The browser connects **directly** to the registry WebSocket (`GET /v1/ws?ticket=...`); the ticket
is minted server-side by `/api/ws/ticket`. Expose the registry's `/v1/ws` on the console origin
(recommended) or on a dedicated host and set `NEXT_PUBLIC_WS_URL` accordingly. The proxy must
forward `Upgrade`/`Connection` headers and allow idle connections of at least 60 s (the client
pings every 30 s). If the WebSocket is served from another origin, add that origin to the CSP
`connect-src` (`next.config.ts` derives it from `NEXT_PUBLIC_WS_URL`).

Example nginx location block:

```nginx
location /v1/ws {
  proxy_pass http://registry:8000/v1/ws;
  proxy_http_version 1.1;
  proxy_set_header Upgrade $http_upgrade;
  proxy_set_header Connection "upgrade";
  proxy_read_timeout 120s;
}
```

### Docker

```bash
docker build -t ironmesh/console \
  --build-arg NEXT_PUBLIC_APP_URL=https://console.example.com \
  --build-arg NEXT_PUBLIC_WS_URL=wss://console.example.com/v1/ws \
  --build-arg NEXT_PUBLIC_ENVIRONMENT=staging .
docker run -p 3000:3000 --env-file .env ironmesh/console
```

Multi-stage image (deps → build → `node:24-alpine` runner), non-root `nextjs` user, `HEALTHCHECK`
on `/api/health`. Set `AUTH_TRUST_HOST=true` behind a proxy. Security headers (CSP, HSTS, frame
denial, referrer and permissions policies) are emitted by `next.config.ts`.

## Testing

- `npm test` — Vitest: API client (pagination, problem parsing, idempotency, schema mismatch),
  Zod schemas against the fixtures, RBAC matrix and proxy guard, stage validator, WebSocket client
  (reconnect/backoff/resubscribe/ping), WebSocket invalidation mapping, mock policy evaluator;
  component tests for the device table filters, campaign stage editor and policy dry-run panel.
- `npm run test:e2e` — Playwright against the demo build (`npm run build:mock && npm run start:mock`
  on port 3100): sign-in redirect and demo sign-in, overview KPIs and map, device filter → detail,
  quarantine dialog flow, campaign builder validation and creation, policy dry-run and owner save
  diagnostics, alert acknowledgement, viewer read-only checks, provisioning / quarantine / audit /
  settings pages. Every page and dialog state is scanned with axe (WCAG 2.x A/AA tags) and must
  have zero serious or critical violations. Browsers are installed in CI with
  `npx playwright install --with-deps chromium`; a ready-to-use GitHub Actions workflow is in
  `ci/github-workflow-console.yml` (copy to `.github/workflows/`).
- `npm run lhci` — Lighthouse CI (`lighthouserc.json`, desktop preset, three runs, assertions ≥ 0.95
  for Performance, Accessibility, Best Practices and SEO on `/`). `scripts/lhci.mjs` signs an
  Auth.js session cookie with the server's `AUTH_SECRET` so the authenticated overview is audited.

## Accessibility statement

The console targets WCAG 2.2 AA: semantic landmarks and a skip link, visible focus rings, keyboard
operable tables, menus, dialogs and tabs (Radix primitives), labels and descriptions associated
with every form control and error message, polite live regions for toasts and status, colour
tokens chosen for ≥ 4.5:1 contrast in both light and dark themes, reduced-motion support, minimum
24 px targets, responsive layouts from 360 px (tables collapse to cards) up to 4K, and axe scans in
the end-to-end suite. Charts carry text alternatives (`role="img"` labels and a visually hidden
data table); map markers are real buttons with descriptive labels and a textual fallback when
WebGL is unavailable. Known limitation: MapLibre's own canvas controls are excluded from the axe
scan; keyboard users can reach every device through the device list and command palette.
