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
| `MAP_TILE_ORIGINS`                                                                     | `https://tile.openstreetmap.org`                   | Tile origins allowed by the CSP (read per request by the middleware)                       |
| `CONSOLE_STEP_UP_MAX_AGE`                                                              | `300`                                              | Max age in seconds of the last sign-in for destructive actions (step-up, minimum 30)       |
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
  `/internal/*` paths (also when reached through dot segments or encoded slashes), cross-origin
  mutations (403), every mutating method for the `viewer` role (403 problem) and destructive
  actions without a recent sign-in (401 `step_up_required`, see [Security](#security)); expired
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
| `/auth/continue`, `/auth/reauth[/complete]`       | Same-origin hop for cross-site navigations (SameSite=Strict cookie); step-up re-authentication pop-up                                                                                                              |

## Deployment notes

### Reverse proxy and WebSocket

The browser connects **directly** to the registry WebSocket (`GET /v1/ws?ticket=...`); the ticket
is minted server-side by `/api/ws/ticket`. Expose the registry's `/v1/ws` on the console origin
(recommended) or on a dedicated host and set `NEXT_PUBLIC_WS_URL` accordingly. The proxy must
forward `Upgrade`/`Connection` headers and allow idle connections of at least 60 s (the client
pings every 30 s). If the WebSocket is served from another origin, add that origin to the CSP
`connect-src` (`src/middleware.ts` derives it from `NEXT_PUBLIC_WS_URL`).

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
on `/api/health`. Set `AUTH_TRUST_HOST=true` behind a proxy. Static security headers (HSTS, frame
denial, referrer, permissions and opener policies) are emitted by `next.config.ts`; the CSP is
per request (see [Security](#security)).

## Security

These controls close the console gaps recorded under T-51 and T-65 in `THREAT_MODEL.md`.

**Content-Security-Policy with nonces.** `src/middleware.ts` generates a 128-bit nonce per request
and builds the policy with `src/lib/security/csp.ts`:

```text
default-src 'self'; script-src 'self' 'nonce-<random>' 'strict-dynamic'; style-src 'self' 'unsafe-inline';
img-src 'self' data: blob: <tiles> <map style>; font-src 'self'; connect-src 'self' <tiles> <map style> <ws>;
worker-src 'self' blob:; manifest-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self';
object-src 'none'
```

The policy goes on the response and on the forwarded request (`content-security-policy` and
`x-nonce` request headers). Next.js 15 reads the nonce from the request header and puts it on its
own inline and chunk scripts; the root layout reads `x-nonce` and passes it to next-themes for its
inline theme script. Reading request headers in the root layout makes every page dynamically
rendered, which nonces require. `'strict-dynamic'` lets nonce-bearing scripts load the
code-split chunks (CSP3 browsers then ignore `'self'`, which stays as a CSP2 fallback). There is no
`'unsafe-inline'` for scripts; `'unsafe-eval'` and `ws:` (HMR) are added in `next dev` only.
`style-src` keeps `'unsafe-inline'`: Radix UI and next-themes set `style` attributes and CodeMirror
and Sonner inject `<style>` elements at runtime. Nonces cannot cover style attributes, and a nonce
in `style-src` would turn off `'unsafe-inline'` for them. Injected markup can therefore restyle the
page but cannot run script. Paths the middleware skips (static assets, `/api/auth`, `/api/health`)
get no CSP; they serve no HTML.

**CSRF (Origin check).** `/api/proxy/*` and `/api/ws/ticket` refuse POST, PUT, PATCH and DELETE with
a 403 problem unless `Origin` is the console's own origin; `Referer` is used only when `Origin` is
missing. If both are missing, or `Origin` is `null`, the request is refused. The console origin is
`AUTH_URL` / `NEXT_PUBLIC_APP_URL` (either is accepted). With neither configured it comes from the
request `Host`, and from `X-Forwarded-Host` / `X-Forwarded-Proto` when `AUTH_TRUST_HOST=true`
(`src/lib/security/origin.ts`). Auth.js endpoints keep their own double-submit CSRF token and server
actions keep Next.js's Origin check.

**Session cookie.** The Auth.js JWT session cookie is `HttpOnly`, `SameSite=Strict` and `Path=/`.
When the public URL is https (or, with no URL configured, in a production build other than the demo
build) it is also `Secure` and named `__Host-authjs.session-token`, so no subdomain can set or
shadow it (`src/lib/security/session-cookie.ts`). A Strict cookie is not sent on cross-site
navigations, including the redirect back from the IdP. The middleware therefore sends a cross-site
navigation without a session (`Sec-Fetch-Site: cross-site`) to `/auth/continue`, which re-navigates
from the console origin and so carries the cookie. The PKCE, state and callback-URL cookies stay
`SameSite=Lax` because the OIDC callback needs them.

**Step-up re-authentication.** The JWT stores `authTime`: the OIDC `auth_time` claim when the IdP
sends it, otherwise the sign-in time (also used by the demo provider). The proxy classifies the
upstream path after resolving dot segments and decoding `%2F` (`src/lib/security/step-up.ts`). It
refuses the routes below with `401` and a problem
`{"code": "step_up_required", "type": "urn:ironmesh:problem:step_up_required", "action": ..., "max_age": ...}`
(plus an RFC 9470 `WWW-Authenticate: Bearer error="insufficient_user_authentication"`) when
`authTime` is older than `CONSOLE_STEP_UP_MAX_AGE` (default 300 s) or missing:

| Action                           | Route                                                     |
| -------------------------------- | --------------------------------------------------------- |
| Quarantine / release device      | `POST registry /v1/devices/{id}/quarantine`, `/release`   |
| Decommission device              | `POST registry /v1/devices/{id}/decommission`             |
| Device config write              | `PUT registry /v1/devices/{id}/config`                    |
| API key create / revoke          | `POST registry /v1/api-keys`, `DELETE /v1/api-keys/{id}`  |
| Tenant settings                  | `PATCH registry /v1/tenants/me/settings`                  |
| User role change                 | `PUT registry /v1/users/{id}/role`                        |
| Policy save                      | `PUT policy /v1/policy` (not `/v1/policy/evaluate`)       |
| Campaign start / halt / rollback | `POST ota /v1/campaigns/{id}/start`, `/halt`, `/rollback` |

`apiFetch` passes that problem to `StepUpProvider` (`src/providers/step-up-provider.tsx`), which
opens a "Confirm it's you" dialog. With OIDC it opens `/auth/reauth` in a pop-up, which calls
`signIn('oidc', …, { prompt: 'login', max_age: '0' })`; `/auth/reauth/complete` reports back over a
`BroadcastChannel` (COOP `same-origin` severs `window.opener` once the pop-up visits the IdP). If the
pop-up is blocked, the whole tab goes through the same forced login and the operator repeats the
action afterwards. With the demo provider the demo sign-in is re-run in place. After
re-authentication the provider checks that `/api/auth/session` still belongs to the same user, and
then retries the original request once, with the same body and idempotency key: the proxy refused
it before contacting the service. In demo mode the Mock Service Worker answers `/api/proxy/*` in the
browser, so a passthrough MSW handler reproduces the same check from `/api/auth/session`. The
Playwright suite runs with `CONSOLE_STEP_UP_MAX_AGE=3600` so a long run is not interrupted.

Limits: if an IdP omits `auth_time`, the sign-in time is used. Under IdP SSO this can overstate
freshness for the first `CONSOLE_STEP_UP_MAX_AGE` seconds after a silent sign-in; the step-up flow
itself always forces `prompt=login`. The registry, OTA and policy services do not check
`auth_time` themselves, so the step-up control lives in the console BFF.

## Testing

- `npm test` — Vitest: security helpers (CSP builder and nonce, Origin check, step-up route
  classifier and age check, session cookie settings, redirect sanitiser), proxy and WebSocket ticket
  route handlers (allowed and blocked origins, step-up refusals, path-normalisation bypasses), the
  step-up dialog (demo re-sign-in, OIDC pop-up, blocked pop-up fallback, cancel), API client
  (pagination, problem parsing, idempotency, schema mismatch, step-up retry),
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
