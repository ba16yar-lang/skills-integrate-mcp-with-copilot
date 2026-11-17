# ResuMint — architecture and delivery plan

## Phase 1: repository assessment

The existing application is a small extracurricular-activities example, not a
career-management product:

- **Backend:** Python and FastAPI in `app.py`; Uvicorn is the development server.
- **Frontend:** static HTML, CSS, and JavaScript under `static/`, served by
  FastAPI. There is no React or Next.js application.
- **Data:** a module-level Python dictionary. Changes are lost when the process
  restarts.
- **Authentication and authorization:** absent. The activities API accepts an
  email from the request and does not establish a user identity.
- **Documents and AI:** no import/export, document processing, or AI integration.
- **Tests and deployment:** no application tests, database migrations, or
  production build configuration. The GitHub Actions workflows support the
  repository's learning exercise, not application CI.
- **Dependencies:** FastAPI and Uvicorn (`requirements.txt`).

The existing application and its exercise materials should not be mistaken for
implemented career features. No production-readiness or product acceptance
criteria are met by the current code.
This section records the original repository baseline; the account and CV
foundation below supersedes its statements about authentication and tests.

## Account, identity, and Master CV foundation

The app now includes a first usable ResuMint account and career-data slice:

- Email registration requires one-time email verification before password
  login. Verification and password-reset tokens are high-entropy, stored only
  as SHA-256 digests, expire after one hour, and are consumed once.
- `POST /auth/forgot-password` returns the same response for known and unknown
  addresses. Password reset revokes every active session.
- Email is delivered through configured SMTP using SSL or STARTTLS.
- Sign-in/sign-up supports Google, a configured Microsoft Entra tenant, and a
  generic OpenID Connect discovery endpoint. OAuth authorization-code flow uses
  signed state, nonce, and PKCE. Provider subjects—not matching email addresses—
  identify accounts; automatic email-based account linking is prohibited.
- Redis provides atomic, shared request limits for email, password, recovery,
  verification, and OIDC endpoints. Local development uses a bounded in-process
  fallback only; production refuses to start without Redis.
- Authenticated profile routes and `/master-cv/me` are user-scoped. The Master
  CV API validates structured contact, summary, work, education, certification,
  skill, and project data; revision conflicts return HTTP 409, and each save
  creates an immutable revision visible at `/master-cv/revisions/me`.
- Email/password is the local authentication option. Google, a configured
  Microsoft Entra tenant, and one generic OIDC provider are optional sign-in
  choices; each requires credentials and callback registration. OIDC sign-up
  creates a separate identity and does not automatically link accounts by
  matching email.
- Persisted accounts have a server-managed `candidate` role. Master CV
  operations require both an allowed role permission (RBAC) and an owner match
  derived from the authenticated session (ABAC). No user-facing role elevation,
  recruiter access, sharing, or organization/tenant policies are implemented.
- `/static/account.html` provides email registration/sign-in, recovery,
  provider buttons, and an editable JSON Master CV. The original activities
  demo remains at `/legacy` and `/activities`; its routes are still public and
  must not be used for career data.

### Local development

```sh
python -m pip install -r requirements-dev.txt
alembic -c src/alembic.ini upgrade head
uvicorn src.app:app --reload
python -m pytest
```

The local default database is `./core456.db`. For email flows, configure
`SMTP_HOST`, `SMTP_PORT`, `SMTP_STARTTLS` (or `SMTP_SSL`), `EMAIL_FROM`, and any
SMTP credentials. The app deliberately does not log or return verification or
reset tokens. Configure OAuth variables to enable provider buttons.

## Production deployment: resumint.core456.com

The repository includes a production-oriented Dockerfile, Compose stack,
Caddy-managed HTTPS, and `.env.example`. DNS and cloud infrastructure cannot
be provisioned from this repository. Point `resumint.core456.com` to the host
and allow inbound TCP ports 80 and 443 so Caddy can issue and renew the TLS
certificate before accepting production traffic.

1. Install Docker Engine and the Compose plugin on the deployment host.
2. Copy `.env.example` to `.env`; keep `.env` private and out of version
   control. Create a 48-character-or-longer `APP_SECRET_KEY` (for example with
   `openssl rand -hex 32`), a strong URL-safe PostgreSQL password, and a
   `DATABASE_URL` such as
   `postgresql+psycopg://<user>:<url-encoded-password>@db:5432/<database>`.
3. Configure an SMTP provider with SSL or STARTTLS, and set `EMAIL_FROM`.
   Configure Google/Microsoft/OIDC credentials only for providers you intend to
   expose. Register exact HTTPS callback URLs:
   `https://resumint.core456.com/auth/oauth/google/callback`,
   `https://resumint.core456.com/auth/oauth/microsoft/callback`, and/or
   `https://resumint.core456.com/auth/oauth/oidc/callback`.
4. Set `PUBLIC_APP_URL` and `OAUTH_REDIRECT_BASE_URL` exactly to
   `https://resumint.core456.com`. Set `MICROSOFT_TENANT_ID` to your tenant ID
   or verified tenant domain. For a third-party OIDC provider, set its HTTPS
   discovery URL; the issuer and signing keys are validated by Authlib.
5. Compose includes Caddy, which terminates TLS, redirects HTTP to HTTPS, and
   forwards the original Host and client address. It uses a fixed container
   address (`172.30.0.2`) on the Compose network, and Uvicorn trusts only Caddy
   and loopback. If you change the Compose subnet or use another proxy, change
   the trusted proxy list to its exact source address. Never use `*`. The app
   only accepts the configured production Host header.
6. Build and migrate before starting the service:

   ```sh
   docker compose build
   docker compose run --rm app alembic -c src/alembic.ini upgrade head
   docker compose up -d
   docker compose ps
   ```

The Compose file publishes only Caddy's HTTP/HTTPS ports; PostgreSQL and Redis
are private to the application network. Back up the named database volume,
monitor `/health/live` and `/health/ready`, rotate provider and SMTP secrets,
and test restore and account deletion procedures before launch.
Production startup fails closed if the domain, HTTPS settings, database,
migrations, SMTP, Redis, or signing key are missing or inconsistent. Use a
managed PostgreSQL/Redis service with TLS and backups instead when required by
your hosting environment. HTTP request bodies are capped at 1 MiB; define and
test a separate upload limit and storage policy before enabling document import.

### External integration limits

The configured SMTP connection sends account verification and password-recovery
messages only; it does not connect to a user's mailbox or provide email search,
sending, or calendar access. Google/Microsoft/OIDC are authentication providers,
not recruitment-data integrations. No recruitment database, job-board, employer
website, job-discovery, application-submission, or job-specific CV-tailoring
connector is currently implemented.

Those integrations require named providers and supported APIs, provider
credentials, least-privilege scopes, user consent, privacy/retention decisions,
and testing against provider terms and rate limits. Do not grant the service
unrestricted mailbox access or scrape sites without authorization. Until these
integrations and the remaining career features are implemented and tested,
deployment provides the account and Master CV foundation only; it is not ready
to apply for jobs or to be represented as the completed ResuMint platform.

This is not yet a complete production career platform: account linking,
passwordless email login, recovery notifications/monitoring, audit trails,
account export/deletion, file import/export, CV templates/editor beyond the
structured Master CV, AI, tailoring, ATS, applications, and interview/career
features still need implementation and end-to-end testing. Do not represent
the current increment as meeting all final acceptance criteria.

Focused tests run with `python -m pytest`; migration checks should be run with
Alembic against a disposable database before deployment.

## Recommended target architecture

Extend the existing FastAPI service rather than replacing it with a new
framework before product needs are validated. Keep the static client for the
first vertical slice; introduce a component-based frontend only if the editor
and document-preview complexity justifies the migration. Separate API routes,
validation/schemas, domain services, persistence, and provider integrations as
those features are added.

- **API:** FastAPI with typed request/response schemas and authenticated,
  user-scoped routes.
- **Frontend:** responsive, accessible web client served separately or by
  FastAPI; use a component framework when building the interactive CV editor.
- **Persistence:** SQLAlchemy 2.x and Alembic migrations; SQLite for local
  development and PostgreSQL for deployed multi-user environments.
- **Authentication:** established session-based authentication with secure,
  HttpOnly, SameSite cookies, CSRF protection for mutations, and verified
  account recovery. Do not treat a submitted email address as identity.
- **AI:** provider-neutral service interface with configured server-side
  credentials, schema-validated responses, usage limits, and explicit
  provenance. Suggestions must be reviewable and must not modify the Master CV
  without user confirmation.
- **Documents:** validate file type and size, process uploads in an isolated
  service, and keep source files separate from generated versions. Generate PDF
  and DOCX from shared structured CV data and test generated output.
- **Operations:** environment-based configuration, structured audit events for
  sensitive operations, backups/retention controls, and a production deployment
  with HTTPS and restricted upload storage.

This keeps the current Python backend while avoiding an unneeded frontend or
database rewrite in the first increment. PostgreSQL is the production target;
SQLite is not a substitute for production deployment or authentication.

## Initial relational data model

Use an authenticated `User` as the ownership boundary. Every user-owned row
must carry or inherit an owner relationship, and every read, update, and delete
must be scoped to the authenticated user.

- `User` — unique normalized email, password hash or external identity, account
  state, and timestamps.
- `UserProfile` — contact details and locale/preferences.
- `MasterCV` — one or more named source profiles per user; versioned snapshots
  preserve originals.
- `Employment`, `Education`, `Certification`, `Skill`, `Project`, and
  `CustomSection` — ordered, structured evidence attached to a Master CV.
- `CVDocument` and `CVVersion` — generated CV metadata, source snapshot,
  selected template/settings, and export references.
- `Template` — application-managed template metadata; never stores user CV
  content.
- `JobDescription`, `JobApplication`, and `CoverLetter` — job-specific inputs,
  generated content, status, and user-editable application history.
- `ATSAnalysis`, `InterviewSession`, and `AIInteraction` — explainable results
  and suggestions linked to their source document/job and user.
- `AuditLog` — minimal security-relevant events, avoiding unnecessary CV text
  or credentials.

Add foreign keys, uniqueness constraints, indexes on ownership and lookup
fields, and migrations with each persistence phase. Uploaded files should live
in private object storage or a protected local storage adapter, not in public
static files.

## Dependency plan

Do not install the full preferred stack pre-emptively. Add and assess packages
when their phase begins:

| Need | Candidate | Timing |
| --- | --- | --- |
| ORM and migrations | SQLAlchemy 2.x, Alembic | Persistence |
| Schemas/settings | Pydantic (already provided by FastAPI), pydantic-settings if needed | API/configuration |
| Authentication | A maintained OAuth/OIDC or session-auth package selected for deployment | Identity |
| Tests | pytest, HTTPX | First API test slice |
| PDF/DOCX input | pypdf, python-docx | Import |
| PDF/DOCX output | ReportLab or HTML-to-PDF tooling, python-docx | Export |
| AI provider | Provider SDK behind a small adapter | AI features |
| Frontend tooling | React/TypeScript and a build tool, only if justified | CV editor |

Check package advisories and compatibility before adding each dependency, and
keep provider secrets out of source control and browser code.

## Security and privacy considerations

CVs contain personal and potentially sensitive employment information. Enforce
authorization at every object access; never rely on client-supplied user IDs.
Hash passwords with a maintained password-hashing implementation, rate-limit
authentication and costly AI endpoints, validate all inputs, and protect
cookie-authenticated mutations against CSRF. Restrict uploads by size and
verified content, store them outside the web root, and avoid unsafe document
parsing in request handlers. Keep AI credentials server-side, send only the
minimum required data to a configured provider, disclose that processing, and
make generated suggestions traceable to candidate evidence. Provide account
export/deletion and retention controls; avoid logging CV contents, tokens, or
passwords. Obtain a privacy/legal review before production use.

## Phased roadmap and acceptance gates

Each phase starts with a scoped objective, dependencies, risks, and acceptance
criteria. Do not claim a capability is complete until its acceptance checks
pass.

1. **Repository inspection and architecture (current):** record the existing
   stack, data/security gaps, target design, and staged plan. Acceptance:
   architecture and risks are documented without claiming unimplemented
   product features.
2. **Database, authentication, and user management (in progress):** migrations,
   verified registration, login/session, email recovery, OIDC sign-in, shared
   rate limits, and cross-user isolation tests. Account linking and external
   email-provider operational testing remain.
3. **Master CV (in progress):** structured editable sections and immutable
   revisions are implemented. Safe document import and a polished section
   editor remain.
4. **CV builder:** editable/reorderable sections, multiple saved CVs, and
   preview synchronized with saved content.
5. **Template engine:** at least ten meaningfully distinct layouts, including
   ATS-friendly structure.
6. **PDF/DOCX/TXT export:** multi-page export and content/layout verification.
7. **AI writing:** configured provider adapter, evidence-grounded suggestions,
   accept/reject/edit flow, and failure/usage handling.
8. **Job analysis and tailoring:** criteria/evidence mapping, unsupported
   requirements, and an original-preserving targeted version.
9. **ATS analysis:** explainable internal estimates and actionable findings;
   never imply proprietary scoring equivalence.
10. **Cover letters:** editable job-specific drafts with evidence traceability
    and export.
11. **Job tracker:** persistent applications, statuses, search, filters, and
    history.
12. **Interview preparation and Career Intelligence:** evidence-based question
    practice and reasoned skills/pathway suggestions.
13. **Security, testing, and production readiness:** end-to-end workflows,
    accessibility/responsive checks, deployment configuration, privacy
    controls, and operational documentation.

### Phase 1 completion

The assessment and target design above are the Phase 1 deliverable. This phase
does not add product functionality. The next implementation increment should
establish persistence and identity before storing CVs, because building
personal-data features on the current global in-memory state would risk data
loss and cross-user exposure.
