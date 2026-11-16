# CORE456 Career Intelligence — architecture and delivery plan

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
2. **Database, authentication, and user management:** migrations, registration,
   login/session/recovery, and cross-user isolation tests.
3. **Master CV:** structured editable sections, source-preserving versioning,
   and safe document import with manual review.
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
