# Open Democracy on Hyperledger Fabric

A minimal yet functional implementation of a democratic decision-making workflow on a permissioned blockchain (Hyperledger Fabric). It includes:

- **Chaincode (Go)** for bills/proposals, per-bill RBAC using bitwise roles, hierarchical scope checks from X.509 attributes, versioning of bill text (via IPFS hash) and domain events;
- A pure-Go **Service** layer that owns the business rules, used both by the chaincode entrypoint inside Fabric and by the in-process gateway outside it;
- A **Gateway + Dashboard** (`cmd/gateway`) that runs the same Service against a JSON-backed local store and exposes a REST API and a server-rendered HTML dashboard for bills, versions, votes, roles, participants, entities, and a live event feed (Server-Sent Events);
- A **Dockerfile + docker-compose** so the whole project can be brought up with a single command and the dashboard explored in a browser at `http://localhost:8080/`;
- A lightweight off‑chain event listener (Go, Fabric SDK, behind the `fabric_sdk` build tag) that subscribes to chaincode events when deployed against a real Fabric network.

This repository is intended as a clear, extensible base to prototype governance and participatory decision-making.

## Quickstart (dashboard in a container)

```
docker compose up --build
# then open http://localhost:8080/
```

The first boot seeds the ledger with **the project's own governance structure**
— participants are project contributors (Savio the lead, Alice the senior
maintainer, Bob the reviewer, community members, etc.) and proposals represent
real repository decisions:

| Proposal | Status | Purpose |
|---|---|---|
| **PROP-001** | `executed` | Architecture decision: extract the Service layer (completed full cycle) |
| **PROP-002** | `draft` (agreed) | Feature: migrate to Hotwire Turbo + Tailwind (ready for voting window) |
| **PROP-003** | `draft` | Governance: tighten quorum to 60% and count absence as rejection |
| **PROP-004** | `draft` | Community: contributor onboarding guide (community scope, not core) |
| **PROP-005** | `voting` | Release approval: v0.2.0 (active window, 2 of 5 votes cast — try it!) |

Use the "Acting as" selector in the header to switch between identities and
exercise the workflow:

- Create a proposal (PROPOSER or ADMIN authority required for the chosen scope)
- Add new versions while in draft (EDITOR or owner)
- Assign per-bill roles (ADMIN with hierarchical scope coverage)
- Vote on a draft version (VOTER role) until quorum + criteria are met → version is "agreed"
- Open the formal voting window (owner / proposer)
- Cast formal votes within the window (VOTER)
- End the vote and watch the proposal transition to `executed` or `rejected`

The bill ledger persists to a Docker volume (`open-democracy-ledger`), so the
dashboard survives restarts. Drop the volume with `docker compose down -v` to
re-seed.

### Local development without Docker

```
make test          # run unit tests
make run           # build and run the gateway on :8080 with ./data/ledger.json
```

Both modes use the same `bill.Service` that the chaincode wraps; only the
storage backend (Fabric stub vs. JSON file) and the identity source (X.509
attributes vs. seeded participants) differ.

## Introduction

Modern institutions often struggle to balance inclusiveness, auditability, and efficiency in collective decisions. Blockchains can provide verifiable state transitions and transparent audit logs, while permissioned networks like Hyperledger Fabric retain governance, privacy, and scalability for public sector, unions, or enterprise consortia. This project demonstrates:

- How to model a “bill” with draft versions and an agreement step before formal voting;
- How to encode eligibility and outcomes with bitwise roles and bitwise vote criteria, including explicit treatment of abstention and absence;
- How to gate actions by hierarchical scope claims in certificates (e.g., ES:TEACHER_UNION:DIVISION_2:ADMIN) so higher-level peers can authorize at lower levels.

## Motivation (Social Science Context)

Democratic governance is not only a technical problem; it is a social one. This prototype intentionally separates:

- Agreement on content (per-version votes while in draft), and
- Execution decision (formal ballot window with quorum and outcome masks).

Drawing from Karl Marx’s focus on material conditions and class power, durable governance must account for who is effectively present or absent from decision-making and how that absence is counted. By making “absence” a first-class category (via criteria masks), the system can model rules where non-participation can either block change or advance it, reflecting institutional norms.

Vladimir Lenin’s notion of democratic centralism emphasized broad debate followed by unified action. The two-stage process here (version agreement then bounded voting) offers a technical analogue: deliberation and convergence in draft, then a clear execution decision under explicit quorum. The hierarchical scope model also resembles federated structures (e.g., soviets/councils and higher bodies), where authority can cascade from broader to narrower levels. While this software is ideologically neutral, these references motivate design choices that make rules explicit and auditable: who is eligible, which roles count, and how abstentions/absence affect outcomes.

Related theory: participatory democracy, polycentric governance (Ostrom), and accountability in representative structures. This system aims to make such rules programmable and transparent.

## System Requirements

- OS: Linux or macOS (Windows via WSL2 recommended)
- Go: 1.24+ (module mode). Note: the module declares a newer Go directive; if your toolchain is older, adjust the `go` line in go.mod accordingly.
- Docker: 24+ and Docker Compose v2 plugin (or Podman 4+ as an alternative)
- Hyperledger Fabric: 2.5+ binaries and Docker images
- Fabric CA: 1.5+ (if issuing X.509 with attributes)
- fabric-samples: for the test-network scripts and channel setup
- Make, Bash, cURL, OpenSSL, Fabric CA client (fabric-ca-client)
- Network access to fetch Go modules (run `go mod tidy` if go.sum is missing)

Optional (for the listener):
- A Fabric connection profile (YAML) and credentials
- Environment variables described below

## Repository Layout

```
.
├── chaincode/
│   └── bill/
│       ├── types.go            # Data model (Bill, Version, Vote), bitwise Roles/Choices, Criteria
│       ├── invoker.go          # Pure-data Invoker with hierarchical scope helpers
│       ├── store.go            # Store interface + chaincode-stub adapter
│       ├── memstore.go         # In-memory Store used by the gateway and tests
│       ├── events.go           # EventSink interface + chaincode-stub adapter
│       ├── service.go          # Pure-Go business logic (CreateBill, voting, etc.)
│       ├── service_test.go     # Unit tests covering RBAC, scope, voting, end-to-end flow
│       ├── helpers.go          # Small string utilities
│       ├── contract.go         # Thin Fabric chaincode wrappers around Service
│       └── cmd/
│           └── main.go         # Chaincode entrypoint
├── cmd/
│   └── gateway/
│       └── main.go             # Gateway entrypoint (REST + dashboard, persists to JSON)
├── internal/
│   └── gateway/
│       ├── server.go           # HTTP server, embedded templates, middleware
│       ├── routes.go           # Route table
│       ├── api.go              # REST handlers + DTOs + SSE stream
│       ├── dashboard.go        # HTML dashboard handlers + form actions
│       ├── store.go            # JSON file persistence on top of bill.MemStore
│       ├── identity.go         # Participant registry (gateway's stand-in for X.509)
│       ├── seed.go             # Seeded participants and sample bills
│       ├── events.go           # In-process event broadcaster (history + live subscribers)
│       └── web/
│           ├── templates/      # layout.html + per-page templates (bill, entities, etc.)
│           └── static/style.css
├── notify/
│   └── listener/
│       └── main.go             # Real-Fabric SDK listener (build tag: fabric_sdk)
├── Dockerfile                  # Multi-stage static-binary build
├── docker-compose.yml          # Single-service stack with persistent volume
├── Makefile                    # test / build / run / image / up / down / logs
├── go.mod
└── README.md
```

## Architecture Overview

The project ships two deployment modes that share the same business logic:

```
                  ┌─────────────────────────────┐
                  │       bill.Service          │
                  │  (pure Go, no Fabric deps)  │
                  └──────┬───────────────┬──────┘
                         │               │
                ┌────────▼────┐    ┌─────▼──────┐
                │  Store /    │    │ EventSink  │
                │  EventSink  │    │            │
                │  interfaces │    │            │
                └────┬───┬────┘    └──┬───┬─────┘
                     │   │            │   │
        ┌────────────▼┐  └────┐  ┌────┘   └──────────┐
        │ Fabric stub │       │  │                   │
        │ adapters    │       │  │                   │
        │ (chaincode) │       │  │                   │
        └──────┬──────┘       │  │                   │
               │              │  │                   │
        ┌──────▼──────────┐   │  │   ┌───────────────▼───────────────┐
        │ Hyperledger     │   │  │   │  In-process gateway           │
        │ Fabric peers    │   │  │   │  (cmd/gateway)                │
        │ + chaincode/cmd │   │  │   │   • JSON-file Store           │
        └─────────────────┘   │  │   │   • SSE event broadcaster     │
                              │  │   │   • REST API + HTML dashboard │
                              │  │   │   • Seeded Participant registry│
                              │  │   └───────────────────────────────┘
                              │  │
                              ▼  ▼
                       MemStore + tests
```

- **Network (real deployment):** Hyperledger Fabric 2.5+ (peers per org, ordering service, channels by domain).
- **Identity (real deployment):** X.509 certificates carry hierarchical scope claims in attributes `scope` or `scopes`. A claim looks like `SEG1:SEG2:...:SEGN:ROLE`, where ROLE ∈ {ADMIN, PROPOSER, EDITOR, VOTER, AUDITOR}. Wildcard `*` is supported per segment.
- **Identity (gateway demo):** A `Participant` registry seeded at startup, with the same string-based scope claim format. The gateway resolves the active user from the `X-User` header (REST), the `?as=` query string (dashboard), or the `_user` form field.
- **Chaincode:** Thin wrappers in `chaincode/bill/contract.go` extract caller + tx timestamp from the Fabric context and call into `bill.Service`. Both deployment paths execute the exact same RBAC, scope, quorum, and criteria rules.
- **Off‑chain:** A real Fabric event listener still lives in `notify/listener/main.go` behind the `fabric_sdk` build tag (the upstream `fabric-sdk-go` is end-of-life and incompatible with the current `fabric-protos-go`, so it is not built by default). For the dashboard scenario the gateway's in-process broadcaster supersedes it: every domain event is fanned out to a ring buffer for the `/events` page and to a Server-Sent Events stream at `/api/events/stream`.

## Data Model (on‑ledger)

- Bill
  - id, owner, status ∈ {draft, voting, executed, rejected}
  - quorum ∈ [0,1]
  - criteria: bitwise masks {executeMask, rejectMask} over choices {YES, NO, ABSTAIN, ABSENCE}
  - scope: hierarchical scope pattern (e.g., `ES:TEACHER_UNION:DIVISION_2:*`)
  - versions: []Version (each Version keeps its own per‑version votes during draft)
  - roles: map[userID]Role (bitwise mask: PROPOSER, EDITOR, VOTER, AUDITOR, ADMIN)
  - votes: map[userID]Vote (votes in the formal voting window)
  - voteStart, voteEnd (epoch seconds)
  - agreedVersionIndex (index of version that reached agreement; -1 if none)
- Version
  - ipfsHash, description, timestamp, editor, votes (map[userID]Vote during draft)
- Vote
  - voterId, choice ∈ {YES, NO, ABSTAIN} (bitwise encoded), timestamp
- Criteria
  - executeMask, rejectMask (bitwise Choice). Masks may include ABSENCE to treat non-voters as counted toward a side.

## Access Control and Scopes

- Per-bill roles are bitwise (RoleProposer, RoleEditor, RoleVoter, RoleAuditor, RoleAdmin)
- Invoker reads `scope`/`scopes` attributes from the certificate. Claims are hierarchical; the final segment is a role token (e.g., `...:ADMIN`). Higher-level claims cover lower levels.
- Examples:
  - `ES:*:ADMIN` covers `ES:TEACHER_UNION:DIVISION_2:*`
  - `ES:TEACHER_UNION:*:PROPOSER` allows proposing under any division of that union

## Public Chaincode API (Fabric Contract API)

- CreateBill(ctx, billID, ipfsHash, description, quorum, scope, executeMask, rejectMask)
  - Create a new bill in draft and register the first version.
  - Authorization: PROPOSER or ADMIN (hierarchical). If `scope` is set, the invoker must have PROPOSER or ADMIN that covers it.
  - Criteria masks: expressions like `YES|ABSENCE` or `NO|ABSTAIN`. If both are empty, defaults are Execute=YES, Reject=NO.
  - Event: BillCreated { billId }
- EditBill(ctx, billID, ipfsHash, description)
  - Add a new version while status=draft. Authorization: EDITOR or owner.
  - Event: BillVersionAdded { billId, versionIndex }
- VoteOnVersion(ctx, billID, versionIndex, choice)
  - Vote YES/NO/ABSTAIN on a specific version while draft; requires VOTER role and scope.
  - Uses Criteria masks to compute participation and agreement; if quorum is met and execute > reject, sets agreedVersionIndex.
  - Events: VersionVoteAdded; VersionAgreed
- AssignRoleForBill(ctx, billID, userID, role)
  - Assign per-bill roles (e.g., `VOTER|EDITOR`). Authorization: ADMIN for the bill’s scope (hierarchical).
- SetBillScope(ctx, billID, scope)
  - Set hierarchical scope. Authorization: owner or PROPOSER (per-bill).
- SetBillCriteria(ctx, billID, executeMask, rejectMask)
  - Update criteria masks while draft. Authorization: owner or PROPOSER.
  - Event: CriteriaUpdated
- SubmitBill(ctx, billID, startTimeSeconds, durationSeconds)
  - Open formal voting window on the agreed version. Authorization: owner or PROPOSER.
  - Event: VoteStarted { billId, start, end, versionIndex }
- CastVote(ctx, billID, choice)
  - Cast a single vote (YES/NO/ABSTAIN) during the window; requires VOTER role and scope.
- EndVote(ctx, billID)
  - Finalize vote; compute participation based on masks, include ABSENCE if configured; set status executed/rejected.
  - Event: VoteEnded { billId, yes, no, abstain, absence, eligible, participation, executeCount, rejectCount, status }
- GetBill(ctx, billID) → string JSON

Notes:
- Full text is not stored on-chain; store content in IPFS and reference by hash in Version.
- Per-version votes are kept inside each Version for auditability.

## Events

- BillCreated
- BillVersionAdded
- VersionVoteAdded
- VersionAgreed
- VoteStarted
- VoteEnded
- CriteriaUpdated

## Gateway and Dashboard

`cmd/gateway` is the dashboard binary. It runs the same `bill.Service` the
chaincode wraps, against a JSON-backed local store, and exposes:

- **Dashboard pages** (server-rendered with `html/template`)
  - `GET /` — bills list with status, quorum, scope, version count
  - `GET /bills/{id}` — bill detail (versions, roles, formal votes, action forms)
  - `GET /participants` — directory of seeded identities and their scope claims
  - `GET /entities` — top-level scope segments with bills + participants under each
  - `GET /events` — chronological event feed updated live via SSE
- **REST API** (JSON over HTTP)
  - `GET /api/health`
  - `GET /api/bills` · `POST /api/bills` · `GET /api/bills/{id}`
  - `POST /api/bills/{id}/versions` (edit) · `POST /api/bills/{id}/versions/{idx}/votes`
  - `POST /api/bills/{id}/roles` · `POST /api/bills/{id}/submit`
  - `POST /api/bills/{id}/votes` (cast) · `POST /api/bills/{id}/end`
  - `GET /api/participants` · `GET /api/entities`
  - `GET /api/events` · `GET /api/events/stream` (SSE)

Authorization is resolved per request from one of (in priority order):
1. The `_user` form field (dashboard form actions)
2. The `X-User` header (REST API)
3. The `?as=` query string (dashboard navigation)
4. `GATEWAY_USER` environment variable (default participant id)

The id is looked up in the participant registry; the registry produces an
`*bill.Invoker` carrying the same kind of scope claims a Fabric X.509 cert
would carry, and the Service makes its authorization decisions on that.

### Configuration

| Variable        | Default      | Purpose                                  |
|-----------------|--------------|------------------------------------------|
| `GATEWAY_ADDR`  | `:8080`      | Listen address                           |
| `GATEWAY_DATA`  | `./data`     | Directory for `ledger.json` persistence  |
| `GATEWAY_USER`  | `ada`        | Default acting user                      |

### Curl examples

```bash
# Health
curl localhost:8080/api/health

# Create a bill as Ada (Division 1 proposer)
curl -X POST localhost:8080/api/bills \
  -H 'X-User: ada' -H 'Content-Type: application/json' \
  -d '{"id":"BILL-123","ipfsHash":"QmHash","description":"…","quorum":"0.5","scope":"ES:TEACHER_UNION:DIVISION_1:*","executeMask":"YES","rejectMask":"NO"}'

# Assign a voter as Felipe (Division 1 admin)
curl -X POST localhost:8080/api/bills/BILL-123/roles \
  -H 'X-User: felipe' -H 'Content-Type: application/json' \
  -d '{"userId":"carla","role":"VOTER"}'

# Subscribe to live events
curl -N localhost:8080/api/events/stream
```

## Off‑chain Listener (real Fabric only)

File: `notify/listener/main.go`. Built only with `-tags fabric_sdk` because
the upstream `fabric-sdk-go` is end-of-life and incompatible with the
`fabric-protos-go` version pulled in by the chaincode. For the dashboard
scenario the gateway's broadcaster (`/api/events/stream`) supersedes it.

Environment variables:
- FABRIC_SDK_CONFIG: path to the connection profile YAML
- FABRIC_CHANNEL: channel (e.g., mychannel)
- FABRIC_ORG: organization (e.g., Org1)
- FABRIC_USER: SDK user (e.g., User1)
- FABRIC_CC: chaincode name (e.g., bill)
- FABRIC_EVENT_FILTER: regex for event names (e.g., `.*`)

Run (real Fabric network only):
```
go run -tags fabric_sdk ./notify/listener
```

Replace `notifyUsersOfNewBill` with your messaging integration (e-mail, push, etc.).

## Deployment (test-network quickstart)

Using `fabric-samples/test-network` (Fabric 2.5+):
```
# From fabric-samples/test-network
./network.sh up createChannel -c mychannel -ca

# Deploy chaincode (adjust -ccp to your local path of this repo)
./network.sh deployCC -c mychannel -ccn bill -ccp ../../path/to/open-democracy/chaincode/bill -ccl go
```

Notes:
- The chaincode name `bill` should match FABRIC_CC used by the listener.
- Ensure users’ certificates carry proper `scope`/`scopes` claims like `SEG1:SEG2:...:ROLE`.

## Development and Build Notes

- Fetch dependencies: run `go mod tidy` at repository root (internet required). If a build fails with `-mod=readonly`, set `GOFLAGS=-mod=mod` or run with module downloads enabled.
- Toolchains: If your Go version predates the `go` directive in go.mod, update your toolchain or edit go.mod accordingly.
- Build listener: `go build ./notify/listener`
- Build chaincode package: follow your Fabric packaging flow, pointing to `chaincode/bill` (module root is this repository).

## IPFS Integration

- Upload document to IPFS, obtain the CID (Qm...)
- Call CreateBill/EditBill with the IPFS hash to pin the version content immutably off‑chain

## Security and Governance

- Role assignment requires ADMIN authority via hierarchical scope claims; higher scopes cover lower ones.
- Scope checks enforce that voters and editors belong to (or are above) the bill’s scope.
- Outcome rules are explicit via bitwise criteria; ABSENCE can be configured to count toward execution or rejection.
- Endorsement policies for chaincode should be set at deployment according to your network’s governance.

## Roadmap

- ~~Unit tests for RBAC, scope checks, quorum logic, and events~~ (done — `chaincode/bill/service_test.go`)
- ~~Web/API layer to drive the chaincode workflows~~ (done — `cmd/gateway` + dashboard)
- ~~Container build and one-command bring-up~~ (done — `Dockerfile`, `docker-compose.yml`, `Makefile`)
- Real Hyperledger Fabric network bring-up via `fabric-samples/test-network`, with the gateway pointing at it through a Fabric Gateway client instead of the in-process Service
- Replace the JSON-file Store with bbolt or Postgres for higher write volume
- Migrate the listener off the end-of-life `fabric-sdk-go` to `fabric-gateway`
- Real notification channels (e-mail, push) for the listener
- Certificate-based auth and IPFS pinning integration
- Governance-driven evolution of roles and criteria masks
