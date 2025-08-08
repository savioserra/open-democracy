# Open Democracy on Hyperledger Fabric

A minimal yet functional implementation of a democratic decision-making workflow on a permissioned blockchain (Hyperledger Fabric). It includes:

- Chaincode (Go) for bills/proposals, per-bill RBAC using bitwise roles, hierarchical scope checks from X.509 attributes, versioning of bill text (via IPFS hash) and domain events;
- A lightweight off‑chain event listener (Go, Fabric SDK) that subscribes to chaincode events.

This repository is intended as a clear, extensible base to prototype governance and participatory decision-making.

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
│       ├── types.go           # Data model (Bill, Version, Vote), bitwise Roles/Choices, Criteria
│       ├── contract.go        # Business rules, hierarchical scope checks, events
│       └── cmd/
│           └── main.go        # Chaincode entrypoint
├── notify/
│   └── listener/
│       └── main.go            # Event listener skeleton (Fabric SDK)
├── go.mod
├── plan.pdf
└── README.md
```

## Architecture Overview

- Network: Hyperledger Fabric 2.5+ (peers per org, ordering service, channels by domain)
- Identity: X.509 certificates carry hierarchical scope claims in attributes `scope` or `scopes`. A claim looks like `SEG1:SEG2:...:SEGN:ROLE`, where ROLE ∈ {ADMIN, PROPOSER, EDITOR, VOTER, AUDITOR}. Wildcard `*` is supported per segment.
- Chaincode: Implements Bills, Versions, per-bill Roles, Version votes (in draft), formal voting window, and events.
- Off‑chain: Listener subscribes to events for notification workflows; full text is stored off‑chain (e.g., IPFS), on‑chain stores hashes.

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

## Off‑chain Listener

File: `notify/listener/main.go`

Environment variables:
- FABRIC_SDK_CONFIG: path to the connection profile YAML
- FABRIC_CHANNEL: channel (e.g., mychannel)
- FABRIC_ORG: organization (e.g., Org1)
- FABRIC_USER: SDK user (e.g., User1)
- FABRIC_CC: chaincode name (e.g., bill)
- FABRIC_EVENT_FILTER: regex for event names (e.g., `.*`)

Run:
```
export FABRIC_SDK_CONFIG=$PWD/connection-profile.yaml
export FABRIC_CHANNEL=mychannel
export FABRIC_ORG=Org1
export FABRIC_USER=User1
export FABRIC_CC=bill
export FABRIC_EVENT_FILTER=.*

go run ./notify/listener
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

- Unit and integration tests for RBAC, scope checks, quorum logic, and events
- Preference service and real notification channels for the listener
- Web/API layer for certificate-based auth and IPFS integration
- Governance-driven evolution of roles and criteria masks
