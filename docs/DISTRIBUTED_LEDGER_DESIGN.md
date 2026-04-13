# Distributed Ledger Design: Unified Federation Architecture

> How unions, governments, companies, and communities coexist as
> co-participating nodes in a single governance network.

## 1. Where We Are Today

### What exists and works

The core governance engine (`chaincode/bill/service.go`) is **complete and
production-tested**. It already handles:

| Capability | Status | Notes |
|---|---|---|
| Two-stage decision making (draft + vote) | Done | Democratic centralism model |
| Hierarchical scope authority (`ES:UNION:DIV:ROLE`) | Done | Covers any nesting depth |
| Bitwise RBAC (PROPOSER, EDITOR, VOTER, AUDITOR, ADMIN) | Done | Per-bill + per-scope |
| Liquid democracy (depth-1 delegation) | Done | Scope-specific, revocable |
| Popular initiative (petitions) | Done | Threshold-triggered auto-bill |
| Vote receipts (verifiable, privacy-preserving) | Done | One-time receipt tokens |
| Event sourcing (immutable audit log) | Done | SSE stream for live updates |
| Absence as first-class category | Done | Bitwise criteria masks |
| Hyperledger Fabric chaincode wrapper | Done | `contract.go` ready to deploy |
| Single-node container (gateway + JSON store) | Done | `docker compose up --build` |

### What is missing for multi-node federation

| Gap | Severity | Description |
|---|---|---|
| **Multi-org Fabric network orchestration** | Critical | No docker-compose or scripts to bring up a real multi-peer, multi-org Fabric network |
| **Organization onboarding workflow** | Critical | No automated way for a new entity to generate crypto material, join a channel, and install chaincode |
| **Certificate Authority with scope attributes** | Critical | Fabric CA must issue X.509 certs carrying `scope` attributes — no enrollment scripts exist |
| **Gateway ↔ Fabric connection** | High | The gateway currently runs in-process (`MemStore`); needs a Fabric Gateway client mode |
| **Cross-network relay (inter-federation)** | Medium | Separate Fabric networks (e.g., two governments) cannot talk to each other yet |
| **IPFS integration** | Medium | Bill text references IPFS hashes but no pinning service is wired up |
| **Production store backend** | Low | JSON file works for demo; bbolt or PostgreSQL for write volume |
| **Notification channels** | Low | Listener stub exists; needs email/push integration |

**Bottom line:** The governance logic is ready. The gap is **infrastructure
orchestration** — getting multiple organizations to run peers, share a channel,
and issue certificates with the right scope claims.

## 2. Federation Architecture

### 2.1 What "a node in the network" means

In Hyperledger Fabric, a **node** is not a single container — it is an
**organization's infrastructure**:

```
Organization (e.g., "City of Porto Alegre")
├── Peer node(s)         — stores ledger, executes chaincode, endorses txs
├── Certificate Authority — issues X.509 identities with scope attributes
├── Ordering node*       — participates in Raft consensus (optional per org)
├── Gateway service      — REST API + dashboard for human interaction
└── IPFS node (optional) — pins bill text content
```

*Ordering nodes can be shared across orgs or each org can contribute one to
the Raft cluster for stronger decentralization.*

### 2.2 Network topology

```
                    ┌──────────────────────────────────┐
                    │      Raft Ordering Service        │
                    │  orderer1.od  orderer2.od  ...    │
                    └──────┬───────────┬───────────┬───┘
                           │           │           │
            ┌──────────────┤           │           ├───────────────┐
            │              │           │           │               │
     ┌──────▼──────┐ ┌────▼─────┐ ┌───▼────┐ ┌───▼─────┐  ┌─────▼──────┐
     │  Org: Open  │ │Org: City │ │Org:    │ │Org:     │  │ Org: Corp  │
     │  Democracy  │ │Gov       │ │Union   │ │State    │  │ XYZ        │
     │  Foundation │ │          │ │        │ │Gov      │  │            │
     │             │ │          │ │        │ │         │  │            │
     │ peer0       │ │ peer0    │ │ peer0  │ │ peer0   │  │ peer0      │
     │ ca          │ │ ca       │ │ ca     │ │ ca      │  │ ca         │
     │ gateway     │ │ gateway  │ │gateway │ │ gateway │  │ gateway    │
     └──────┬──────┘ └────┬─────┘ └───┬────┘ └───┬─────┘  └─────┬──────┘
            │              │           │           │               │
            └──────────────┴─────┬─────┴───────────┘               │
                                 │                                 │
                    ┌────────────▼─────────────┐     ┌─────────────▼────────┐
                    │  Channel: governance     │     │ Channel: corp-internal│
                    │  (cross-org decisions)   │     │ (private to Corp XYZ)│
                    └──────────────────────────┘     └──────────────────────┘
```

### 2.3 Channel strategy for co-participation

Fabric **channels** are the isolation boundary. Each channel has its own
ledger, its own chaincode instances, and its own endorsement policies.

| Channel | Members | Purpose |
|---|---|---|
| `governance` | All federation members | Cross-org proposals, network-wide votes |
| `{org}-internal` | Single org | Internal decisions (HR, budget, policy) |
| `{topic}-working-group` | Subset of orgs | Thematic collaboration (education, health) |
| `bilateral-{org1}-{org2}` | Two orgs | Bilateral agreements |

**The same chaincode** (`bill`) is installed on every channel. The **scope
hierarchy** naturally namespaces decisions:

```
FEDERATION                          → network-wide governance channel
├── GOV:CITY_PORTO_ALEGRE           → city government internal channel
│   ├── HEALTH                      → health department scope
│   └── EDUCATION                   → education department scope
├── UNION:TEACHERS                  → teachers' union internal channel
│   ├── DIVISION_SOUTH              → regional division
│   └── DIVISION_NORTH
├── CORP:XYZ                        → corporate internal channel
│   ├── ENGINEERING
│   └── OPERATIONS
└── OPENDEMOCRACY                   → this project's own governance
    ├── CORE
    └── COMMUNITY
```

### 2.4 How scope claims enable natural federation

The `Invoker` already parses hierarchical scope claims from X.509
attributes. When a government employee's certificate carries:

```
scope=GOV:CITY_PORTO_ALEGRE:HEALTH:ADMIN
```

They automatically have:
- ADMIN authority over `GOV:CITY_PORTO_ALEGRE:HEALTH:*` bills
- Scope coverage for any sub-scope under HEALTH
- No authority over `UNION:TEACHERS:*` or `CORP:XYZ:*` scopes

This is **already implemented** in `invoker.go:scopeCovers()`. The scope
hierarchy IS the federation mechanism — no additional protocol needed.

## 3. How Entities Onboard

### 3.1 Government adaptation

A government adapting the system would:

1. **Stand up infrastructure** (see `federation/docker-compose.node.yml`):
   - 1+ Fabric peer containers
   - 1 Fabric CA container
   - 1 open-democracy gateway container
   - 1 CouchDB container (optional, for rich queries)

2. **Generate crypto material**:
   - The CA issues certificates to government employees
   - Each cert carries scope attributes matching the org structure:
     ```
     Mayor         → GOV:CITY:ADMIN
     Dept. Head    → GOV:CITY:HEALTH:ADMIN
     Civil servant → GOV:CITY:HEALTH:VOTER
     Citizen       → GOV:CITY:COMMUNITY:VOTER
     ```

3. **Join the federation channel**:
   - Submit their MSP definition to existing members
   - Existing members vote (using the system itself!) to approve
   - Once approved, their peer syncs the ledger and installs chaincode

4. **Create internal channels** (optional):
   - For decisions that don't need network-wide visibility
   - Same chaincode, same dashboard, different privacy boundary

5. **Map existing processes**:
   - City council votes → bills with `GOV:CITY:COUNCIL:*` scope
   - Public consultations → petitions at `GOV:CITY:COMMUNITY:*` scope
   - Budget approval → bills requiring 2/3 quorum with absence-as-rejection

### 3.2 Union adaptation

A union would similarly:

1. Stand up their node (same container stack)
2. Map their internal structure to scopes:
   ```
   UNION:TEACHERS:NATIONAL:ADMIN        → national leadership
   UNION:TEACHERS:STATE_SP:VOTER        → Sao Paulo chapter member
   UNION:TEACHERS:STATE_RJ:PROPOSER     → Rio chapter can propose
   ```
3. Join the federation channel for cross-org matters
4. Use petitions for rank-and-file initiatives (no admin can block)
5. Use delegations for assemblies where members can't attend

### 3.3 Company adaptation

A company would:

1. Stand up their node
2. Map corporate governance to scopes:
   ```
   CORP:XYZ:BOARD:ADMIN                 → board of directors
   CORP:XYZ:ENGINEERING:PROPOSER        → eng team can propose
   CORP:XYZ:ENGINEERING:TEAM_A:VOTER    → team-level votes
   ```
3. Use private channels for sensitive decisions
4. Optionally join a consortium channel for industry-wide standards

### 3.4 This repository joining its own network

Open Democracy already governs itself through the system (see seed data).
To move from demo to production, it needs to:

1. Deploy chaincode to a real Fabric peer
2. Replace `MemStore` with the Fabric stub adapter
3. Issue contributor certificates via Fabric CA with existing scope claims

## 4. Does a Container Suffice?

**Yes, but it's not one container — it's a container stack per organization.**

### Minimal node (single-org, joining existing network)

```yaml
# 4 containers per organization:
services:
  peer:      # Fabric peer — stores ledger, runs chaincode
  ca:        # Certificate Authority — issues identities
  gateway:   # Open Democracy dashboard + REST API
  couchdb:   # Optional — rich queries on ledger state
```

This is packaged as `federation/docker-compose.node.yml`. A new organization
runs:

```bash
# 1. Configure their org name, scope prefix, and runtime domain
./bin/odctl node setup --org-name city-gov --scope-prefix GOV:CITY_PORTO_ALEGRE --domain city-gov.od.local

# 2. Generate crypto material
./bin/odctl node bootstrap

# 3. Start the node
./bin/odctl node start

# 4. Join the federation (requires approval from existing members)
./federation/scripts/join-network.sh --channel governance --orderer orderer1.od.example.com:7050
```

### Full network bootstrap (founding consortium)

The first time the network is created, a founding set of organizations
bootstraps the orderer cluster and genesis channel:

```bash
./bin/odctl network start
```

This generates an isolated founding-network run under
`federation/runs/<instance>/`, writes the compose/configtx/crypto-config files
for that topology, bootstraps the Fabric artifacts, and starts Docker Compose
with an instance-specific project name so repeated runs stay isolated.

## 5. How Blockchains Talk Across Networks

### 5.1 Within a single Fabric network (our primary model)

Inside one Fabric network, communication happens through **channels**:

```
Org A's peer ──endorses──▶ Orderer ──distributes──▶ Org B's peer
                              │
                    committed to shared ledger
```

- **Endorsement policies** ensure multiple orgs must agree on state changes
- **Private data collections** allow org-to-org secrets within a channel
- **Chaincode-to-chaincode calls** allow cross-channel reads (same peer)

This is the **recommended model** for open-democracy federation. All member
organizations share a Fabric network and communicate through channels.

### 5.2 Across separate Fabric networks (inter-federation)

When two completely separate Fabric networks need to communicate (e.g.,
Brazil's federation and Spain's federation), there are several patterns:

#### Pattern A: Relay / Bridge Service

```
┌─────────────────┐         ┌──────────┐         ┌─────────────────┐
│ Fabric Network A │◀──────▶│  Relay   │◀──────▶│ Fabric Network B │
│ (Brazil Fed.)    │  gRPC  │  Service │  gRPC  │ (Spain Fed.)     │
└─────────────────┘         └──────────┘         └─────────────────┘
```

- **Hyperledger Weaver** (now part of Hyperledger Cacti) provides exactly
  this: cross-network data sharing and asset exchange with cryptographic
  proofs
- The relay verifies state proofs from network A before writing to network B
- Both networks retain sovereignty — they only share what they choose to

#### Pattern B: Hash anchoring

```
Network A                              Network B
┌────────────┐    Merkle root hash     ┌────────────┐
│ Bill passes │ ──────────────────────▶ │ Anchor tx  │
│ in Brazil   │    (posted as proof)    │ records    │
└────────────┘                         │ Brazil's   │
                                       │ decision   │
                                       └────────────┘
```

- Network A publishes a Merkle root or state proof to Network B
- Network B can verify the proof without trusting Network A's peers
- Used for mutual recognition of decisions without full integration

#### Pattern C: Cosmos IBC / Polkadot XCMP model

Public blockchain ecosystems solve cross-chain communication with:

- **IBC (Inter-Blockchain Communication)**: Light clients of chain A run on
  chain B, verifying headers and state proofs. Each chain is sovereign but
  can send packets to any other IBC-enabled chain.
- **XCMP (Cross-Consensus Message Passing)**: Polkadot parachains share a
  relay chain that provides finality. Messages are routed through the relay.

For Hyperledger Fabric, the equivalent is **Hyperledger Cacti** (formerly
Cactus + Weaver), which provides:
- Cross-network identity verification
- Atomic asset transfers
- Data sharing with state proofs
- Protocol-agnostic relay architecture

#### Pattern D: Federated API layer (pragmatic first step)

Before implementing full cross-chain protocols, federations can communicate
through their **gateway APIs**:

```
Federation A's Gateway ──REST/gRPC──▶ Federation B's Gateway
     │                                        │
     ▼                                        ▼
  Fabric Network A                    Fabric Network B
```

- Gateways expose read-only APIs for decision verification
- A bill passed in Federation A can be referenced in Federation B
- No shared ledger — each federation verifies via API + digital signatures
- This is the **fastest path to inter-federation** and can be implemented now

### 5.3 Recommended progression

| Phase | Scope | Mechanism |
|---|---|---|
| **Phase 1** (now) | Single Fabric network, multiple orgs | Channels + endorsement policies |
| **Phase 2** | Cross-network reads | Gateway API federation + hash anchoring |
| **Phase 3** | Cross-network writes | Hyperledger Cacti relay |
| **Phase 4** | Global federation | IBC-style light client verification |

## 6. Endorsement and Consensus

### How decisions get committed

Hyperledger Fabric uses a **execute-order-validate** model:

1. **Execute**: Client sends proposal to endorsing peers (from multiple orgs)
2. **Order**: Orderer (Raft consensus) sequences endorsed transactions
3. **Validate**: All peers validate endorsements and commit to ledger

For open-democracy, the endorsement policy should reflect governance:

```
# Require endorsement from a majority of member organizations
# This means no single org can unilaterally modify the ledger
AND(
  OutOf(majority, 'OrgA.peer', 'OrgB.peer', 'OrgC.peer', ...),
  # OR for internal channels, just the owning org:
  'OrgA.peer'
)
```

### Double layer of consensus

Open-democracy has **two consensus layers**:

1. **Infrastructure consensus** (Fabric): ensures the ledger is consistent
   across all peers — no org can forge transactions
2. **Governance consensus** (bill.Service): ensures decisions follow
   democratic rules — quorum, criteria masks, scope authority, delegation

This separation is a strength: the infrastructure guarantees integrity,
the application guarantees legitimacy.

## 7. Security Model for Federation

### Trust boundaries

| Boundary | Mechanism |
|---|---|
| Identity | X.509 certificates from each org's CA |
| Authorization | Scope claims in cert attributes + per-bill RBAC |
| Ledger integrity | Fabric endorsement policies (multi-org) |
| Privacy | Channel isolation + private data collections |
| Audit | Immutable event log + vote receipts |
| Inter-org trust | Endorsement requires multiple org signatures |

### What prevents abuse

- **No single org controls the ordering service** (Raft cluster across orgs)
- **Endorsement policies require multi-org agreement** for state changes
- **Scope hierarchy prevents lateral movement** (union admin can't touch gov scope)
- **Petitions bypass admin gatekeeping** (popular mandate creates bills directly)
- **Vote receipts enable verification** without compromising ballot secrecy
- **Absence counting prevents** silent non-participation from blocking progress

## 8. Summary: Distance to "New Node in the Network"

### What exists (ready today)
- Complete governance logic (bills, votes, delegations, petitions)
- Hierarchical scope system (the federation mechanism)
- Chaincode ready for Fabric deployment
- Single-node containerized demo

### What this design adds
- Multi-org Fabric network templates (`federation/`)
- Node bootstrap scripts for new organizations
- Organization onboarding workflow
- Channel strategy for co-participation
- Cross-network communication roadmap

### What remains after this
- Gateway ↔ Fabric client integration (replace MemStore with Fabric Gateway SDK)
- IPFS pinning service integration
- Production CA enrollment workflows
- Cross-network relay (Hyperledger Cacti) for inter-federation
- Quadratic voting and conviction voting (future voting mechanisms)

### Estimated effort to first multi-org demo

| Task | Effort |
|---|---|
| Fabric network with 2 orgs (using test-network) | Hours |
| Chaincode deployed with endorsement policy | Hours |
| CA issuing certs with scope attributes | Days |
| Gateway connected to Fabric (instead of JSON) | Days |
| Third org joins via onboarding scripts | Days |
| Cross-network relay (Cacti) | Weeks |

The system is architecturally ready for federation. The gap is operational
tooling, not fundamental design.
