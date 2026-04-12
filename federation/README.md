# Federation Guide: Joining the Open Democracy Network

This directory contains everything needed to run an open-democracy node and
join the federated governance network. Whether you are a **government**,
**union**, **company**, or **community organization**, the process is the same:
stand up a container stack, get approved by existing members, and start
participating.

## What is a federation node?

A node is your organization's infrastructure in the network — typically **3-4
containers** running on a single machine (or spread across a cluster):

| Container | Purpose | Required? |
|---|---|---|
| **Fabric Peer** | Stores the blockchain ledger, executes chaincode | Yes |
| **Fabric CA** | Issues X.509 certificates with scope attributes | Yes |
| **Gateway** | Dashboard + REST API for humans | Yes |
| **CouchDB** | Rich queries on ledger state | Optional |

All containers are standard Docker images. A modest server (2 CPU, 4GB RAM)
is sufficient for a peer with thousands of participants.

## Quick start (5 steps)

```bash
# 1. Clone the repository
git clone https://github.com/savioserra/open-democracy.git
cd open-democracy/federation

# 2. Configure your organization
cp config/org-template.env .env
# Edit .env — set ORG_NAME, SCOPE_PREFIX, etc.

# 3. Bootstrap your node (generates crypto material)
./scripts/bootstrap-node.sh

# 4. Start the containers
docker compose -f docker-compose.node.yml up -d

# 5. Open the dashboard
open http://localhost:8080
```

Your node starts in **demo mode** with the in-process governance engine. To
connect to the live federation, complete the onboarding workflow below.

## Onboarding workflow

### Phase 1: Prepare your node

1. **Configure `.env`** with your organization identity:
   ```env
   ORG_NAME=city-porto-alegre
   ORG_DISPLAY="City of Porto Alegre"
   ORG_MSP_ID=CityPortoAlegreMSP
   ORG_DOMAIN=portoalegre.od.example.com
   SCOPE_PREFIX=GOV:CITY_PORTO_ALEGRE
   ```

2. **Run `bootstrap-node.sh`** to generate:
   - CA certificate and key
   - Peer TLS certificates
   - MSP directory structure
   - Connection profile

3. **Start your containers** to verify everything works locally.

### Phase 2: Join the federation

4. **Share your MSP** (`federation/crypto/msp/`) with a federation admin.
   This contains your CA's root certificate — no private keys.

5. **Federation votes on your membership.** An existing admin creates a
   proposal (bill) to add your organization. Member orgs vote. This uses
   the system itself — your admission is a governance decision.

6. **Admin runs `add-organization.sh`** to update the channel config:
   ```bash
   ./scripts/add-organization.sh \
       --org-name city-porto-alegre \
       --org-msp-id CityPortoAlegreMSP \
       --org-msp-dir /path/to/your/msp
   ```

7. **Your peer joins the channel:**
   ```bash
   peer channel fetch 0 governance.block -o orderer1.od.example.com:7050 -c governance --tls ...
   peer channel join -b governance.block
   ```

8. **Install the chaincode** on your peer:
   ```bash
   peer lifecycle chaincode install bill.tar.gz
   ```

### Phase 3: Register participants

9. **Create a participants CSV** mapping your org structure to scope claims:
   ```csv
   mayor,"Mayor João",GOV:CITY_PORTO_ALEGRE:ADMIN
   health_dir,"Dr. Maria",GOV:CITY_PORTO_ALEGRE:HEALTH:ADMIN
   nurse_ana,"Ana",GOV:CITY_PORTO_ALEGRE:HEALTH:VOTER
   citizen_carlos,"Carlos",GOV:CITY_PORTO_ALEGRE:COMMUNITY:VOTER
   ```

10. **Register them** with your CA:
    ```bash
    ./scripts/register-participants.sh participants.csv
    ```

    Each participant receives an X.509 certificate with their scope claims
    embedded. The governance engine reads these claims automatically.

## Adaptation guides by entity type

### Government

**Scope structure:**
```
GOV:{JURISDICTION}                    root
├── COUNCIL                           legislative body
│   ├── ADMIN                         council president
│   ├── PROPOSER                      council members
│   └── VOTER                         all council members
├── EXECUTIVE                         executive branch
│   ├── ADMIN                         mayor / governor
│   └── {DEPARTMENT}                  department scopes
│       ├── ADMIN                     department head
│       ├── PROPOSER                  senior civil servants
│       └── VOTER                     department staff
└── COMMUNITY                         public participation
    ├── PROPOSER                      any registered citizen
    └── VOTER                         any registered citizen
```

**Mapping existing processes:**
| Government process | Open Democracy mechanism |
|---|---|
| City council vote | Bill at `GOV:CITY:COUNCIL:*` scope |
| Public consultation | Petition at `GOV:CITY:COMMUNITY:*` scope |
| Budget approval | Bill with 2/3 quorum + absence-as-rejection |
| Departmental policy | Bill at `GOV:CITY:{DEPT}:*` scope |
| Citizen initiative | Petition (threshold-triggered, admin cannot block) |

**Channel strategy:**
- `governance` — cross-org federation decisions
- `gov-{jurisdiction}-internal` — internal government decisions
- `gov-{jurisdiction}-public` — transparency channel (read-only for citizens)

### Union

**Scope structure:**
```
UNION:{NAME}                          root
├── NATIONAL                          national leadership
│   ├── ADMIN                         national executive
│   ├── PROPOSER                      national committee
│   └── VOTER                         national delegates
├── STATE_{CODE}                      state/regional chapters
│   ├── ADMIN                         state leadership
│   ├── PROPOSER                      local organizers
│   └── VOTER                         all chapter members
└── ASSEMBLY                          general assembly
    └── VOTER                         all union members
```

**Mapping existing processes:**
| Union process | Open Democracy mechanism |
|---|---|
| General assembly vote | Bill at `UNION:NAME:ASSEMBLY:*` scope |
| Strike authorization | Bill with high quorum + absence counts |
| Collective bargaining position | Bill at national scope, delegations from chapters |
| Rank-and-file initiative | Petition (bypasses leadership gatekeeping) |
| Chapter election | Bill at `UNION:NAME:STATE_XX:*` scope |

**Why delegations matter for unions:**
Members who cannot attend assemblies can delegate to a trusted colleague.
The depth-1 constraint prevents power concentration through chains. Direct
votes always override delegations — every member retains their voice.

### Company

**Scope structure:**
```
CORP:{NAME}                           root
├── BOARD                             board of directors
│   ├── ADMIN                         chairman
│   └── VOTER                         all board members
├── {DEPARTMENT}                      business units
│   ├── ADMIN                         department head
│   ├── PROPOSER                      team leads
│   ├── EDITOR                        technical contributors
│   └── VOTER                         all department members
└── ALL_HANDS                         company-wide
    └── VOTER                         all employees
```

**Mapping existing processes:**
| Corporate process | Open Democracy mechanism |
|---|---|
| Board resolution | Bill at `CORP:NAME:BOARD:*` scope |
| Architecture decision record | Bill at department scope |
| Company-wide policy | Bill at `CORP:NAME:ALL_HANDS:*` scope |
| Employee suggestion | Petition at all-hands scope |
| Team-level decision | Bill at team scope with low quorum |

**Privacy:** Use a **private channel** (`corp-{name}-internal`) for sensitive
decisions. Only your organization's peers see the data. Cross-org decisions
go to the shared `governance` channel.

### Community / NGO

**Scope structure:**
```
COMMUNITY:{NAME}                      root
├── BOARD                             steering committee
│   └── ADMIN                         elected coordinators
├── WORKING_GROUP_{TOPIC}             thematic groups
│   ├── PROPOSER                      group facilitators
│   └── VOTER                         group members
└── GENERAL                           all members
    ├── PROPOSER                      any member
    └── VOTER                         any member
```

## Network architecture

### Single-network federation (recommended)

All member organizations share one Hyperledger Fabric network:

```
  Org A          Org B          Org C
   peer  ←───→  peer  ←───→  peer
     ↕            ↕            ↕
   ┌──────────────────────────────┐
   │     Raft Ordering Service    │
   │  (consensus across orgs)     │
   └──────────────────────────────┘
```

- **Channels** isolate different decision contexts
- **Endorsement policies** ensure multi-org agreement
- **Same chaincode** on every channel

### Multi-network federation (future)

Separate Fabric networks communicate via:
1. **Gateway API federation** — REST calls between gateways (simplest)
2. **Hash anchoring** — publish decision proofs across networks
3. **Hyperledger Cacti relay** — cryptographically verified cross-network calls
4. **IBC-style light clients** — full cross-chain verification

See `docs/DISTRIBUTED_LEDGER_DESIGN.md` for details on each pattern.

## File reference

```
federation/
├── README.md                           ← you are here
├── docker-compose.fabric.yml           multi-org Fabric network (founders)
├── docker-compose.node.yml             single-org node (new members)
├── config/
│   ├── configtx.yaml                   Fabric channel configuration
│   ├── crypto-config.yaml              certificate generation template
│   ├── org-template.env                organization configuration template
│   └── connection-profile-template.yaml  SDK connection profile
└── scripts/
    ├── bootstrap-network.sh            initialize the founding network
    ├── bootstrap-node.sh               prepare a new org's node
    ├── add-organization.sh             add an org to an existing network
    ├── deploy-chaincode.sh             package and deploy the chaincode
    └── register-participants.sh        register users with scope claims
```

## FAQ

**Q: Do I need to understand blockchain to use this?**
No. The dashboard provides a familiar web interface. The blockchain runs
underneath — you interact with proposals, votes, and delegations through
forms and API calls.

**Q: Can I run the demo without a Fabric network?**
Yes. `docker compose up --build` from the project root runs the gateway in
demo mode with the same governance logic, persisted to a JSON file.

**Q: How many transactions per second can the network handle?**
Hyperledger Fabric typically handles 1,000-3,000 TPS depending on
configuration. For governance decisions (not high-frequency trading), this
is orders of magnitude more than needed.

**Q: What if my organization structure changes?**
Scope claims are in certificates. Re-enroll affected users with updated
scope attributes. The governance engine will immediately respect the new
claims. No chaincode changes needed.

**Q: Can I run my node on a cloud provider?**
Yes. Any platform that runs Docker containers works: AWS ECS/EKS, Azure
AKS, Google GKE, DigitalOcean, or a simple VPS. The peer containers are
stateless (ledger is on a Docker volume) so they can be moved or
replicated.
