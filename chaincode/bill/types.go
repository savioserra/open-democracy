// Package bill implements the on-ledger data model and business rules for a
// democratic decision-making system on a permissioned blockchain.
//
// The design draws from several traditions in political theory:
//
// Deliberation and execution stages:
//   Lenin, V. I. "Freedom to Criticise and Unity of Action." Vperyod,
//   20 May 1906. — Democratic centralism: broad debate on draft versions
//   (stage 1), then binding formal vote with quorum (stage 2).
//
// Absence as a first-class category:
//   Marx, K. The Eighteenth Brumaire of Louis Bonaparte. 1852. — Analysis
//   of how those absent from decision-making are acted upon rather than
//   acting: "they cannot represent themselves, they must be represented."
//   The ChoiceAbsence bitmask operationalises this insight.
//
// Polycentric governance and scope hierarchy:
//   Ostrom, E. Governing the Commons. Cambridge UP, 1990. — Nested,
//   locally-adapted rule systems. Each scope level can evolve its own
//   quorum and criteria.
//   V. Ostrom, Tiebout & Warren. "The Organization of Government in
//   Metropolitan Areas." APSR 55(4), 1961. — Coined "polycentric."
//
// Liquid democracy (delegation):
//   Ford, B. "Delegative Democracy." Unpublished manuscript, 2002. —
//   Origin of the liquid democracy concept.
//   Blum, C. & Zuber, C. I. "Liquid Democracy: Potentials, Problems, and
//   Perspectives." J. Political Philosophy 24(2), 2016. — Rigorous
//   philosophical analysis defining four properties (direct democracy,
//   flexible delegation, meta-delegation, instant recall).
//   Constituição da República Federativa do Brasil, 1988, Art. 1,
//   parágrafo único — "Todo o poder emana do povo, que o exerce por
//   meio de representantes eleitos ou diretamente."
//
// Popular initiative (petitions):
//   Trechsel, A. H. & Kriesi, H. "Switzerland: The Referendum and
//   Initiative as a Centrepiece of the Political System." In The
//   Referendum Experience in Europe, Macmillan, 1996.
//   Santos, B. de S. "Participatory Budgeting in Porto Alegre." Politics
//   & Society 26(4), 1998. — Democratising democracy from below.
//
// Vote receipts and verifiable voting:
//   Chaum, D. "Secret-Ballot Receipts: True Voter-Verifiable Elections."
//   IEEE Security & Privacy 2(1), 2004.
//   Benaloh, J. "Verifiable Secret-Ballot Elections." PhD Thesis, Yale,
//   1987.
//
// Federated council structures:
//   Lenin, V. I. The State and Revolution. 1917. — Soviet model.
//   Bookchin, M. "Libertarian Municipalism: An Overview." 1991. —
//   Confederation of face-to-face assemblies with mandated, recallable
//   delegates.
//
// Future directions (not yet implemented):
//   Lalley, S. P. & Weyl, E. G. "Quadratic Voting." AEA Papers and
//   Proceedings 108, 2018. — Voice credits at quadratic cost.
//   Zargham, M. "Social Sensor Fusion." BlockScience WP, 2018. —
//   Conviction voting: continuous preference signalling.
package bill

import (
    "errors"
    "fmt"
    "strings"
)

// Status of a bill. The lifecycle follows Lenin's democratic centralism:
// draft (deliberation) → voting (binding decision) → executed or rejected.
const (
    StatusDraft    = "draft"
    StatusVoting   = "voting"
    StatusExecuted = "executed"
    StatusRejected = "rejected"
)

// Bitwise roles for per-bill RBAC
// Use like: RoleVoter | RoleProposer
// Stored on-ledger as uint64 mask per user
// Note: numeric values are stable bit positions; add new roles as needed.
type Role uint64

const (
    RoleNone     Role = 0
    RoleProposer Role = 1 << iota
    RoleEditor
    RoleVoter
    RoleAuditor
    RoleAdmin
)

// Helpers for working with role masks
func (m Role) Has(r Role) bool { return m&r != 0 }
func (m Role) With(r Role) Role { return m | r }
func (m Role) Without(r Role) Role { return m &^ r }

// Choice is a bitmask for vote choices and counting categories
// Single-cast votes should use exactly one of the following single-bit flags.
type Choice uint32

const (
    ChoiceNone     Choice = 0
    ChoiceYes      Choice = 1 << iota
    ChoiceNo
    ChoiceAbstain
    // ChoiceAbsence is not a cast vote; it's derived as eligible - (YES+NO+ABSTAIN)
    ChoiceAbsence
)

func (m Choice) Has(flag Choice) bool { return m&flag != 0 }

// ParseChoiceToken parses a single token into a Choice bit.
// Accepts synonyms: YES|Y, NO|N, ABSTAIN|ABSTENTION, ABSENCE|ABSENT, NONE.
func ParseChoiceToken(token string) (Choice, error) {
    tok := strings.ToUpper(strings.TrimSpace(token))
    switch tok {
    case "YES", "Y":
        return ChoiceYes, nil
    case "NO", "N":
        return ChoiceNo, nil
    case "ABSTAIN", "ABSTENTION":
        return ChoiceAbstain, nil
    case "ABSENCE", "ABSENT":
        return ChoiceAbsence, nil
    case "NONE", "":
        return ChoiceNone, nil
    default:
        return ChoiceNone, fmt.Errorf("unknown choice token: %s", token)
    }
}

// ParseChoiceMask parses expressions like "YES|NO" or "yes, abstain" into a Choice bitmask.
func ParseChoiceMask(expr string) (Choice, error) {
    expr = strings.TrimSpace(expr)
    if expr == "" {
        return ChoiceNone, errors.New("choice mask is empty")
    }
    tokens := strings.FieldsFunc(expr, func(r rune) bool { return r == '|' || r == ',' || r == ' ' || r == '\t' })
    var mask Choice
    for _, t := range tokens {
        if strings.TrimSpace(t) == "" {
            continue
        }
        ch, err := ParseChoiceToken(t)
        if err != nil {
            return ChoiceNone, err
        }
        mask |= ch
    }
    return mask, nil
}

// Version of the bill text (stores only a content hash and metadata)
type Version struct {
    IPFSHash    string            `json:"ipfsHash"`
    Description string            `json:"description"`
    Timestamp   int64             `json:"timestamp"`
    Editor      string            `json:"editor"`
    Votes       map[string]Vote   `json:"votes"`
}

// Vote cast by a user. The VoterID is stored on the bill for tallying.
// The VoteID is a random receipt token returned once to the voter and
// stored separately in a receipt record (without voter identity) so the
// voter can verify their vote was counted without anyone else being able
// to link the receipt back to them through the system.
type Vote struct {
    VoterID   string `json:"voterId"`
    Choice    Choice `json:"choice"`
    Timestamp int64  `json:"timestamp"`
}

// VoteReceipt is stored under RECEIPT|{voteID}. It deliberately does NOT
// contain the voter identity — only the vote ID holder can prove ownership.
type VoteReceipt struct {
    VoteID    string `json:"voteId"`
    BillID    string `json:"billId"`
    Choice    Choice `json:"choice"`
    Timestamp int64  `json:"timestamp"`
}

// Delegation represents a liquid-democracy delegation. A delegator gives
// their voting weight to a delegatee for a specific scope. The delegation
// is:
//   - Scope-specific: you can delegate at each scope level independently,
//     just like having a different representative at neighborhood, city,
//     state, and federal levels.
//   - Depth-1: only direct delegation — no transitive chains. If Alice
//     delegates to Bob and Bob delegates to Carol, and Bob doesn't vote,
//     Alice is absent (not silently forwarded to Carol). This prevents
//     power concentration through long chains.
//   - Revocable at any time: the delegator can always take their vote back.
//   - Overridable: if the delegator votes directly on a bill, the delegation
//     is bypassed for that bill — direct participation always wins.
//
// This mirrors the Brazilian constitutional model (Art. 1, sole paragraph:
// "All power emanates from the people, who exercise it through elected
// representatives or directly") — citizens always retain the right to vote
// directly, but can choose representation at each level of the hierarchy.
type Delegation struct {
    Delegator string `json:"delegator"`
    Delegatee string `json:"delegatee"`
    Scope     string `json:"scope"`
    Timestamp int64  `json:"timestamp"`
}
// ExecuteMask: choices counted toward execution; RejectMask: counted toward rejection.
// ABSENCE can be included to treat non-voters as one of the sides.
type Criteria struct {
    ExecuteMask Choice `json:"executeMask"`
    RejectMask  Choice `json:"rejectMask"`
}

// Bill is the on-ledger entity
type Bill struct {
    ID                 string          `json:"id"`
    Owner              string          `json:"owner"`
    Status             string          `json:"status"`
    Quorum             float64         `json:"quorum"`
    Criteria           Criteria        `json:"criteria"`
    Scope              string          `json:"scope"`
    Versions           []Version       `json:"versions"`
    Roles              map[string]Role `json:"roles"`
    Votes              map[string]Vote `json:"votes"`
    VoteStart          int64           `json:"voteStart"`
    VoteEnd            int64           `json:"voteEnd"`
    AgreedVersionIndex int             `json:"agreedVersionIndex"`
    // SourcePetitionID links the bill back to the petition that created it.
    // Empty for bills created directly through CreateBill.
    SourcePetitionID string `json:"sourcePetitionId,omitempty"`
}

// Petition status
const (
    PetitionOpen      = "open"
    PetitionTriggered = "triggered"
)

// Petition is a popular initiative. Any participant can start one regardless
// of role. When enough people sign it, a bill is automatically created at the
// target scope with every in-scope participant enrolled as VOTER. No admin
// can block the creation or cherry-pick the electorate — the signatures are
// the mandate. This is the mechanism by which the base can force the
// leadership to act, consistent with the project's grounding in Marx's
// material-conditions analysis and Lenin's democratic centralism.
type Petition struct {
    ID            string           `json:"id"`
    Initiator     string           `json:"initiator"`
    TargetScope   string           `json:"targetScope"`
    IPFSHash      string           `json:"ipfsHash"`
    Description   string           `json:"description"`
    Quorum        float64          `json:"quorum"`
    Criteria      Criteria         `json:"criteria"`
    Threshold     int              `json:"threshold"`
    Signatures    map[string]int64 `json:"signatures"`
    Status        string           `json:"status"`
    CreatedBillID string           `json:"createdBillId,omitempty"`
    Timestamp     int64            `json:"timestamp"`
}
