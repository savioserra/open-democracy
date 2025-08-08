package bill

import (
    "errors"
    "fmt"
    "strings"
)

// Status of a bill
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

// Vote cast by a user
type Vote struct {
    VoterID   string `json:"voterId"`
    Choice    Choice `json:"choice"`
    Timestamp int64  `json:"timestamp"`
}

// Criteria controls how votes are interpreted to decide outcome.
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
}
