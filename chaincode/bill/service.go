package bill

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Service holds the pure-Go business logic for the bill ledger. It depends
// only on a Store and an EventSink and is therefore safe to use both inside
// a Hyperledger Fabric chaincode (via stub adapters in store.go/events.go)
// and inside the in-process gateway exposed to the dashboard.
//
// The shared logic guarantees both deployment paths execute the exact same
// rules around RBAC, scope checks, quorum, criteria masks, and events.
type Service struct {
	store  Store
	events EventSink
}

// NewService constructs a Service from a Store and an EventSink.
func NewService(store Store, events EventSink) *Service {
	if events == nil {
		events = NopEventSink()
	}
	return &Service{store: store, events: events}
}

// Store exposes the underlying store, useful for the gateway to scan bills.
func (s *Service) Store() Store { return s.store }

// CreateBill creates a new bill in draft status and registers the first
// version. See contract.go's CreateBill for the wire-level wrapper.
func (s *Service) CreateBill(caller *Invoker, now int64, billID, ipfsHash, description, quorum, scope, executeMask, rejectMask string) error {
	if caller == nil {
		return errors.New("caller is required")
	}
	if billID == "" {
		return errors.New("billID is required")
	}
	if ipfsHash == "" {
		return errors.New("ipfsHash is required")
	}
	q, err := strconv.ParseFloat(quorum, 64)
	if err != nil || q < 0 || q > 1 {
		return fmt.Errorf("invalid quorum: %s (must be between 0 and 1)", quorum)
	}
	key := billKey(billID)
	exists, err := s.store.Exists(key)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("bill %s already exists", billID)
	}

	execMask, rejMask, err := parseCriteriaMasks(executeMask, rejectMask)
	if err != nil {
		return err
	}

	scopeStr, err := normalizeAndAuthorizeCreateScope(caller, scope)
	if err != nil {
		return err
	}

	if scopeStr == "" {
		if !(caller.HasAnyRole(RoleProposer) || caller.HasAnyAdmin()) {
			return errors.New("not authorized: missing PROPOSER or ADMIN authority")
		}
	}

	v := Version{IPFSHash: ipfsHash, Description: description, Timestamp: now, Editor: caller.ID, Votes: map[string]Vote{}}
	b := &Bill{
		ID:                 billID,
		Owner:              caller.ID,
		Status:             StatusDraft,
		Quorum:             q,
		Criteria:           Criteria{ExecuteMask: execMask, RejectMask: rejMask},
		Scope:              scopeStr,
		Versions:           []Version{v},
		Roles:              map[string]Role{caller.ID: RoleProposer | RoleEditor},
		Votes:              map[string]Vote{},
		VoteStart:          0,
		VoteEnd:            0,
		AgreedVersionIndex: -1,
	}
	if err := s.putBill(b); err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]string{"billId": billID})
	_ = s.events.Emit("BillCreated", payload)
	return nil
}

// EditBill adds a new version while the bill is in draft status.
func (s *Service) EditBill(caller *Invoker, now int64, billID, ipfsHash, description string) error {
	if ipfsHash == "" {
		return errors.New("ipfsHash is required")
	}
	b, err := s.getBill(billID)
	if err != nil {
		return err
	}
	if b.Status != StatusDraft {
		return errors.New("bill must be in draft status to edit")
	}
	if !caller.HasRole(b, RoleEditor) && caller.ID != b.Owner {
		return errors.New("not authorized: requires EDITOR role or owner")
	}
	b.Versions = append(b.Versions, Version{IPFSHash: ipfsHash, Description: description, Timestamp: now, Editor: caller.ID, Votes: map[string]Vote{}})
	b.AgreedVersionIndex = -1
	if err := s.putBill(b); err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]any{"billId": billID, "versionIndex": len(b.Versions) - 1})
	_ = s.events.Emit("BillVersionAdded", payload)
	return nil
}

// AssignRoleForBill grants per-bill roles to a user. Only ADMINs (per scope)
// may assign.
func (s *Service) AssignRoleForBill(caller *Invoker, billID, userID, role string) error {
	if userID == "" || strings.TrimSpace(role) == "" {
		return errors.New("userID and role are required")
	}
	b, err := s.getBill(billID)
	if err != nil {
		return err
	}
	if !caller.HasAdminFor(b.Scope) {
		return errors.New("not authorized: ADMIN authority for bill scope required to assign roles")
	}
	mask, err := parseRoleExpr(role)
	if err != nil {
		return err
	}
	if b.Roles == nil {
		b.Roles = map[string]Role{}
	}
	current := b.Roles[userID]
	b.Roles[userID] = current.With(mask)
	return s.putBill(b)
}

// VoteOnVersion records a vote for a specific draft version and updates the
// agreement state when criteria/quorum are met.
func (s *Service) VoteOnVersion(caller *Invoker, now int64, billID, versionIndex, choice string) error {
	b, err := s.getBill(billID)
	if err != nil {
		return err
	}
	if b.Status != StatusDraft {
		return errors.New("bill must be in draft status to vote on a version")
	}
	if b.AgreedVersionIndex >= 0 {
		return errors.New("a version has already reached quorum agreement for this bill")
	}
	idx, err := strconv.Atoi(strings.TrimSpace(versionIndex))
	if err != nil {
		return fmt.Errorf("invalid versionIndex: %v", err)
	}
	if idx < 0 || idx >= len(b.Versions) {
		return fmt.Errorf("versionIndex out of range: %d", idx)
	}
	if !caller.HasRole(b, RoleVoter) {
		return errors.New("not authorized: requires VOTER role for this bill")
	}
	if !caller.InScope(b.Scope) {
		return errors.New("scope not allowed for this bill")
	}
	for i := range b.Versions {
		if b.Versions[i].Votes == nil {
			b.Versions[i].Votes = map[string]Vote{}
		}
	}
	ch, err := ParseChoiceToken(choice)
	if err != nil {
		return fmt.Errorf("invalid choice: %v", err)
	}
	if ch == ChoiceAbsence || ch == ChoiceNone {
		return errors.New("invalid choice (expected YES, NO, or ABSTAIN)")
	}
	b.Versions[idx].Votes[caller.ID] = Vote{VoterID: caller.ID, Choice: ch, Timestamp: now}

	yes, no, abstain, absence, eligible := tallyVotes(b, b.Versions[idx].Votes)
	participation, _, _ := computeParticipation(b, yes, no, abstain, absence, eligible)
	if participation >= b.Quorum {
		execCount := countByMask(b.Criteria.ExecuteMask, yes, no, abstain, absence)
		rejCount := countByMask(b.Criteria.RejectMask, yes, no, abstain, absence)
		if execCount > rejCount {
			b.AgreedVersionIndex = idx
		}
	}
	if err := s.putBill(b); err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]any{
		"billId":        billID,
		"versionIndex":  idx,
		"yes":           yes,
		"no":            no,
		"abstain":       abstain,
		"absence":       absence,
		"eligible":      eligible,
		"participation": participation,
	})
	_ = s.events.Emit("VersionVoteAdded", payload)
	if b.AgreedVersionIndex == idx {
		payload2, _ := json.Marshal(map[string]any{"billId": billID, "versionIndex": idx})
		_ = s.events.Emit("VersionAgreed", payload2)
	}
	return nil
}

// SubmitBill opens the formal voting window on the agreed version.
func (s *Service) SubmitBill(caller *Invoker, billID, startTimeSeconds, durationSeconds string) error {
	b, err := s.getBill(billID)
	if err != nil {
		return err
	}
	if caller.ID != b.Owner && !caller.HasRole(b, RoleProposer) {
		return errors.New("not authorized: only owner/proposer can submit bill for voting")
	}
	if b.Status != StatusDraft {
		return errors.New("bill must be in draft status to submit")
	}
	idx := b.AgreedVersionIndex
	if idx < 0 || idx >= len(b.Versions) {
		return errors.New("no version has reached quorum agreement")
	}
	yes, no, abstain, absence, eligible := tallyVotes(b, b.Versions[idx].Votes)
	participation, _, _ := computeParticipation(b, yes, no, abstain, absence, eligible)
	if participation < b.Quorum {
		return errors.New("agreed version quorum not met")
	}
	start, err := strconv.ParseInt(startTimeSeconds, 10, 64)
	if err != nil {
		return fmt.Errorf("invalid start time: %w", err)
	}
	dur, err := strconv.ParseInt(durationSeconds, 10, 64)
	if err != nil || dur <= 0 {
		return errors.New("invalid duration seconds")
	}
	b.VoteStart = start
	b.VoteEnd = start + dur
	b.Status = StatusVoting
	if err := s.putBill(b); err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]any{"billId": billID, "start": b.VoteStart, "end": b.VoteEnd, "versionIndex": idx})
	_ = s.events.Emit("VoteStarted", payload)
	return nil
}

// CastVote records a vote during the open voting window.
func (s *Service) CastVote(caller *Invoker, now int64, billID, choice string) error {
	b, err := s.getBill(billID)
	if err != nil {
		return err
	}
	if b.Status != StatusVoting {
		return errors.New("voting is not open")
	}
	if now < b.VoteStart || now > b.VoteEnd {
		return errors.New("outside voting window")
	}
	if !caller.HasRole(b, RoleVoter) {
		return errors.New("not authorized: missing VOTER role for this bill")
	}
	if !caller.InScope(b.Scope) {
		return errors.New("scope not allowed for this bill")
	}
	if b.Votes == nil {
		b.Votes = map[string]Vote{}
	}
	if _, exists := b.Votes[caller.ID]; exists {
		return errors.New("user has already voted")
	}
	ch, err := ParseChoiceToken(choice)
	if err != nil {
		return fmt.Errorf("invalid choice: %v", err)
	}
	if ch == ChoiceAbsence || ch == ChoiceNone {
		return errors.New("invalid choice (expected YES, NO, or ABSTAIN)")
	}
	b.Votes[caller.ID] = Vote{VoterID: caller.ID, Choice: ch, Timestamp: now}
	return s.putBill(b)
}

// EndVote finalizes the vote, computes the outcome, and transitions status.
func (s *Service) EndVote(caller *Invoker, now int64, billID string) error {
	_ = caller // anyone may attempt to end the vote; the time check enforces correctness
	b, err := s.getBill(billID)
	if err != nil {
		return err
	}
	if b.Status != StatusVoting {
		return errors.New("bill is not in voting status")
	}
	if now < b.VoteEnd {
		return errors.New("voting period has not ended yet")
	}
	yes, no, abstain, absence, eligible := tallyVotes(b, b.Votes)
	participation, executeCount, rejectCount := computeParticipation(b, yes, no, abstain, absence, eligible)

	if participation < b.Quorum {
		b.Status = StatusRejected
	} else if executeCount > rejectCount {
		b.Status = StatusExecuted
	} else {
		b.Status = StatusRejected
	}

	if err := s.putBill(b); err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]any{
		"billId":        billID,
		"yes":           yes,
		"no":            no,
		"abstain":       abstain,
		"absence":       absence,
		"eligible":      eligible,
		"participation": participation,
		"executeCount":  executeCount,
		"rejectCount":   rejectCount,
		"status":        b.Status,
	})
	_ = s.events.Emit("VoteEnded", payload)
	return nil
}

// SetBillScope updates the bill scope. Only owner or proposer.
func (s *Service) SetBillScope(caller *Invoker, billID, scope string) error {
	b, err := s.getBill(billID)
	if err != nil {
		return err
	}
	if caller.ID != b.Owner && !caller.HasRole(b, RoleProposer) {
		return errors.New("not authorized: only owner/proposer can set scope")
	}
	scopeStr := normalizeScopePattern(scope)
	if scopeStr == "" {
		return errors.New("scope is required")
	}
	b.Scope = scopeStr
	return s.putBill(b)
}

// SetBillCriteria updates the criteria masks while in draft.
func (s *Service) SetBillCriteria(caller *Invoker, billID, executeMask, rejectMask string) error {
	b, err := s.getBill(billID)
	if err != nil {
		return err
	}
	if caller.ID != b.Owner && !caller.HasRole(b, RoleProposer) {
		return errors.New("not authorized: only owner/proposer can set criteria")
	}
	if b.Status != StatusDraft {
		return errors.New("bill must be in draft status to set criteria")
	}
	exec, err := ParseChoiceMask(executeMask)
	if err != nil {
		return fmt.Errorf("invalid execute mask: %v", err)
	}
	rej, err := ParseChoiceMask(rejectMask)
	if err != nil {
		return fmt.Errorf("invalid reject mask: %v", err)
	}
	if exec == ChoiceNone && rej == ChoiceNone {
		return errors.New("both execute and reject masks are empty")
	}
	b.Criteria = Criteria{ExecuteMask: exec, RejectMask: rej}
	if err := s.putBill(b); err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]any{"billId": billID, "executeMask": exec, "rejectMask": rej})
	_ = s.events.Emit("CriteriaUpdated", payload)
	return nil
}

// GetBill returns the bill or an error if it does not exist.
func (s *Service) GetBill(billID string) (*Bill, error) {
	return s.getBill(billID)
}

// ListBills scans the store for every bill. Used by the gateway dashboard.
func (s *Service) ListBills() ([]*Bill, error) {
	pairs, err := s.store.ScanByPrefix("BILL|")
	if err != nil {
		return nil, err
	}
	out := make([]*Bill, 0, len(pairs))
	for _, kv := range pairs {
		var b Bill
		if err := json.Unmarshal(kv.Value, &b); err != nil {
			return nil, fmt.Errorf("failed to unmarshal bill at %s: %w", kv.Key, err)
		}
		normalizeBill(&b)
		out = append(out, &b)
	}
	return out, nil
}

// internal helpers ----------------------------------------------------------

func (s *Service) getBill(billID string) (*Bill, error) {
	if billID == "" {
		return nil, errors.New("billID is required")
	}
	data, err := s.store.Get(billKey(billID))
	if err != nil {
		return nil, fmt.Errorf("failed to read bill: %w", err)
	}
	if len(data) == 0 {
		return nil, fmt.Errorf("bill %s does not exist", billID)
	}
	var b Bill
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, fmt.Errorf("failed to unmarshal bill: %w", err)
	}
	normalizeBill(&b)
	return &b, nil
}

func (s *Service) putBill(b *Bill) error {
	data, err := json.Marshal(b)
	if err != nil {
		return fmt.Errorf("failed to marshal bill: %w", err)
	}
	return s.store.Put(billKey(b.ID), data)
}

func normalizeBill(b *Bill) {
	if b.Roles == nil {
		b.Roles = map[string]Role{}
	}
	if b.Votes == nil {
		b.Votes = map[string]Vote{}
	}
	for i := range b.Versions {
		if b.Versions[i].Votes == nil {
			b.Versions[i].Votes = map[string]Vote{}
		}
	}
}

func parseCriteriaMasks(executeMask, rejectMask string) (Choice, Choice, error) {
	exec, rej := ChoiceNone, ChoiceNone
	if strings.TrimSpace(executeMask) != "" {
		m, err := ParseChoiceMask(executeMask)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid execute mask: %v", err)
		}
		exec = m
	}
	if strings.TrimSpace(rejectMask) != "" {
		m, err := ParseChoiceMask(rejectMask)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid reject mask: %v", err)
		}
		rej = m
	}
	if exec == ChoiceNone && rej == ChoiceNone {
		exec = ChoiceYes
		rej = ChoiceNo
	}
	return exec, rej, nil
}

// normalizeAndAuthorizeCreateScope strips a trailing role token from the
// scope (if any) and verifies the caller has PROPOSER or ADMIN authority for
// it. Returns the cleaned scope or an error.
func normalizeAndAuthorizeCreateScope(caller *Invoker, scope string) (string, error) {
	s := normalizeScopePattern(scope)
	if s == "" {
		return "", nil
	}
	parts := splitScopePath(s)
	if len(parts) > 0 {
		last := parts[len(parts)-1]
		if _, ok := authorityRoles[last]; ok {
			if len(parts) == 1 {
				return "", errors.New("scope cannot be only a role token")
			}
			s = strings.Join(parts[:len(parts)-1], ":")
		}
	}
	if !(caller.HasRoleInScope(RoleProposer, s) || caller.HasRoleInScope(RoleAdmin, s)) {
		return "", errors.New("not authorized: missing PROPOSER or ADMIN authority for the provided scope")
	}
	return s, nil
}

// tallyVotes counts the YES/NO/ABSTAIN votes from a votes map and derives
// ABSENCE from the eligible voter count.
func tallyVotes(b *Bill, votes map[string]Vote) (yes, no, abstain, absence, eligible int) {
	for _, rs := range b.Roles {
		if rs.Has(RoleVoter) {
			eligible++
		}
	}
	for _, v := range votes {
		switch v.Choice {
		case ChoiceYes:
			yes++
		case ChoiceNo:
			no++
		case ChoiceAbstain:
			abstain++
		}
	}
	if eligible > 0 {
		cast := yes + no + abstain
		if cast > eligible {
			cast = eligible
		}
		if cast < 0 {
			cast = 0
		}
		absence = eligible - cast
	}
	return
}

func countByMask(mask Choice, yes, no, abstain, absence int) int {
	total := 0
	if mask.Has(ChoiceYes) {
		total += yes
	}
	if mask.Has(ChoiceNo) {
		total += no
	}
	if mask.Has(ChoiceAbstain) {
		total += abstain
	}
	if mask.Has(ChoiceAbsence) {
		total += absence
	}
	return total
}

func computeParticipation(b *Bill, yes, no, abstain, absence, eligible int) (participation float64, executeCount int, rejectCount int) {
	included := b.Criteria.ExecuteMask | b.Criteria.RejectMask
	if eligible > 0 {
		participation = float64(countByMask(included, yes, no, abstain, absence)) / float64(eligible)
	}
	executeCount = countByMask(b.Criteria.ExecuteMask, yes, no, abstain, absence)
	rejectCount = countByMask(b.Criteria.RejectMask, yes, no, abstain, absence)
	return
}

func billKey(id string) string { return "BILL|" + id }

// parseRoleExpr parses expressions like "VOTER|PROPOSER" or "voter, editor".
func parseRoleExpr(expr string) (Role, error) {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return RoleNone, errors.New("role expression is empty")
	}
	tokens := strings.FieldsFunc(expr, func(r rune) bool {
		return r == '|' || r == ',' || r == ' ' || r == '\t'
	})
	var mask Role
	for _, t := range tokens {
		tok := strings.ToUpper(strings.TrimSpace(t))
		if tok == "" {
			continue
		}
		switch tok {
		case "PROPOSER":
			mask |= RoleProposer
		case "EDITOR":
			mask |= RoleEditor
		case "VOTER":
			mask |= RoleVoter
		case "AUDITOR":
			mask |= RoleAuditor
		case "ADMIN":
			mask |= RoleAdmin
		case "NONE":
			// no-op
		default:
			return RoleNone, fmt.Errorf("unknown role token: %s", tok)
		}
	}
	return mask, nil
}
