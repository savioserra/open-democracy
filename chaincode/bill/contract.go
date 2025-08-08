package bill

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/hyperledger/fabric-chaincode-go/pkg/cid"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// BillContract: RBAC, region checks via cert attributes, events for off-chain listeners.
type BillContract struct {
	contractapi.Contract
}

// CreateBill creates a new bill in draft status and registers the first version.
// New signature: scope, executeMask, rejectMask allow setting bill scope and criteria at creation.
func (c *BillContract) CreateBill(ctx contractapi.TransactionContextInterface, billID, ipfsHash, description, quorum, scope, executeMask, rejectMask string) error {
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
	exists, err := c.assetExists(ctx, key)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("bill %s already exists", billID)
	}
	inv, err := GetInvoker(ctx)
	if err != nil {
		return err
	}
	invokerID := inv.ID

	// Parse criteria masks (with defaults if both omitted)
	var execMask, rejMask Choice
	execMask = ChoiceNone
	rejMask = ChoiceNone
	if strings.TrimSpace(executeMask) != "" {
		m, err := ParseChoiceMask(executeMask)
		if err != nil {
			return fmt.Errorf("invalid execute mask: %v", err)
		}
		execMask = m
	}
	if strings.TrimSpace(rejectMask) != "" {
		m, err := ParseChoiceMask(rejectMask)
		if err != nil {
			return fmt.Errorf("invalid reject mask: %v", err)
		}
		rejMask = m
	}
	if execMask == ChoiceNone && rejMask == ChoiceNone {
		// Reasonable defaults
		execMask = ChoiceYes
		rejMask = ChoiceNo
	}

	// Clean and validate scope
	s := normalizeScopePattern(scope)
	if s != "" {
		// If last segment is a role, strip it
		parts := splitScopePath(s)
		if len(parts) > 0 {
			last := parts[len(parts)-1]
			if _, ok := authorityRoles[last]; ok {
				if len(parts) == 1 {
					return errors.New("scope cannot be only a role token")
				}
				s = strings.Join(parts[:len(parts)-1], ":")
			}
		}
		// Authorization: when scope provided, must have PROPOSER or ADMIN for that scope (hierarchical)
  if !(inv.HasRoleInScope(RoleProposer, s) || inv.HasRoleInScope(RoleAdmin, s)) {
			return errors.New("not authorized: missing PROPOSER or ADMIN authority for the provided scope")
		}
	}

	// Base authorization: require PROPOSER or ADMIN in general (covers no-scope case)
 if s == "" {
		if !(inv.HasAnyRole(RoleProposer) || inv.HasAnyAdmin()) {
			return errors.New("not authorized: missing PROPOSER or ADMIN authority")
		}
	}

	ts, err := txTimestampSeconds(ctx)
	if err != nil {
		return err
	}
	v := Version{IPFSHash: ipfsHash, Description: description, Timestamp: ts, Editor: invokerID, Votes: map[string]Vote{}}
	b := &Bill{
		ID:                 billID,
		Owner:              invokerID,
		Status:             StatusDraft,
		Quorum:             q,
		Criteria:           Criteria{ExecuteMask: execMask, RejectMask: rejMask},
		Scope:              s,
		Versions:           []Version{v},
		Roles:              map[string]Role{invokerID: RoleProposer | RoleEditor},
		Votes:              map[string]Vote{},
		VoteStart:          0,
		VoteEnd:            0,
		AgreedVersionIndex: -1,
	}
	if err := c.putBill(ctx, b); err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]string{"billId": billID})
	_ = ctx.GetStub().SetEvent("BillCreated", payload)
	return nil
}

// EditBill adds a new version while the bill is in draft status.
func (c *BillContract) EditBill(ctx contractapi.TransactionContextInterface, billID, ipfsHash, description string) error {
	if ipfsHash == "" {
		return errors.New("ipfsHash is required")
	}
	b, err := c.getBill(ctx, billID)
	if err != nil {
		return err
	}
	if b.Status != StatusDraft {
		return errors.New("bill must be in draft status to edit")
	}
	inv, err := GetInvoker(ctx)
	if err != nil {
		return err
	}
	invokerID := inv.ID
	if !inv.HasRole(b, RoleEditor) && invokerID != b.Owner {
		return errors.New("not authorized: requires EDITOR role or owner")
	}
	ts, err := txTimestampSeconds(ctx)
	if err != nil {
		return err
	}
	b.Versions = append(b.Versions, Version{IPFSHash: ipfsHash, Description: description, Timestamp: ts, Editor: invokerID, Votes: map[string]Vote{}})
	// Editing invalidates previous version agreement
	b.AgreedVersionIndex = -1
	if err := c.putBill(ctx, b); err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]any{"billId": billID, "versionIndex": len(b.Versions) - 1})
	_ = ctx.GetStub().SetEvent("BillVersionAdded", payload)
	return nil
}

// AssignRoleForBill grants one or more roles to a user for a specific bill (only admin can assign)
// role parameter supports bitwise-like expression, e.g.: "VOTER|PROPOSER" (also accepts commas or spaces)
func (c *BillContract) AssignRoleForBill(ctx contractapi.TransactionContextInterface, billID, userID, role string) error {
	if userID == "" || strings.TrimSpace(role) == "" {
		return errors.New("userID and role are required")
	}
	b, err := c.getBill(ctx, billID)
	if err != nil {
		return err
	}
	// Only ADMINs (via hierarchical scope claims) can assign roles
	inv, err := GetInvoker(ctx)
	if err != nil {
		return err
	}
	if !inv.HasAdminFor(b.Scope) {
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
	return c.putBill(ctx, b)
}

// VoteOnVersion records a vote for a specific version while in draft, from an eligible voter, and uses Criteria to decide agreement.
func (c *BillContract) VoteOnVersion(ctx contractapi.TransactionContextInterface, billID, versionIndex, choice string) error {
	b, err := c.getBill(ctx, billID)
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
	inv, err := GetInvoker(ctx)
	if err != nil {
		return err
	}
	invokerID := inv.ID
	if !inv.HasRole(b, RoleVoter) {
		return errors.New("not authorized: requires VOTER role for this bill")
	}
	// Scope check (hierarchical)
	if !inv.InScope(b.Scope) {
		return errors.New("scope not allowed for this bill")
	}
	// Ensure votes maps exist
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
	now, err := txTimestampSeconds(ctx)
	if err != nil {
		return err
	}
	b.Versions[idx].Votes[invokerID] = Vote{VoterID: invokerID, Choice: ch, Timestamp: now}

	// compute eligible voters
	eligible := 0
	for _, rs := range b.Roles {
		if rs.Has(RoleVoter) {
			eligible++
		}
	}
	// tally votes for this version
	yes, no, abstain := 0, 0, 0
	for _, v := range b.Versions[idx].Votes {
		switch v.Choice {
		case ChoiceYes:
			yes++
		case ChoiceNo:
			no++
		case ChoiceAbstain:
			abstain++
		}
	}
	absence := 0
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
	countFor := func(mask Choice) int {
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
	included := b.Criteria.ExecuteMask | b.Criteria.RejectMask
	participation := 0.0
	if eligible > 0 {
		participation = float64(countFor(included)) / float64(eligible)
	}
	if participation >= b.Quorum {
		execCount := countFor(b.Criteria.ExecuteMask)
		rejCount := countFor(b.Criteria.RejectMask)
		if execCount > rejCount {
			b.AgreedVersionIndex = idx
		}
	}
	if err := c.putBill(ctx, b); err != nil {
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
	_ = ctx.GetStub().SetEvent("VersionVoteAdded", payload)

	if b.AgreedVersionIndex == idx {
		payload2, _ := json.Marshal(map[string]any{"billId": billID, "versionIndex": idx})
		_ = ctx.GetStub().SetEvent("VersionAgreed", payload2)
	}
	return nil
}

// SubmitBill opens the voting window if a version has reached quorum agreement; emits VoteStarted
func (c *BillContract) SubmitBill(ctx contractapi.TransactionContextInterface, billID, startTimeSeconds, durationSeconds string) error {
	b, err := c.getBill(ctx, billID)
	if err != nil {
		return err
	}
	inv, err := GetInvoker(ctx)
	if err != nil {
		return err
	}
	invokerID := inv.ID
	if invokerID != b.Owner && !inv.HasRole(b, RoleProposer) {
		return errors.New("not authorized: only owner/proposer can submit bill for voting")
	}
	if b.Status != StatusDraft {
		return errors.New("bill must be in draft status to submit")
	}
	// Enforce agreed version quorum
	idx := b.AgreedVersionIndex
	if idx < 0 || idx >= len(b.Versions) {
		return errors.New("no version has reached quorum agreement")
	}
	// compute eligible voters and per-version vote counts using Criteria masks
	eligible := 0
	for _, rs := range b.Roles {
		if rs.Has(RoleVoter) {
			eligible++
		}
	}
	yes, no, abstain := 0, 0, 0
	for _, v := range b.Versions[idx].Votes {
		switch v.Choice {
		case ChoiceYes:
			yes++
		case ChoiceNo:
			no++
		case ChoiceAbstain:
			abstain++
		}
	}
	absence := 0
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
	countFor := func(mask Choice) int {
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
	included := b.Criteria.ExecuteMask | b.Criteria.RejectMask
	participation := 0.0
	if eligible > 0 {
		participation = float64(countFor(included)) / float64(eligible)
	}
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
	if err := c.putBill(ctx, b); err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]any{"billId": billID, "start": b.VoteStart, "end": b.VoteEnd, "versionIndex": idx})
	_ = ctx.GetStub().SetEvent("VoteStarted", payload)
	return nil
}

// CastVote records a vote if the invoker is eligible and hasn't voted yet
func (c *BillContract) CastVote(ctx contractapi.TransactionContextInterface, billID, choice string) error {
	b, err := c.getBill(ctx, billID)
	if err != nil {
		return err
	}
	if b.Status != StatusVoting {
		return errors.New("voting is not open")
	}
	now, err := txTimestampSeconds(ctx)
	if err != nil {
		return err
	}
	if now < b.VoteStart || now > b.VoteEnd {
		return errors.New("outside voting window")
	}
	inv, err := GetInvoker(ctx)
	if err != nil {
		return err
	}
	invokerID := inv.ID
	// RBAC: must have VOTER role for this bill
	if !inv.HasRole(b, RoleVoter) {
		return errors.New("not authorized: missing VOTER role for this bill")
	}
	// Scope check (hierarchical)
	if !inv.InScope(b.Scope) {
		return errors.New("scope not allowed for this bill")
	}
	if b.Votes == nil {
		b.Votes = map[string]Vote{}
	}
	if _, exists := b.Votes[invokerID]; exists {
		return errors.New("user has already voted")
	}
	ch, err := ParseChoiceToken(choice)
	if err != nil {
		return fmt.Errorf("invalid choice: %v", err)
	}
	if ch == ChoiceAbsence || ch == ChoiceNone {
		return errors.New("invalid choice (expected YES, NO, or ABSTAIN)")
	}
	b.Votes[invokerID] = Vote{VoterID: invokerID, Choice: ch, Timestamp: now}
	return c.putBill(ctx, b)
}

// EndVote finalizes the vote, computes quorum and outcome using Criteria masks, updates status, emits event
func (c *BillContract) EndVote(ctx contractapi.TransactionContextInterface, billID string) error {
	b, err := c.getBill(ctx, billID)
	if err != nil {
		return err
	}
	if b.Status != StatusVoting {
		return errors.New("bill is not in voting status")
	}
	now, err := txTimestampSeconds(ctx)
	if err != nil {
		return err
	}
	if now < b.VoteEnd {
		return errors.New("voting period has not ended yet")
	}
	// compute counts
	var yes, no, abstain int
	for _, v := range b.Votes {
		switch v.Choice {
		case ChoiceYes:
			yes++
		case ChoiceNo:
			no++
		case ChoiceAbstain:
			abstain++
		}
	}
	// compute eligible voters as those explicitly assigned VOTER role
	eligible := 0
	for _, rs := range b.Roles {
		if rs.Has(RoleVoter) {
			eligible++
		}
	}
	// derive absence
	absence := 0
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
	// helper to sum counts for mask
	countFor := func(mask Choice) int {
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

	included := b.Criteria.ExecuteMask | b.Criteria.RejectMask
	participation := 0.0
	if eligible > 0 {
		participation = float64(countFor(included)) / float64(eligible)
	}

	if participation < b.Quorum {
		b.Status = StatusRejected
	} else {
		execCount := countFor(b.Criteria.ExecuteMask)
		rejCount := countFor(b.Criteria.RejectMask)
		if execCount > rejCount {
			b.Status = StatusExecuted
		} else {
			b.Status = StatusRejected
		}
	}

	if err := c.putBill(ctx, b); err != nil {
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
		"executeCount":  countFor(b.Criteria.ExecuteMask),
		"rejectCount":   countFor(b.Criteria.RejectMask),
		"status":        b.Status,
	})
	_ = ctx.GetStub().SetEvent("VoteEnded", payload)
	return nil
}

// GetBill returns the bill as JSON string
func (c *BillContract) GetBill(ctx contractapi.TransactionContextInterface, billID string) (string, error) {
	b, err := c.getBill(ctx, billID)
	if err != nil {
		return "", err
	}
	out, _ := json.Marshal(b)
	return string(out), nil
}

// Internal helpers
func (c *BillContract) getBill(ctx contractapi.TransactionContextInterface, billID string) (*Bill, error) {
	if billID == "" {
		return nil, errors.New("billID is required")
	}
	key := billKey(billID)
	data, err := ctx.GetStub().GetState(key)
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
	return &b, nil
}

func (c *BillContract) putBill(ctx contractapi.TransactionContextInterface, b *Bill) error {
	data, err := json.Marshal(b)
	if err != nil {
		return fmt.Errorf("failed to marshal bill: %w", err)
	}
	return ctx.GetStub().PutState(billKey(b.ID), data)
}

func (c *BillContract) assetExists(ctx contractapi.TransactionContextInterface, key string) (bool, error) {
	data, err := ctx.GetStub().GetState(key)
	if err != nil {
		return false, err
	}
	return len(data) > 0, nil
}

func billKey(id string) string { return "BILL|" + id }

func txTimestampSeconds(ctx contractapi.TransactionContextInterface) (int64, error) {
	ts, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return 0, err
	}
	return protobufTimestampToSeconds(ts), nil
}

func protobufTimestampToSeconds(ts *timestamp.Timestamp) int64 {
	if ts == nil {
		return 0
	}
	return ts.Seconds
}

func getInvokerID(ctx contractapi.TransactionContextInterface) (string, error) {
	id, err := cid.GetID(ctx.GetStub())
	if err != nil {
		return "", fmt.Errorf("failed to get invoker ID: %w", err)
	}
	return id, nil
}

func getInvokerAttribute(ctx contractapi.TransactionContextInterface, name string) (string, bool) {
	v, ok, err := cid.GetAttributeValue(ctx.GetStub(), name)
	if err != nil || !ok {
		return "", false
	}
	return v, true
}

func firstNonEmpty(a string, aok bool, b string, bok bool) (string, bool) {
	if aok && strings.TrimSpace(a) != "" {
		return a, true
	}
	if bok && strings.TrimSpace(b) != "" {
		return b, true
	}
	return "", false
}

func getFirstNonEmptyString(v string, ok bool) (string, bool) { // helper wrapper
	if ok && strings.TrimSpace(v) != "" {
		return v, true
	}
	return "", false
}

func userHasRole(b *Bill, userID string, role Role) bool {
	mask := b.Roles[userID]
	return mask.Has(role)
}

// checkScope validates if the invoker belongs to the required scope (empty scope means open)
func checkScope(ctx contractapi.TransactionContextInterface, required string) bool {
	required = strings.ToUpper(strings.TrimSpace(required))
	if required == "" {
		return true
	}
	// Accept either single "scope" attribute or CSV list in "scopes"
	if v, ok := getInvokerAttribute(ctx, "scope"); ok {
		if strings.ToUpper(strings.TrimSpace(v)) == required {
			return true
		}
	}
	if v, ok := getInvokerAttribute(ctx, "scopes"); ok {
		for _, s := range splitCSV(v) {
			if strings.ToUpper(strings.TrimSpace(s)) == required {
				return true
			}
		}
	}
	return false
}

func stringSliceContains(items []string, target string) bool {
	for _, v := range items {
		if v == target {
			return true
		}
	}
	return false
}

func stringSliceContainsFold(items []string, targetLower string) bool {
	tl := strings.ToLower(targetLower)
	for _, v := range items {
		if strings.ToLower(strings.TrimSpace(v)) == tl {
			return true
		}
	}
	return false
}

func splitCSV(s string) []string {
	if strings.TrimSpace(s) == "" {
		return []string{}
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func uniqueAppend(items []string, v string) []string {
	for _, it := range items {
		if it == v {
			return items
		}
	}
	return append(items, v)
}

func isTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "t", "yes", "y":
		return true
	default:
		return false
	}
}

// SetBillScope sets the bill scope used for ABAC scope checks. Only owner or PROPOSER may set it.
func (c *BillContract) SetBillScope(ctx contractapi.TransactionContextInterface, billID, scope string) error {
	b, err := c.getBill(ctx, billID)
	if err != nil {
		return err
	}
	inv, err := GetInvoker(ctx)
	if err != nil {
		return err
	}
	invokerID := inv.ID
	if invokerID != b.Owner && !inv.HasRole(b, RoleProposer) {
		return errors.New("not authorized: only owner/proposer can set scope")
	}
	s := normalizeScopePattern(scope)
	if s == "" {
		return errors.New("scope is required")
	}
	b.Scope = s
	return c.putBill(ctx, b)
}

// parseRoleExpr parses expressions like "VOTER|PROPOSER" or "voter, editor" into a Role bitmask.
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
		case "NONE":
			// no-op
		default:
			return RoleNone, fmt.Errorf("unknown role token: %s", tok)
		}
	}
	return mask, nil
}

// SetBillCriteria sets the execution and rejection masks for a bill. Only owner or PROPOSER may set it while in draft.
func (c *BillContract) SetBillCriteria(ctx contractapi.TransactionContextInterface, billID, executeMask, rejectMask string) error {
	b, err := c.getBill(ctx, billID)
	if err != nil {
		return err
	}
	inv, err := GetInvoker(ctx)
	if err != nil {
		return err
	}
	invokerID := inv.ID
	if invokerID != b.Owner && !inv.HasRole(b, RoleProposer) {
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
	if err := c.putBill(ctx, b); err != nil {
		return err
	}
	payload, _ := json.Marshal(map[string]any{"billId": billID, "executeMask": exec, "rejectMask": rej})
	_ = ctx.GetStub().SetEvent("CriteriaUpdated", payload)
	return nil
}
