package bill

import (
	"strings"
	"sync"
	"testing"
)

// recordingSink captures emitted events for assertion in tests.
type recordingSink struct {
	mu     sync.Mutex
	events []string
}

func (r *recordingSink) Emit(name string, _ []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, name)
	return nil
}

func (r *recordingSink) names() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.events))
	copy(out, r.events)
	return out
}

func newTestService() (*Service, *recordingSink) {
	sink := &recordingSink{}
	return NewService(NewMemStore(), sink), sink
}

func admin(scope string) *Invoker { return NewInvoker("admin", []string{scope + ":ADMIN"}) }

func proposer(id, scope string) *Invoker {
	return NewInvoker(id, []string{scope + ":PROPOSER"})
}

func voter(id, scope string) *Invoker { return NewInvoker(id, []string{scope}) }

func TestCreateBillRequiresAuthority(t *testing.T) {
	svc, _ := newTestService()
	stranger := NewInvoker("nobody", nil)
	err := svc.CreateBill(stranger, 1, "B1", "Qm1", "draft 1", "0.5", "", "", "")
	if err == nil {
		t.Fatal("expected error for unauthorized caller")
	}
}

func TestCreateBillProposerCanCreateInScope(t *testing.T) {
	svc, sink := newTestService()
	p := proposer("alice", "ES:UNION:DIV1")
	if err := svc.CreateBill(p, 100, "B1", "QmHash", "first draft", "0.5", "ES:UNION:DIV1:*", "", ""); err != nil {
		t.Fatalf("create: %v", err)
	}
	b, err := svc.GetBill("B1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if b.Owner != "alice" || b.Status != StatusDraft {
		t.Fatalf("unexpected bill: %+v", b)
	}
	if b.Scope != "ES:UNION:DIV1:*" {
		t.Fatalf("unexpected scope %q", b.Scope)
	}
	if want, got := 1, len(b.Versions); want != got {
		t.Fatalf("versions: want %d got %d", want, got)
	}
	// proposer becomes editor by default
	if !b.Roles["alice"].Has(RoleEditor) {
		t.Fatalf("creator should have editor role")
	}
	if !contains(sink.names(), "BillCreated") {
		t.Fatalf("expected BillCreated event, got %v", sink.names())
	}
}

func TestCreateBillRejectsScopeOutsideAuthority(t *testing.T) {
	svc, _ := newTestService()
	p := proposer("alice", "ES:UNION:DIV1")
	err := svc.CreateBill(p, 1, "B1", "Qm", "d", "0.5", "ES:UNION:DIV2:*", "", "")
	if err == nil || !strings.Contains(err.Error(), "not authorized") {
		t.Fatalf("expected scope authorization error, got %v", err)
	}
}

func TestEditBillRequiresEditorOrOwner(t *testing.T) {
	svc, _ := newTestService()
	owner := proposer("owner", "ES:UNION")
	if err := svc.CreateBill(owner, 1, "B1", "Qm1", "v1", "0.5", "ES:UNION:*", "", ""); err != nil {
		t.Fatalf("create: %v", err)
	}
	stranger := NewInvoker("eve", []string{"ES:UNION"})
	if err := svc.EditBill(stranger, 2, "B1", "Qm2", "v2"); err == nil {
		t.Fatal("expected unauthorized edit error")
	}
	if err := svc.EditBill(owner, 2, "B1", "Qm2", "v2"); err != nil {
		t.Fatalf("owner edit: %v", err)
	}
	b, _ := svc.GetBill("B1")
	if len(b.Versions) != 2 {
		t.Fatalf("expected 2 versions, got %d", len(b.Versions))
	}
}

func TestVotingFlowEndToEnd(t *testing.T) {
	svc, sink := newTestService()
	electorate := 4 // simulating 4 in-scope participants
	owner := proposer("owner", "ES:UNION")
	if err := svc.CreateBill(owner, 1, "B1", "Qm1", "v1", "0.5", "ES:UNION:*", "YES", "NO"); err != nil {
		t.Fatalf("create: %v", err)
	}
	// No VOTER role assignment needed — scope is the authorization.
	v1 := voter("v1", "ES:UNION")
	v2 := voter("v2", "ES:UNION")
	v3 := voter("v3", "ES:UNION")
	if _, err := svc.VoteOnVersion(v1, 10, "B1", "0", "YES", electorate); err != nil {
		t.Fatalf("v1 yes: %v", err)
	}
	if _, err := svc.VoteOnVersion(v2, 11, "B1", "0", "YES", electorate); err != nil {
		t.Fatalf("v2 yes: %v", err)
	}
	// Quorum reached (2/4 = 50%), version agreed
	b, _ := svc.GetBill("B1")
	if b.AgreedVersionIndex != 0 {
		t.Fatalf("expected version 0 agreed, got %d", b.AgreedVersionIndex)
	}
	// Submit for formal voting
	if err := svc.SubmitBill(owner, "B1", "100", "100", electorate); err != nil {
		t.Fatalf("submit: %v", err)
	}
	b, _ = svc.GetBill("B1")
	if b.Status != StatusVoting {
		t.Fatalf("expected voting status, got %s", b.Status)
	}
	// Cast formal votes — anyone in scope can vote, returns receipt IDs
	owner2 := NewInvoker("owner", []string{"ES:UNION:PROPOSER"})
	receipt1, err := svc.CastVote(v1, 150, "B1", "YES")
	if err != nil {
		t.Fatalf("v1 cast: %v", err)
	}
	if receipt1 == "" {
		t.Fatal("expected non-empty vote receipt")
	}
	if _, err := svc.CastVote(v2, 150, "B1", "YES"); err != nil {
		t.Fatalf("v2 cast: %v", err)
	}
	if _, err := svc.CastVote(v3, 150, "B1", "YES"); err != nil {
		t.Fatalf("v3 cast: %v", err)
	}
	if _, err := svc.CastVote(owner2, 150, "B1", "ABSTAIN"); err != nil {
		t.Fatalf("owner cast: %v", err)
	}
	// Verify vote receipt
	r, err := svc.VerifyVote(receipt1)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if r.BillID != "B1" || r.Choice != ChoiceYes {
		t.Fatalf("receipt mismatch: %+v", r)
	}
	// Try ending too early
	if err := svc.EndVote(owner, 150, "B1", electorate); err == nil {
		t.Fatal("expected end vote too early error")
	}
	// End after window
	if err := svc.EndVote(owner, 999, "B1", electorate); err != nil {
		t.Fatalf("end vote: %v", err)
	}
	b, _ = svc.GetBill("B1")
	if b.Status != StatusExecuted {
		t.Fatalf("expected executed, got %s", b.Status)
	}
	if !contains(sink.names(), "VoteEnded") {
		t.Fatalf("expected VoteEnded event")
	}
}

func TestCastVoteRejectsOutsideWindow(t *testing.T) {
	svc, _ := newTestService()
	electorate := 2
	owner := proposer("owner", "ES:UNION")
	_ = svc.CreateBill(owner, 1, "B1", "Qm1", "v1", "0.5", "ES:UNION:*", "YES", "NO")
	v := voter("v1", "ES:UNION")
	_, _ = svc.VoteOnVersion(v, 10, "B1", "0", "YES", electorate)
	_, _ = svc.VoteOnVersion(NewInvoker("owner", []string{"ES:UNION:PROPOSER"}), 11, "B1", "0", "YES", electorate)
	if err := svc.SubmitBill(owner, "B1", "200", "100", electorate); err != nil {
		t.Fatalf("submit: %v", err)
	}
	if _, err := svc.CastVote(v, 50, "B1", "YES"); err == nil {
		t.Fatal("expected outside-window error")
	}
}

func TestScopeBasedVotingRejectsOutOfScope(t *testing.T) {
	svc, _ := newTestService()
	owner := proposer("owner", "ES:UNION:DIV1")
	_ = svc.CreateBill(owner, 1, "B1", "Qm1", "v1", "0.5", "ES:UNION:DIV1:*", "YES", "NO")
	outsider := NewInvoker("outsider", []string{"ES:UNION:DIV2"})
	if _, err := svc.VoteOnVersion(outsider, 10, "B1", "0", "YES", 5); err == nil {
		t.Fatal("expected scope rejection for out-of-scope voter")
	}
}

func TestAssignRoleRequiresAdmin(t *testing.T) {
	svc, _ := newTestService()
	owner := proposer("owner", "ES:UNION")
	_ = svc.CreateBill(owner, 1, "B1", "Qm1", "v1", "0.5", "ES:UNION:*", "", "")
	if err := svc.AssignRoleForBill(owner, "B1", "v1", "VOTER"); err == nil {
		t.Fatal("expected proposer-without-admin to be rejected")
	}
	a := admin("ES:UNION")
	if err := svc.AssignRoleForBill(a, "B1", "v1", "VOTER"); err != nil {
		t.Fatalf("admin assign: %v", err)
	}
}

func TestScopeHierarchyCovers(t *testing.T) {
	// Higher-level admin should be able to act on a more specific scope.
	svc, _ := newTestService()
	highAdmin := admin("ES")
	owner := NewInvoker("owner", []string{"ES:UNION:DIV1:PROPOSER"})
	if err := svc.CreateBill(owner, 1, "B1", "Qm1", "v1", "0.5", "ES:UNION:DIV1:*", "", ""); err != nil {
		t.Fatalf("create: %v", err)
	}
	if err := svc.AssignRoleForBill(highAdmin, "B1", "v1", "VOTER"); err != nil {
		t.Fatalf("high admin assign: %v", err)
	}
}

func TestListBillsReturnsAll(t *testing.T) {
	svc, _ := newTestService()
	p := proposer("alice", "ES:UNION")
	for _, id := range []string{"B1", "B2", "B3"} {
		if err := svc.CreateBill(p, 1, id, "Qm", "v", "0.5", "ES:UNION:*", "", ""); err != nil {
			t.Fatalf("create %s: %v", id, err)
		}
	}
	bills, err := svc.ListBills()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(bills) != 3 {
		t.Fatalf("expected 3 bills, got %d", len(bills))
	}
}

// ── Petition tests ──────────────────────────────────────────────────────

func TestPetitionAnyoneCanCreate(t *testing.T) {
	svc, sink := newTestService()
	// "nobody" has no roles at all — they should still be able to petition.
	nobody := NewInvoker("nobody", []string{"ES:UNION"})
	if err := svc.CreatePetition(nobody, 1, "PET-1", "QmP", "demand X", "ES:UNION:*", "0.5", "YES", "NO", 3); err != nil {
		t.Fatalf("create petition: %v", err)
	}
	p, err := svc.GetPetition("PET-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if p.Status != PetitionOpen {
		t.Fatalf("expected open, got %s", p.Status)
	}
	if len(p.Signatures) != 1 {
		t.Fatalf("expected initiator auto-signed, got %d", len(p.Signatures))
	}
	if !contains(sink.names(), "PetitionCreated") {
		t.Fatalf("expected PetitionCreated event")
	}
}

func TestPetitionThresholdTriggersBill(t *testing.T) {
	svc, sink := newTestService()
	// Community members petition for a change at the CORE scope — the
	// revolutionary use case. They cannot normally create bills there.
	community1 := NewInvoker("frank", []string{"ES:COMMUNITY"})
	community2 := NewInvoker("grace", []string{"ES:COMMUNITY"})
	community3 := NewInvoker("hank", []string{"ES:COMMUNITY"})

	if err := svc.CreatePetition(community1, 1, "PET-X", "QmX", "community demands feature X at core level", "ES:CORE:*", "0.5", "YES", "NO", 3); err != nil {
		t.Fatalf("create: %v", err)
	}

	// All eligible voters who will be enrolled on the resulting bill.
	allVoters := []string{"alice", "bob", "carol", "frank", "grace", "hank"}

	if err := svc.SignPetition(community2, 2, "PET-X", allVoters); err != nil {
		t.Fatalf("sign 2: %v", err)
	}
	// Not yet triggered (2 of 3).
	p, _ := svc.GetPetition("PET-X")
	if p.Status != PetitionOpen {
		t.Fatalf("should still be open after 2 sigs")
	}

	// Third signature triggers it.
	if err := svc.SignPetition(community3, 3, "PET-X", allVoters); err != nil {
		t.Fatalf("sign 3 (trigger): %v", err)
	}
	p, _ = svc.GetPetition("PET-X")
	if p.Status != PetitionTriggered {
		t.Fatalf("expected triggered, got %s", p.Status)
	}
	if p.CreatedBillID != "PET-PET-X" {
		t.Fatalf("expected bill PET-PET-X, got %s", p.CreatedBillID)
	}

	// The auto-created bill should exist, be scoped to CORE, and have
	// all voters enrolled — including the community members who could
	// never have been enrolled by a core admin.
	b, err := svc.GetBill("PET-PET-X")
	if err != nil {
		t.Fatalf("get bill: %v", err)
	}
	if b.Scope != "ES:CORE:*" {
		t.Fatalf("expected ES:CORE:*, got %s", b.Scope)
	}
	if b.SourcePetitionID != "PET-X" {
		t.Fatalf("expected source petition PET-X, got %s", b.SourcePetitionID)
	}
	for _, uid := range allVoters {
		if !b.Roles[uid].Has(RoleVoter) {
			t.Fatalf("expected %s to have VOTER role", uid)
		}
	}
	if !contains(sink.names(), "PetitionTriggered") {
		t.Fatalf("expected PetitionTriggered event")
	}
}

func TestPetitionRejectsDuplicateSignature(t *testing.T) {
	svc, _ := newTestService()
	u := NewInvoker("u1", []string{"ES"})
	_ = svc.CreatePetition(u, 1, "PET-D", "Qm", "dup", "ES:*", "0.5", "YES", "NO", 5)
	if err := svc.SignPetition(u, 2, "PET-D", nil); err == nil {
		t.Fatal("expected duplicate signature error")
	}
}

func TestPetitionCannotSignAfterTriggered(t *testing.T) {
	svc, _ := newTestService()
	u1 := NewInvoker("u1", []string{"ES"})
	_ = svc.CreatePetition(u1, 1, "PET-T", "Qm", "t", "ES:*", "0.5", "YES", "NO", 1)
	// threshold=1 means the creator's auto-signature already triggered it.
	p, _ := svc.GetPetition("PET-T")
	if p.Status != PetitionTriggered {
		t.Fatalf("expected triggered, got %s", p.Status)
	}
	u2 := NewInvoker("u2", []string{"ES"})
	if err := svc.SignPetition(u2, 2, "PET-T", nil); err == nil {
		t.Fatal("expected error signing a triggered petition")
	}
}

func TestListPetitions(t *testing.T) {
	svc, _ := newTestService()
	u := NewInvoker("u1", []string{"ES:PROPOSER"})
	for _, id := range []string{"P1", "P2", "P3"} {
		_ = svc.CreatePetition(u, 1, id, "Qm", "d", "ES:*", "0.5", "YES", "NO", 10)
	}
	petitions, err := svc.ListPetitions()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(petitions) != 3 {
		t.Fatalf("expected 3, got %d", len(petitions))
	}
}

func contains(s []string, target string) bool {
	for _, v := range s {
		if v == target {
			return true
		}
	}
	return false
}
