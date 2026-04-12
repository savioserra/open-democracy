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
	electorateIDs := []string{"owner", "v1", "v2", "v3"}
	if err := svc.EndVote(owner, 150, "B1", electorateIDs); err == nil {
		t.Fatal("expected end vote too early error")
	}
	// End after window — delegations resolved automatically
	if err := svc.EndVote(owner, 999, "B1", electorateIDs); err != nil {
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

// ── Delegation / Liquid Democracy tests ─────────────────────────────────

func TestDelegationBasic(t *testing.T) {
	svc, sink := newTestService()
	alice := NewInvoker("alice", []string{"ES:UNION"})
	if err := svc.Delegate(alice, 1, "bob", "ES:UNION:*"); err != nil {
		t.Fatalf("delegate: %v", err)
	}
	d, err := svc.GetDelegation("alice", "ES:UNION:*")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if d.Delegatee != "bob" {
		t.Fatalf("expected bob, got %s", d.Delegatee)
	}
	if !contains(sink.names(), "DelegationCreated") {
		t.Fatal("expected DelegationCreated event")
	}
}

func TestMutualDelegationIsHarmless(t *testing.T) {
	// With depth-1, mutual delegation is harmless: Alice→Bob and Bob→Alice.
	// If neither votes, both are absent. If one votes, the other is represented.
	svc, _ := newTestService()
	alice := NewInvoker("alice", []string{"ES"})
	bob := NewInvoker("bob", []string{"ES"})
	_ = svc.Delegate(alice, 1, "bob", "ES:*")
	if err := svc.Delegate(bob, 2, "alice", "ES:*"); err != nil {
		t.Fatalf("mutual delegation should be allowed with depth-1: %v", err)
	}
	// If only alice votes, bob's delegation to alice gives alice weight 2
	votes := map[string]Vote{"alice": {Choice: ChoiceYes}}
	weights, absent := svc.ResolveDelegatedWeight("ES:*", votes, []string{"alice", "bob"})
	if weights["alice"] != 2 {
		t.Fatalf("expected alice=2 (herself + bob's delegation), got %d", weights["alice"])
	}
	if absent != 0 {
		t.Fatalf("expected 0 absent, got %d", absent)
	}
}

func TestDelegationDepthOneOnly(t *testing.T) {
	// Depth-1: alice → bob → carol. Carol votes YES, dave votes NO.
	// Bob didn't vote, so alice's delegation to bob is wasted (alice absent).
	// Carol gets weight 2 (herself + bob's direct delegation), not 3.
	// YES=2, NO=1, absent=1 → executed (2 > 1).
	svc, _ := newTestService()
	carol := NewInvoker("carol", []string{"ES:UNION:PROPOSER"})
	dave := NewInvoker("dave", []string{"ES:UNION"})

	_ = svc.Delegate(NewInvoker("alice", []string{"ES:UNION"}), 1, "bob", "ES:UNION:*")
	_ = svc.Delegate(NewInvoker("bob", []string{"ES:UNION"}), 2, "carol", "ES:UNION:*")

	_ = svc.CreateBill(carol, 10, "B1", "Qm", "v", "0.25", "ES:UNION:*", "YES", "NO")
	if _, err := svc.VoteOnVersion(carol, 11, "B1", "0", "YES", 4); err != nil {
		t.Fatalf("version vote: %v", err)
	}
	if err := svc.SubmitBill(carol, "B1", "100", "100", 4); err != nil {
		t.Fatalf("submit: %v", err)
	}
	if _, err := svc.CastVote(carol, 150, "B1", "YES"); err != nil {
		t.Fatalf("carol cast: %v", err)
	}
	if _, err := svc.CastVote(dave, 150, "B1", "NO"); err != nil {
		t.Fatalf("dave cast: %v", err)
	}

	// Verify weights directly
	electorate := []string{"alice", "bob", "carol", "dave"}
	votes := map[string]Vote{
		"carol": {Choice: ChoiceYes},
		"dave":  {Choice: ChoiceNo},
	}
	weights, absent := svc.ResolveDelegatedWeight("ES:UNION:*", votes, electorate)
	// carol=2 (herself + bob→carol), dave=1, alice=absent (bob didn't vote)
	if weights["carol"] != 2 {
		t.Fatalf("expected carol weight 2, got %d", weights["carol"])
	}
	if weights["dave"] != 1 {
		t.Fatalf("expected dave weight 1, got %d", weights["dave"])
	}
	if absent != 1 {
		t.Fatalf("expected 1 absent (alice), got %d", absent)
	}

	if err := svc.EndVote(carol, 999, "B1", electorate); err != nil {
		t.Fatalf("end: %v", err)
	}
	b, _ := svc.GetBill("B1")
	if b.Status != StatusExecuted {
		t.Fatalf("expected executed (YES=2 vs NO=1), got %s", b.Status)
	}
}

func TestDelegationMultipleScopes(t *testing.T) {
	// One person can delegate to different people at different scope levels.
	// This mirrors the Brazilian federal model: different representatives
	// at municipal, state, and federal levels.
	svc, _ := newTestService()
	user := NewInvoker("user", []string{"ES:ORG:DIV"})
	_ = svc.Delegate(user, 1, "local_rep", "ES:ORG:DIV:*")
	_ = svc.Delegate(user, 2, "org_rep", "ES:ORG:*")
	_ = svc.Delegate(user, 3, "root_rep", "ES:*")

	d1, _ := svc.GetDelegation("user", "ES:ORG:DIV:*")
	d2, _ := svc.GetDelegation("user", "ES:ORG:*")
	d3, _ := svc.GetDelegation("user", "ES:*")

	if d1.Delegatee != "local_rep" {
		t.Fatalf("expected local_rep at DIV, got %s", d1.Delegatee)
	}
	if d2.Delegatee != "org_rep" {
		t.Fatalf("expected org_rep at ORG, got %s", d2.Delegatee)
	}
	if d3.Delegatee != "root_rep" {
		t.Fatalf("expected root_rep at root, got %s", d3.Delegatee)
	}
}

func TestDelegationOverriddenByDirectVote(t *testing.T) {
	// Alice delegates to Bob, but then votes directly. Her direct vote
	// should count — Bob should NOT get her weight.
	svc, _ := newTestService()
	alice := NewInvoker("alice", []string{"ES:UNION"})
	bob := NewInvoker("bob", []string{"ES:UNION"})
	carol := NewInvoker("carol", []string{"ES:UNION:PROPOSER"})

	_ = svc.Delegate(alice, 1, "bob", "ES:UNION:*")
	_ = svc.CreateBill(carol, 10, "B1", "Qm", "v", "0.25", "ES:UNION:*", "YES", "NO")
	if _, err := svc.VoteOnVersion(carol, 11, "B1", "0", "YES", 3); err != nil {
		t.Fatalf("version vote: %v", err)
	}
	if err := svc.SubmitBill(carol, "B1", "100", "100", 3); err != nil {
		t.Fatalf("submit: %v", err)
	}
	// Both Alice and Bob vote directly
	if _, err := svc.CastVote(alice, 150, "B1", "NO"); err != nil {
		t.Fatalf("alice cast: %v", err)
	}
	if _, err := svc.CastVote(bob, 150, "B1", "YES"); err != nil {
		t.Fatalf("bob cast: %v", err)
	}

	electorate := []string{"alice", "bob", "carol"}
	weights, absence := svc.ResolveDelegatedWeight("ES:UNION:*", map[string]Vote{
		"alice": {Choice: ChoiceNo},
		"bob":   {Choice: ChoiceYes},
	}, electorate)
	// Alice voted directly → weight 1, Bob voted → weight 1 (no delegation absorbed)
	// Carol didn't vote → absent
	if weights["alice"] != 1 || weights["bob"] != 1 {
		t.Fatalf("expected alice=1 bob=1, got alice=%d bob=%d", weights["alice"], weights["bob"])
	}
	if absence != 1 {
		t.Fatalf("expected 1 absent (carol), got %d", absence)
	}
}

func TestRevokeDelegation(t *testing.T) {
	svc, _ := newTestService()
	alice := NewInvoker("alice", []string{"ES"})
	_ = svc.Delegate(alice, 1, "bob", "ES:*")
	if err := svc.RevokeDelegation(alice, "ES:*"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	d, _ := svc.GetDelegation("alice", "ES:*")
	if d != nil {
		t.Fatal("expected nil after revoke")
	}
}

// ── Collecting (popular initiative) tests ────────────────────────────────

func TestCollectingBillAnyoneCanCreate(t *testing.T) {
	svc, sink := newTestService()
	// "nobody" has no roles at all — they should still be able to create a collecting bill.
	nobody := NewInvoker("nobody", []string{"ES:UNION"})
	if err := svc.CreateCollectingBill(nobody, 1, "PET-1", "QmP", "demand X", "ES:UNION:*", "0.5", "YES", "NO", 3); err != nil {
		t.Fatalf("create collecting bill: %v", err)
	}
	b, err := svc.GetBill("PET-1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if b.Status != StatusCollecting {
		t.Fatalf("expected collecting, got %s", b.Status)
	}
	if len(b.Signatures) != 1 {
		t.Fatalf("expected initiator auto-signed, got %d", len(b.Signatures))
	}
	if !contains(sink.names(), "BillCollecting") {
		t.Fatalf("expected BillCollecting event")
	}
}

func TestCollectingThresholdAdvancesToDraft(t *testing.T) {
	svc, sink := newTestService()
	// Community members create a collecting bill for a change at the CORE
	// scope — the revolutionary use case. They cannot normally create bills there.
	community1 := NewInvoker("frank", []string{"ES:COMMUNITY"})
	community2 := NewInvoker("grace", []string{"ES:COMMUNITY"})
	community3 := NewInvoker("hank", []string{"ES:COMMUNITY"})

	if err := svc.CreateCollectingBill(community1, 1, "PET-X", "QmX", "community demands feature X at core level", "ES:CORE:*", "0.5", "YES", "NO", 3); err != nil {
		t.Fatalf("create: %v", err)
	}

	// All eligible voters who will be enrolled on the bill.
	allVoters := []string{"alice", "bob", "carol", "frank", "grace", "hank"}

	if err := svc.SignBill(community2, 2, "PET-X", allVoters); err != nil {
		t.Fatalf("sign 2: %v", err)
	}
	// Not yet advanced (2 of 3).
	b, _ := svc.GetBill("PET-X")
	if b.Status != StatusCollecting {
		t.Fatalf("should still be collecting after 2 sigs")
	}

	// Third signature advances to draft.
	if err := svc.SignBill(community3, 3, "PET-X", allVoters); err != nil {
		t.Fatalf("sign 3 (trigger): %v", err)
	}
	b, _ = svc.GetBill("PET-X")
	if b.Status != StatusDraft {
		t.Fatalf("expected draft, got %s", b.Status)
	}
	if b.Scope != "ES:CORE:*" {
		t.Fatalf("expected ES:CORE:*, got %s", b.Scope)
	}
	// All voters enrolled — including the community members who could
	// never have been enrolled by a core admin.
	for _, uid := range allVoters {
		if !b.Roles[uid].Has(RoleVoter) {
			t.Fatalf("expected %s to have VOTER role", uid)
		}
	}
	if !contains(sink.names(), "BillCollected") {
		t.Fatalf("expected BillCollected event")
	}
}

func TestCollectingRejectsDuplicateSignature(t *testing.T) {
	svc, _ := newTestService()
	u := NewInvoker("u1", []string{"ES"})
	_ = svc.CreateCollectingBill(u, 1, "PET-D", "Qm", "dup", "ES:*", "0.5", "YES", "NO", 5)
	if err := svc.SignBill(u, 2, "PET-D", nil); err == nil {
		t.Fatal("expected duplicate signature error")
	}
}

func TestCollectingCannotSignAfterDraft(t *testing.T) {
	svc, _ := newTestService()
	u1 := NewInvoker("u1", []string{"ES"})
	_ = svc.CreateCollectingBill(u1, 1, "PET-T", "Qm", "t", "ES:*", "0.5", "YES", "NO", 1)
	// threshold=1 means the creator's auto-signature already advanced it.
	b, _ := svc.GetBill("PET-T")
	if b.Status != StatusDraft {
		t.Fatalf("expected draft, got %s", b.Status)
	}
	u2 := NewInvoker("u2", []string{"ES"})
	if err := svc.SignBill(u2, 2, "PET-T", nil); err == nil {
		t.Fatal("expected error signing a non-collecting bill")
	}
}

func TestCollectingBillsAppearInListBills(t *testing.T) {
	svc, _ := newTestService()
	u := NewInvoker("u1", []string{"ES:PROPOSER"})
	for _, id := range []string{"C1", "C2", "C3"} {
		_ = svc.CreateCollectingBill(u, 1, id, "Qm", "d", "ES:*", "0.5", "YES", "NO", 10)
	}
	bills, err := svc.ListBills()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(bills) != 3 {
		t.Fatalf("expected 3, got %d", len(bills))
	}
	for _, b := range bills {
		if b.Status != StatusCollecting {
			t.Fatalf("expected collecting, got %s", b.Status)
		}
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
