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
	owner := proposer("owner", "ES:UNION")
	if err := svc.CreateBill(owner, 1, "B1", "Qm1", "v1", "0.5", "ES:UNION:*", "YES", "NO"); err != nil {
		t.Fatalf("create: %v", err)
	}
	// Admin grants voter roles to three users
	a := admin("ES:UNION")
	for _, u := range []string{"v1", "v2", "v3"} {
		if err := svc.AssignRoleForBill(a, "B1", u, "VOTER"); err != nil {
			t.Fatalf("assign %s: %v", u, err)
		}
	}
	// Grant owner voter too so owner is eligible (owner already had PROPOSER|EDITOR)
	if err := svc.AssignRoleForBill(a, "B1", "owner", "VOTER"); err != nil {
		t.Fatalf("assign owner: %v", err)
	}
	v1 := voter("v1", "ES:UNION")
	v2 := voter("v2", "ES:UNION")
	v3 := voter("v3", "ES:UNION")
	if err := svc.VoteOnVersion(v1, 10, "B1", "0", "YES"); err != nil {
		t.Fatalf("v1 yes: %v", err)
	}
	if err := svc.VoteOnVersion(v2, 11, "B1", "0", "YES"); err != nil {
		t.Fatalf("v2 yes: %v", err)
	}
	// Quorum should now be reached (2/4 = 50%) and execMask>rejMask, version agreed
	b, _ := svc.GetBill("B1")
	if b.AgreedVersionIndex != 0 {
		t.Fatalf("expected version 0 agreed, got %d", b.AgreedVersionIndex)
	}
	// Submit for formal voting
	if err := svc.SubmitBill(owner, "B1", "100", "100"); err != nil {
		t.Fatalf("submit: %v", err)
	}
	b, _ = svc.GetBill("B1")
	if b.Status != StatusVoting {
		t.Fatalf("expected voting status, got %s", b.Status)
	}
	// Cast formal votes within window: 3 yes, owner abstains
	owner2 := NewInvoker("owner", []string{"ES:UNION:PROPOSER"})
	if err := svc.CastVote(v1, 150, "B1", "YES"); err != nil {
		t.Fatalf("v1 cast: %v", err)
	}
	if err := svc.CastVote(v2, 150, "B1", "YES"); err != nil {
		t.Fatalf("v2 cast: %v", err)
	}
	if err := svc.CastVote(v3, 150, "B1", "YES"); err != nil {
		t.Fatalf("v3 cast: %v", err)
	}
	if err := svc.CastVote(owner2, 150, "B1", "ABSTAIN"); err != nil {
		t.Fatalf("owner cast: %v", err)
	}
	// Try ending too early
	if err := svc.EndVote(owner, 150, "B1"); err == nil {
		t.Fatal("expected end vote too early error")
	}
	// End after window
	if err := svc.EndVote(owner, 999, "B1"); err != nil {
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
	owner := proposer("owner", "ES:UNION")
	_ = svc.CreateBill(owner, 1, "B1", "Qm1", "v1", "0.5", "ES:UNION:*", "YES", "NO")
	a := admin("ES:UNION")
	_ = svc.AssignRoleForBill(a, "B1", "owner", "VOTER")
	_ = svc.AssignRoleForBill(a, "B1", "v1", "VOTER")
	v := voter("v1", "ES:UNION")
	_ = svc.VoteOnVersion(v, 10, "B1", "0", "YES")
	_ = svc.VoteOnVersion(NewInvoker("owner", []string{"ES:UNION:PROPOSER"}), 11, "B1", "0", "YES")
	if err := svc.SubmitBill(owner, "B1", "200", "100"); err != nil {
		t.Fatalf("submit: %v", err)
	}
	if err := svc.CastVote(v, 50, "B1", "YES"); err == nil {
		t.Fatal("expected outside-window error")
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

func contains(s []string, target string) bool {
	for _, v := range s {
		if v == target {
			return true
		}
	}
	return false
}
