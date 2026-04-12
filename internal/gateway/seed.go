package gateway

import (
	"errors"
	"fmt"
	"log"
	"strconv"
	"time"

	"open-democracy/chaincode/bill"
)

// Seed populates the registry with participants representing the
// open-democracy project's own contributor hierarchy and, if the ledger is
// empty, creates sample proposals that demonstrate how the repository itself
// can be governed through its own decision-making system — architecture
// changes, feature additions, and release approvals all go through the same
// bill → version → quorum → vote → execute flow that the chaincode models.
//
// Hierarchy (scope tree):
//
//	OPENDEMOCRACY                                    → project root
//	├─ CORE                                          → core maintainers team
//	│  ├─ admin      (savio)                         → project lead, full admin
//	│  ├─ proposer   (alice)                         → senior maintainer, can propose
//	│  ├─ editor     (bob)                           → technical writer / reviewer
//	│  └─ voters     (alice, bob, carol, dave, eve)  → all core contributors vote
//	├─ COMMUNITY                                     → community contributors
//	│  ├─ admin      (alice, scope COMMUNITY)        → community team lead
//	│  ├─ proposer   (frank)                         → community contributor
//	│  └─ voters     (frank, grace)                  → community members vote
//	└─ root admin    (savio, scope OPENDEMOCRACY)    → can act across all scopes
func Seed(reg *Registry, svc *bill.Service) error {
	// Register default participants. Skip any that already exist in the
	// registry (loaded from the ledger by loadPersistedParticipants) so
	// user modifications are never silently overwritten by seed data.
	seedAdmin := bill.NewInvoker("_seed", []string{"OPENDEMOCRACY:ADMIN"})
	now := time.Now().Unix()
	for _, p := range defaultParticipants() {
		if _, err := reg.Get(p.ID); err == nil {
			continue // already loaded from ledger — don't overwrite
		}
		// Write to ledger so seed participants are on-ledger like
		// dashboard-added ones (auditable, event-sourced).
		if err := svc.RegisterParticipant(seedAdmin, now, p.ID, p.Display, p.Claims); err != nil {
			log.Printf("seed: register participant %s: %v", p.ID, err)
		}
		reg.Add(p)
	}
	bills, err := svc.ListBills()
	if err != nil {
		return fmt.Errorf("list bills during seed: %w", err)
	}
	if len(bills) > 0 {
		return nil
	}
	return seedSampleBills(reg, svc)
}

func defaultParticipants() []Participant {
	return []Participant{
		// Project lead — root admin over the entire project scope.
		{ID: "savio", Display: "Savio (project lead)", Claims: []string{
			"OPENDEMOCRACY:ADMIN",
			"OPENDEMOCRACY:PROPOSER",
			"OPENDEMOCRACY",
		}},
		// Senior maintainer — can propose and vote on core decisions.
		{ID: "alice", Display: "Alice (senior maintainer)", Claims: []string{
			"OPENDEMOCRACY:CORE:PROPOSER",
			"OPENDEMOCRACY:COMMUNITY:ADMIN",
			"OPENDEMOCRACY:CORE",
			"OPENDEMOCRACY:COMMUNITY",
		}},
		// Technical reviewer — can edit proposals and vote.
		{ID: "bob", Display: "Bob (tech reviewer)", Claims: []string{
			"OPENDEMOCRACY:CORE:EDITOR",
			"OPENDEMOCRACY:CORE",
		}},
		// Core contributors — vote on architecture and feature decisions.
		{ID: "carol", Display: "Carol (core contributor)", Claims: []string{
			"OPENDEMOCRACY:CORE",
		}},
		{ID: "dave", Display: "Dave (core contributor)", Claims: []string{
			"OPENDEMOCRACY:CORE",
		}},
		{ID: "eve", Display: "Eve (core contributor)", Claims: []string{
			"OPENDEMOCRACY:CORE",
		}},
		// Community contributors — can propose and vote on community-scoped items.
		{ID: "frank", Display: "Frank (community contributor)", Claims: []string{
			"OPENDEMOCRACY:COMMUNITY:PROPOSER",
			"OPENDEMOCRACY:COMMUNITY",
		}},
		{ID: "grace", Display: "Grace (community contributor)", Claims: []string{
			"OPENDEMOCRACY:COMMUNITY",
		}},
	}
}

func seedSampleBills(reg *Registry, svc *bill.Service) error {
	now := time.Now().Unix()
	savio, _ := reg.Get("savio")
	alice, _ := reg.Get("alice")
	bob, _ := reg.Get("bob")
	carol, _ := reg.Get("carol")
	dave, _ := reg.Get("dave")
	frank, _ := reg.Get("frank")

	// Electorate counts (resolved from the registry by scope).
	// CORE scope covers: savio, alice, bob, carol, dave, eve = 6
	// COMMUNITY scope covers: alice, frank, grace = 3 (alice has both)
	coreElectorate := 6

	// ── PROP-001: Architecture decision — extract Service layer ──────
	//
	// This mirrors the actual refactoring that was done in this repo:
	// separating chaincode business logic into a pure-Go Service so the
	// same rules run both inside Fabric and in the gateway. Already
	// agreed and executed — demonstrates a completed governance cycle.
	// No VOTER role assignment — everyone in CORE scope can vote.
	if err := svc.CreateBill(alice.Invoker(), now-3600, "PROP-001",
		"QmServiceLayerRefactor2024",
		"Extract chaincode business logic into a reusable Service layer decoupled from Fabric stub interfaces",
		"0.5",
		"OPENDEMOCRACY:CORE:*",
		"YES", "NO",
	); err != nil {
		return fmt.Errorf("seed PROP-001: %w", err)
	}
	// Bob gets EDITOR role so he can refine the proposal text.
	if err := svc.AssignRoleForBill(savio.Invoker(), "PROP-001", "bob", "EDITOR"); err != nil {
		return fmt.Errorf("seed assign bob editor PROP-001: %w", err)
	}
	if err := svc.EditBill(bob.Invoker(), now-3500, "PROP-001",
		"QmServiceLayerRefactorV2",
		"v2: adds Store/EventSink interfaces and MemStore for gateway + tests",
	); err != nil {
		return fmt.Errorf("seed PROP-001 edit: %w", err)
	}
	// Core team votes on version 1. Anyone in scope can vote — no
	// VOTER assignment needed.
	for _, v := range []struct {
		id     string
		choice string
	}{
		{"alice", "YES"}, {"bob", "YES"}, {"carol", "YES"},
	} {
		p, _ := reg.Get(v.id)
		if _, err := svc.VoteOnVersion(p.Invoker(), now-3400, "PROP-001", "1", v.choice, coreElectorate); err != nil {
			return fmt.Errorf("seed %s vote PROP-001: %w", v.id, err)
		}
	}
	// Submit, formal votes, end → executed
	if err := svc.SubmitBill(alice.Invoker(), "PROP-001",
		fmt.Sprintf("%d", now-3300), "600", coreElectorate,
	); err != nil {
		return fmt.Errorf("seed submit PROP-001: %w", err)
	}
	for _, v := range []struct {
		id     string
		choice string
	}{
		{"alice", "YES"}, {"bob", "YES"}, {"carol", "YES"}, {"dave", "YES"}, {"eve", "ABSTAIN"},
	} {
		p, _ := reg.Get(v.id)
		if _, err := svc.CastVote(p.Invoker(), now-3200, "PROP-001", v.choice); err != nil {
			return fmt.Errorf("seed %s cast PROP-001: %w", v.id, err)
		}
	}
	coreIDs := []string{"savio", "alice", "bob", "carol", "dave", "eve"}
	if err := svc.EndVote(savio.Invoker(), now-2600, "PROP-001", coreIDs); err != nil {
		return fmt.Errorf("seed end PROP-001: %w", err)
	}

	// ── PROP-002: Feature proposal — Hotwire Turbo + Tailwind CSS ────
	if err := svc.CreateBill(alice.Invoker(), now-1800, "PROP-002",
		"QmHotwireTurboTailwind",
		"Migrate dashboard frontend from hand-written CSS to Tailwind CSS with Hotwire Turbo for partial page updates and Turbo Streams over SSE",
		"0.5",
		"OPENDEMOCRACY:CORE:*",
		"YES", "NO",
	); err != nil {
		return fmt.Errorf("seed PROP-002: %w", err)
	}
	for _, v := range []struct {
		id     string
		choice string
	}{
		{"alice", "YES"}, {"carol", "YES"}, {"dave", "YES"},
	} {
		p, _ := reg.Get(v.id)
		if _, err := svc.VoteOnVersion(p.Invoker(), now-1700, "PROP-002", "0", v.choice, coreElectorate); err != nil {
			return fmt.Errorf("seed %s vote PROP-002: %w", v.id, err)
		}
	}

	// ── PROP-003: Governance policy — 60% quorum + ABSENCE in reject ─
	if err := svc.CreateBill(savio.Invoker(), now-900, "PROP-003",
		"QmGovernanceQuorumPolicy",
		"Require 60% quorum for architecture decisions; count absent voters toward rejection to ensure active participation",
		"0.6",
		"OPENDEMOCRACY:CORE:*",
		"YES", "NO|ABSENCE",
	); err != nil {
		return fmt.Errorf("seed PROP-003: %w", err)
	}
	if _, err := svc.VoteOnVersion(carol.Invoker(), now-800, "PROP-003", "0", "YES", coreElectorate); err != nil {
		return fmt.Errorf("seed carol vote PROP-003: %w", err)
	}

	// ── PROP-004: Community scope — contributor onboarding guide ──────
	if err := svc.CreateBill(frank.Invoker(), now-600, "PROP-004",
		"QmContributorOnboarding",
		"Write a contributor onboarding guide covering local setup, coding standards, and the proposal workflow itself",
		"0.5",
		"OPENDEMOCRACY:COMMUNITY:*",
		"YES", "NO",
	); err != nil {
		return fmt.Errorf("seed PROP-004: %w", err)
	}

	// ── PROP-005: Release approval — v0.2.0, active voting window ────
	if err := svc.CreateBill(savio.Invoker(), now-300, "PROP-005",
		"QmReleaseV020Checklist",
		"Approve release v0.2.0: gateway + dashboard + Tailwind/Turbo frontend, containerized with docker-compose",
		"0.6",
		"OPENDEMOCRACY:CORE:*",
		"YES", "NO",
	); err != nil {
		return fmt.Errorf("seed PROP-005: %w", err)
	}
	// 4 of 6 = 67% ≥ 60% quorum needed for PROP-005
	for _, v := range []struct {
		id     string
		choice string
	}{
		{"alice", "YES"}, {"bob", "YES"}, {"carol", "YES"}, {"dave", "YES"},
	} {
		p, _ := reg.Get(v.id)
		if _, err := svc.VoteOnVersion(p.Invoker(), now-250, "PROP-005", "0", v.choice, coreElectorate); err != nil {
			return fmt.Errorf("seed %s vote PROP-005: %w", v.id, err)
		}
	}
	if err := svc.SubmitBill(savio.Invoker(), "PROP-005",
		fmt.Sprintf("%d", now-200), "86400", coreElectorate,
	); err != nil {
		return fmt.Errorf("seed submit PROP-005: %w", err)
	}
	// Two early votes cast — dashboard shows active window to interact with.
	if _, err := svc.CastVote(alice.Invoker(), now-150, "PROP-005", "YES"); err != nil {
		return fmt.Errorf("seed alice cast PROP-005: %w", err)
	}
	if _, err := svc.CastVote(dave.Invoker(), now-100, "PROP-005", "YES"); err != nil {
		return fmt.Errorf("seed dave cast PROP-005: %w", err)
	}

	// ── Delegations (Liquid Democracy) ───────────────────────────────
	//
	// Brazilian Constitution, Art. 1, sole paragraph: "All power emanates
	// from the people, who exercise it through elected representatives or
	// directly." The delegation model implements this dual path: every
	// participant retains the right to vote directly, but can choose to
	// delegate to a trusted representative.
	//
	// Seeded delegations:
	// - Eve delegates to Alice on CORE scope (trusts her technical judgment)
	// - Grace delegates to Frank on COMMUNITY scope (Frank is her voice)
	// - Dave delegates to Carol on CORE scope (Carol is active, Dave is busy)
	//
	// Depth-1: each delegate must vote directly. If Carol delegates to
	// Alice, Alice gets +1 weight — but only if Alice votes personally.
	eve, _ := reg.Get("eve")
	grace, _ := reg.Get("grace")
	if err := svc.Delegate(eve.Invoker(), now-50, "alice", "OPENDEMOCRACY:CORE:*"); err != nil {
		return fmt.Errorf("seed delegation eve→alice: %w", err)
	}
	if err := svc.Delegate(grace.Invoker(), now-40, "frank", "OPENDEMOCRACY:COMMUNITY:*"); err != nil {
		return fmt.Errorf("seed delegation grace→frank: %w", err)
	}
	if err := svc.Delegate(dave.Invoker(), now-30, "carol", "OPENDEMOCRACY:CORE:*"); err != nil {
		return fmt.Errorf("seed delegation dave→carol: %w", err)
	}

	return nil
}

// formatTime is a tiny helper used by the dashboard templates.
func formatTime(epoch int64) string {
	if epoch == 0 {
		return "—"
	}
	return time.Unix(epoch, 0).UTC().Format(time.RFC3339)
}

// parseQuorum accepts quorum as either "0.5" or "50%" and returns the
// canonical "0.5" string.
func parseQuorum(s string) (string, error) {
	if s == "" {
		return "", errors.New("quorum is required")
	}
	if len(s) > 0 && s[len(s)-1] == '%' {
		v, err := strconv.ParseFloat(s[:len(s)-1], 64)
		if err != nil {
			return "", err
		}
		return strconv.FormatFloat(v/100.0, 'f', -1, 64), nil
	}
	return s, nil
}
