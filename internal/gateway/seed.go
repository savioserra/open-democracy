package gateway

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"open-democracy/chaincode/bill"
)

// Seed populates the registry with a small federation of demo participants
// and, if the ledger is empty, creates a sample bill so the dashboard has
// something to render on first boot.
//
// The participants form a two-org hierarchy under "ES" (a placeholder root
// for "España" / Educational Society / whatever the deployer wants):
//
//	ES                                 → root
//	└─ TEACHER_UNION                   → org
//	   ├─ DIVISION_1                   → division
//	   │  ├─ proposer (Ada)
//	   │  ├─ editor   (Bea)
//	   │  ├─ voter    (Carla, Diego, Elena)
//	   │  └─ admin    (Felipe, scope DIVISION_1)
//	   └─ DIVISION_2
//	      └─ admin    (Gala, scope DIVISION_2)
//	└─ root admin     (Helena, scope ES)
func Seed(reg *Registry, svc *bill.Service) error {
	for _, p := range defaultParticipants() {
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
		{ID: "helena", Display: "Helena (root admin)", Claims: []string{"ES:ADMIN"}},
		{ID: "felipe", Display: "Felipe (Div1 admin)", Claims: []string{"ES:TEACHER_UNION:DIVISION_1:ADMIN"}},
		{ID: "gala", Display: "Gala (Div2 admin)", Claims: []string{"ES:TEACHER_UNION:DIVISION_2:ADMIN"}},
		{ID: "ada", Display: "Ada (Div1 proposer)", Claims: []string{"ES:TEACHER_UNION:DIVISION_1:PROPOSER", "ES:TEACHER_UNION:DIVISION_1"}},
		{ID: "bea", Display: "Bea (Div1 editor)", Claims: []string{"ES:TEACHER_UNION:DIVISION_1:EDITOR", "ES:TEACHER_UNION:DIVISION_1"}},
		{ID: "carla", Display: "Carla (Div1 voter)", Claims: []string{"ES:TEACHER_UNION:DIVISION_1"}},
		{ID: "diego", Display: "Diego (Div1 voter)", Claims: []string{"ES:TEACHER_UNION:DIVISION_1"}},
		{ID: "elena", Display: "Elena (Div1 voter)", Claims: []string{"ES:TEACHER_UNION:DIVISION_1"}},
		{ID: "ivan", Display: "Iván (Div2 proposer)", Claims: []string{"ES:TEACHER_UNION:DIVISION_2:PROPOSER", "ES:TEACHER_UNION:DIVISION_2"}},
		{ID: "julia", Display: "Julia (Div2 voter)", Claims: []string{"ES:TEACHER_UNION:DIVISION_2"}},
	}
}

func seedSampleBills(reg *Registry, svc *bill.Service) error {
	now := time.Now().Unix()
	ada, _ := reg.Get("ada")
	felipe, _ := reg.Get("felipe")
	helena, _ := reg.Get("helena")
	ivan, _ := reg.Get("ivan")
	gala, _ := reg.Get("gala")

	// Bill 1: Division 1 proposal, in draft, with assigned voters and one
	// version vote already cast so the dashboard shows non-trivial state.
	if err := svc.CreateBill(ada.Invoker(), now, "BILL-001",
		"QmExampleHashOne",
		"Adopt remote teaching guidelines for Division 1",
		"0.5",
		"ES:TEACHER_UNION:DIVISION_1:*",
		"YES", "NO",
	); err != nil {
		return fmt.Errorf("seed BILL-001: %w", err)
	}
	for _, vid := range []string{"carla", "diego", "elena", "ada"} {
		if err := svc.AssignRoleForBill(felipe.Invoker(), "BILL-001", vid, "VOTER"); err != nil {
			return fmt.Errorf("seed assign %s: %w", vid, err)
		}
	}
	if err := svc.AssignRoleForBill(helena.Invoker(), "BILL-001", "bea", "EDITOR"); err != nil {
		return fmt.Errorf("seed assign bea: %w", err)
	}
	carla, _ := reg.Get("carla")
	if err := svc.VoteOnVersion(carla.Invoker(), now+1, "BILL-001", "0", "YES"); err != nil {
		return fmt.Errorf("seed carla vote: %w", err)
	}

	// Bill 2: Division 2 proposal, in draft, no votes yet, includes ABSENCE
	// in reject mask so the dashboard shows criteria handling.
	if err := svc.CreateBill(ivan.Invoker(), now, "BILL-002",
		"QmExampleHashTwo",
		"Allocate Division 2 budget for Q3",
		"0.6",
		"ES:TEACHER_UNION:DIVISION_2:*",
		"YES", "NO|ABSENCE",
	); err != nil {
		return fmt.Errorf("seed BILL-002: %w", err)
	}
	for _, vid := range []string{"julia", "ivan"} {
		if err := svc.AssignRoleForBill(gala.Invoker(), "BILL-002", vid, "VOTER"); err != nil {
			return fmt.Errorf("seed assign %s: %w", vid, err)
		}
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
