package bill

import (
	"encoding/json"
	"fmt"
	"strconv"

	"github.com/golang/protobuf/ptypes/timestamp"
	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// BillContract is the Hyperledger Fabric chaincode entrypoint. Every method
// is a thin wrapper that:
//
//  1. Builds an *Invoker from the X.509 certificate attributes via cid.
//  2. Reads the transaction timestamp from the stub.
//  3. Constructs a Service backed by stub-based Store and EventSink adapters.
//  4. Delegates to the Service so the same business logic runs in Fabric and
//     in the in-process gateway used by the dashboard.
type BillContract struct {
	contractapi.Contract
}

// service builds a Service wired to the given Fabric transaction context.
func (c *BillContract) service(ctx contractapi.TransactionContextInterface) *Service {
	return NewService(newStubStore(ctx), newStubEventSink(ctx))
}

// CreateBill creates a new bill in draft status and registers the first version.
func (c *BillContract) CreateBill(ctx contractapi.TransactionContextInterface, billID, ipfsHash, description, quorum, scope, executeMask, rejectMask string) error {
	caller, err := GetInvoker(ctx)
	if err != nil {
		return err
	}
	now, err := txTimestampSeconds(ctx)
	if err != nil {
		return err
	}
	return c.service(ctx).CreateBill(caller, now, billID, ipfsHash, description, quorum, scope, executeMask, rejectMask)
}

// EditBill adds a new version to a draft bill.
func (c *BillContract) EditBill(ctx contractapi.TransactionContextInterface, billID, ipfsHash, description string) error {
	caller, err := GetInvoker(ctx)
	if err != nil {
		return err
	}
	now, err := txTimestampSeconds(ctx)
	if err != nil {
		return err
	}
	return c.service(ctx).EditBill(caller, now, billID, ipfsHash, description)
}

// AssignRoleForBill grants per-bill roles to a user.
func (c *BillContract) AssignRoleForBill(ctx contractapi.TransactionContextInterface, billID, userID, role string) error {
	caller, err := GetInvoker(ctx)
	if err != nil {
		return err
	}
	return c.service(ctx).AssignRoleForBill(caller, billID, userID, role)
}

// VoteOnVersion records a vote against a draft version. electorate is the
// number of in-scope participants (from MSP or external source).
func (c *BillContract) VoteOnVersion(ctx contractapi.TransactionContextInterface, billID, versionIndex, choice, electorate string) (string, error) {
	caller, err := GetInvoker(ctx)
	if err != nil {
		return "", err
	}
	now, err := txTimestampSeconds(ctx)
	if err != nil {
		return "", err
	}
	n, err := strconv.Atoi(electorate)
	if err != nil || n < 0 {
		return "", fmt.Errorf("invalid electorate: %s", electorate)
	}
	return c.service(ctx).VoteOnVersion(caller, now, billID, versionIndex, choice, n)
}

// SubmitBill opens the formal voting window.
func (c *BillContract) SubmitBill(ctx contractapi.TransactionContextInterface, billID, startTimeSeconds, durationSeconds, electorate string) error {
	caller, err := GetInvoker(ctx)
	if err != nil {
		return err
	}
	n, err := strconv.Atoi(electorate)
	if err != nil || n < 0 {
		return fmt.Errorf("invalid electorate: %s", electorate)
	}
	return c.service(ctx).SubmitBill(caller, billID, startTimeSeconds, durationSeconds, n)
}

// CastVote records a vote during the open voting window. Returns the
// one-time vote receipt ID.
func (c *BillContract) CastVote(ctx contractapi.TransactionContextInterface, billID, choice string) (string, error) {
	caller, err := GetInvoker(ctx)
	if err != nil {
		return "", err
	}
	now, err := txTimestampSeconds(ctx)
	if err != nil {
		return "", err
	}
	return c.service(ctx).CastVote(caller, now, billID, choice)
}

// EndVote finalizes the vote. electorate is the in-scope participant count
// at close time.
// EndVote finalizes the vote. electorateCSV is a comma-separated list of
// in-scope participant IDs used for delegation resolution and ABSENCE.
func (c *BillContract) EndVote(ctx contractapi.TransactionContextInterface, billID, electorateCSV string) error {
	caller, err := GetInvoker(ctx)
	if err != nil {
		return err
	}
	now, err := txTimestampSeconds(ctx)
	if err != nil {
		return err
	}
	ids := splitCSV(electorateCSV)
	return c.service(ctx).EndVote(caller, now, billID, ids)
}

// SetBillScope updates the scope of a bill.
func (c *BillContract) SetBillScope(ctx contractapi.TransactionContextInterface, billID, scope string) error {
	caller, err := GetInvoker(ctx)
	if err != nil {
		return err
	}
	return c.service(ctx).SetBillScope(caller, billID, scope)
}

// SetBillCriteria updates the execution / rejection masks of a draft bill.
func (c *BillContract) SetBillCriteria(ctx contractapi.TransactionContextInterface, billID, executeMask, rejectMask string) error {
	caller, err := GetInvoker(ctx)
	if err != nil {
		return err
	}
	return c.service(ctx).SetBillCriteria(caller, billID, executeMask, rejectMask)
}

// CreateCollectingBill creates a bill in "collecting" status (popular
// initiative). Anyone can call this — no PROPOSER/ADMIN role required.
func (c *BillContract) CreateCollectingBill(ctx contractapi.TransactionContextInterface, billID, ipfsHash, description, targetScope, quorum, executeMask, rejectMask, threshold string) error {
	caller, err := GetInvoker(ctx)
	if err != nil {
		return err
	}
	now, err := txTimestampSeconds(ctx)
	if err != nil {
		return err
	}
	th, err := strconv.Atoi(threshold)
	if err != nil || th < 1 {
		return fmt.Errorf("invalid threshold: %s", threshold)
	}
	return c.service(ctx).CreateCollectingBill(caller, now, billID, ipfsHash, description, targetScope, quorum, executeMask, rejectMask, th)
}

// SignBill adds a signature to a collecting-status bill. When the threshold
// is reached, the bill transitions to draft with eligible voters enrolled.
func (c *BillContract) SignBill(ctx contractapi.TransactionContextInterface, billID, eligibleVotersCSV string) error {
	caller, err := GetInvoker(ctx)
	if err != nil {
		return err
	}
	now, err := txTimestampSeconds(ctx)
	if err != nil {
		return err
	}
	eligible := splitCSV(eligibleVotersCSV)
	return c.service(ctx).SignBill(caller, now, billID, eligible)
}

// GetBill returns the bill as a JSON string.
func (c *BillContract) GetBill(ctx contractapi.TransactionContextInterface, billID string) (string, error) {
	b, err := c.service(ctx).GetBill(billID)
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(b)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

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
